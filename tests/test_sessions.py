from __future__ import annotations

import asyncio
import base64
import json
import subprocess
import sys
from pathlib import Path

import httpx
import psutil
import pytest
from aiohttp import ClientSession, web
from conftest import envelope, profile

from openvpn_cli import runtime, session, supervisor
from openvpn_cli.config import Settings
from openvpn_cli.errors import ClientError
from openvpn_cli.models import decode_servers
from openvpn_cli.process import OwnedProcess, parse_service_reply, windows_startup_message
from openvpn_cli.supervisor import ManagementEngine, SessionController, rpc_application


class FakeProcess:
    def alive(self):
        return True


class FakeEngine:
    instances = []

    def __init__(self, binary, directory, owner):
        self.state, self.failure = "CONNECTING", None
        self.process = FakeProcess()
        self.stops = 0
        self.directory = directory
        self.instances.append(self)

    async def start(self, raw):
        self.raw = raw

    async def stop(self):
        self.stops += 1


def payload():
    server = decode_servers(envelope()).servers[0]
    return {"server": server.public(), "profile": base64.b64encode(profile()).decode()}


@pytest.fixture
def controller(tmp_path):
    FakeEngine.instances = []
    return SessionController(Path("/openvpn"), tmp_path, "owner", engine_factory=FakeEngine)


async def test_single_session_connected_only_after_management_state(controller):
    started = await controller.connect(payload())
    assert started["state"] == "CONNECTING"
    engine = FakeEngine.instances[-1]
    with pytest.raises(ClientError, match="already"):
        await controller.connect(payload())
    engine.state = "CONNECTED"
    await asyncio.sleep(0.15)
    assert controller.status()["state"] == "CONNECTED"
    with pytest.raises(ClientError, match="changed"):
        await controller.disconnect("stale-session")
    assert engine.stops == 0
    await controller.disconnect(started["session_id"])
    assert engine.stops == 1
    assert controller.status()["state"] == "DISCONNECTED"
    restarted = await controller.connect(payload())
    assert restarted["session_id"] != started["session_id"]
    await controller.close()


async def test_same_server_recovery_and_deadline(controller):
    controller.timeout = 0.15
    await controller.connect(payload())
    engine = FakeEngine.instances[-1]
    engine.state = "CONNECTED"
    await asyncio.sleep(0.12)
    engine.state = "RECONNECTING"
    await asyncio.sleep(0.12)
    assert controller.status()["state"] == "RECONNECTING"
    for _ in range(20):
        if controller.status()["state"] == "FAILED":
            break
        await asyncio.sleep(0.05)
    assert controller.status()["state"] == "FAILED"
    assert engine.stops == 1
    assert controller.engine is None
    await controller.close()


async def test_bad_profile_or_extra_rpc_fields_cannot_start_process(controller):
    bad = payload()
    bad["profile"] = base64.b64encode(b"bad-profile").decode()
    with pytest.raises(ClientError):
        await controller.connect(bad)
    with pytest.raises(ClientError):
        await controller.connect({**payload(), "executable": "/arbitrary"})
    assert FakeEngine.instances == []


async def test_concurrent_connections_cannot_launch_two_tunnels(controller):
    results = await asyncio.gather(
        controller.connect(payload()), controller.connect(payload()), return_exceptions=True
    )
    assert sum(isinstance(result, dict) for result in results) == 1
    assert sum(isinstance(result, ClientError) for result in results) == 1
    assert len(FakeEngine.instances) == 1
    await controller.close()


async def test_authenticated_rpc_rejects_origin_unknown_route_and_oversize(controller):
    token, generation = "a" * 64, "b" * 32
    runner = web.AppRunner(rpc_application(controller, token, generation))
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    url = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
    headers = {"Authorization": "Bearer " + token, "X-Session-Generation": generation}
    try:
        async with ClientSession() as client:
            assert (await client.get(url + "/status")).status == 401
            assert (
                await client.get(
                    url + "/status", headers={**headers, "Origin": "https://evil.test"}
                )
            ).status == 401
            assert (await client.get(url + "/execute", headers=headers)).status == 404
            assert (
                await client.post(url + "/connect", data="x" * 400_000, headers=headers)
            ).status == 413
            connected = await client.post(url + "/connect", json=payload(), headers=headers)
            assert connected.status == 200
            result = await connected.json()
            assert result["state"] == "CONNECTING"
            # Another interface attaches to the same supervisor.
            status = await (await client.get(url + "/status", headers=headers)).json()
            assert status["session_id"] == result["session_id"]
            assert (
                await client.post(
                    url + "/disconnect", json={"session_id": "stale"}, headers=headers
                )
            ).status == 409
            assert (
                await client.post(
                    url + "/disconnect", json={"session_id": result["session_id"]}, headers=headers
                )
            ).status == 200
    finally:
        await controller.close()
        await runner.cleanup()


def test_descriptor_validation_and_lock(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "protect", lambda *args, **kwargs: None)
    monkeypatch.setattr(runtime, "verify_descriptor_permissions", lambda *args: None)
    path = tmp_path / "session.json"
    owner = runtime.owner_id()
    data = {
        "protocol_version": 1,
        "owner": owner,
        "port": 43210,
        "token": "a" * 64,
        "generation": "b" * 32,
    }
    runtime.write_descriptor(path, owner, data)
    if sys.platform != "win32":
        path.chmod(0o600)
    assert runtime.read_descriptor(path, owner) == data
    data["port"] = "arbitrary-host"
    path.write_text(json.dumps(data))
    with pytest.raises(ClientError):
        runtime.read_descriptor(path, owner)
    lock = runtime.LifetimeLock(tmp_path / "supervisor.lock")
    try:
        with pytest.raises(ClientError):
            runtime.LifetimeLock(tmp_path / "supervisor.lock")
    finally:
        lock.close()


def test_unavailable_supervisor_does_not_adopt_pid(tmp_path, monkeypatch):
    monkeypatch.setattr(session, "runtime_path", lambda _: tmp_path)
    monkeypatch.setattr(session, "owner_id", lambda _: "owner")
    monkeypatch.setattr(
        session,
        "read_descriptor",
        lambda path, owner: {"port": 43210, "token": "a" * 64, "generation": "b" * 32, "pid": 1},
    )

    def fail(request):
        raise httpx.ConnectError("unavailable", request=request)

    client = session.SessionClient(Settings(), transport=httpx.MockTransport(fail))
    with pytest.raises(ClientError, match="No saved PID"):
        client.status()
    client.close()


def test_service_message_and_pid_protocol():
    message = windows_startup_message(
        Path("C:/runtime with spaces"), ["--config", "C:/runtime with spaces/a.ovpn"]
    )
    parts = message.decode("utf-16-le").split("\0")
    assert len(parts) == 4
    assert '"C:/runtime with spaces/a.ovpn"' in parts[1]
    assert parse_service_reply("0x00000000\n0x00001234\nProcess ID\n".encode("utf-16-le")) == 0x1234
    with pytest.raises(ClientError):
        parse_service_reply("0x20000000\nstartup failed\nerror".encode("utf-16-le"))


@pytest.mark.parametrize("lost_management", [False, True])
async def test_real_management_transport_fake_process_and_cleanup(
    tmp_path, monkeypatch, lost_management
):
    monkeypatch.setattr(supervisor, "protect", lambda *args, **kwargs: None)
    script = Path(__file__).parent / "fake_openvpn.py"
    error_path = tmp_path / "fake-process-error.txt"

    def launcher(binary, args, directory):
        with error_path.open("wb") as errors:
            process = subprocess.Popen(
                [sys._base_executable, str(script), *args],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=errors,
            )
        return OwnedProcess(psutil.Process(process.pid), popen=process)

    directory = tmp_path / "runtime"
    engine = ManagementEngine(Path(sys.executable), directory, "owner", launcher=launcher)
    await engine.start(profile())
    try:
        for _ in range(100):
            if engine.state == "CONNECTED":
                break
            await asyncio.sleep(0.05)
        assert engine.state == "CONNECTED", (
            engine.failure,
            engine.process.alive(),
            engine.writer is not None,
            engine.process.popen.poll(),
            error_path.read_text(),
        )
        assert engine.process.alive()
        if lost_management:
            # A supervisor crash closes this socket; the reverse management child
            # must exit instead of leaving a tunnel owned only by a saved PID.
            engine.writer.close()
            await engine.writer.wait_closed()
            for _ in range(100):
                if not engine.process.alive():
                    break
                await asyncio.sleep(0.05)
            assert not engine.process.alive()
    finally:
        await engine.stop()
    assert not directory.exists()
    assert not engine.process.alive()


def test_crash_leftover_profiles_are_cleaned_under_lifetime_lock(tmp_path):
    directory = tmp_path / ("c" * 32)
    directory.mkdir()
    (directory / "profile.ovpn").write_bytes(b"synthetic profile")
    (directory / "management.secret").write_text("synthetic management secret")
    unrelated = tmp_path / "unrelated.txt"
    unrelated.write_text("preserve")
    supervisor.cleanup_runtime_profiles(tmp_path)
    assert not directory.exists()
    assert unrelated.read_text() == "preserve"
    directory.mkdir()
    (directory / "unexpected-file").write_text("preserve")
    with pytest.raises(ClientError, match="Unexpected"):
        supervisor.cleanup_runtime_profiles(tmp_path)
    assert (directory / "unexpected-file").exists()


def test_frontend_disconnect_keeps_previously_observed_session_id(monkeypatch):
    monkeypatch.setattr(session, "require_privilege", lambda: None)
    client = session.SessionClient(Settings())
    requests = []
    client.observed_session_id = "old-session"

    def request(endpoint, data=None, **kwargs):
        requests.append((endpoint, data))
        return {"state": "CONNECTED", "session_id": "new-session"}

    monkeypatch.setattr(client, "descriptor", lambda: {"port": 43210})
    monkeypatch.setattr(client, "request", request)
    try:
        client.disconnect()
        assert requests[-1] == ("/disconnect", {"session_id": "old-session"})
    finally:
        client.close()


@pytest.mark.skipif(
    not runtime.privileged(), reason="Native ACL/ownership verification requires manual elevation"
)
def test_native_discovery_permissions(tmp_path):
    owner = runtime.owner_id()
    path = tmp_path / "protected-session.json"
    data = {
        "protocol_version": 1,
        "owner": owner,
        "port": 43210,
        "token": "a" * 64,
        "generation": "b" * 32,
    }
    runtime.write_descriptor(path, owner, data)
    assert runtime.read_descriptor(path, owner) == data
    if sys.platform == "win32":
        import win32security

        security = win32security.GetNamedSecurityInfo(
            str(path), win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION
        )
        acl = security.GetSecurityDescriptorDacl()
        acl.AddAccessAllowedAce(
            win32security.ACL_REVISION, 0x1F01FF, win32security.ConvertStringSidToSid("S-1-1-0")
        )
        win32security.SetNamedSecurityInfo(
            str(path),
            win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION,
            None,
            None,
            acl,
            None,
        )
    else:
        path.chmod(0o644)
    with pytest.raises(ClientError, match="permissions"):
        runtime.read_descriptor(path, owner)
