"""Detached elevated session owner; this is a process, never an installed service."""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import json
import re
import secrets
import signal
import uuid
from pathlib import Path

from aiohttp import web

from .errors import ClientError
from .models import SOURCES, Server, decode_servers, now
from .process import launch
from .profiles import verify_profile
from .runtime import LifetimeLock, owner_id, prepare_runtime, protect, reject_link, write_descriptor

MAX_RPC_BYTES = 384_000
KNOWN_STATES = {
    "INITIAL",
    "CONNECTING",
    "WAIT",
    "AUTH",
    "GET_CONFIG",
    "ASSIGN_IP",
    "ADD_ROUTES",
    "CONNECTED",
    "RECONNECTING",
    "EXITING",
    "RESOLVE",
    "TCP_CONNECT",
}


def cleanup_runtime_profiles(directory: Path):
    """Called only after acquiring the lifetime lock; remove crash leftovers."""
    for child in directory.iterdir():
        if not re.fullmatch(r"[a-f0-9]{32}", child.name):
            continue
        reject_link(child)
        if not child.is_dir():
            raise ClientError("Unexpected runtime session storage; review it manually.")
        if any(path.name not in {"profile.ovpn", "management.secret"} for path in child.iterdir()):
            raise ClientError("Unexpected runtime session files; review them manually.")
        for name in ("profile.ovpn", "management.secret"):
            path = child / name
            reject_link(path)
            path.unlink(missing_ok=True)
        child.rmdir()


def server_from_rpc(row: dict) -> Server:
    if not isinstance(row, dict):
        raise ClientError("Invalid session server metadata.")
    row = dict(row)
    row["profile_distribution"] = row.pop("distribution", None)
    current = now().isoformat()
    # Reuse the same endpoint/identity/distribution decoder rather than trusting IPC fields.
    envelope = {
        "schema_version": 1,
        "captured_at": current,
        "published_at": current,
        "publication_id": "sha256:" + "0" * 64,
        "content_sha256": "0" * 64,
        "payload": {
            "index": {
                "schema_version": 2,
                "source": SOURCES["ipspeed"],
                "generated_at": current,
                "sources": {k: {"url": v, "status": "complete"} for k, v in SOURCES.items()},
                "crawl_status": "complete",
                "server_count": 1,
                "active_count": int(row.get("active") is True),
                "servers": [row],
            }
        },
    }
    return decode_servers(envelope).servers[0]


class ManagementEngine:
    def __init__(self, binary: Path, directory: Path, owner: str, *, launcher=None):
        from functools import partial

        self.binary, self.directory, self.owner = binary, directory, owner
        self.launcher = launcher or partial(launch, owner=owner)
        self.process = None
        self.listener = self.writer = None
        self.state = "CONNECTING"
        self.failure = None
        self.password = secrets.token_hex(32)
        self.tasks = set()
        self.closed = False

    async def start(self, raw: bytes):
        self.directory.mkdir(exist_ok=False)
        protect(self.directory, self.owner, directory=True)
        profile = self.directory / "profile.ovpn"
        password = self.directory / "management.secret"
        for path, data in ((profile, raw), (password, (self.password + "\n").encode())):
            with path.open("xb") as handle:
                handle.write(data)
            protect(path, self.owner)
        self.listener = await asyncio.start_server(self._accept, "127.0.0.1", 0, limit=16384)
        port = self.listener.sockets[0].getsockname()[1]
        args = [
            "--config",
            str(profile),
            "--management",
            "127.0.0.1",
            str(port),
            str(password),
            "--management-client",
            "--management-hold",
            "--management-query-passwords",
            "--verb",
            "3",
        ]
        try:
            self.process = await asyncio.to_thread(self.launcher, self.binary, args, self.directory)
        except Exception:
            await self.stop()
            raise

    def _accept(self, reader, writer):
        task = asyncio.create_task(self._peer(reader, writer))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def _peer(self, reader, writer):
        peer = writer.get_extra_info("peername")
        accepted = False
        try:
            # A reverse management password authenticates us to OpenVPN. Verify
            # the peer belongs to our retained child before revealing that password.
            for _ in range(200):
                if self.closed or self.writer is not None:
                    return
                if self.process and peer and peer[0] == "127.0.0.1":
                    if await asyncio.to_thread(self.process.owns_peer, peer[1]):
                        accepted = True
                        break
                await asyncio.sleep(0.05)
            if not accepted:
                return
            self.writer = writer
            writer.write((self.password + "\nstate on\nbytecount 1\nhold release\n").encode())
            await writer.drain()
            while not self.closed:
                line = await reader.readline()
                if not line:
                    break
                value = line.decode("utf-8", errors="replace").strip()
                if value.startswith(">STATE:"):
                    parts = value[7:].split(",")
                    if len(parts) > 1 and parts[1] in KNOWN_STATES:
                        self.state = parts[1]
                elif value.startswith((">PASSWORD:", ">FATAL:")):
                    self.failure = (
                        "OpenVPN requested unsupported credentials or reported a fatal error."
                    )
                    break
            if not self.closed and self.failure is None:
                self.failure = "OpenVPN management connection closed."
        except (OSError, ValueError, asyncio.LimitOverrunError):
            if accepted and not self.closed:
                self.failure = "OpenVPN management communication failed."
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
            if accepted:
                self.writer = None

    async def stop(self):
        if self.closed:
            return
        self.closed = True
        writer = self.writer
        if writer:
            with contextlib.suppress(OSError):
                writer.write(b"signal SIGTERM\n")
                await writer.drain()
            for _ in range(100):
                if not self.process or not self.process.alive():
                    break
                await asyncio.sleep(0.1)
            writer.close()
        if self.listener:
            self.listener.close()
            await self.listener.wait_closed()
        try:
            if self.process:
                await self.process.stop()
        finally:
            for task in list(self.tasks):
                task.cancel()
            await asyncio.gather(*self.tasks, return_exceptions=True)
            for name in ("profile.ovpn", "management.secret"):
                path = self.directory / name
                reject_link(path)
                path.unlink(missing_ok=True)
            if self.directory.exists():
                self.directory.rmdir()


class SessionController:
    def __init__(
        self,
        binary: Path,
        directory: Path,
        owner: str,
        *,
        engine_factory=ManagementEngine,
        timeout=60,
    ):
        self.binary, self.directory, self.owner = binary, directory, owner
        self.engine_factory, self.timeout = engine_factory, timeout
        self.engine = self.monitor = None
        self.session_id = self.server_id = None
        self.state, self.error = "DISCONNECTED", None
        self.events = []
        self.lock = asyncio.Lock()

    def status(self) -> dict:
        return {
            "state": self.state,
            "session_id": self.session_id,
            "server_id": self.server_id,
            "error": self.error,
            "logs": list(self.events[-30:]),
        }

    def event(self, state: str):
        self.events.append({"at": now().isoformat(), "state": state})
        del self.events[:-100]

    async def connect(self, data: dict) -> dict:
        async with self.lock:
            if self.engine is not None:
                raise ClientError(
                    "A session already exists; disconnect it before connecting another server."
                )
            if not isinstance(data, dict) or set(data) != {"server", "profile"}:
                raise ClientError("Invalid connect request fields.")
            server = server_from_rpc(data["server"])
            try:
                if not isinstance(data["profile"], str) or len(data["profile"]) > 342_000:
                    raise ValueError
                raw = base64.b64decode(data["profile"], validate=True)
            except (ValueError, TypeError):
                raise ClientError("Invalid encoded profile.") from None
            verify_profile(raw, server, for_connection=True)
            self.session_id, self.server_id = uuid.uuid4().hex, server.id
            self.state, self.error = "CONNECTING", None
            self.event(self.state)
            engine = self.engine_factory(self.binary, self.directory / self.session_id, self.owner)
            self.engine = engine
            try:
                await engine.start(raw)
            except Exception:
                self.engine = None
                self.state, self.error = (
                    "FAILED",
                    "OpenVPN startup failed; check prerequisites and permissions.",
                )
                self.event(self.state)
                with contextlib.suppress(Exception):
                    await engine.stop()
                raise ClientError(self.error) from None
            self.monitor = asyncio.create_task(self._monitor(engine))
            return self.status()

    async def _monitor(self, engine):
        deadline = asyncio.get_running_loop().time() + self.timeout
        connected = False
        previous = None
        while self.engine is engine:
            failure = engine.failure
            if not failure and engine.process and not engine.process.alive():
                failure = "OpenVPN process exited."
            current = engine.state
            if current == "CONNECTED":
                connected = True
                deadline = None
                self.state = "CONNECTED"
            else:
                self.state = "RECONNECTING" if connected else "CONNECTING"
                if deadline is None:
                    deadline = asyncio.get_running_loop().time() + self.timeout
            if previous != self.state:
                self.event(self.state)
                previous = self.state
            if deadline is not None and asyncio.get_running_loop().time() >= deadline:
                failure = "OpenVPN startup/recovery exceeded the 60-second deadline."
            if failure:
                async with self.lock:
                    if self.engine is engine:
                        self.state, self.error = "FAILED", failure
                        self.event(self.state)
                        await engine.stop()
                        self.engine = None
                return
            await asyncio.sleep(0.1)

    async def disconnect(self, expected: str | None) -> dict:
        async with self.lock:
            if expected != self.session_id:
                raise ClientError("Session changed; inspect status before disconnecting.")
            if self.monitor:
                self.monitor.cancel()
                await asyncio.gather(self.monitor, return_exceptions=True)
                self.monitor = None
            if self.engine:
                await self.engine.stop()
                self.engine = None
            self.state, self.error = "DISCONNECTED", None
            self.event(self.state)
            return self.status()

    async def close(self):
        await self.disconnect(self.session_id)


def rpc_application(controller: SessionController, token: str, generation: str) -> web.Application:
    @web.middleware
    async def authenticate(request, handler):
        authorization = request.headers.get("Authorization", "")
        if (
            request.headers.get("Origin")
            or not secrets.compare_digest(authorization.encode(), ("Bearer " + token).encode())
            or request.headers.get("X-Session-Generation") != generation
        ):
            return web.json_response({"error": "Unauthorized local session request."}, status=401)
        try:
            return await handler(request)
        except ClientError as error:
            return web.json_response({"error": str(error)}, status=409)
        except (ValueError, TypeError, json.JSONDecodeError):
            return web.json_response({"error": "Invalid local session request."}, status=400)

    app = web.Application(middlewares=[authenticate], client_max_size=MAX_RPC_BYTES)

    async def status(request):
        return web.json_response(controller.status())

    async def connect(request):
        return web.json_response(await controller.connect(await request.json()))

    async def disconnect(request):
        body = await request.json()
        if not isinstance(body, dict) or set(body) != {"session_id"}:
            raise ClientError("Invalid disconnect request fields.")
        return web.json_response(await controller.disconnect(body["session_id"]))

    app.router.add_get("/status", status)
    app.router.add_get("/logs", status)
    app.router.add_post("/connect", connect)
    app.router.add_post("/disconnect", disconnect)
    return app


async def run(owner: str, binary: Path):
    directory = prepare_runtime(owner)
    lock = LifetimeLock(directory / "supervisor.lock")
    protect(directory / "supervisor.lock", owner)
    descriptor = directory / "session.json"
    token, generation = secrets.token_hex(32), uuid.uuid4().hex
    controller = SessionController(binary, directory, owner)
    runner = web.AppRunner(rpc_application(controller, token, generation), access_log=None)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for name in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(name, stop.set)
        except NotImplementedError:
            signal.signal(name, lambda *_: loop.call_soon_threadsafe(stop.set))
    try:
        cleanup_runtime_profiles(directory)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        write_descriptor(
            descriptor,
            owner,
            {
                "protocol_version": 1,
                "owner": owner,
                "port": port,
                "token": token,
                "generation": generation,
            },
        )
        await stop.wait()
    finally:
        try:
            await controller.close()
        finally:
            try:
                await runner.cleanup()
            finally:
                # Only the lifetime-lock owner can remove this generation's descriptor.
                descriptor.unlink(missing_ok=True)
                lock.close()


def main():
    parser = argparse.ArgumentParser(description="Internal elevated OpenVPN session supervisor")
    parser.add_argument("--owner", required=True)
    parser.add_argument("--openvpn-path", type=Path, required=True)
    args = parser.parse_args()
    try:
        asyncio.run(run(owner_id(args.owner), args.openvpn_path))
    except (ClientError, OSError, KeyboardInterrupt):
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
