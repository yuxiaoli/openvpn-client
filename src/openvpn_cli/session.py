"""Frontend connection to the shared supervisor, independent of the Worker API."""

from __future__ import annotations

import base64
import os
import subprocess
import sys
import time

import httpx

from .config import Settings
from .errors import ClientError
from .installer import Runner, discover_openvpn, native_checks, require_version
from .models import Server
from .runtime import owner_id, read_descriptor, require_privilege, runtime_path


class SessionClient:
    def __init__(self, settings: Settings, *, transport=None):
        self.settings = settings
        self.owner = owner_id(settings.owner)
        self.path = runtime_path(self.owner) / "session.json"
        self.observed_session_id = None
        self.http = httpx.Client(
            timeout=15, trust_env=False, follow_redirects=False, transport=transport
        )

    def close(self):
        self.http.close()

    def descriptor(self):
        return read_descriptor(self.path, self.owner)

    def request(self, endpoint: str, data: dict | None = None, *, descriptor=None) -> dict:
        descriptor = descriptor or self.descriptor()
        if descriptor is None:
            raise ClientError("No session supervisor is running.")
        try:
            with self.http.stream(
                "GET" if data is None else "POST",
                f"http://127.0.0.1:{descriptor['port']}{endpoint}",
                headers={
                    "Authorization": "Bearer " + descriptor["token"],
                    "X-Session-Generation": descriptor["generation"],
                },
                json=data,
                timeout=30 if endpoint == "/disconnect" else 15 if endpoint == "/connect" else 3,
            ) as response:
                body = bytearray()
                for chunk in response.iter_bytes(chunk_size=8192):
                    if len(body) + len(chunk) > 65_536:
                        raise ClientError("Local session returned an oversized response.")
                    body.extend(chunk)
                import json

                value = json.loads(body)
            if not isinstance(value, dict):
                raise ValueError
            if response.status_code != 200:
                # The RPC peer is local and authenticated; still don't echo arbitrary bodies.
                if response.status_code == 409:
                    raise ClientError(
                        "Session request conflicted or failed validation; inspect status and retry."
                    )
                raise ClientError(f"Local session request failed (HTTP {response.status_code}).")
            return value
        except (httpx.HTTPError, ValueError):
            raise ClientError(
                "Session supervisor is unavailable. No saved PID will be adopted or terminated."
            ) from None

    def status(self) -> dict:
        if self.descriptor() is None:
            return {
                "state": "DISCONNECTED",
                "session_id": None,
                "server_id": None,
                "error": None,
                "logs": [],
            }
        result = self.request("/status")
        self.observed_session_id = result.get("session_id")
        return result

    def ensure(self):
        descriptor = self.descriptor()
        if descriptor:
            try:
                self.request("/status", descriptor=descriptor)
                return
            except ClientError:
                pass
        require_privilege()
        binary = discover_openvpn(self.settings.openvpn_path)
        if binary is None:
            raise ClientError("OpenVPN Community is missing. Run setup --install first.")
        output = Runner()([str(binary), "--version"])
        import re

        match = re.search(r"OpenVPN\s+(\S+)", output)
        if not match:
            raise ClientError("Configured executable is not OpenVPN Community.")
        require_version(match.group(1))
        if not native_checks(binary)["networking_ready"]:
            raise ClientError(
                "OpenVPN driver/service or native DNS helpers are unavailable. Run doctor."
            )
        environment = {
            k: v
            for k, v in os.environ.items()
            if k not in {"OPENVPN_KV_TOKEN", "CLOUDFLARE_API_TOKEN"}
        }
        kwargs = {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "shell": False,
            "env": environment,
            "close_fds": True,
        }
        if os.name == "nt":
            kwargs["creationflags"] = (
                subprocess.DETACHED_PROCESS
                | subprocess.CREATE_NEW_PROCESS_GROUP
                | subprocess.CREATE_NO_WINDOW
            )
        else:
            kwargs["start_new_session"] = True
        subprocess.Popen(
            [
                sys.executable,
                "-m",
                "openvpn_cli.supervisor",
                "--owner",
                self.owner,
                "--openvpn-path",
                str(binary),
            ],
            **kwargs,
        )
        for _ in range(100):
            descriptor = self.descriptor()
            if descriptor:
                try:
                    self.request("/status", descriptor=descriptor)
                    return
                except ClientError:
                    pass
            time.sleep(0.1)
        raise ClientError(
            "Supervisor startup failed. Check elevation, account ownership and OpenVPN prerequisites."
        )

    def connect(self, server: Server, raw: bytes, *, cancelled=None) -> dict:
        require_privilege()
        self.ensure()
        result = self.request(
            "/connect",
            {"server": server.public(), "profile": base64.b64encode(raw).decode("ascii")},
        )
        expected = result.get("session_id")
        self.observed_session_id = expected
        try:
            deadline = time.monotonic() + 75
            while (
                result.get("state") in {"CONNECTING", "RECONNECTING"}
                and time.monotonic() < deadline
            ):
                if cancelled and cancelled():
                    # A closing TUI detaches while the supervisor completes startup.
                    return result
                time.sleep(0.2)
                result = self.status()
                if result.get("session_id") != expected:
                    raise ClientError("Session changed while waiting for connection.")
            if result.get("state") != "CONNECTED":
                raise ClientError(result.get("error") or "VPN did not reach CONNECTED state.")
            return result
        except KeyboardInterrupt:
            self.disconnect(expected)
            raise

    def disconnect(self, expected: str | None = None) -> dict:
        require_privilege()
        expected = expected or self.observed_session_id
        status = self.status()
        if status["session_id"] is None:
            return status
        result = self.request("/disconnect", {"session_id": expected or status["session_id"]})
        self.observed_session_id = result.get("session_id")
        return result
