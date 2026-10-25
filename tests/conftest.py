from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import httpx
import pytest

from openvpn_cli.api import CatalogService, WorkerClient
from openvpn_cli.config import Settings
from openvpn_cli.models import SOURCES, identity
from openvpn_cli.profiles import PROFILE_HOST


def profile(host="1.1.1.1", extra=""):
    return (
        f"client\ndev tun\nproto udp\nremote {host} 1194\n{extra}"
        "<ca>\nSYNTHETIC CA - NOT A CERTIFICATE\n</ca>\n"
        "<cert>\nSYNTHETIC CERTIFICATE\n</cert>\n"
        "<key>\nSYNTHETIC PRIVATE KEY - NO CREDENTIAL\n</key>\n"
    ).encode()


def row(
    *,
    host="1.1.1.1",
    source="ipspeed",
    active=True,
    rank=1,
    ping=20,
    uptime=3,
    location="Japan",
    extra="",
):
    raw = profile(host, extra)
    digest = hashlib.sha256(raw).hexdigest()
    timestamp = datetime.now(timezone.utc).isoformat()
    key = f"ovpn/sha256/{digest}/fixture.ovpn"
    return {
        "id": identity(source, host, 1194, "udp"),
        "source": source,
        "location": location,
        "remote_host": host,
        "remote_port": 1194,
        "protocol": "udp",
        "active": active,
        "refresh_status": "current" if active else "not_selected",
        "rank": rank,
        "rank_score": 0.8,
        "ping_ms": ping,
        "uptime_days": uptime,
        "first_seen_at": timestamp,
        "last_seen_at": timestamp,
        "seen_count": 2,
        "filename": "fixture.ovpn",
        "config_sha256": digest,
        "config_bytes": len(raw),
        "object_key": key,
        "download_url": f"https://{PROFILE_HOST}/{key}",
        "profile_distribution": {
            "status": "verified",
            "sha256": digest,
            "bytes": len(raw),
            "public_verified_at": timestamp,
        },
    }


def envelope(rows=None):
    rows = (
        rows
        if rows is not None
        else [
            row(),
            row(host="8.8.8.8", source="vpngate", active=False, rank=2, ping=9999, location="USA"),
        ]
    )
    timestamp = datetime.now(timezone.utc).isoformat()
    return {
        "schema_version": 1,
        "captured_at": timestamp,
        "published_at": timestamp,
        "publication_id": "sha256:" + "a" * 64,
        "content_sha256": "a" * 64,
        "payload": {
            "index": {
                "schema_version": 2,
                "source": SOURCES["ipspeed"],
                "sources": {k: {"url": v, "status": "complete"} for k, v in SOURCES.items()},
                "generated_at": timestamp,
                "crawl_status": "complete",
                "server_count": len(rows),
                "active_count": sum(r["active"] for r in rows),
                "servers": rows,
            }
        },
    }


def geography():
    timestamp = datetime.now(timezone.utc).isoformat()
    return {
        "schema": "ipspeed-geolocation-cache-v1",
        "schema_version": 1,
        "updated_at": timestamp,
        "entries": {
            "1.1.1.1": {
                "ip": "1.1.1.1",
                "provider": "GeoJS",
                "status": "success",
                "queried_at": timestamp,
                "latitude": 40.0,
                "longitude": -73.0,
                "country": "United States",
                "country_code": "US",
                "city": "Fixture City",
            }
        },
    }


class FixtureAPI:
    def __init__(self):
        self.requests = []
        self.servers, self.geo = envelope(), geography()
        self.failure = None
        self.geo_failure = None

    def __call__(self, request):
        self.requests.append(request)
        if request.url.path == "/api/servers":
            if self.failure:
                return httpx.Response(self.failure)
            return httpx.Response(200, json=self.servers)
        if request.url.path == "/api/geolocation":
            if self.geo_failure:
                return httpx.Response(self.geo_failure)
            return httpx.Response(200, json=self.geo)
        if request.url.host == PROFILE_HOST:
            if "up-unsafe" in request.url.path:
                return httpx.Response(200, content=profile(extra="up /unsafe\n"))
            return httpx.Response(200, content=profile())
        return httpx.Response(404)


@pytest.fixture
def api():
    return FixtureAPI()


@pytest.fixture
def service(api):
    client = WorkerClient(Settings(token="fixture-token"), transport=httpx.MockTransport(api))
    value = CatalogService(client)
    yield value
    client.close()


class FakeSession:
    def __init__(self):
        self.current = {
            "state": "DISCONNECTED",
            "session_id": None,
            "server_id": None,
            "error": None,
            "logs": [],
        }
        self.connections = []
        self.disconnects = 0

    def status(self):
        return dict(self.current)

    def connect(self, server, raw, **kwargs):
        self.connections.append(server.id)
        self.current = {
            "state": "CONNECTED",
            "session_id": "fake-session",
            "server_id": server.id,
            "error": None,
            "logs": [],
        }
        return self.status()

    def disconnect(self, expected=None):
        self.disconnects += 1
        self.current["state"] = "DISCONNECTED"
        return self.status()

    def close(self):
        pass


@pytest.fixture
def session():
    return FakeSession()
