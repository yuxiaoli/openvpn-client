"""Allowlisted public domain models for the published v1/v2 KV contract."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import unicodedata
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

import pycountry

from .errors import ClientError

SOURCES = {
    "ipspeed": "https://ipspeed.info/free-openvpn.php",
    "vpngate": "https://www.vpngate.net/en/",
}
REFRESH = {"current", "download_failed", "not_listed", "source_failed", "not_selected"}
HASH = re.compile(r"[a-f0-9]{64}")


def now() -> datetime:
    return datetime.now(timezone.utc)


def age_seconds(value: str) -> int:
    return max(0, int((now() - timestamp(value)).total_seconds()))


def timestamp(value) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError
        return result.astimezone(timezone.utc)
    except (AttributeError, TypeError, ValueError):
        raise ClientError("Snapshot contains an invalid timestamp.") from None


def text(value, name: str, maximum=1024) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ClientError(f"Snapshot contains an invalid {name}.")
    if any(unicodedata.category(char) in {"Cc", "Cf"} for char in value):
        raise ClientError(f"Snapshot contains control characters in {name}.")
    return value


def integer(value, name: str, low: int, high: int = 2**53) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ClientError(f"Snapshot contains an invalid {name}.")
    return value


def canonical_host(value: str) -> str:
    value = text(value, "endpoint host", 253)
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        host = value.lower().rstrip(".")
        if re.fullmatch(r"[\d.]+", host) or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in host.split(".")
        ):
            raise ClientError("Invalid endpoint host.") from None
        return host


def protocol(value: str) -> str:
    if value in {"udp", "udp4", "udp6"}:
        return "udp"
    if value in {"tcp", "tcp-client", "tcp4", "tcp6", "tcp4-client", "tcp6-client"}:
        return "tcp"
    raise ClientError("Unsupported OpenVPN protocol.")


def identity(source: str, host: str, port: int, proto: str) -> str:
    encoded = json.dumps([canonical_host(host), port, protocol(proto)], separators=(",", ":"))
    return f"{source}:" + hashlib.sha256(encoded.encode()).hexdigest()


def country_code(value: str) -> str | None:
    aliases = {
        "usa": "US",
        "south korea": "KR",
        "russia": "RU",
        "viet nam": "VN",
        "taiwan": "TW",
        "iran": "IR",
        "hong kong": "HK",
    }
    if value.lower() in aliases:
        return aliases[value.lower()]
    try:
        return pycountry.countries.lookup(value).alpha_2
    except LookupError:
        return None


@dataclass(frozen=True)
class Geography:
    ip: str
    provider: str
    queried_at: str
    latitude: float
    longitude: float
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    region: str | None = None
    organization: str | None = None
    isp: str | None = None
    timezone: str | None = None
    accuracy_km: float | None = None
    asn: int | None = None

    def public(self) -> dict:
        data = asdict(self)
        age = age_seconds(self.queried_at)
        return {**data, "age_seconds": age, "stale": age > 7 * 86400}


@dataclass(frozen=True)
class Distribution:
    status: str
    sha256: str | None = None
    bytes: int | None = None
    public_verified_at: str | None = None


@dataclass(frozen=True)
class Server:
    id: str
    source: str
    location: str
    remote_host: str
    remote_port: int
    protocol: str
    active: bool
    refresh_status: str
    rank: int
    ping_ms: int | None
    uptime_days: int | None
    rank_score: float | None
    first_seen_at: str
    last_seen_at: str
    seen_count: int
    filename: str | None = None
    config_sha256: str | None = None
    config_bytes: int | None = None
    object_key: str | None = None
    download_url: str | None = None
    distribution: Distribution | None = None
    geography: Geography | None = None

    @property
    def country_code(self) -> str | None:
        return country_code(self.location)

    @property
    def downloadable(self) -> bool:
        # Exact URL/path/metadata checks are shared with the downloader.
        from .profiles import eligible

        return eligible(self)

    def public(self) -> dict:
        data = asdict(self)
        data.update(country_code=self.country_code, downloadable=self.downloadable)
        data["last_seen_age_seconds"] = age_seconds(self.last_seen_at)
        if self.geography:
            data["geography"] = self.geography.public()
        return data


@dataclass
class Catalog:
    servers: list[Server]
    publication_id: str
    captured_at: str
    published_at: str
    fetched_at: str
    source_statuses: dict[str, str]
    geography_updated_at: str | None = None
    geographies: dict[str, Geography] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def get(self, server_id: str) -> Server:
        for server in self.servers:
            if server.id == server_id:
                return server
        raise ClientError("Server ID is not in the current catalog.")

    def update_age_warnings(self):
        self.warnings = [
            w
            for w in self.warnings
            if w != "Server snapshot is older than 36 hours."
            and "server lookup(s) are older than seven days." not in w
        ]
        if age_seconds(self.captured_at) > 36 * 3600:
            self.warnings.append("Server snapshot is older than 36 hours.")
        stale = sum(
            s.geography is not None and age_seconds(s.geography.queried_at) > 7 * 86400
            for s in self.servers
        )
        if stale:
            self.warnings.append(f"{stale} server lookup(s) are older than seven days.")

    def public(self, servers: list[Server] | None = None) -> dict:
        self.update_age_warnings()
        return {
            "schema_version": 1,
            "publication_id": self.publication_id,
            "captured_at": self.captured_at,
            "published_at": self.published_at,
            "fetched_at": self.fetched_at,
            "captured_age_seconds": age_seconds(self.captured_at),
            "published_age_seconds": age_seconds(self.published_at),
            "source_statuses": self.source_statuses,
            "geography_updated_at": self.geography_updated_at,
            "geography_cache_age_seconds": age_seconds(self.geography_updated_at)
            if self.geography_updated_at
            else None,
            "warnings": self.warnings,
            "servers": [s.public() for s in (self.servers if servers is None else servers)],
        }


def decode_servers(envelope: dict, *, clock: datetime | None = None) -> Catalog:
    if (
        not isinstance(envelope, dict)
        or type(envelope.get("schema_version")) is not int
        or envelope.get("schema_version") != 1
    ):
        raise ClientError("Unsupported server envelope version.")
    if envelope.get("fixture_only") or envelope.get("data_kind") == "fixture":
        raise ClientError("Production API returned a fixture envelope.")
    index = (
        envelope.get("payload", {}).get("index")
        if isinstance(envelope.get("payload"), dict)
        else None
    )
    if (
        not isinstance(index, dict)
        or type(index.get("schema_version")) is not int
        or index.get("schema_version") != 2
    ):
        raise ClientError("Unsupported server index version.")
    if index.get("source") != SOURCES["ipspeed"]:
        raise ClientError("Unsupported server index provenance.")
    for key in ("captured_at", "published_at"):
        timestamp(envelope.get(key))
    timestamp(index.get("generated_at"))
    publication = text(envelope.get("publication_id"), "publication ID", 256)
    digest = envelope.get("content_sha256")
    if (
        not isinstance(digest, str)
        or not HASH.fullmatch(digest)
        or publication != "sha256:" + digest
    ):
        raise ClientError("Invalid publication digest metadata.")
    statuses = index.get("sources")
    if not isinstance(statuses, dict) or set(statuses) != set(SOURCES):
        raise ClientError("Invalid source status map.")
    source_statuses = {}
    for source, url in SOURCES.items():
        item = statuses[source]
        if (
            not isinstance(item, dict)
            or item.get("url") != url
            or not isinstance(item.get("status"), str)
            or item.get("status") not in {"complete", "partial", "failed", "not_selected"}
        ):
            raise ClientError("Invalid source status or provenance.")
        source_statuses[source] = item["status"]
    if not isinstance(index.get("crawl_status"), str) or index.get("crawl_status") not in {
        "complete",
        "partial",
    }:
        raise ClientError("Invalid capture status.")
    rows = index.get("servers")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 5000:
        raise ClientError("Invalid server array or record limit.")
    if type(index.get("server_count")) is not int or index["server_count"] != len(rows):
        raise ClientError("Server count does not match the record array.")
    result, ids = [], set()
    for row in rows:
        if not isinstance(row, dict):
            raise ClientError("Invalid server record.")
        source = row.get("source")
        if not isinstance(source, str) or source not in SOURCES:
            raise ClientError("Invalid server source.")
        host = canonical_host(row.get("remote_host"))
        port = integer(row.get("remote_port"), "port", 1, 65535)
        proto = row.get("protocol")
        if not isinstance(proto, str) or proto not in {"tcp", "udp"}:
            raise ClientError("Invalid endpoint protocol.")
        server_id = row.get("id")
        if server_id != identity(source, host, port, proto) or server_id in ids:
            raise ClientError("Invalid or duplicate server identity.")
        ids.add(server_id)
        active, refresh = row.get("active"), row.get("refresh_status")
        if (
            type(active) is not bool
            or not isinstance(refresh, str)
            or refresh not in REFRESH
            or active != (refresh == "current")
        ):
            raise ClientError("Invalid server freshness state.")
        for key in ("first_seen_at", "last_seen_at"):
            timestamp(row.get(key))
        ping = row.get("ping_ms")
        if ping is not None:
            ping = integer(ping, "latency", 0)
        uptime = row.get("uptime_days")
        if uptime is not None:
            uptime = integer(uptime, "uptime", 0)
        score = row.get("rank_score")
        if score is not None and (
            type(score) not in {int, float} or not math.isfinite(score) or not 0 <= score <= 1
        ):
            raise ClientError("Invalid ranking score.")
        dist = row.get("profile_distribution")
        distribution = None
        if isinstance(dist, dict):
            if dist.get("status") == "verified":
                if not isinstance(dist.get("sha256"), str) or not HASH.fullmatch(dist["sha256"]):
                    raise ClientError("Invalid distribution digest.")
                integer(dist.get("bytes"), "distribution byte count", 1, 256_000)
                verified_at = dist.get("verified_at", dist.get("public_verified_at"))
                timestamp(verified_at)
                distribution = Distribution("verified", dist["sha256"], dist["bytes"], verified_at)
            else:
                distribution = Distribution("unavailable")
        elif dist is not None:
            raise ClientError("Invalid distribution metadata.")
        for key in ("filename", "config_sha256", "object_key", "download_url"):
            if row.get(key) is not None:
                text(row[key], key, 2048)
        if row.get("config_bytes") is not None:
            integer(row["config_bytes"], "profile bytes", 1, 256_000)
        result.append(
            Server(
                server_id,
                source,
                text(row.get("location"), "source country", 256),
                host,
                port,
                proto,
                active,
                refresh,
                integer(row.get("rank"), "rank", 1),
                None if ping == 9999 else ping,
                uptime,
                score,
                row["first_seen_at"],
                row["last_seen_at"],
                integer(row.get("seen_count"), "observation count", 1),
                row.get("filename"),
                row.get("config_sha256"),
                row.get("config_bytes"),
                row.get("object_key"),
                row.get("download_url"),
                distribution,
            )
        )
    if type(index.get("active_count")) is not int or index["active_count"] != sum(
        s.active for s in result
    ):
        raise ClientError("Active count does not match the record array.")
    current = clock or now()
    catalog = Catalog(
        sorted(result, key=lambda s: (s.rank, s.id)),
        publication,
        envelope["captured_at"],
        envelope["published_at"],
        current.isoformat(),
        source_statuses,
    )
    if current - timestamp(catalog.captured_at) > timedelta(hours=36):
        catalog.warnings.append("Server snapshot is older than 36 hours.")
    for source, status in source_statuses.items():
        if status != "complete":
            catalog.warnings.append(f"{source} capture status: {status}.")
    return catalog


def decode_geographies(cache: dict) -> tuple[str, dict[str, Geography]]:
    if (
        not isinstance(cache, dict)
        or cache.get("schema") != "ipspeed-geolocation-cache-v1"
        or type(cache.get("schema_version")) is not int
        or cache.get("schema_version") != 1
    ):
        raise ClientError("Unsupported geolocation cache version.")
    timestamp(cache.get("updated_at"))
    entries = cache.get("entries")
    if not isinstance(entries, dict) or len(entries) > 5000:
        raise ClientError("Invalid geolocation entry limit.")
    result = {}
    for ip, row in entries.items():
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            raise ClientError("Invalid geolocation IP.") from None
        if not address.is_global or not isinstance(row, dict) or row.get("ip") != ip:
            raise ClientError("Invalid geolocation entry identity.")
        if row.get("provider") != "GeoJS" or row.get("status") != "success":
            raise ClientError("Unsupported geolocation provenance.")
        timestamp(row.get("queried_at"))
        for name, low, high in (("latitude", -90, 90), ("longitude", -180, 180)):
            value = row.get(name)
            if (
                type(value) not in {int, float}
                or not math.isfinite(value)
                or not low <= value <= high
            ):
                raise ClientError("Invalid geolocation coordinates.")
        optional = {}
        for key in ("country", "country_code", "city", "region", "organization", "isp", "timezone"):
            optional[key] = text(row[key], key) if row.get(key) is not None else None
        if optional["country_code"] is not None and not re.fullmatch(
            r"[A-Z]{2}", optional["country_code"]
        ):
            raise ClientError("Invalid lookup country code.")
        radius, asn = row.get("accuracy_km"), row.get("asn")
        if radius is not None and (
            type(radius) not in {int, float}
            or not math.isfinite(radius)
            or not 0 <= radius <= 20040
        ):
            raise ClientError("Invalid lookup accuracy.")
        if asn is not None:
            integer(asn, "ASN", 1, 2**32 - 1)
        result[ip] = Geography(
            ip,
            "GeoJS",
            row["queried_at"],
            row["latitude"],
            row["longitude"],
            **optional,
            accuracy_km=radius,
            asn=asn,
        )
    return cache["updated_at"], result
