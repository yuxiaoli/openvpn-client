from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from pathlib import Path

from .errors import ClientError
from .models import Catalog, Server, country_code, timestamp


@dataclass(frozen=True)
class Query:
    country: str | None = None
    source: str | None = None
    protocol: str | None = None
    freshness: str = "all"
    profiles: str = "all"
    search: str = ""
    sort: str = "rank"

    def validate(self):
        if self.source not in {None, "ipspeed", "vpngate"}:
            raise ClientError("Source must be ipspeed or vpngate.")
        if self.protocol not in {None, "tcp", "udp"}:
            raise ClientError("Protocol must be tcp or udp.")
        if self.freshness not in {"all", "fresh", "retained"}:
            raise ClientError("Freshness must be all, fresh or retained.")
        if self.profiles not in {"all", "available", "unavailable"}:
            raise ClientError("Profiles must be all, available or unavailable.")
        if self.sort not in {"rank", "latency", "uptime", "last-seen"}:
            raise ClientError("Sort must be rank, latency, uptime or last-seen.")


def select(catalog: Catalog, query: Query) -> list[Server]:
    query.validate()
    rows = []
    code = country_code(query.country) if query.country else None
    for server in catalog.servers:
        if (
            query.country
            and not (code and server.country_code == code)
            and server.location.casefold() != query.country.casefold()
        ):
            continue
        if query.source and query.source != server.source:
            continue
        if query.protocol and query.protocol != server.protocol:
            continue
        if query.freshness == "fresh" and not server.active:
            continue
        if query.freshness == "retained" and server.active:
            continue
        if query.profiles == "available" and not server.downloadable:
            continue
        if query.profiles == "unavailable" and server.downloadable:
            continue
        haystack = " ".join(
            (
                server.id,
                server.remote_host,
                server.location,
                server.source,
                server.geography.city or "" if server.geography else "",
            )
        )
        if query.search and query.search.casefold() not in haystack.casefold():
            continue
        rows.append(server)

    def key(server: Server):
        if query.sort == "latency":
            return server.ping_ms is None, server.ping_ms or 0, server.id
        if query.sort == "uptime":
            return server.uptime_days is None, -(server.uptime_days or 0), server.id
        if query.sort == "last-seen":
            return False, -timestamp(server.last_seen_at).timestamp(), server.id
        return False, server.rank, server.id

    return sorted(rows, key=key)


def best(catalog: Catalog, query: Query) -> Server:
    rows = [s for s in select(catalog, query) if s.active and s.downloadable]
    if not rows:
        raise ClientError("No fresh record with a verified profile matches these filters.")
    return min(rows, key=lambda s: (s.rank, s.id))


def export_text(catalog: Catalog, rows: list[Server], format: str) -> str:
    if format == "json":
        return json.dumps(catalog.public(rows), ensure_ascii=False, indent=2) + "\n"
    if format != "csv":
        raise ClientError("Export format must be json or csv.")
    output = io.StringIO(newline="")
    fields = [
        "id",
        "source",
        "location",
        "country_code",
        "remote_host",
        "remote_port",
        "protocol",
        "active",
        "refresh_status",
        "rank",
        "ping_ms",
        "uptime_days",
        "last_seen_at",
        "downloadable",
        "lookup_country",
        "lookup_city",
        "lookup_queried_at",
    ]
    writer = csv.DictWriter(output, fields)
    writer.writeheader()
    for server in rows:
        data = server.public()
        data.update(
            lookup_country=server.geography.country if server.geography else None,
            lookup_city=server.geography.city if server.geography else None,
            lookup_queried_at=server.geography.queried_at if server.geography else None,
        )
        # Prevent spreadsheet formula interpretation of untrusted textual fields.
        writer.writerow(
            {
                k: ("'" + v if isinstance(v, str) and v.startswith(("=", "+", "-", "@")) else v)
                for k in fields
                for v in [data.get(k)]
            }
        )
    return output.getvalue()


def write_export(catalog: Catalog, rows: list[Server], format: str, path: Path) -> Path:
    content = export_text(catalog, rows, format)
    try:
        with path.open("x", encoding="utf-8", newline="") as handle:
            handle.write(content)
    except FileExistsError:
        raise ClientError("Export output already exists; choose another path.") from None
    except OSError:
        raise ClientError("Cannot write export output.") from None
    return path
