from __future__ import annotations

import json

from rich.table import Table
from rich.text import Text

from .models import Catalog, Server, age_seconds

ACCENT = "#11ff00"


def age_label(value: str) -> str:
    seconds = age_seconds(value)
    if seconds >= 86400:
        return f"{seconds // 86400}d {(seconds % 86400) // 3600}h ago"
    if seconds >= 3600:
        return f"{seconds // 3600}h {(seconds % 3600) // 60}m ago"
    return f"{seconds // 60}m ago"


def server_table(catalog: Catalog, rows: list[Server]) -> Table:
    table = Table(
        border_style=ACCENT,
        header_style=f"bold {ACCENT}",
        title_style=f"bold {ACCENT}",
        title="Published OpenVPN servers · source metrics",
        caption=(
            f"Captured: {catalog.captured_at} ({age_label(catalog.captured_at)}) | Published: {catalog.published_at} ({age_label(catalog.published_at)}) | Fetched: {catalog.fetched_at}"
        ),
    )
    for name in (
        "Rank",
        "ID",
        "Source",
        "Source country",
        "Endpoint",
        "Latency",
        "Uptime",
        "Config",
        "Profile",
    ):
        table.add_column(name)
    for s in rows:
        table.add_row(
            str(s.rank),
            Text(s.id),
            s.source,
            Text(s.location),
            Text(f"{s.remote_host}:{s.remote_port}/{s.protocol}"),
            "N/A" if s.ping_ms is None else f"{s.ping_ms} ms",
            "N/A" if s.uptime_days is None else f"{s.uptime_days}d",
            "Fresh" if s.active else "Retained",
            "Verified" if s.downloadable else "Unavailable",
        )
    return table


def detail_table(server: Server) -> Table:
    table = Table(
        title="Server detail · collection freshness is separate from VPN status",
        border_style=ACCENT,
        header_style=f"bold {ACCENT}",
        title_style=f"bold {ACCENT}",
    )
    table.add_column("Field")
    table.add_column("Value")
    for name, value in server.public().items():
        if isinstance(value, dict):
            value = json.dumps(value, ensure_ascii=False)
        table.add_row(name.replace("_", " "), Text("N/A" if value is None else str(value)))
    return table


def mapping_table(data: dict, title="Status") -> Table:
    table = Table(
        title=title,
        border_style=ACCENT,
        header_style=f"bold {ACCENT}",
        title_style=f"bold {ACCENT}",
    )
    table.add_column("Field")
    table.add_column("Value")
    for key, value in data.items():
        table.add_row(
            Text(str(key)),
            Text(
                json.dumps(value, ensure_ascii=False)
                if isinstance(value, (list, dict))
                else str(value)
            ),
        )
    return table
