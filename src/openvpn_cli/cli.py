from __future__ import annotations

import functools
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.text import Text

from .api import CatalogService, WorkerClient
from .config import Settings, load_settings, save_settings
from .errors import ClientError
from .installer import doctor as check_doctor
from .installer import install_openvpn
from .profiles import save_profile
from .query import Query, select, write_export
from .query import best as pick_best
from .render import detail_table, mapping_table, server_table
from .session import SessionClient

app = typer.Typer(
    no_args_is_help=True, help="Browse the OpenVPN KV catalog and control one persistent VPN."
)
console = Console()
errors = Console(stderr=True)


class Source(StrEnum):
    ipspeed = "ipspeed"
    vpngate = "vpngate"


class Protocol(StrEnum):
    tcp = "tcp"
    udp = "udp"


class Freshness(StrEnum):
    all = "all"
    fresh = "fresh"
    retained = "retained"


class Profiles(StrEnum):
    all = "all"
    available = "available"
    unavailable = "unavailable"


class Sort(StrEnum):
    rank = "rank"
    latency = "latency"
    uptime = "uptime"
    last_seen = "last-seen"


class Format(StrEnum):
    json = "json"
    csv = "csv"


@dataclass
class Context:
    settings: Settings
    json: bool = False


def guarded(function):
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except ClientError as error:
            errors.print(Text(str(error)))
            raise typer.Exit(1) from None
        except KeyboardInterrupt:
            raise typer.Exit(130) from None

    return wrapper


@app.callback()
@guarded
def configure(
    ctx: typer.Context,
    api_url: Annotated[str | None, typer.Option(help="HTTPS Worker origin.")] = None,
    env_file: Annotated[
        Path | None, typer.Option(help="Explicit .env file; never discovered automatically.")
    ] = None,
    openvpn_path: Annotated[
        str | None, typer.Option(help="Absolute Community executable path.")
    ] = None,
    owner: Annotated[
        str | None, typer.Option(help="Originating Unix UID or Windows SID after elevation.")
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
):
    ctx.obj = Context(
        load_settings(api_url=api_url, env_file=env_file, openvpn_path=openvpn_path, owner=owner),
        json_output,
    )


def warn(catalog):
    catalog.update_age_warnings()
    for warning in catalog.warnings:
        errors.print(Text(warning, style="yellow"))


def fetched(ctx):
    client = WorkerClient(ctx.obj.settings)
    try:
        catalog = client.fetch()
    except Exception:
        client.close()
        raise
    warn(catalog)
    return client, catalog


def output(ctx, data: dict, renderable, json_output=False):
    if ctx.obj.json or json_output:
        typer.echo(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        console.print(renderable)


@app.command("list")
@guarded
def list_servers(
    ctx: typer.Context,
    country: str | None = None,
    source: Source | None = None,
    protocol: Protocol | None = None,
    freshness: Freshness = Freshness.all,
    profiles: Profiles = Profiles.all,
    search: str = "",
    sort: Sort = Sort.rank,
    json_output: Annotated[bool, typer.Option("--json")] = False,
):
    """List all published records by rank, including retained configurations."""
    client, catalog = fetched(ctx)
    try:
        rows = select(catalog, Query(country, source, protocol, freshness, profiles, search, sort))
        output(ctx, catalog.public(rows), server_table(catalog, rows), json_output)
    finally:
        client.close()


@app.command()
@guarded
def show(
    ctx: typer.Context,
    server_id: Annotated[str, typer.Argument()],
    json_output: Annotated[bool, typer.Option("--json")] = False,
):
    """Inspect a full canonical server ID."""
    client, catalog = fetched(ctx)
    try:
        server = catalog.get(server_id)
        output(ctx, server.public(), detail_table(server), json_output)
    finally:
        client.close()


@app.command()
@guarded
def geo(
    ctx: typer.Context,
    ip: Annotated[str, typer.Argument()],
    json_output: Annotated[bool, typer.Option("--json")] = False,
):
    """Inspect the saved GeoJS entry for an exact public IP; performs no lookup."""
    client, catalog = fetched(ctx)
    try:
        if ip not in catalog.geographies:
            raise ClientError("No verified cached geography for this exact IP.")
        data = catalog.geographies[ip].public()
        output(ctx, data, mapping_table(data, "Cached IP geography"), json_output)
    finally:
        client.close()


@app.command()
@guarded
def export(
    ctx: typer.Context,
    output_path: Annotated[Path, typer.Option("--output")],
    format: Format = Format.json,
    country: str | None = None,
    source: Source | None = None,
    protocol: Protocol | None = None,
    freshness: Freshness = Freshness.all,
    profiles: Profiles = Profiles.all,
    search: str = "",
    sort: Sort = Sort.rank,
):
    """Explicitly export the selected view; catalog snapshots are never cached."""
    client, catalog = fetched(ctx)
    try:
        rows = select(catalog, Query(country, source, protocol, freshness, profiles, search, sort))
        path = write_export(catalog, rows, format, output_path)
        output(
            ctx,
            {"output": str(path), "count": len(rows)},
            Text(f"Exported {len(rows)} records to {path}."),
        )
    finally:
        client.close()


@app.command()
@guarded
def download(
    ctx: typer.Context,
    server_id: Annotated[str, typer.Argument()],
    output_path: Annotated[Path, typer.Option("--output")],
):
    """Save the exact digest-verified immutable .ovpn profile without overwriting."""
    client, catalog = fetched(ctx)
    try:
        server = catalog.get(server_id)
        raw = client.profile(server)
        path = save_profile(raw, output_path)
        output(
            ctx,
            {"output": str(path), "sha256": server.config_sha256},
            Text(f"Verified profile saved to {path}."),
        )
    finally:
        client.close()


@app.command()
@guarded
def connect(
    ctx: typer.Context,
    server_id: Annotated[str | None, typer.Argument()] = None,
    best: Annotated[bool, typer.Option("--best")] = False,
    country: str | None = None,
    source: Source | None = None,
    protocol: Protocol | None = None,
    freshness: Freshness = Freshness.all,
    profiles: Profiles = Profiles.all,
    search: str = "",
    json_output: Annotated[bool, typer.Option("--json")] = False,
):
    """Connect an explicit ID or the best matching active profile; requires elevation."""
    if bool(server_id) == best:
        raise typer.BadParameter("Provide a server ID or --best, exclusively.")
    client, catalog = fetched(ctx)
    session = SessionClient(ctx.obj.settings)
    try:
        server = (
            pick_best(catalog, Query(country, source, protocol, freshness, profiles, search))
            if best
            else catalog.get(server_id)
        )
        if not server.active:
            errors.print(
                Text(
                    "Connecting a retained configuration; source observation may be old.",
                    style="yellow",
                )
            )
        raw = client.profile(server, for_connection=True)
        result = session.connect(server, raw)
        output(ctx, result, mapping_table(result, "VPN session"), json_output)
    finally:
        client.close()
        session.close()


@app.command()
@guarded
def status(ctx: typer.Context, json_output: Annotated[bool, typer.Option("--json")] = False):
    """Inspect the local supervisor without needing the Worker or its API token."""
    session = SessionClient(ctx.obj.settings)
    try:
        result = session.status()
        output(ctx, result, mapping_table(result, "VPN session"), json_output)
    finally:
        session.close()


@app.command()
@guarded
def disconnect(ctx: typer.Context, json_output: Annotated[bool, typer.Option("--json")] = False):
    """Stop the shared owned session without consulting the Worker."""
    session = SessionClient(ctx.obj.settings)
    try:
        result = session.disconnect()
        output(ctx, result, mapping_table(result, "VPN session"), json_output)
    finally:
        session.close()


@app.command("doctor")
@guarded
def doctor_command(
    ctx: typer.Context, json_output: Annotated[bool, typer.Option("--json")] = False
):
    """Inspect installation, candidate version, DNS prerequisites and elevation."""
    result = check_doctor(ctx.obj.settings)
    output(ctx, result, mapping_table(result, "OpenVPN prerequisites"), json_output)
    if not result["ready"]:
        raise typer.Exit(1)


@app.command()
@guarded
def setup(
    ctx: typer.Context,
    install: bool = False,
    add_openvpn_repo: bool = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
):
    """Save nonsecret settings and optionally install Community through the OS manager."""
    if add_openvpn_repo and not install:
        raise typer.BadParameter("--add-openvpn-repo requires --install.")
    if install:
        install_openvpn(add_repository=add_openvpn_repo)
    path = save_settings(ctx.obj.settings)
    result = check_doctor(ctx.obj.settings)
    result["config"] = str(path)
    output(ctx, result, mapping_table(result, "Client setup"), json_output)
    if install and not result["ready"]:
        raise ClientError(
            "Package installation finished but networking prerequisites are not ready. Review doctor output."
        )


@app.command()
@guarded
def shell(ctx: typer.Context):
    """Start the cmd2/Rich shell; fetches once on launch."""
    from .shell import OpenVPNShell

    client = WorkerClient(ctx.obj.settings)
    service = CatalogService(client)
    instance = OpenVPNShell(service, SessionClient(ctx.obj.settings))
    try:
        instance.cmdloop()
    finally:
        instance.close()


@app.command()
@guarded
def tui(ctx: typer.Context):
    """Start the Textual table/detail interface; fetches once on launch."""
    from .tui import OpenVPNTUI

    client = WorkerClient(ctx.obj.settings)
    application = OpenVPNTUI(CatalogService(client), SessionClient(ctx.obj.settings))
    try:
        application.run()
    finally:
        application.close()


def main():
    app()


if __name__ == "__main__":
    main()
