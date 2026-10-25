from __future__ import annotations

import functools
import json
import sys
from pathlib import Path

import cmd2
from rich.text import Text

from .api import CatalogService
from .config import save_settings
from .errors import ClientError
from .installer import doctor, install_openvpn
from .profiles import save_profile
from .query import Query, best, select, write_export
from .render import detail_table, mapping_table, server_table
from .session import SessionClient


def server_ids(shell):
    return [s.id for s in shell.service.catalog.servers] if shell.service.catalog else []


def parser(*, filters=False, server=False, optional_server=False, json_output=True):
    result = cmd2.Cmd2ArgumentParser()
    if server:
        result.add_argument(
            "server_id", nargs="?" if optional_server else None, choices_provider=server_ids
        )
    if filters:
        result.add_argument("--country")
        result.add_argument("--source", choices=["ipspeed", "vpngate"])
        result.add_argument("--protocol", choices=["tcp", "udp"])
        result.add_argument("--freshness", choices=["all", "fresh", "retained"], default="all")
        result.add_argument(
            "--profiles", choices=["all", "available", "unavailable"], default="all"
        )
        result.add_argument("--search", default="")
        result.add_argument(
            "--sort", choices=["rank", "latency", "uptime", "last-seen"], default="rank"
        )
    if json_output:
        result.add_argument("--json", action="store_true")
    return result


def query(args):
    return Query(
        args.country,
        args.source,
        args.protocol,
        args.freshness,
        args.profiles,
        args.search,
        args.sort,
    )


def guarded(function):
    @functools.wraps(function)
    def wrapper(self, *args, **kwargs):
        try:
            return function(self, *args, **kwargs)
        except ClientError as error:
            self.perror(Text(str(error)))
        except KeyboardInterrupt:
            self.perror("Interrupted.")

    return wrapper


class OpenVPNShell(cmd2.Cmd):
    prompt = "openvpn-kv> "
    intro = "OpenVPN KV shell · help lists commands · refresh reads the Worker · quit detaches"

    def __init__(self, service: CatalogService, session: SessionClient, *, stdout=None, stdin=None):
        self.service, self.session = service, session
        super().__init__(
            stdout=stdout,
            stdin=stdin,
            allow_cli_args=False,
            persistent_history_file="",
            include_py=False,
            include_ipy=False,
            intro=self.intro,
        )
        try:
            self.service.refresh()
            self.warnings()
        except ClientError as error:
            self.perror(Text(str(error)))

    def close(self):
        self.service.client.close()
        self.session.close()

    def warnings(self):
        for warning in self.service.require().warnings:
            self.perror(Text(warning, style="yellow"))
        if self.service.refresh_error:
            self.perror(
                Text(
                    f"Refresh failed; using memory fetched at {self.service.require().fetched_at}: {self.service.refresh_error}",
                    style="yellow",
                )
            )

    def emit(self, args, data, renderable):
        self.poutput(json.dumps(data, ensure_ascii=False, indent=2) if args.json else renderable)

    @cmd2.with_argparser(parser())
    @guarded
    def do_refresh(self, args):
        """Fetch a replacement in-memory catalog; a failure retains the old one."""
        catalog = self.service.refresh()
        self.warnings()
        self.emit(
            args,
            catalog.public(),
            Text(f"Loaded {len(catalog.servers)} records at {catalog.fetched_at}."),
        )

    @cmd2.with_argparser(parser(filters=True))
    @guarded
    def do_list(self, args):
        """Filter and sort the current memory catalog."""
        catalog = self.service.require()
        self.warnings()
        rows = select(catalog, query(args))
        self.emit(args, catalog.public(rows), server_table(catalog, rows))

    @cmd2.with_argparser(parser(server=True))
    @guarded
    def do_show(self, args):
        """Inspect a canonical server ID (Tab completes IDs)."""
        self.warnings()
        server = self.service.require().get(args.server_id)
        self.emit(args, server.public(), detail_table(server))

    geo_parser = parser()
    geo_parser.add_argument(
        "ip",
        choices_provider=lambda shell: (
            list(shell.service.catalog.geographies) if shell.service.catalog else []
        ),
    )

    @cmd2.with_argparser(geo_parser)
    @guarded
    def do_geo(self, args):
        """Inspect exact-IP cached geography without performing a lookup."""
        catalog = self.service.require()
        if args.ip not in catalog.geographies:
            raise ClientError("No verified cached geography for this exact IP.")
        data = catalog.geographies[args.ip].public()
        self.emit(args, data, mapping_table(data, "Cached IP geography"))

    export_parser = parser(filters=True)
    export_parser.add_argument("--format", choices=["json", "csv"], default="json")
    export_parser.add_argument(
        "--output", required=True, type=Path, completer=cmd2.Cmd.path_complete
    )

    @cmd2.with_argparser(export_parser)
    @guarded
    def do_export(self, args):
        """Explicitly export a selected view without creating a catalog cache."""
        catalog = self.service.require()
        self.warnings()
        rows = select(catalog, query(args))
        path = write_export(catalog, rows, args.format, args.output)
        self.emit(
            args,
            {"output": str(path), "count": len(rows)},
            Text(f"Exported {len(rows)} records to {path}."),
        )

    download_parser = parser(server=True)
    download_parser.add_argument(
        "--output", required=True, type=Path, completer=cmd2.Cmd.path_complete
    )

    @cmd2.with_argparser(download_parser)
    @guarded
    def do_download(self, args):
        """Save a digest-verified original profile without overwriting."""
        server = self.service.require().get(args.server_id)
        path = save_profile(self.service.client.profile(server), args.output)
        self.emit(
            args,
            {"output": str(path), "sha256": server.config_sha256},
            Text(f"Verified profile saved to {path}."),
        )

    connect_parser = parser(server=True, optional_server=True, filters=True)
    connect_parser.add_argument("--best", action="store_true")

    @cmd2.with_argparser(connect_parser)
    @guarded
    def do_connect(self, args):
        """Connect a selected ID or --best; the VPN survives shell exit."""
        if bool(args.server_id) == args.best:
            raise ClientError("Provide a server ID or --best, exclusively.")
        catalog = self.service.require()
        self.warnings()
        server = best(catalog, query(args)) if args.best else catalog.get(args.server_id)
        if not server.active:
            self.perror("Connecting a retained configuration; source observation may be old.")
        result = self.session.connect(
            server, self.service.client.profile(server, for_connection=True)
        )
        self.emit(args, result, mapping_table(result, "VPN session"))

    @cmd2.with_argparser(parser())
    @guarded
    def do_status(self, args):
        """Inspect local VPN status without reading KV."""
        result = self.session.status()
        self.emit(args, result, mapping_table(result, "VPN session"))

    @cmd2.with_argparser(parser())
    @guarded
    def do_disconnect(self, args):
        """Disconnect only the shared owned session."""
        result = self.session.disconnect()
        self.emit(args, result, mapping_table(result, "VPN session"))

    @cmd2.with_argparser(parser())
    @guarded
    def do_doctor(self, args):
        """Check Community installation, package candidate and networking prerequisites."""
        result = doctor(self.service.client.settings)
        self.emit(args, result, mapping_table(result, "OpenVPN prerequisites"))

    setup_parser = parser()
    setup_parser.add_argument("--install", action="store_true")
    setup_parser.add_argument("--add-openvpn-repo", action="store_true")

    @cmd2.with_argparser(setup_parser)
    @guarded
    def do_setup(self, args):
        """Save nonsecret settings; install only with --install."""
        if args.add_openvpn_repo and not args.install:
            raise ClientError("--add-openvpn-repo requires --install.")
        if args.install:
            install_openvpn(add_repository=args.add_openvpn_repo)
        settings = self.service.client.settings
        path = save_settings(settings)
        result = doctor(settings)
        result["config"] = str(path)
        self.emit(args, result, mapping_table(result, "Client setup"))
        if args.install and not result["ready"]:
            raise ClientError(
                "Installation finished but prerequisites remain unavailable. Review doctor output."
            )


def main():
    from .cli import app

    app([*sys.argv[1:], "shell"])
