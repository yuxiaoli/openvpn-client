from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.message import Message
from textual.screen import ModalScreen
from textual.theme import BUILTIN_THEMES
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, Select, Static
from textual.worker import get_current_worker

from .api import CatalogService
from .errors import ClientError
from .profiles import save_profile
from .query import Query, best, select, write_export
from .render import ACCENT, age_label, detail_table, mapping_table
from .session import SessionClient


class PathDialog(ModalScreen[tuple[str, str] | None]):
    DEFAULT_CSS = """
    PathDialog { align: center middle; }
    PathDialog > VerticalScroll { width: 70; height: auto; max-height: 90%; padding: 1 2; border: thick $accent; background: $surface; }
    PathDialog Button { margin: 1; }
    """

    def __init__(self, kind: str, default_name: str):
        super().__init__()
        self.kind, self.default_name = kind, default_name

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Label(f"{self.kind.title()} · existing files will not be overwritten")
            yield Input(value=self.default_name, id="file-path")
            if self.kind == "export":
                yield Select(
                    [("JSON", "json"), ("CSV", "csv")],
                    value="json",
                    allow_blank=False,
                    id="file-format",
                )
            with Horizontal():
                yield Button("Save", id="save", variant="primary")
                yield Button("Cancel", id="cancel")

    @on(Button.Pressed, "#cancel")
    def cancel(self):
        self.dismiss(None)

    @on(Button.Pressed, "#save")
    @on(Input.Submitted, "#file-path")
    def save(self):
        path = self.query_one("#file-path", Input).value.strip()
        if path:
            format = (
                str(self.query_one("#file-format", Select).value)
                if self.kind == "export"
                else "ovpn"
            )
            self.dismiss((path, format))


class CatalogResult(Message):
    def __init__(self, catalog, error, generation):
        super().__init__()
        self.catalog, self.error, self.generation = catalog, error, generation


class GeographyDialog(ModalScreen[str | None]):
    DEFAULT_CSS = PathDialog.DEFAULT_CSS.replace("PathDialog", "GeographyDialog")

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Label("Inspect an exact public IP in the current geography catalog")
            yield Input(placeholder="Public endpoint IP", id="geo-ip")
            with Horizontal():
                yield Button("Inspect", id="inspect", variant="primary")
                yield Button("Cancel", id="geo-cancel")

    @on(Button.Pressed, "#geo-cancel")
    def cancel(self):
        self.dismiss(None)

    @on(Button.Pressed, "#inspect")
    @on(Input.Submitted, "#geo-ip")
    def inspect_ip(self):
        self.dismiss(self.query_one("#geo-ip", Input).value.strip() or None)


class OperationResult(Message):
    def __init__(self, message, error=False, status=None, connection_finished=False):
        super().__init__()
        self.message, self.error, self.status = message, error, status
        self.connection_finished = connection_finished


class StatusResult(Message):
    def __init__(self, status, error=None):
        super().__init__()
        self.status, self.error = status, error


class OpenVPNTUI(App):
    TITLE = "OpenVPN KV"
    SUB_TITLE = "Published source metrics · local VPN session"
    BINDINGS = [
        ("r", "refresh", "Refresh"),
        ("c", "connect", "Connect selected"),
        ("b", "best", "Connect best"),
        ("d", "disconnect", "Disconnect"),
        ("e", "export", "Export"),
        ("p", "download", "Profile"),
        ("g", "geo", "IP geography"),
        ("q", "quit", "Detach"),
    ]
    CSS = """
    Screen { overflow-y: auto; }
    #filters { height: auto; layout: grid; grid-size: 4; grid-gutter: 0 1; }
    #filters Input, #filters Select { width: 1fr; }
    #catalog-status { height: auto; max-height: 5; padding: 0 1; }
    #vpn-status { height: auto; max-height: 3; padding: 0 1; color: $accent; }
    #servers { height: 1fr; min-height: 6; }
    #detail { height: 12; border-top: solid $accent; }
    #detail-content { height: auto; }
    #actions { height: auto; layout: grid; grid-size: 6; }
    #actions Button { min-width: 9; width: 1fr; }
    #notice { height: auto; max-height: 3; }
    """

    def __init__(self, service: CatalogService, session: SessionClient):
        super().__init__()
        self.register_theme(
            replace(
                BUILTIN_THEMES["textual-dark"],
                name="openvpn-kv",
                primary=ACCENT,
                secondary="#087700",
                accent=ACCENT,
            )
        )
        self.theme = "openvpn-kv"
        self.service, self.session = service, session
        self.selected_id = None
        self.refresh_generation = 0
        self.connection_busy = False

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="filters"):
            yield Input(placeholder="Country name/code", id="country")
            yield Input(placeholder="Search ID/host/city", id="search")
            yield Select(
                [("All sources", ""), ("IPSpeed", "ipspeed"), ("VPNGate", "vpngate")],
                value="",
                allow_blank=False,
                id="source",
            )
            yield Select(
                [("All protocols", ""), ("TCP", "tcp"), ("UDP", "udp")],
                value="",
                allow_blank=False,
                id="protocol",
            )
            yield Select(
                [("All freshness", "all"), ("Fresh config", "fresh"), ("Retained", "retained")],
                value="all",
                allow_blank=False,
                id="freshness",
            )
            yield Select(
                [
                    ("All profiles", "all"),
                    ("Verified profiles", "available"),
                    ("Unavailable", "unavailable"),
                ],
                value="all",
                allow_blank=False,
                id="profiles",
            )
            yield Select(
                [
                    ("Published rank", "rank"),
                    ("Latency", "latency"),
                    ("Uptime", "uptime"),
                    ("Last seen", "last-seen"),
                ],
                value="rank",
                allow_blank=False,
                id="sort",
            )
        yield Static("Loading catalog…", id="catalog-status", markup=False)
        yield Static("VPN: checking local session…", id="vpn-status", markup=False)
        yield DataTable(id="servers", cursor_type="row", zebra_stripes=True)
        with VerticalScroll(id="detail"):
            yield Static(
                "Select a server to inspect details and exact-IP geography.",
                id="detail-content",
                markup=False,
            )
        with Horizontal(id="actions"):
            for label, action in (
                ("Refresh", "refresh"),
                ("Connect", "connect"),
                ("Best", "best"),
                ("Disconnect", "disconnect"),
                ("Export", "export"),
                ("Profile", "download"),
            ):
                yield Button(label, id=action)
        yield Static("Closing this interface leaves the VPN running.", id="notice", markup=False)
        yield Footer()

    def on_mount(self):
        self.query_one("#servers", DataTable).add_columns(
            "Rank", "Source", "Country", "Endpoint", "Latency", "Uptime", "Config", "Profile"
        )
        self.action_refresh()
        self.poll_status()
        self.set_interval(1, self.poll_status)
        self.responsive_layout()

    def on_resize(self):
        if self.is_mounted:
            self.responsive_layout()

    def responsive_layout(self):
        if not self.query("#filters"):
            return
        self.query_one("#filters").styles.grid_size_columns = 2 if self.size.width < 80 else 4
        self.query_one("#actions").styles.grid_size_columns = 3 if self.size.width < 80 else 6
        self.query_one("#detail").styles.height = 9 if self.size.height < 32 else 12

    def close(self):
        self.service.client.close()
        self.session.close()

    def current_query(self):
        def choice(name):
            value = self.query_one("#" + name, Select).value
            return "" if value is Select.BLANK else str(value)

        return Query(
            self.query_one("#country", Input).value.strip() or None,
            choice("source") or None,
            choice("protocol") or None,
            choice("freshness"),
            choice("profiles"),
            self.query_one("#search", Input).value,
            choice("sort"),
        )

    def action_refresh(self):
        self.refresh_generation += 1
        self.query_one("#catalog-status", Static).update("Loading catalog…")
        self.fetch_catalog(self.refresh_generation)

    @work(thread=True, exclusive=True, group="catalog", exit_on_error=False)
    def fetch_catalog(self, generation):
        try:
            catalog = self.service.client.fetch()
            message = CatalogResult(catalog, None, generation)
        except ClientError as error:
            message = CatalogResult(None, str(error), generation)
        if not get_current_worker().is_cancelled:
            self.post_message(message)

    def on_catalog_result(self, message: CatalogResult):
        if message.generation != self.refresh_generation:
            return
        if message.error:
            self.service.refresh_error = message.error
        else:
            self.service.catalog, self.service.refresh_error = message.catalog, None
        self.render_rows()

    @on(Input.Changed)
    @on(Select.Changed)
    def filters_changed(self):
        if self.is_mounted and self.service.catalog:
            self.render_rows()

    def render_rows(self):
        table = self.query_one("#servers", DataTable)
        catalog = self.service.catalog
        if catalog is None:
            self.query_one("#catalog-status", Static).update(
                self.service.refresh_error or "No catalog loaded."
            )
            return
        catalog.update_age_warnings()
        rows = select(catalog, self.current_query())
        previous = self.selected_id
        table.clear()
        for server in rows:
            table.add_row(
                str(server.rank),
                server.source,
                Text(server.location),
                Text(f"{server.remote_host}:{server.remote_port}/{server.protocol}"),
                "N/A" if server.ping_ms is None else f"{server.ping_ms} ms",
                "N/A" if server.uptime_days is None else f"{server.uptime_days}d",
                "Fresh" if server.active else "Retained",
                "Verified" if server.downloadable else "Unavailable",
                key=server.id,
            )
        selected = next((i for i, server in enumerate(rows) if server.id == previous), 0)
        self.selected_id = rows[selected].id if rows else None
        if rows:
            table.move_cursor(row=selected)
        self.render_detail()
        status = f"{len(rows)}/{len(catalog.servers)} records · Captured {catalog.captured_at} ({age_label(catalog.captured_at)}) · Published {catalog.published_at} ({age_label(catalog.published_at)}) · Fetched {catalog.fetched_at}"
        if catalog.warnings:
            status += "\n" + " ".join(catalog.warnings)
        if self.service.refresh_error:
            status += "\nRefresh failed; retaining memory: " + self.service.refresh_error
        self.query_one("#catalog-status", Static).update(status)

    @on(DataTable.RowHighlighted, "#servers")
    def selected(self, event: DataTable.RowHighlighted):
        self.selected_id = event.row_key.value
        self.render_detail()

    def render_detail(self):
        widget = self.query_one("#detail-content", Static)
        if self.selected_id and self.service.catalog:
            widget.update(detail_table(self.service.catalog.get(self.selected_id)))
        else:
            widget.update("No matching servers.")

    @on(Button.Pressed)
    def button(self, event: Button.Pressed):
        if event.button.id in {"refresh", "connect", "best", "disconnect", "export", "download"}:
            getattr(self, "action_" + event.button.id)()

    def action_connect(self):
        self.begin_connect(False)

    def action_best(self):
        self.begin_connect(True)

    def begin_connect(self, automatic):
        if self.connection_busy:
            self.notify("Connection operation is already running.")
            return
        try:
            catalog = self.service.require()
            server = (
                best(catalog, self.current_query()) if automatic else catalog.get(self.selected_id)
            )
            self.connection_busy = True
            self.query_one("#notice", Static).update(
                "Connecting selected server…"
                + (" Retained configuration." if not server.active else "")
            )
            self.connection_operation("connect", server)
        except ClientError as error:
            self.notify(str(error), severity="error")

    def action_disconnect(self):
        # Disconnect can cancel a pending startup through the independent RPC route.
        self.connection_operation("disconnect", None)

    @work(thread=True, group="connections", exit_on_error=False)
    def connection_operation(self, action, server):
        try:
            if action == "connect":
                raw = self.service.client.profile(server, for_connection=True)
                if get_current_worker().is_cancelled:
                    return
                worker = get_current_worker()
                status = self.session.connect(server, raw, cancelled=lambda: worker.is_cancelled)
            else:
                status = self.session.disconnect()
            result = OperationResult(
                f"VPN: {status['state']}", status=status, connection_finished=True
            )
        except ClientError as error:
            result = OperationResult(str(error), error=True, connection_finished=True)
        if not get_current_worker().is_cancelled:
            self.post_message(result)

    @work(thread=True, exclusive=True, group="status", exit_on_error=False)
    def poll_status(self):
        try:
            message = StatusResult(self.session.status())
        except ClientError as error:
            message = StatusResult(None, str(error))
        if not get_current_worker().is_cancelled:
            self.post_message(message)

    def on_status_result(self, message: StatusResult):
        content = "VPN: " + (message.error if message.error else message.status["state"])
        if message.status and message.status.get("error"):
            content += " · " + message.status["error"]
        self.query_one("#vpn-status", Static).update(content)

    def on_operation_result(self, message: OperationResult):
        if message.connection_finished:
            self.connection_busy = False
        self.query_one("#notice", Static).update(message.message)
        self.notify(message.message, severity="error" if message.error else "information")
        if message.status:
            self.post_message(StatusResult(message.status))

    def action_export(self):
        self.open_file_dialog("export")

    def action_download(self):
        self.open_file_dialog("download")

    def action_geo(self):
        def inspect_ip(ip):
            if not ip:
                return
            try:
                catalog = self.service.require()
                if ip not in catalog.geographies:
                    raise ClientError("No verified cached geography for this exact IP.")
                self.query_one("#detail-content", Static).update(
                    mapping_table(catalog.geographies[ip].public(), "Cached IP geography")
                )
            except ClientError as error:
                self.notify(str(error), severity="error")

        self.push_screen(GeographyDialog(), inspect_ip)

    def open_file_dialog(self, kind):
        try:
            catalog = self.service.require()
            server = catalog.get(self.selected_id) if kind == "download" else None
            rows = select(catalog, self.current_query())
        except ClientError as error:
            self.notify(str(error), severity="error")
            return

        def selected_path(result):
            if result:
                self.file_operation(kind, Path(result[0]), result[1], catalog, rows, server)

        self.push_screen(
            PathDialog(kind, server.filename if server else "openvpn-export.json"), selected_path
        )

    @work(thread=True, exclusive=True, group="files", exit_on_error=False)
    def file_operation(self, kind, path, format, catalog, rows, server):
        try:
            if kind == "download":
                raw = self.service.client.profile(server)
                if get_current_worker().is_cancelled:
                    return
                save_profile(raw, path)
            else:
                write_export(catalog, rows, format, path)
            result = OperationResult(f"Saved {path}.")
        except ClientError as error:
            result = OperationResult(str(error), error=True)
        if not get_current_worker().is_cancelled:
            self.post_message(result)


def main():
    from .cli import app

    app([*sys.argv[1:], "tui"])
