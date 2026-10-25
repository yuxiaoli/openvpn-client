import io
import json

import httpx
import pytest
from textual.widgets import DataTable, Input, Static
from typer.testing import CliRunner

from openvpn_cli import cli
from openvpn_cli.api import WorkerClient
from openvpn_cli.shell import OpenVPNShell, server_ids
from openvpn_cli.tui import OpenVPNTUI, OperationResult


@pytest.fixture
def command(monkeypatch, api, session, tmp_path):
    from openvpn_cli import config

    monkeypatch.setattr(config, "config_path", lambda: tmp_path / "config.json")
    monkeypatch.setenv("OPENVPN_KV_TOKEN", "fixture-token")
    monkeypatch.setattr(
        cli,
        "WorkerClient",
        lambda settings: WorkerClient(settings, transport=httpx.MockTransport(api)),
    )
    monkeypatch.setattr(cli, "SessionClient", lambda _: session)
    return CliRunner()


def test_cli_launch_fetch_json_and_filters(command, api):
    result = command.invoke(cli.app, ["list", "--country", "JP", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert len(data["servers"]) == 1
    assert len(api.requests) == 2
    assert "fixture-token" not in result.output
    result = command.invoke(cli.app, ["list", "--json", "--freshness", "retained"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["servers"][0]["source"] == "vpngate"
    assert len(api.requests) == 4


def test_cli_connection_selection_and_api_independent_status(command, api, session):
    result = command.invoke(cli.app, ["connect", "--best", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["state"] == "CONNECTED"
    before = len(api.requests)
    api.failure = 503
    assert command.invoke(cli.app, ["status", "--json"]).exit_code == 0
    assert command.invoke(cli.app, ["disconnect"]).exit_code == 0
    assert len(api.requests) == before
    assert session.disconnects == 1


def test_cli_errors_codes_and_file_exports(command, api, tmp_path):
    assert command.invoke(cli.app, ["connect"]).exit_code == 2
    assert command.invoke(cli.app, ["list", "--sort", "speed"]).exit_code == 2
    path = tmp_path / "export.csv"
    assert (
        command.invoke(cli.app, ["export", "--format", "csv", "--output", str(path)]).exit_code == 0
    )
    assert path.read_text().startswith("id,source,")
    assert command.invoke(cli.app, ["export", "--output", str(path)]).exit_code == 1
    api.failure = 401
    result = command.invoke(cli.app, ["list", "--json"])
    assert result.exit_code == 1
    assert result.stdout == ""
    assert "401" in result.stderr
    assert "fixture-token" not in result.output


def test_cli_setup_requires_explicit_repo_opt_in(command, monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "install_openvpn", lambda **kwargs: calls.append(kwargs))
    monkeypatch.setattr(cli, "check_doctor", lambda _: {"ready": True})
    assert command.invoke(cli.app, ["setup", "--add-openvpn-repo"]).exit_code == 2
    assert calls == []
    assert command.invoke(cli.app, ["setup", "--install", "--add-openvpn-repo"]).exit_code == 0
    assert calls == [{"add_repository": True}]


def test_shell_launch_refresh_redirection_completion_and_session(service, session, api, tmp_path):
    stream = io.StringIO()
    shell = OpenVPNShell(service, session, stdout=stream)
    assert len(api.requests) == 2
    assert len(server_ids(shell)) == 2
    shell.onecmd_plus_hooks("list --country JP --json")
    assert "ipspeed" in stream.getvalue()
    assert len(api.requests) == 2
    output = tmp_path / "shell-output.json"
    shell.onecmd_plus_hooks(f'list --json > "{output}"')
    assert len(json.loads(output.read_text())["servers"]) == 2
    shell.onecmd_plus_hooks("help connect")
    assert "--best" in stream.getvalue()
    shell.onecmd_plus_hooks("connect --best --json")
    assert session.current["state"] == "CONNECTED"
    shell.onecmd_plus_hooks("refresh")
    assert len([r for r in api.requests if r.url.path == "/api/servers"]) == 2
    shell.close()
    assert session.current["state"] == "CONNECTED"


def test_shell_failed_refresh_keeps_catalog(service, session, api):
    shell = OpenVPNShell(service, session, stdout=io.StringIO())
    catalog = service.catalog
    api.failure = 503
    shell.onecmd_plus_hooks("refresh")
    assert service.catalog is catalog
    assert service.refresh_error
    shell.onecmd_plus_hooks("status --json")


@pytest.mark.parametrize("size", [(120, 42), (78, 25)])
async def test_tui_start_filter_refresh_connect_and_detach(service, session, api, size):
    app = OpenVPNTUI(service, session)
    async with app.run_test(size=size) as pilot:
        await app.workers.wait_for_complete()
        await pilot.pause()
        table = app.query_one("#servers", DataTable)
        assert table.row_count == 2
        assert len(api.requests) == 2
        app.query_one("#country", Input).value = "JP"
        await pilot.pause()
        assert table.row_count == 1
        assert len(api.requests) == 2
        app.action_connect()
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert session.current["state"] == "CONNECTED"
        api.failure = 503
        app.action_refresh()
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert table.row_count == 1
        assert "retaining memory" in str(app.query_one("#catalog-status", Static).render())
    assert session.current["state"] == "CONNECTED"


async def test_tui_api_failure_still_allows_disconnect(service, session, api):
    api.failure = 401
    app = OpenVPNTUI(service, session)
    async with app.run_test() as pilot:
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert app.query_one("#servers", DataTable).row_count == 0
        app.action_disconnect()
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert session.disconnects == 1


async def test_tui_exact_geo_uses_current_catalog_and_file_result_keeps_connection_busy(
    service, session, api
):
    app = OpenVPNTUI(service, session)
    async with app.run_test() as pilot:
        await app.workers.wait_for_complete()
        await pilot.pause()
        requests = len(api.requests)
        app.action_geo()
        await pilot.pause()
        app.screen.query_one("#geo-ip", Input).value = "1.1.1.1"
        await pilot.click("#inspect")
        await pilot.pause()
        assert app.query_one("#detail-content", Static).content.title == "Cached IP geography"
        assert len(api.requests) == requests
        app.connection_busy = True
        app.on_operation_result(OperationResult("Saved explicit export."))
        assert app.connection_busy
