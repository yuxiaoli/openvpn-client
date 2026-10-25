from dataclasses import replace

import httpx
import pytest
from conftest import envelope, profile

from openvpn_cli.api import WorkerClient
from openvpn_cli.config import Settings
from openvpn_cli.errors import ClientError
from openvpn_cli.models import decode_servers
from openvpn_cli.profiles import eligible, parse_profile, save_profile, verify_profile
from openvpn_cli.query import export_text, write_export


def test_download_uses_worker_url_and_bearer_auth(service, api):
    server = service.refresh().servers[0]
    assert service.client.profile(server, for_connection=True) == profile()
    request = api.requests[-1]
    assert request.headers["Authorization"] == "Bearer fixture-token"
    assert request.url.host == "vpn.example.com"
    assert request.url.path.endswith("fixture.ovpn")


def test_download_accepts_new_worker_url_and_verification_timestamp():
    value = envelope()
    row = value["payload"]["index"]["servers"][0]
    row["download_url"] = "https://vpn.example.com/" + row["object_key"]
    row["profile_distribution"]["verified_at"] = row["profile_distribution"].pop(
        "public_verified_at"
    )
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, content=profile())

    client = WorkerClient(Settings(token="testtoken"), transport=httpx.MockTransport(handler))
    try:
        server = decode_servers(value).servers[0]
        assert eligible(server)
        assert client.profile(server) == profile()
        assert str(requests[0].url) == row["download_url"]
        assert requests[0].headers["Authorization"] == "Bearer testtoken"
    finally:
        client.close()


def test_legacy_links_use_configured_worker_and_do_not_leak_token_to_other_urls():
    server = decode_servers(envelope()).servers[0]
    legacy = "https://profiles.example.com/" + server.object_key
    server = replace(server, download_url=legacy)
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, content=profile())

    client = WorkerClient(
        Settings(api_url="https://configured.worker.test", token="testtoken"),
        transport=httpx.MockTransport(handler),
    )
    try:
        assert client.profile(server) == profile()
        assert str(requests[0].url) == "https://configured.worker.test/" + server.object_key
        assert requests[0].headers["Authorization"] == "Bearer testtoken"
        for url in [
            legacy,
            "https://configured.worker.test.evil.test/api/servers",
            "https://configured.worker.test/" + server.object_key + "?token=x",
        ]:
            with pytest.raises(ClientError, match="Only fixed Worker"):
                client.read(url, 256_000, api=True)
        assert len(requests) == 1
    finally:
        client.close()


def test_custom_catalog_origin_downloads_only_from_configured_worker():
    server = decode_servers(envelope()).servers[0]
    server = replace(server, download_url="https://catalog.example.net/" + server.object_key)
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, content=profile())

    client = WorkerClient(
        Settings(api_url="https://configured.worker.test", token="fixture-token"),
        transport=httpx.MockTransport(handler),
    )
    try:
        assert eligible(server)
        assert client.profile(server, for_connection=True) == profile()
        assert len(requests) == 1
        assert str(requests[0].url) == "https://configured.worker.test/" + server.object_key
        assert requests[0].headers["Authorization"] == "Bearer fixture-token"
        with pytest.raises(ClientError, match="Only fixed Worker"):
            client.read(server.download_url, 256_000, api=True)
        assert len(requests) == 1
    finally:
        client.close()


@pytest.mark.parametrize(
    "origin",
    [
        "http://catalog.example.net",
        "https://user:password@catalog.example.net",
        "https://catalog.example.net:443",
        "https://[invalid",
    ],
)
def test_profile_metadata_rejects_unsafe_origins(origin):
    server = decode_servers(envelope()).servers[0]
    assert not eligible(replace(server, download_url=origin + "/" + server.object_key))


@pytest.mark.parametrize(
    "field,value",
    [
        ("download_url", "https://evil.test/x"),
        ("download_url", "https://profiles.example.com/jp"),
        ("config_bytes", 256001),
        ("object_key", "ovpn/not-immutable"),
        ("filename", "../x.ovpn"),
    ],
)
def test_unavailable_metadata(field, value):
    server = decode_servers(envelope()).servers[0]
    assert not eligible(replace(server, **{field: value}))


def test_corrupt_bytes_and_endpoint():
    server = decode_servers(envelope()).servers[0]
    with pytest.raises(ClientError, match="verification"):
        verify_profile(profile() + b"bad", server)
    with pytest.raises(ClientError, match="endpoint"):
        server = replace(server, remote_host="8.8.8.8")
        verify_profile(profile(), server)


@pytest.mark.parametrize(
    "directive",
    [
        "up /tmp/run",
        "plugin /tmp/p.so",
        "config other.ovpn",
        "auth-user-pass",
        "ca /tmp/ca",
        "management 0.0.0.0 1234",
        "log /tmp/log",
        "daemon",
        "setenv OPENVPN_PLUGIN /tmp/p.so",
        "script-security 3",
        "http-proxy host 1",
        "ignore-unknown-option up",
        "dev tap",
    ],
)
def test_unsafe_and_unsupported_profiles(directive):
    with pytest.raises(ClientError):
        parse_profile(profile(extra=directive + "\n"), for_connection=True)


def test_unclosed_blocks_multiple_remotes_and_inline_connection():
    for value in (
        profile().replace(b"</key>", b""),
        profile(extra="remote 8.8.8.8 1194\n"),
        profile(extra="<connection>\nremote evil 2\n</connection>\n"),
    ):
        with pytest.raises(ClientError):
            parse_profile(value, for_connection=True)


def test_download_redirect_rejected():
    server = decode_servers(envelope()).servers[0]
    client = WorkerClient(
        Settings(token="token"),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(302, headers={"location": "https://evil.test"})
        ),
    )
    with pytest.raises(ClientError, match="302"):
        client.profile(server)
    client.close()


def test_explicit_files_preserve_bytes_and_refuse_overwrite(tmp_path):
    path = tmp_path / "profile.ovpn"
    save_profile(profile(), path)
    assert path.read_bytes() == profile()
    with pytest.raises(ClientError, match="exists"):
        save_profile(b"other", path)
    catalog = decode_servers(envelope())
    exported = tmp_path / "view.json"
    write_export(catalog, catalog.servers, "json", exported)
    with pytest.raises(ClientError, match="exists"):
        write_export(catalog, [], "csv", exported)
    assert "PRIVATE KEY" not in exported.read_text()


def test_csv_units_missing_values_and_formula_escape():
    catalog = decode_servers(envelope())
    catalog.servers[0] = replace(catalog.servers[0], location="=HYPERLINK(fake)")
    content = export_text(catalog, catalog.servers, "csv")
    assert "ping_ms" in content
    assert "'=HYPERLINK(fake)" in content
    assert "9999" not in content


def test_inline_username_password_supported_without_prompt():
    raw = profile(extra="<auth-user-pass>\nsynthetic-user\nsynthetic-password\n</auth-user-pass>\n")
    assert parse_profile(raw, for_connection=True) == ("1.1.1.1", 1194, "udp")
    start, end = raw.index(b"<cert>"), raw.index(b"</key>") + len(b"</key>")
    assert parse_profile(raw[:start] + raw[end:], for_connection=True) == ("1.1.1.1", 1194, "udp")


def test_inline_username_without_password_is_unsupported():
    with pytest.raises(ClientError, match="interactive credentials"):
        parse_profile(
            profile(extra="<auth-user-pass>\nsynthetic-user\n</auth-user-pass>\n"),
            for_connection=True,
        )
