from datetime import timedelta

import httpx
import pytest
from conftest import envelope, geography, row

from openvpn_cli.api import WorkerClient
from openvpn_cli.config import Settings
from openvpn_cli.errors import ClientError
from openvpn_cli.models import decode_geographies, decode_servers, now
from openvpn_cli.query import Query, best, export_text, select


def test_fetch_provenance_join_and_no_disk_cache(service, api, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    catalog = service.refresh()
    assert catalog.servers[0].location == "Japan"
    assert catalog.servers[0].geography.country_code == "US"
    assert catalog.servers[1].ping_ms is None
    assert len(api.requests) == 2
    assert all(r.headers["Authorization"] == "Bearer fixture-token" for r in api.requests)
    assert list(tmp_path.iterdir()) == []
    assert "fixture-token" not in export_text(catalog, catalog.servers, "json")


def test_optional_geography_failure(service, api):
    api.geo_failure = 503
    catalog = service.refresh()
    assert len(catalog.servers) == 2
    assert catalog.servers[0].geography is None
    assert any("unavailable" in w.lower() for w in catalog.warnings)


def test_failed_refresh_retains_only_memory(service, api):
    catalog = service.refresh()
    api.failure = 401
    with pytest.raises(ClientError, match="401"):
        service.refresh()
    assert service.catalog is catalog
    assert "401" in service.refresh_error


@pytest.mark.parametrize(
    "mutation",
    [
        lambda e: e.update(schema_version=3),
        lambda e: e.update(fixture_only=True),
        lambda e: e["payload"]["index"].update(schema_version=1),
        lambda e: e["payload"]["index"].update(server_count=999),
        lambda e: e["payload"]["index"].update(active_count=False),
        lambda e: e["payload"]["index"].update(source="https://evil.test"),
        lambda e: e.update(captured_at="not-a-date"),
        lambda e: e["payload"]["index"]["servers"][0].update(id="ipspeed:" + "0" * 64),
        lambda e: e["payload"]["index"]["servers"][0].update(remote_port=True),
        lambda e: e["payload"]["index"]["servers"][0].update(active=False),
        lambda e: e["payload"]["index"]["servers"][0].update(location="\x1b[2J"),
        lambda e: e["payload"]["index"]["servers"][0].update(rank_score=float("nan")),
    ],
)
def test_reject_bad_contract(mutation):
    value = envelope()
    mutation(value)
    with pytest.raises(ClientError):
        decode_servers(value)


def test_duplicate_id_and_cross_source_same_endpoint():
    with pytest.raises(ClientError, match="duplicate"):
        decode_servers(envelope([row(), row()]))
    catalog = decode_servers(envelope([row(), row(source="vpngate", rank=2)]))
    assert catalog.servers[0].id != catalog.servers[1].id


def test_age_and_retained_warning():
    value = envelope()
    value["captured_at"] = (now() - timedelta(hours=37)).isoformat()
    assert "36 hours" in decode_servers(value).warnings[0]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda e: e.update(schema_version=2),
        lambda e: e["entries"]["1.1.1.1"].update(ip="8.8.8.8"),
        lambda e: e["entries"]["1.1.1.1"].update(provider="unknown"),
        lambda e: e["entries"]["1.1.1.1"].update(latitude=91),
        lambda e: e["entries"]["1.1.1.1"].update(longitude=float("inf")),
        lambda e: e["entries"]["1.1.1.1"].update(queried_at="bad"),
    ],
)
def test_bad_geography(mutation):
    data = geography()
    mutation(data)
    with pytest.raises(ClientError):
        decode_geographies(data)


def test_filters_unknown_last_and_best():
    catalog = decode_servers(envelope())
    assert [s.source for s in select(catalog, Query(country="US"))] == ["vpngate"]
    assert select(catalog, Query(country="Japan"))[0].source == "ipspeed"
    assert select(catalog, Query(freshness="retained"))[0].source == "vpngate"
    assert select(catalog, Query(sort="latency"))[-1].ping_ms is None
    assert best(catalog, Query()).source == "ipspeed"
    with pytest.raises(ClientError, match="No fresh"):
        best(catalog, Query(source="vpngate"))
    with pytest.raises(ClientError, match="Sort"):
        select(catalog, Query(sort="speed"))


@pytest.mark.parametrize("status", [400, 401, 404, 503, 302])
def test_http_errors_have_no_secret(status):
    client = WorkerClient(
        Settings(token="private-fixture-token"),
        transport=httpx.MockTransport(lambda _: httpx.Response(status)),
    )
    with pytest.raises(ClientError) as caught:
        client.fetch()
    assert "private-fixture-token" not in str(caught.value)
    client.close()


def test_stream_limit_and_invalid_json():
    client = WorkerClient(
        Settings(token="token"),
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b"x" * 101)),
    )
    with pytest.raises(ClientError, match="byte limit"):
        client.read("https://example.test", 100)
    with pytest.raises(ClientError, match="invalid JSON"):
        client.json("/api/servers", 1000)
    client.close()


def test_timeout_is_sanitized():
    def request(req):
        raise httpx.ReadTimeout("contains-sensitive-token", request=req)

    client = WorkerClient(Settings(token="token"), transport=httpx.MockTransport(request))
    with pytest.raises(ClientError, match="timed out") as caught:
        client.fetch()
    assert "sensitive" not in str(caught.value)
    client.close()


@pytest.mark.parametrize(
    "field,value", [("source", []), ("refresh_status", {}), ("protocol", []), ("rank", True)]
)
def test_malformed_field_types_produce_operational_errors(field, value):
    data = envelope()
    data["payload"]["index"]["servers"][0][field] = value
    with pytest.raises(ClientError):
        decode_servers(data)


def test_cookie_and_bearer_never_leak_to_profile_requests():
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(200, content=b"{}", headers={"set-cookie": "secret=private; Path=/"})

    client = WorkerClient(Settings(token="fixture-token"), transport=httpx.MockTransport(respond))
    try:
        client.json("/api/servers", 100)
        client.read(client.settings.api_url + "/profile-test", 100)
        assert "Authorization" not in requests[-1].headers
        assert "Cookie" not in requests[-1].headers
        with pytest.raises(ClientError, match="fixed"):
            client.read("https://other.test/api/servers", 100, api=True)
    finally:
        client.close()
