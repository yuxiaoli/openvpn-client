from __future__ import annotations

import ipaddress
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta

import httpx

from .config import Settings
from .errors import ClientError
from .models import Catalog, Server, decode_geographies, decode_servers, now, timestamp
from .profiles import MAX_PROFILE_BYTES, PROFILE_PATH, eligible, verify_profile


class WorkerClient:
    def __init__(self, settings: Settings, *, transport=None):
        self.settings = settings
        # Credentials are attached only to the configured Worker's KV/profile routes.
        self.http = httpx.Client(
            timeout=10,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
            event_hooks={"request": [lambda request: request.headers.pop("Cookie", None)]},
        )

    def close(self):
        self.http.close()

    def read(self, url: str, maximum: int, *, api=False) -> bytes:
        if (
            api
            and url
            not in {
                self.settings.api_url + "/api/servers",
                self.settings.api_url + "/api/geolocation",
            }
            and not (
                url.startswith(self.settings.api_url + "/")
                and PROFILE_PATH.fullmatch(url[len(self.settings.api_url) :])
            )
        ):
            raise ClientError(
                "Only fixed Worker KV and immutable profile endpoints accept API credentials."
            )
        headers = {"Authorization": f"Bearer {self.settings.require_token()}"} if api else {}
        try:
            with self.http.stream("GET", url, headers=headers) as response:
                if response.status_code != 200:
                    if api and response.status_code == 401:
                        raise ClientError("Worker rejected the API token (HTTP 401).")
                    raise ClientError(
                        f"{'Worker' if api else 'Profile download'} returned HTTP {response.status_code}."
                    )
                length = response.headers.get("content-length")
                if length is not None:
                    try:
                        if int(length) < 0 or int(length) > maximum:
                            raise ClientError("Response exceeds the allowed byte limit.")
                    except ValueError:
                        raise ClientError("Response has an invalid byte-count header.") from None
                body = bytearray()
                for chunk in response.iter_bytes(chunk_size=65536):
                    if len(body) + len(chunk) > maximum:
                        raise ClientError("Response exceeds the allowed byte limit.")
                    body.extend(chunk)
                return bytes(body)
        except httpx.HTTPError:
            raise ClientError(
                "Network request failed or timed out. Check network access and retry."
            ) from None

    def json(self, endpoint: str, maximum: int) -> dict:
        raw = self.read(self.settings.api_url + endpoint, maximum, api=True)
        try:
            return json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        except (ValueError, UnicodeError, RecursionError):
            raise ClientError("Worker returned invalid JSON.") from None

    def fetch(self) -> Catalog:
        self.settings.require_token()
        with ThreadPoolExecutor(max_workers=2) as executor:
            servers = executor.submit(self.json, "/api/servers", 2_000_000)
            geography = executor.submit(self.json, "/api/geolocation", 1_500_000)
            catalog = decode_servers(servers.result())
            try:
                updated_at, entries = decode_geographies(geography.result())
                catalog.geography_updated_at, catalog.geographies = updated_at, entries
            except ClientError as error:
                catalog.warnings.append(f"Geography unavailable: {error}")
                return catalog
        joined = []
        stale = 0
        for server in catalog.servers:
            geo = None
            try:
                ip = ipaddress.ip_address(server.remote_host)
                if ip.is_global:
                    geo = entries.get(server.remote_host)
            except ValueError:
                pass
            if geo and now() - timestamp(geo.queried_at) > timedelta(days=7):
                stale += 1
            joined.append(replace(server, geography=geo))
        catalog.servers = joined
        if stale:
            catalog.warnings.append(f"{stale} server lookup(s) are older than seven days.")
        return catalog

    def profile(self, server: Server, *, for_connection=False) -> bytes:
        if not eligible(server):
            raise ClientError("Server has no verified immutable downloadable profile.")
        # Old R2 links and current Worker links resolve to the configured Worker;
        # never send credentials to the URL supplied by catalog metadata.
        raw = self.read(f"{self.settings.api_url}/{server.object_key}", MAX_PROFILE_BYTES, api=True)
        return verify_profile(raw, server, for_connection=for_connection)


class CatalogService:
    """In-memory session state only. Refresh never writes a catalog to disk."""

    def __init__(self, client: WorkerClient):
        self.client = client
        self.catalog: Catalog | None = None
        self.refresh_error: str | None = None

    def refresh(self) -> Catalog:
        try:
            catalog = self.client.fetch()
        except ClientError as error:
            self.refresh_error = str(error)
            raise
        self.catalog, self.refresh_error = catalog, None
        return catalog

    def require(self) -> Catalog:
        if self.catalog is None:
            raise ClientError("No catalog loaded. Refresh after checking API configuration.")
        self.catalog.update_age_warnings()
        return self.catalog
