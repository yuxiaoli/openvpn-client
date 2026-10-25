from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import dotenv_values
from platformdirs import user_config_path

from .errors import ClientError

DEFAULT_API = "https://vpn.example.com"


def config_path() -> Path:
    return user_config_path("openvpn-kv", appauthor=False) / "config.json"


def validate_api_url(value: str) -> str:
    try:
        url = urlsplit(value)
    except (TypeError, ValueError):
        raise ClientError("API URL must be a valid HTTPS origin.") from None
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username
        or url.password
        or url.query
        or url.fragment
        or url.path not in ("", "/")
    ):
        raise ClientError("API URL must be an HTTPS origin without credentials, path or query.")
    try:
        url.port
    except ValueError:
        raise ClientError("API URL has an invalid port.") from None
    return value.rstrip("/")


@dataclass(frozen=True)
class Settings:
    api_url: str = DEFAULT_API
    token: str = field(default="", repr=False)
    openvpn_path: str | None = None
    owner: str | None = None

    def require_token(self) -> str:
        if not re.fullmatch(r"[A-Za-z0-9._~+/\-]+=*", self.token) or len(self.token) > 4000:
            raise ClientError("Set OPENVPN_KV_TOKEN in the environment or an explicit --env-file.")
        return self.token


def load_settings(
    *,
    api_url: str | None = None,
    env_file: Path | None = None,
    openvpn_path: str | None = None,
    owner: str | None = None,
) -> Settings:
    stored: dict = {}
    path = config_path()
    if path.exists():
        try:
            stored = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(stored, dict):
                raise ValueError
        except (OSError, ValueError):
            raise ClientError("Client config is invalid. Run setup to replace it.") from None
    file_env = {}
    if env_file is not None:
        if not env_file.is_file():
            raise ClientError("The explicit environment file is unavailable.")
        try:
            file_env = dotenv_values(env_file, interpolate=False)
        except (OSError, UnicodeError):
            raise ClientError("Cannot read the explicit environment file.") from None

    def value(name: str, default=None):
        return os.environ.get(name, file_env.get(name, default))

    return Settings(
        validate_api_url(
            api_url or value("OPENVPN_KV_API_URL") or stored.get("api_url", DEFAULT_API)
        ),
        value("OPENVPN_KV_TOKEN", "") or "",
        openvpn_path or value("OPENVPN_KV_OPENVPN_PATH") or stored.get("openvpn_path"),
        owner,
    )


def save_settings(settings: Settings) -> Path:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Deliberately no token or automatic .env discovery/persistence.
    data = {"api_url": settings.api_url, "openvpn_path": settings.openvpn_path}
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    temp.replace(path)
    return path
