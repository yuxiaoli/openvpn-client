import json

import pytest

from openvpn_cli import config
from openvpn_cli.errors import ClientError


def test_explicit_env_only_and_precedence(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "config_path", lambda: tmp_path / "config.json")
    monkeypatch.delenv("OPENVPN_KV_TOKEN", raising=False)
    (tmp_path / ".env").write_text("OPENVPN_KV_TOKEN=automatic-discovery-forbidden\n")
    monkeypatch.chdir(tmp_path)
    assert config.load_settings().token == ""
    explicit = tmp_path / "explicit.env"
    explicit.write_text("OPENVPN_KV_TOKEN=file-token\n")
    assert config.load_settings(env_file=explicit).token == "file-token"
    monkeypatch.setenv("OPENVPN_KV_TOKEN", "env-token")
    settings = config.load_settings(env_file=explicit)
    assert settings.token == "env-token"
    assert "env-token" not in repr(settings)
    saved = config.save_settings(settings)
    assert "TOKEN" not in saved.read_text() and "env-token" not in saved.read_text()
    assert json.loads(saved.read_text())["api_url"] == config.DEFAULT_API


@pytest.mark.parametrize(
    "url",
    [
        "http://example.test",
        "https://user:password@example.test",
        "https://example.test/api",
        "https://example.test?token=value",
        "https://example.test/#fragment",
        "https://[invalid",
        "https://example.test:invalid",
    ],
)
def test_invalid_api_origins(url):
    with pytest.raises(ClientError):
        config.validate_api_url(url)
