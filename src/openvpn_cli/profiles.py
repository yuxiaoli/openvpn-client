"""Verify immutable profile bytes, without executing or modifying them."""

from __future__ import annotations

import hashlib
import re
import shlex
from pathlib import Path
from urllib.parse import urlsplit

from .errors import ClientError
from .models import HASH, Server, canonical_host, protocol, timestamp

PROFILE_HOST = "vpn.example.com"
LEGACY_PROFILE_HOST = "profiles.example.com"
PROFILE_PATH = re.compile(r"/ovpn/sha256/[a-f0-9]{64}/[A-Za-z0-9][A-Za-z0-9._-]{0,219}\.ovpn")
MAX_PROFILE_BYTES = 256_000
PROFILE_POLICY_VERSION = 1
# Unknown directives are deliberately rejected for elevated execution. This covers
# the published profiles without admitting hooks, includes, paths or plugins.
ALLOWED = {
    "client",
    "dev",
    "remote",
    "proto",
    "nobind",
    "persist-key",
    "persist-tun",
    "resolv-retry",
    "verb",
    "auth",
    "cipher",
    "data-ciphers",
    "data-ciphers-fallback",
    "ignore-unknown-option",
    "remote-cert-tls",
    "tls-version-min",
    "tls-version-max",
    "reneg-sec",
    "mute",
    "connect-retry",
    "connect-timeout",
    "auth-nocache",
    "explicit-exit-notify",
    "sndbuf",
    "rcvbuf",
    "tun-mtu",
    "mssfix",
}
INLINE = {"ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "auth-user-pass"}


def eligible(server: Server) -> bool:
    dist = server.distribution
    digest, size, filename = server.config_sha256, server.config_bytes, server.filename
    if (
        not dist
        or dist.status != "verified"
        or not isinstance(digest, str)
        or not HASH.fullmatch(digest)
        or type(size) is not int
        or not 1 <= size <= MAX_PROFILE_BYTES
        or dist.sha256 != digest
        or type(dist.bytes) is not int
        or dist.bytes != size
        or not isinstance(filename, str)
        or ".." in filename
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,219}\.ovpn", filename)
        or re.fullmatch(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])", filename.split(".")[0], re.I)
    ):
        return False
    key = f"ovpn/sha256/{digest}/{filename}"
    if server.object_key != key or not isinstance(server.download_url, str):
        return False
    try:
        url = urlsplit(server.download_url)
        timestamp(dist.public_verified_at)
        return (
            url.scheme == "https"
            # Catalog URLs describe provenance only. Downloads always use the
            # configured Worker's immutable route, never this URL or its host.
            and bool(url.hostname)
            and url.username is None
            and url.password is None
            and url.path == f"/{key}"
            and not url.query
            and not url.fragment
            and url.port is None
        )
    except (ValueError, ClientError):
        return False


def parse_profile(raw: bytes, *, for_connection: bool = False) -> tuple[str, int, str]:
    if not raw or len(raw) > MAX_PROFILE_BYTES:
        raise ClientError("Profile is empty or exceeds 256,000 bytes.")
    try:
        content = raw.decode("utf-8-sig")
    except UnicodeError:
        raise ClientError("Profile is not UTF-8.") from None
    if "\x00" in content or any(ord(c) < 32 and c not in "\n\r\t" for c in content):
        raise ClientError("Profile contains invalid control characters.")
    remotes, proto, client, block = [], "udp", False, None
    blocks, directives = set(), set()
    inline_credentials = []
    for line in content.splitlines():
        line = line.strip()
        if block:
            if line == f"</{block}>":
                block = None
            elif line.startswith("<"):
                raise ClientError("Nested profile blocks are unsupported.")
            elif block == "auth-user-pass":
                inline_credentials.append(line)
            continue
        if not line or line.startswith(("#", ";")):
            continue
        tag = re.fullmatch(r"<([a-zA-Z0-9_-]+)>", line)
        if tag:
            block = tag[1]
            if block not in INLINE or block in blocks:
                raise ClientError("Unsupported or duplicate inline profile block.")
            blocks.add(block)
            continue
        if line.startswith("<"):
            raise ClientError("Malformed inline profile block.")
        try:
            lexer = shlex.shlex(line, posix=True)
            lexer.whitespace_split = True
            lexer.commenters = "#;"
            parts = list(lexer)
        except ValueError:
            raise ClientError("Malformed profile directive.") from None
        if not parts:
            continue
        name, args = parts[0].removeprefix("--"), parts[1:]
        if not re.fullmatch(r"[a-z][a-z0-9-]*", name):
            raise ClientError("Invalid profile directive name.")
        directives.add(name)
        if name in {"http-proxy", "socks-proxy", "remote-random-hostname", "connection"}:
            raise ClientError("Indirect or multiple profile endpoints are unsupported.")
        if for_connection:
            if name == "auth-user-pass":
                raise ClientError("Interactive username/password profiles are unsupported in v1.")
            if name not in ALLOWED:
                raise ClientError(f"Profile directive is unsupported for connection: {name}.")
            if name == "dev" and args != ["tun"]:
                raise ClientError("Only TUN client profiles are supported.")
            if name == "ignore-unknown-option" and (
                not args or any(a.removeprefix("--") not in ALLOWED for a in args)
            ):
                raise ClientError("Profile requests ignoring an unsupported directive.")
            if name == "remote-cert-tls" and args != ["server"]:
                raise ClientError("Unsupported certificate peer role.")
            if name in {"client", "nobind", "persist-key", "persist-tun", "auth-nocache"} and args:
                raise ClientError("Unexpected arguments to a profile flag.")
            if (
                name
                not in {
                    "remote",
                    "ignore-unknown-option",
                    "client",
                    "nobind",
                    "persist-key",
                    "persist-tun",
                    "auth-nocache",
                }
                and len(args) > 2
            ):
                raise ClientError("Too many profile directive arguments.")
        if name == "client":
            client = True
        elif name == "remote":
            remotes.append(args)
        elif name == "proto":
            if len(args) != 1:
                raise ClientError("Malformed profile protocol.")
            proto = protocol(args[0])
    if block or not client or len(remotes) != 1 or not 1 <= len(remotes[0]) <= 3:
        raise ClientError("Expected a client profile with one endpoint and closed inline blocks.")
    args = remotes[0]
    host = canonical_host(args[0])
    try:
        port = int(args[1]) if len(args) >= 2 else 1194
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        raise ClientError("Invalid profile port.") from None
    proto = protocol(args[2]) if len(args) == 3 else proto
    if for_connection:
        if "auth-user-pass" in blocks and (
            len(inline_credentials) != 2 or not all(inline_credentials)
        ):
            raise ClientError(
                "Inline username/password profiles require both values; interactive credentials are unsupported in v1."
            )
        certificate_credentials = {"cert", "key"} <= blocks
        if ("cert" in blocks) != ("key" in blocks):
            raise ClientError("Inline certificate and private key must be supplied together.")
        if (
            "ca" not in blocks
            or "dev" not in directives
            or not (certificate_credentials or "auth-user-pass" in blocks)
        ):
            raise ClientError(
                "Connection requires dev tun, an inline CA and self-contained inline credentials."
            )
    return host, port, proto


def verify_profile(raw: bytes, server: Server, *, for_connection=False) -> bytes:
    if not eligible(server):
        raise ClientError("Server has no verified immutable downloadable profile.")
    if len(raw) != server.config_bytes or hashlib.sha256(raw).hexdigest() != server.config_sha256:
        raise ClientError("Downloaded profile failed byte-count or SHA-256 verification.")
    endpoint = parse_profile(raw, for_connection=for_connection)
    if endpoint != (server.remote_host, server.remote_port, server.protocol):
        raise ClientError("Downloaded profile endpoint does not match the selected server.")
    return raw


def save_profile(raw: bytes, path: Path) -> Path:
    # x mode avoids a check-then-overwrite race and preserves original bytes.
    try:
        with path.open("xb") as handle:
            if __import__("os").name != "nt":
                __import__("os").fchmod(handle.fileno(), 0o600)
            handle.write(raw)
    except FileExistsError:
        raise ClientError("Output file already exists; choose another path.") from None
    except OSError:
        raise ClientError("Cannot write the profile output file.") from None
    return path
