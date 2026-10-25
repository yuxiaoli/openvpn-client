# Configuration and API requirements

OpenVPN Dash Client needs a compatible catalog service operated by you or a
provider who has granted you access. The default `https://vpn.example.com` is a
reserved example origin. A public client download does not grant API access.

## Supply settings

The settings are:

| Setting | Environment variable | Global CLI option |
| --- | --- | --- |
| HTTPS API origin | `OPENVPN_KV_API_URL` | `--api-url` |
| API read token | `OPENVPN_KV_TOKEN` | Environment or explicit file only |
| Community executable path | `OPENVPN_KV_OPENVPN_PATH` | `--openvpn-path` |
| Originating account after elevation | None | `--owner` |

Global options go before the subcommand. For example:

```text
openvpn-kv --api-url https://vpn.example.com --env-file client.env list
openvpn-kv --openvpn-path "C:\Program Files\OpenVPN\bin\openvpn.exe" doctor --json
```

Replace the example API origin with your service. API origins must use HTTPS and
have no credentials, path, query or fragment. An explicit port is supported.

Copy the safe example to `client.env` and edit it locally:

```dotenv
OPENVPN_KV_API_URL=https://vpn.example.com
OPENVPN_KV_TOKEN=replace-with-your-own-read-token
```

Use `--env-file client.env` on commands that need it. Files are parsed as data,
without variable interpolation. The client never searches for `.env` files.
Process environment values take precedence over values in the explicit file.
CLI options take precedence over both; the saved setup file supplies remaining
nonsecret API/path values, followed by the example API default. An existing empty
environment token remains empty rather than falling back to a file token.

`setup` saves the API origin and optional executable path in the platform's user
configuration directory for `openvpn-kv`. It does not save tokens or the `--owner`
value. To change saved settings, pass the new global options before `setup`.

Read tokens are distinct from cloud-account/deployment credentials. Use a token
issued for reading this API and downloading its profiles. Keep it out of command
history, screenshots, logs and version control. Give the same originating owner
to status/disconnect when a different account performs elevation.

## Compatible service contract

The client reads these authenticated routes on the configured origin:

| Route | Purpose | Maximum response size |
| --- | --- | --- |
| `GET /api/servers` | Published v1 envelope containing the v2 server index | 2,000,000 bytes |
| `GET /api/geolocation` | Published cached IP geography | 1,500,000 bytes |
| `GET /ovpn/sha256/<sha256>/<filename>.ovpn` | Immutable profile matching selected server metadata | 256,000 bytes |

Requests use `Authorization: Bearer <read-token>`. Redirects are not followed;
environment proxy configuration is not used. Credentials are attached only to
these allowed paths on the explicitly configured origin. A catalog-supplied
download URL is metadata, not a destination for the token or download request.

The server index includes canonical IDs, source (`ipspeed` or `vpngate`), endpoint,
protocol, timestamps, rank and source metrics. Profile-enabled records must carry
a matching SHA-256, byte count, immutable object key, filename and verified
distribution timestamp. Both `verified_at` and the legacy `public_verified_at`
distribution timestamp are accepted. See the decoders in
[`models.py`](../src/openvpn_cli/models.py), the profile policy in
[`profiles.py`](../src/openvpn_cli/profiles.py), and synthetic fixtures in
[`tests/conftest.py`](../tests/conftest.py) for the exact supported data structures.

These are compatibility requirements for an existing service. This repository
does not deploy a backend, provision credentials or change a service's access
policy. Ordinary `.ovpn` files or arbitrary server-list APIs do not satisfy this
catalog contract automatically.

Geography failures leave an otherwise valid server catalog usable. Catalog
snapshots older than 36 hours and geography entries older than seven days receive
warnings. Geography reflects the saved provider data and performs no fresh IP
lookup. Retained profiles can remain available with warnings; they are not
eligible for automatic `--best` selection.

## Session prerequisites and behavior

OpenVPN Community 2.7+ must be installed separately. On Windows, the Interactive
Service and Community driver must be available. On Unix, the package's native DNS
helper and required interpreter/tools must be available. Linux requires TUN access.
`doctor --json` reports these checks; a failed readiness check exits with code 1.

The client does not invoke UAC, sudo or doas. Open a manually elevated terminal for
connection control. Homebrew must run as your normal user. `setup --install` uses
only an existing supported package manager; APT repository addition requires the
separate `--add-openvpn-repo` option on a supported Debian/Ubuntu release.

Downloaded bytes are verified against the selected record's digest, size and
endpoint. Connection policy additionally rejects script/plugin/include directives,
external credentials and interactive prompts. Profiles may include inline private
keys or credentials: protect explicit downloads as secret files. The client stores
temporary connection profiles in protected runtime storage and removes them after
disconnect.

Closing the CLI, shell or TUI detaches while the owned supervisor continues. There
is one session per originating account, with bounded startup and same-server
recovery. A stale saved PID is not adopted or killed. There is no boot reconnect,
client system service, kill switch, custom firewall policy or cross-server failover.
