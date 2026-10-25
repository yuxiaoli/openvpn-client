# OpenVPN Dash Client

A terminal client for a compatible OpenVPN catalog API, with a **Typer/Rich CLI**,
**cmd2/Rich shell** and **Textual TUI**. Browse published server metrics, filter and
export records, download verified profiles, and control one persistent OpenVPN
Community session across all three interfaces.

The executable names remain `openvpn-kv`, `openvpn-kv-shell` and `openvpn-kv-tui`.
This is an independent client distribution; OpenVPN Community is a separate
prerequisite and is not bundled with the application.

## Windows download

Open [Releases](https://github.com/yuxiaoli/openvpn-client/releases) and download
`openvpn-client-0.1.0-windows-x64.exe` and `SHA256SUMS.txt` from the same release.
The `.exe` is a **Windows x64 installer**, not a standalone portable program. It
includes Python and the client dependencies, so a separate Python installation
is unnecessary for the installed client. Install OpenVPN Community **2.7 or newer**
separately before connecting.

Check the download in PowerShell against the matching line in `SHA256SUMS.txt`:

```powershell
Get-FileHash .\openvpn-client-0.1.0-windows-x64.exe -Algorithm SHA256
```

Run the installer, then use its shell/TUI shortcuts or installed command launchers.
Open a new terminal after installation so that its command directory is on PATH.
Start with `openvpn-kv --help`; displaying help does not contact the API or create a
VPN tunnel. The API origin and read token below must be supplied by you or your API
administrator. This repository does not provide a shared catalog service or token.

## Configure your API

Create a local environment file using [.env.example](.env.example) as a guide.
Replace both example values with your own compatible HTTPS API origin and read
token, and pass the file explicitly:

```text
openvpn-kv --env-file client.env list
openvpn-kv --env-file client.env shell
openvpn-kv --env-file client.env tui
```

`https://vpn.example.com` is a reserved example address, not a working service.
The client never discovers `.env` files automatically. It does not accept tokens
as command-line values or save them during setup. See
[configuration and API requirements](docs/CONFIGURATION.md) for precedence,
authentication and profile validation.

## Browse and download

```text
openvpn-kv --env-file client.env list --country JP --source ipspeed
openvpn-kv --env-file client.env list --protocol udp --profiles available --sort latency --json
openvpn-kv --env-file client.env show FULL_SERVER_ID --json
openvpn-kv --env-file client.env geo EXACT_PUBLIC_IP --json
openvpn-kv --env-file client.env export --format csv --output selected.csv --country JP
openvpn-kv --env-file client.env download FULL_SERVER_ID --output selected.ovpn
```

Replace `FULL_SERVER_ID` with an ID from JSON/detail output and `EXACT_PUBLIC_IP`
with an IP present in your API's geography catalog. Explicit exports and downloads
refuse to overwrite existing files. Downloaded profiles can contain private keys;
keep those files out of public repositories and shared folders.

Filters include country, source (`ipspeed` or `vpngate`), TCP/UDP, freshness
(`all`, `fresh`, `retained`), profile availability and text search. Sort by published
rank, latency, uptime or last observation. Latency and uptime are source metrics;
the client does not probe servers to produce them. `active` means the source
recently collected a configuration, not that the server is reachable.

CLI catalog commands fetch on each invocation. The shell and TUI fetch on launch
and keep their catalog in memory until an explicit refresh. There is no saved
catalog cache, offline fallback or background API polling. Snapshot and geography
age warnings distinguish older data from recent observations.

The shell supports the CLI's catalog and session commands plus `refresh`. Use
`help COMMAND` for flags and Tab to complete server IDs; Rich tables and JSON work
with cmd2 redirection and pipes. `quit` detaches from the session.

The TUI combines a server table, detail pane and filter controls. Keys: **r** refresh,
**c** connect selected, **b** connect best, **d** disconnect, **e** export,
**p** download profile, **g** inspect cached IP geography, **q** detach.

## OpenVPN setup and sessions

Inspect prerequisites before using connection commands:

```text
openvpn-kv doctor --json
openvpn-kv --api-url https://vpn.example.com setup
```

Replace the example origin before saving setup. Setup stores only the API origin
and optional OpenVPN executable path. `doctor` reports the Community version,
privileges and platform networking prerequisites. Windows requires the OpenVPN
Interactive Service and Community driver; Unix requires the package's DNS helper
and its tools, and Linux also requires `/dev/net/tun`.

Optional `setup --install` uses an existing platform package manager: WinGet on
Windows, Homebrew on macOS, or supported Linux distribution managers. It changes
the installed software only when explicitly requested. It does not bootstrap a
package manager, elevate automatically, configure boot-time VPNs or upgrade the
entire system. On supported Debian/Ubuntu releases, the additional explicit
`--add-openvpn-repo` flag enables the official stable APT source.

Connection control requires a terminal you have manually elevated:

```text
openvpn-kv --env-file client.env connect FULL_SERVER_ID
openvpn-kv --env-file client.env connect --best --country JP --source ipspeed
openvpn-kv status --json
openvpn-kv disconnect
```

These commands change network state. `--best` chooses the lowest published rank
among matching active records with verified profiles. It does not fail over to
another server. Startup and same-server recovery are bounded to 60 seconds, and
success requires the management interface to report CONNECTED.

A detached supervisor owns one session per originating account. Closing a
frontend leaves that session running; another frontend can inspect or disconnect
it. Local status and disconnect do not need an API token or contact the API.
When elevating as a different account, use `--owner ORIGINAL_UID_OR_SID` consistently.
Unix sudo normally supplies the originating UID through `SUDO_UID`.

Connection accepts self-contained TUN profiles with an inline CA and either an
inline certificate/key or inline username/password credentials. Hooks, plugins,
includes, external credential files and interactive credential prompts are
rejected. Temporary runtime profiles are protected and removed after disconnect.
Routing and DNS follow the profile and server pushes; there is no kill switch,
forced tunnel policy or automatic server failover.

## Run from source

Source use requires Python **3.12+** and [uv](https://docs.astral.sh/uv/).
The existing project also supports source execution on Linux and macOS; the
published `.exe` targets Windows x64.

```text
git clone https://github.com/yuxiaoli/openvpn-client.git
cd openvpn-client
uv sync --locked
uv run openvpn-kv --help
uv run openvpn-kv --env-file client.env list
uv run openvpn-kv-shell --env-file client.env
uv run openvpn-kv-tui --env-file client.env
```

## Development and Windows packaging

```text
uv sync --locked
uv run pytest -q --basetemp=temp/pytest
uv run ruff check src tests
uv run ruff format --check src tests
uv build
```

Tests use synthetic catalog/profile data, simulated package managers, headless UI
tests and a fake process speaking the management transport. They do not install
OpenVPN or create a VPN tunnel. Native VPN routing/DNS operation requires a
separate, explicitly performed platform test. See release notes for the checks
performed on a particular binary; offline checks do not establish live VPN
connectivity.

To build the installer on Windows, install [NSIS](https://nsis.sourceforge.io/),
then run:

```text
uv run python scripts/package.py
```

The existing Pynsist 2.8 build uses embedded Python 3.12.10 x64 and runtime wheels
pinned by `uv.lock`. Output goes to `dist/`; intermediates go to
`temp/build/pynsist/`. The installer does not include an API token, environment
file, VPN profile, OpenVPN engine or driver. Building alone does not publish a
release.

The [command reference](scripts/commands.sh) lists copyable examples. CLI exit
codes are 0 for success, 1 for an operational failure, 2 for invalid arguments and
130 for interruption.

## License and attribution

See [LICENSE](LICENSE) for the client source license and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for upstream components and bundled
license information. OpenVPN is a trademark of OpenVPN Inc.; this project is not
an official OpenVPN release.
