#!/usr/bin/env bash
# Command reference only. Copy and run individual commands as needed.
# Run source-development commands from the project root. Do not execute or source
# this entire file: connection/installation commands have explicit side effects.
# Replace example API origins, file paths, server IDs and IPs before use.
# Installed Windows commands use the same arguments without the `uv run` prefix.

# Install the locked source-development dependencies (Python 3.12+ and uv required).
uv sync --locked

# Show CLI help without contacting an API or creating a VPN tunnel.
uv run openvpn-kv --help

# Show the dedicated shell launcher's global options without launching a shell.
uv run openvpn-kv-shell --help

# Show the dedicated TUI launcher's global options without launching a TUI.
uv run openvpn-kv-tui --help

# Browse using a user-created file with your compatible API origin and read token.
uv run openvpn-kv --env-file client.env list

# Filter the catalog by country and source.
uv run openvpn-kv --env-file client.env list --country JP --source ipspeed

# Filter available UDP profiles and sort by published latency as JSON.
uv run openvpn-kv --env-file client.env list --protocol udp --profiles available --sort latency --json

# Inspect retained records matching text, ordered by most recent observation.
uv run openvpn-kv --env-file client.env list --freshness retained --search Japan --sort last-seen

# Inspect an exact canonical ID obtained from your catalog's JSON/detail output.
uv run openvpn-kv --env-file client.env show FULL_SERVER_ID --json

# Inspect cached geography for an exact IP already present in the API's catalog.
uv run openvpn-kv --env-file client.env geo EXACT_PUBLIC_IP --json

# Export selected records as CSV; the destination must not already exist.
uv run openvpn-kv --env-file client.env export --format csv --output selected.csv --country JP

# Export active-source observations with verified profiles as JSON.
uv run openvpn-kv --env-file client.env export --format json --output selected.json --freshness fresh --profiles available

# Download a digest-verified profile; it may contain secrets and is never overwritten.
uv run openvpn-kv --env-file client.env download FULL_SERVER_ID --output selected.ovpn

# Start the cmd2/Rich shell (fetches the configured API on launch).
uv run openvpn-kv --env-file client.env shell

# Start the same shell through its dedicated entry point.
uv run openvpn-kv-shell --env-file client.env

# Start the Textual TUI (fetches the configured API on launch).
uv run openvpn-kv --env-file client.env tui

# Start the same TUI through its dedicated entry point.
uv run openvpn-kv-tui --env-file client.env

# Inspect Community version, package candidate and networking prerequisites.
uv run openvpn-kv doctor --json

# Save nonsecret settings; replace the reserved example API origin first.
uv run openvpn-kv --api-url https://vpn.example.com setup

# Windows: inspect an explicitly supplied Community executable path.
uv run openvpn-kv --openvpn-path "C:\Program Files\OpenVPN\bin\openvpn.exe" doctor --json

# Explicitly install OpenVPN Community using an existing platform package manager.
# This changes installed software; follow platform privilege requirements.
uv run openvpn-kv setup --install

# Supported Debian/Ubuntu only: explicitly add the stable OpenVPN APT repository
# and install Community. This changes package sources and installed software.
uv run openvpn-kv setup --install --add-openvpn-repo

# Connect an explicit server; requires manual elevation and changes network state.
uv run openvpn-kv --env-file client.env connect FULL_SERVER_ID

# Connect the best active matching profile by published rank; changes network state.
uv run openvpn-kv --env-file client.env connect --best --country JP --source ipspeed

# Inspect the local owned session without contacting the API.
uv run openvpn-kv status --json

# Stop only the owned session; requires manual elevation and changes network state.
uv run openvpn-kv disconnect

# Elevation as another account: replace the owner with the originating UID or SID.
uv run openvpn-kv --owner ORIGINAL_UID_OR_SID status --json

# Run offline tests with synthetic profiles and the fake management subprocess.
uv run pytest -q --basetemp=temp/pytest

# Run the existing static checks.
uv run ruff check src tests

# Check source/test formatting without modifying files.
uv run ruff format --check src tests

# Build the Python wheel and source distribution.
uv build

# Windows x64 only: build the installer with existing NSIS and Pynsist 2.8.
# The build downloads embedded Python and locked runtime wheels; it does not publish.
uv run python scripts/package.py
