"""Build a Windows x64 installer with Pynsist and the locked runtime dependencies."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tomllib
import urllib.request
from pathlib import Path

from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[1]
PYTHON_VERSION = "3.12.10"  # Last Python 3.12 release with Windows embeddable binaries.
BUILD_SOURCES = [
    (
        "pycountry-26.2.16-git-source.tar.gz",
        "https://codeload.github.com/pycountry/pycountry/tar.gz/4ba3951667c2ed98363a3640c9022cf1b7a59300",
        "db064d7c4656deb38279755c67f9eeed759705c711c2ed362e9f0cf336518bb0",
    ),
    (
        "iso-codes_4.20.1.orig.tar.xz",
        "https://deb.debian.org/debian/pool/main/i/iso-codes/iso-codes_4.20.1.orig.tar.xz",
        "5d551f3ddb32548c4321e9011720fd97751af0107592f79ebffc939bd32f2268",
    ),
]


def run(*args: str, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=ROOT, check=True, **kwargs)


def main() -> None:
    if sys.platform != "win32":
        raise SystemExit("Build this Windows x64 installer on Windows.")
    nsis = shutil.which("makensis")
    if not nsis:
        for directory in ("ProgramFiles(x86)", "ProgramFiles"):
            candidate = Path(os.environ.get(directory, "C:/Program Files")) / "NSIS/makensis.exe"
            if candidate.is_file():
                nsis = str(candidate)
                break
    if not nsis:
        raise SystemExit("Install NSIS first: winget install --id NSIS.NSIS --exact")

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    version = project["version"]
    run("uv", "build")
    exported = run(
        "uv",
        "export",
        "--locked",
        "--no-dev",
        "--no-emit-project",
        "--no-hashes",
        "--no-annotate",
        "--no-header",
        capture_output=True,
        text=True,
    ).stdout
    wheels = []
    for line in exported.splitlines():
        if not line.strip():
            continue
        requirement = Requirement(line)
        if requirement.marker is None or requirement.marker.evaluate(
            {"python_version": "3.12", "python_full_version": PYTHON_VERSION}
        ):
            wheels.append(f"{requirement.name}{requirement.specifier}")

    staging = ROOT / "temp/build/pynsist"
    staging.mkdir(parents=True, exist_ok=True)
    # Ship the exact unmodified source for the bundled LGPL/MPL libraries.
    # Read URLs and hashes from the existing lock instead of resolving new versions.
    sources = staging / "dependency-sources"
    sources.mkdir(exist_ok=True)
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    for package in lock["package"]:
        if package["name"] not in {"pycountry", "certifi"}:
            continue
        source = package["sdist"]
        archive = sources / source["url"].rsplit("/", 1)[-1]
        if not archive.exists():
            with urllib.request.urlopen(source["url"], timeout=60) as response:
                archive.write_bytes(response.read())
        if hashlib.sha256(archive.read_bytes()).hexdigest() != source["hash"].split(":")[1]:
            raise SystemExit(f"Dependency source checksum mismatch: {archive.name}")
    for filename, url, digest in BUILD_SOURCES:
        archive = sources / filename
        if not archive.exists():
            with urllib.request.urlopen(url, timeout=60) as response:
                archive.write_bytes(response.read())
        if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
            raise SystemExit(f"Dependency build source checksum mismatch: {archive.name}")
    nsis_license = Path(nsis).parent / "COPYING"
    if not nsis_license.is_file():
        raise SystemExit("NSIS distribution COPYING file is required for redistribution.")
    shutil.copy2(nsis_license, sources / "NSIS-COPYING.txt")
    wheel = ROOT / "dist" / f"openvpn_client-{version}-py3-none-any.whl"
    installer = f"openvpn-client-{version}-windows-x64.exe"
    config = staging / "installer.cfg"
    config.write_text(
        "[Application]\n"
        f"name = OpenVPN Dash Client\nversion = {version}\npublisher = yuxiaoli\n"
        "entry_point = openvpn_cli.shell:main\nconsole = true\n\n"
        "[Python]\n"
        f"version = {PYTHON_VERSION}\nbitness = 64\n\n"
        "[Include]\n"
        f"local_wheels = {wheel.as_posix()}\n"
        "pypi_wheels = " + "\n    ".join(wheels) + "\n\n"
        "files = "
        + (ROOT / "LICENSE").as_posix()
        + "\n    "
        + (ROOT / "THIRD_PARTY_NOTICES.md").as_posix()
        + "\n    "
        + (ROOT / "README.md").as_posix()
        + "\n    "
        + sources.as_posix()
        + " > $INSTDIR/licenses\n\n"
        "[Command openvpn-kv]\nentry_point = openvpn_cli.cli:main\n\n"
        "[Command openvpn-kv-shell]\nentry_point = openvpn_cli.shell:main\n\n"
        "[Command openvpn-kv-tui]\nentry_point = openvpn_cli.tui:main\n\n"
        "[Shortcut OpenVPN Dash Client TUI]\nentry_point = openvpn_cli.tui:main\nconsole = true\n\n"
        "[Build]\ndirectory = output\n"
        f"installer_name = {installer}\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment["PATH"] = str(Path(nsis).parent) + os.pathsep + environment.get("PATH", "")
    run("uv", "tool", "run", "--from", "pynsist==2.8", "pynsist", str(config), env=environment)
    destination = ROOT / "dist" / installer
    shutil.copy2(staging / "output" / installer, destination)
    for archive in sources.iterdir():
        shutil.copy2(archive, ROOT / "dist" / archive.name)
    print(f"Installer: {destination}")


if __name__ == "__main__":
    main()
