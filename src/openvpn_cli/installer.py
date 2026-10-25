"""Explicit setup actions. Importing/doctor never installs or changes repositories."""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

import httpx

from .config import Settings
from .errors import ClientError

MINIMUM = (2, 7, 0)


def version_tuple(value: str) -> tuple[int, int, int]:
    match = re.search(r"(?<![\d.])(\d+)\.(\d+)(?:\.(\d+))?", value)
    if not match or re.search(r"(?:alpha|beta|[._~-]rc\d)", value, re.I):
        raise ClientError("Cannot determine a stable OpenVPN package version.")
    return tuple(int(x or 0) for x in match.groups())


def require_version(value: str):
    if version_tuple(value) < MINIMUM:
        raise ClientError(
            "OpenVPN Community 2.7+ is required; configured repositories offer an older version."
        )


def privileged() -> bool:
    if os.name == "nt":
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return os.geteuid() == 0


class Runner:
    def __call__(self, args: list[str], *, timeout=45, capture=True, acceptable=(0,)) -> str:
        environment = {
            k: v
            for k, v in os.environ.items()
            if k not in {"OPENVPN_KV_TOKEN", "CLOUDFLARE_API_TOKEN"}
        }
        environment.update(LC_ALL="C", LANG="C")
        try:
            process = subprocess.run(
                args,
                shell=False,
                check=False,
                timeout=timeout,
                capture_output=capture,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=environment,
                creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" and capture else 0),
            )
        except (OSError, subprocess.TimeoutExpired):
            raise ClientError(
                f"Cannot run {Path(args[0]).name}; check installation and permissions."
            ) from None
        if process.returncode not in acceptable:
            raise ClientError(
                f"{Path(args[0]).name} failed (exit {process.returncode}); run the documented command manually."
            )
        return process.stdout or ""


@dataclass(frozen=True)
class Manager:
    name: str
    executable: str

    def query_command(self) -> list[str]:
        commands = {
            "winget": [
                "show",
                "--id",
                "OpenVPNTechnologies.OpenVPN",
                "--exact",
                "--source",
                "winget",
                "--accept-source-agreements",
            ],
            "brew": ["info", "--json=v2", "openvpn"],
            "apt": ["policy", "openvpn"],
            "dnf": ["repoquery", "--latest-limit=1", "--qf", "%{version}", "openvpn"],
            "pacman": ["-Sp", "--print-format", "%n %v", "openvpn"],
            "zypper": ["--xmlout", "--non-interactive", "install", "--dry-run", "openvpn>=2.7"],
            "apk": ["policy", "openvpn"],
        }
        exe = (
            str(Path(self.executable).with_name("apt-cache"))
            if self.name == "apt"
            else self.executable
        )
        return [exe, *commands[self.name]]

    def candidate(self, output: str) -> str:
        try:
            if self.name == "brew":
                return json.loads(output)["formulae"][0]["versions"]["stable"]
            if self.name == "apt":
                match = re.search(r"^\s*Candidate:\s+(\S+)", output, re.M)
            elif self.name == "winget":
                match = re.search(r"^\s*Version:\s+(\S+)", output, re.M)
            elif self.name == "pacman":
                match = re.search(r"^openvpn\s+(\S+)", output, re.M)
            elif self.name == "dnf":
                match = re.search(r"^\s*((?:\d+:)?\d+\.\d+[^\s]*)\s*$", output, re.M)
            elif self.name == "apk":
                # Ignore a version offered only by the installed-package database.
                # Exact-version simulation below lets APK's resolver enforce sources.
                blocks = list(re.finditer(r"^\s+((?:\d+:)?\d+\.\d+\S*):\s*$", output, re.M))
                for position, block in enumerate(blocks):
                    end = (
                        blocks[position + 1].start() if position + 1 < len(blocks) else len(output)
                    )
                    repositories = output[block.end() : end]
                    if "http://" in repositories or "https://" in repositories:
                        return block.group(1)
                match = None
            else:
                root = ET.fromstring(output)
                for element in root.iter():
                    if element.attrib.get("name") == "openvpn" and element.attrib.get("edition"):
                        return element.attrib["edition"]
                match = None
            if match:
                return match.group(1)
        except (ValueError, KeyError, IndexError, TypeError, ET.ParseError):
            pass
        raise ClientError("No qualifying OpenVPN candidate found in configured package sources.")

    def install_command(self, candidate: str) -> list[str]:
        commands = {
            "winget": [
                "install",
                "--id",
                "OpenVPNTechnologies.OpenVPN",
                "--exact",
                "--source",
                "winget",
                "--version",
                candidate,
                "--accept-source-agreements",
                "--accept-package-agreements",
            ],
            "brew": ["install", "openvpn"],
            "apt": ["install", "--no-install-recommends", f"openvpn={candidate}"],
            "dnf": ["install", f"openvpn-{candidate}"],
            "pacman": ["-S", "--needed", "openvpn"],
            "zypper": ["install", f"openvpn={candidate}"],
            "apk": ["add", f"openvpn={candidate}"],
        }
        return [self.executable, *commands[self.name]]


def detect_manager(
    system: str | None = None, *, which=shutil.which, distro: dict | None = None
) -> Manager | None:
    system = system or platform.system()
    if system == "Windows":
        choices = [("winget", "winget")]
    elif system == "Darwin":
        choices = [("brew", "brew")]
    else:
        if distro is None:
            try:
                distro = platform.freedesktop_os_release()
            except OSError:
                distro = {}
        ids = set((distro.get("ID", "") + " " + distro.get("ID_LIKE", "")).split())
        if ids & {"debian", "ubuntu"}:
            choices = [("apt", "apt-get")]
        elif ids & {"fedora", "rhel"}:
            choices = [("dnf", "dnf")]
        elif "arch" in ids:
            choices = [("pacman", "pacman")]
        elif ids & {"opensuse", "opensuse-leap", "opensuse-tumbleweed", "suse"}:
            choices = [("zypper", "zypper")]
        elif "alpine" in ids:
            choices = [("apk", "apk")]
        else:
            choices = []
    for name, binary in choices:
        if path := which(binary):
            return Manager(name, path)
    return None


def discover_openvpn(explicit: str | None = None) -> Path | None:
    if explicit:
        path = Path(explicit)
        if not path.is_absolute() or not path.is_file():
            raise ClientError("--openvpn-path must name an existing absolute executable path.")
        return path.resolve()
    candidates = [shutil.which("openvpn")]
    if os.name == "nt":
        try:
            import winreg

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\OpenVPN") as key:
                try:
                    candidates.append(winreg.QueryValueEx(key, "exe_path")[0])
                except OSError:
                    candidates.append(
                        str(Path(winreg.QueryValueEx(key, "")[0]) / "bin/openvpn.exe")
                    )
        except OSError:
            pass
        candidates.append(
            str(
                Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
                / "OpenVPN/bin/openvpn.exe"
            )
        )
    else:
        candidates += [
            "/opt/homebrew/sbin/openvpn",
            "/usr/local/sbin/openvpn",
            "/usr/sbin/openvpn",
            "/usr/bin/openvpn",
        ]
    return next((Path(p).resolve() for p in candidates if p and Path(p).is_file()), None)


def dns_helper_checks(
    helper: Path | None, *, system: str, which=None, resolver_file=Path("/etc/resolv.conf")
) -> dict:
    """Inspect packaged helper dependencies; never execute helper content."""
    which = which or shutil.which
    missing = []
    resolver = "unavailable"
    if helper is None:
        return {
            "dns_helper_dependencies": False,
            "missing_dns_dependencies": ["packaged dns-updown helper"],
            "resolver": resolver,
        }
    try:
        content = helper.read_text(encoding="utf-8")
        lines = content.splitlines()
        first = lines[0]
        if not first.startswith("#!"):
            missing.append("helper interpreter")
        else:
            interpreter = first[2:].split()[0]
            if not Path(interpreter).is_file() or not os.access(interpreter, os.X_OK):
                missing.append(interpreter)
        code = "\n".join(line for line in lines[1:] if not line.lstrip().startswith("#"))
        for command in ("expr", "seq", "sed", "cat", "readlink", "grep", "cut", "xargs", "sleep"):
            if re.search(r"\b" + command + r"\b", code) and not which(command):
                missing.append(command)
        if system == "Darwin":
            resolver = "scutil"
            for command in ("/usr/sbin/scutil", "/usr/bin/shlock"):
                if not Path(command).is_file() or not os.access(command, os.X_OK):
                    missing.append(command)
        elif resolver_file.is_symlink() and "systemd" in str(resolver_file.resolve()):
            resolver = "resolvectl"
            if not which("resolvectl"):
                missing.append("resolvectl")
        elif "/sbin/resolvconf" in code and os.access("/sbin/resolvconf", os.X_OK):
            resolver = "resolvconf"
        elif "/etc/resolv.conf" in code and resolver_file.is_file():
            resolver = "resolv.conf"
        else:
            missing.append("helper resolver backend (resolvconf/resolvectl/resolv.conf)")
    except (OSError, UnicodeError, IndexError):
        missing.append("readable packaged helper")
    return {
        "dns_helper_dependencies": not missing,
        "missing_dns_dependencies": missing,
        "resolver": resolver,
    }


def native_checks(binary: Path) -> dict:
    if os.name == "nt":
        import win32service

        service = driver = False
        try:
            manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
            try:
                handle = win32service.OpenService(
                    manager, "OpenVPNServiceInteractive", win32service.SERVICE_QUERY_STATUS
                )
                try:
                    service = (
                        win32service.QueryServiceStatus(handle)[1] == win32service.SERVICE_RUNNING
                    )
                finally:
                    win32service.CloseServiceHandle(handle)
            finally:
                win32service.CloseServiceHandle(manager)
        except Exception:
            pass
        for name in ("ovpn-dco.sys", "ovpn-dco-win.sys", "tap0901.sys", "wintun.sys"):
            if (
                Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/drivers" / name
            ).is_file():
                driver = True
        return {
            "interactive_service_running": service,
            "driver_present": driver,
            "networking_ready": service and driver,
        }
    helpers = [
        binary.parent.parent / "libexec/openvpn/dns-updown",
        binary.parent.parent / "lib/openvpn/dns-updown",
        Path("/usr/lib/openvpn/dns-updown"),
        Path("/usr/libexec/openvpn/dns-updown"),
    ]
    if platform.system() == "Darwin":
        helpers += [binary.parent.parent / "libexec/dns-updown"]
    helper = next((p for p in helpers if p.is_file() and os.access(p, os.X_OK)), None)
    system = platform.system()
    dependencies = dns_helper_checks(helper, system=system)
    tun_available = system == "Darwin" or Path("/dev/net/tun").is_char_device()
    return {
        "dns_helper": str(helper) if helper else None,
        **dependencies,
        "tun_available": tun_available,
        "networking_ready": bool(
            helper and dependencies["dns_helper_dependencies"] and tun_available
        ),
    }


def doctor(settings: Settings, *, runner=None) -> dict:
    runner = runner or Runner()
    report = {
        "platform": platform.system(),
        "privileged": privileged(),
        "executable": None,
        "version": None,
        "executable_status": "missing",
        "networking_ready": False,
    }
    try:
        binary = discover_openvpn(settings.openvpn_path)
        if binary:
            report["executable"] = str(binary)
            output = runner([str(binary), "--version"])
            match = re.search(r"OpenVPN\s+(\S+)", output)
            if not match:
                raise ClientError("Executable is not OpenVPN Community.")
            report["version"] = match.group(1)
            require_version(match.group(1))
            report["executable_status"] = "ready"
            report.update(native_checks(binary))
    except ClientError as error:
        report["executable_status"] = "unavailable"
        report["executable_error"] = str(error)
    manager = detect_manager()
    report.update(
        manager=manager.name if manager else None, manager_status="missing", candidate=None
    )
    if manager:
        try:
            candidate = manager.candidate(runner(manager.query_command()))
            report["candidate"] = candidate
            require_version(candidate)
            report["manager_status"] = "ready"
        except ClientError as error:
            report["manager_status"] = "unavailable"
            report["manager_error"] = str(error)
    report["ready"] = report["executable_status"] == "ready" and report["networking_ready"]
    return report


APT_CODENAMES = {"bullseye", "bookworm", "trixie", "focal", "jammy", "noble", "questing"}


def add_apt_repository(*, runner=None, root=Path("/"), distro=None, client=None):
    runner = runner or Runner()
    distro = distro or platform.freedesktop_os_release()
    codename = distro.get("VERSION_CODENAME", "")
    if distro.get("ID") not in {"debian", "ubuntu"} or codename not in APT_CODENAMES:
        raise ClientError(
            "Official APT repository opt-in is unsupported on this distribution release."
        )
    arch = runner(["dpkg", "--print-architecture"]).strip()
    if arch not in {"amd64", "arm64"}:
        raise ClientError("Official APT repository supports amd64 and arm64 here.")
    key_path = root / "etc/apt/keyrings/openvpn-repo-public.asc"
    source_path = root / "etc/apt/sources.list.d/openvpn-kv.list"
    source = (
        f"deb [arch={arch} signed-by=/etc/apt/keyrings/openvpn-repo-public.asc] "
        f"https://build.openvpn.net/debian/openvpn/stable {codename} main\n"
    )
    own_client = client is None
    client = client or httpx.Client(timeout=20, trust_env=False, follow_redirects=False)
    try:
        response = client.get("https://swupdate.openvpn.net/repos/repo-public.gpg")
        if (
            response.status_code != 200
            or len(response.content) > 100_000
            or not response.content.startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK-----")
        ):
            raise ClientError("Cannot retrieve the official repository signing key.")
        key = response.content
        for path, data in ((key_path, key), (source_path, source.encode())):
            if path.exists() and path.read_bytes() != data:
                raise ClientError(
                    "Repository file already exists with different contents; review it manually."
                )
        for path, data in ((key_path, key), (source_path, source.encode())):
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                with path.open("xb") as handle:
                    handle.write(data)
                path.chmod(0o644)
    except (httpx.HTTPError, OSError):
        raise ClientError(
            "Official repository setup failed; review repository files before retrying."
        ) from None
    finally:
        if own_client:
            client.close()


def install_openvpn(*, add_repository=False, manager=None, runner=None):
    manager = manager or detect_manager()
    runner = runner or Runner()
    if not manager:
        raise ClientError(
            "No supported usable package manager found. Install Community 2.7+ manually."
        )
    if add_repository and manager.name != "apt":
        raise ClientError("--add-openvpn-repo is supported only with Debian/Ubuntu APT.")
    if manager.name in {"apt", "dnf", "pacman", "zypper", "apk"} and not privileged():
        raise ClientError("Run setup --install from a root terminal (sudo or doas).")
    if manager.name == "brew" and privileged():
        raise ClientError("Run Homebrew installation as your normal user, not root.")
    if manager.name == "winget" and not privileged():
        raise ClientError("Run setup --install from an administrator terminal.")
    if add_repository:
        add_apt_repository(runner=runner)
    if manager.name == "apt":
        runner([manager.executable, "update"], timeout=180, capture=False)
    elif manager.name == "dnf":
        runner([manager.executable, "makecache"], timeout=180, capture=False)
    elif manager.name == "zypper":
        runner([manager.executable, "refresh"], timeout=180, capture=False)
    elif manager.name == "apk":
        runner([manager.executable, "update"], timeout=180, capture=False)
    candidate_output = runner(manager.query_command())
    candidate = manager.candidate(candidate_output)
    try:
        require_version(candidate)
    except ClientError:
        instructions = {
            "apt": "On a supported Debian/Ubuntu release, opt in with setup --install --add-openvpn-repo; otherwise upgrade your configured source manually.",
            "dnf": "Use a supported Fedora release/repository providing Community 2.7+, then retry.",
            "pacman": "Complete a full pacman -Syu separately, then retry; partial upgrades are not supported.",
            "zypper": "Upgrade to a supported openSUSE release/source providing Community 2.7+, then retry.",
            "apk": "Use a supported stable Alpine release/source providing Community 2.7+; do not mix in edge repositories.",
            "brew": "Update your Homebrew formula metadata manually, then retry or install Community 2.7+ manually.",
            "winget": "Update your WinGet source manually, then retry or install the official Community 2.7+ installer.",
        }
        raise ClientError(
            "OpenVPN Community 2.7+ is required. " + instructions[manager.name]
        ) from None
    if manager.name == "pacman":
        pending = runner([manager.executable, "-Qu"], acceptable=(0, 1)).strip()
        if pending:
            raise ClientError(
                "Arch has pending package upgrades. Complete a full pacman -Syu separately before setup --install; refusing a partial upgrade."
            )
    if manager.name == "apk":
        runner([manager.executable, "add", "--simulate", f"openvpn={candidate}"])
    command = manager.install_command(candidate)
    if manager.name == "brew" and json.loads(candidate_output)["formulae"][0].get("installed"):
        command = [manager.executable, "upgrade", "openvpn"]
    runner(command, timeout=600, capture=False)
    return candidate
