import json
import sys

import httpx
import pytest

from openvpn_cli import installer
from openvpn_cli.errors import ClientError
from openvpn_cli.installer import Manager, add_apt_repository, detect_manager, install_openvpn

OUTPUTS = {
    "winget": "Found OpenVPN\nVersion: 2.7.8\n",
    "brew": json.dumps({"formulae": [{"versions": {"stable": "2.7.8"}}]}),
    "apt": "openvpn:\n  Installed: (none)\n  Candidate: 2.7.8-1\n",
    "dnf": "2.7.8\n",
    "pacman": "openssl 3.5.1\nopenvpn 2.7.8-1\n",
    "zypper": '<stream><install-summary><to-install><solvable name="openvpn" edition="2.7.8-1.1"/></to-install></install-summary></stream>',
    "apk": "openvpn policy:\n  2.7.8-r0:\n    https://configured-repo.test/main\n",
}


@pytest.mark.parametrize("name", OUTPUTS)
def test_review_candidate_then_install_only_openvpn(name, monkeypatch):
    monkeypatch.setattr(installer, "privileged", lambda: name != "brew")
    manager = Manager(name, "/usr/bin/" + ("apt-get" if name == "apt" else name))
    commands = []

    def runner(args, **kwargs):
        commands.append(args)
        if "-Qu" in args:
            return ""
        return OUTPUTS[name]

    candidate = install_openvpn(manager=manager, runner=runner)
    assert installer.version_tuple(candidate) == (2, 7, 8)
    assert commands[-1] == manager.install_command(candidate)
    assert manager.query_command() in commands
    assert all("-Sy" not in args and "-Syu" not in args for args in commands)


@pytest.mark.parametrize("name", OUTPUTS)
def test_old_candidate_never_installed(name, monkeypatch):
    monkeypatch.setattr(installer, "privileged", lambda: name != "brew")
    manager = Manager(name, name)
    commands = []

    def runner(args, **kwargs):
        commands.append(args)
        return OUTPUTS[name].replace("2.7.8", "2.6.20")

    with pytest.raises(ClientError):
        install_openvpn(manager=manager, runner=runner)
    assert not any(
        "install" in args and "--dry-run" not in args and args != manager.query_command()
        for args in commands
    )
    assert not any("add" in args and "--simulate" not in args for args in commands)


@pytest.mark.parametrize(
    "system,distro,expected",
    [
        ("Windows", {}, "winget"),
        ("Darwin", {}, "brew"),
        ("Linux", {"ID": "ubuntu"}, "apt"),
        ("Linux", {"ID": "debian"}, "apt"),
        ("Linux", {"ID": "fedora"}, "dnf"),
        ("Linux", {"ID": "arch"}, "pacman"),
        ("Linux", {"ID": "opensuse-tumbleweed"}, "zypper"),
        ("Linux", {"ID": "alpine"}, "apk"),
    ],
)
def test_manager_detection(system, distro, expected):
    assert detect_manager(system, distro=distro, which=lambda name: "/bin/" + name).name == expected


def test_no_manager_bootstrap_or_wrong_repository(monkeypatch):
    monkeypatch.setattr(installer, "detect_manager", lambda: None)
    with pytest.raises(ClientError, match="No supported"):
        install_openvpn()
    with pytest.raises(ClientError, match="only"):
        install_openvpn(manager=Manager("apk", "apk"), add_repository=True)


def test_manual_privileges_and_homebrew_normal_user(monkeypatch):
    monkeypatch.setattr(installer, "privileged", lambda: False)
    with pytest.raises(ClientError, match="root"):
        install_openvpn(manager=Manager("apt", "apt-get"))
    monkeypatch.setattr(installer, "privileged", lambda: True)
    with pytest.raises(ClientError, match="normal user"):
        install_openvpn(manager=Manager("brew", "brew"))


def test_official_repo_requires_supported_release_and_does_not_overwrite(tmp_path):
    key = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nSYNTHETIC\n"
    client = httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=key))
    )

    def runner(args):
        return "amd64\n"

    distro = {"ID": "ubuntu", "VERSION_CODENAME": "noble"}
    add_apt_repository(root=tmp_path, client=client, runner=runner, distro=distro)
    path = tmp_path / "etc/apt/sources.list.d/openvpn-kv.list"
    assert "https://build.openvpn.net/debian/openvpn/stable noble main" in path.read_text()
    path.write_text("different contents")
    with pytest.raises(ClientError, match="different contents"):
        add_apt_repository(root=tmp_path, client=client, runner=runner, distro=distro)
    with pytest.raises(ClientError, match="unsupported"):
        add_apt_repository(
            root=tmp_path,
            client=client,
            runner=runner,
            distro={"ID": "ubuntu", "VERSION_CODENAME": "unreviewed"},
        )
    client.close()


def test_arch_pending_upgrades_refuse_partial_upgrade(monkeypatch):
    monkeypatch.setattr(installer, "privileged", lambda: True)
    commands = []

    def runner(args, **kwargs):
        commands.append(args)
        return "openssl 3.4 -> 3.5" if "-Qu" in args else OUTPUTS["pacman"]

    with pytest.raises(ClientError, match="partial upgrade"):
        install_openvpn(manager=Manager("pacman", "pacman"), runner=runner)
    assert not any("-S" in command for command in commands)


def test_apk_installed_version_is_not_a_repository_candidate():
    output = "openvpn policy:\n  2.7.8-r0:\n    /lib/apk/db/installed\n  2.6.20-r0:\n    https://stable.test/main\n"
    assert Manager("apk", "apk").candidate(output) == "2.6.20-r0"


def test_brew_upgrades_existing_installation(monkeypatch):
    monkeypatch.setattr(installer, "privileged", lambda: False)
    output = json.loads(OUTPUTS["brew"])
    output["formulae"][0]["installed"] = [{"version": "2.6.20"}]
    commands = []

    def runner(args, **kwargs):
        commands.append(args)
        return json.dumps(output)

    install_openvpn(manager=Manager("brew", "brew"), runner=runner)
    assert commands[-1] == ["brew", "upgrade", "openvpn"]


def test_unix_dns_helper_dependency_checks(tmp_path):
    helper = tmp_path / "dns-updown"
    resolver = tmp_path / "resolv.conf"
    resolver.write_text("nameserver 1.1.1.1\n")
    helper.write_text(f"#!{sys.executable}\nsed -i example /etc/resolv.conf\n")
    report = installer.dns_helper_checks(
        helper, system="Linux", which=lambda _: None, resolver_file=resolver
    )
    assert not report["dns_helper_dependencies"]
    assert "sed" in report["missing_dns_dependencies"]
    report = installer.dns_helper_checks(
        helper, system="Linux", which=lambda _: "/bin/sed", resolver_file=resolver
    )
    assert report["dns_helper_dependencies"]
    assert report["resolver"] == "resolv.conf"


def test_unix_missing_dns_helper_is_actionable():
    report = installer.dns_helper_checks(None, system="Linux")
    assert not report["dns_helper_dependencies"]
    assert "packaged dns-updown helper" in report["missing_dns_dependencies"]
