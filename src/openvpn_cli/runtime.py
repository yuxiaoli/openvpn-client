"""Account identity, protected runtime storage and lifetime locking."""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

from .errors import ClientError
from .installer import privileged


def owner_id(explicit: str | None = None) -> str:
    if os.name == "nt":
        import win32api
        import win32con
        import win32security

        if explicit:
            try:
                sid = win32security.ConvertStringSidToSid(explicit)
                if win32security.LookupAccountSid(None, sid)[2] != win32security.SidTypeUser:
                    raise ValueError
                return win32security.ConvertSidToStringSid(sid)
            except Exception:
                raise ClientError("--owner must be a valid Windows account SID.") from None
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        try:
            sid, _ = win32security.GetTokenInformation(token, win32security.TokenUser)
            return win32security.ConvertSidToStringSid(sid)
        finally:
            token.Close()
    import pwd

    value = explicit if explicit is not None else os.environ.get("SUDO_UID", str(os.getuid()))
    try:
        if not re.fullmatch(r"\d+", value):
            raise ValueError
        pwd.getpwuid(int(value))
        return str(int(value))
    except (KeyError, ValueError):
        raise ClientError("--owner must be an existing numeric Unix account UID.") from None


def runtime_path(owner: str) -> Path:
    if os.name == "nt":
        import win32com.shell.shell as shell
        import win32com.shell.shellcon as shellcon

        root = Path(shell.SHGetFolderPath(0, shellcon.CSIDL_COMMON_APPDATA, None, 0))
        return root / "OpenVPNKV/sessions" / owner
    import sys

    return Path("/var/run" if sys.platform == "darwin" else "/run") / "openvpn-kv" / owner


def require_privilege():
    if not privileged():
        raise ClientError(
            "Connection control requires an administrator/root terminal. Use manual elevation; preserve OPENVPN_KV_TOKEN or pass --env-file. Use --owner with your UID/SID if elevating as a different account."
        )


def protect(path: Path, owner: str, *, readable=False, directory=False):
    if os.name == "nt":
        import ntsecuritycon
        import win32security

        acl = win32security.ACL()
        for sid in ("S-1-5-18", "S-1-5-32-544"):
            acl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                ntsecuritycon.FILE_ALL_ACCESS,
                win32security.ConvertStringSidToSid(sid),
            )
        if readable:
            acl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                ntsecuritycon.FILE_GENERIC_READ | ntsecuritycon.FILE_GENERIC_EXECUTE,
                win32security.ConvertStringSidToSid(owner),
            )
        win32security.SetNamedSecurityInfo(
            str(path),
            win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION
            | win32security.OWNER_SECURITY_INFORMATION
            | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            win32security.ConvertStringSidToSid("S-1-5-32-544"),
            None,
            acl,
            None,
        )
    else:
        os.chmod(
            path,
            0o711
            if directory and readable
            else 0o700
            if directory
            else 0o400
            if readable
            else 0o600,
        )
        os.chown(path, int(owner) if readable and not directory else 0, -1)


def reject_link(path: Path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ClientError("Runtime storage contains a symlink/reparse point; refusing it.")


def prepare_runtime(owner: str) -> Path:
    require_privilege()
    path = runtime_path(owner)
    # The OS-provided parent exists. Every client-created directory is protected,
    # and unprivileged users cannot replace children in the privileged root.
    for part in (path.parent.parent, path.parent, path) if os.name == "nt" else (path.parent, path):
        reject_link(part)
        if part.exists() and not part.is_dir():
            raise ClientError("Runtime storage is not a directory.")
        if os.name != "nt" and part.exists():
            info = part.stat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ClientError("Runtime directory ownership/permissions are unsafe.")
        part.mkdir(exist_ok=True)
        protect(part, owner, readable=True, directory=True)
    return path


def write_descriptor(path: Path, owner: str, data: dict):
    temporary = path.with_suffix(".new")
    reject_link(temporary)
    reject_link(path)
    with temporary.open("w", encoding="utf-8") as handle:
        handle.write(json.dumps(data))
    protect(temporary, owner, readable=True)
    temporary.replace(path)


def verify_descriptor_permissions(path: Path, owner: str):
    if os.name != "nt":
        info = path.stat()
        if info.st_uid != int(owner) or info.st_mode & 0o077:
            raise ClientError("Session descriptor has unsafe permissions.")
        return
    import ntsecuritycon
    import win32security

    try:
        security = win32security.GetNamedSecurityInfo(
            str(path),
            win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION,
        )
        privileged_sids = {"S-1-5-18", "S-1-5-32-544"}
        file_owner = win32security.ConvertSidToStringSid(security.GetSecurityDescriptorOwner())
        acl = security.GetSecurityDescriptorDacl()
        control, _ = security.GetSecurityDescriptorControl()
        if (
            file_owner not in privileged_sids
            or acl is None
            or not control & win32security.SE_DACL_PROTECTED
        ):
            raise ValueError
        read_mask = ntsecuritycon.FILE_GENERIC_READ | ntsecuritycon.FILE_GENERIC_EXECUTE
        for index in range(acl.GetAceCount()):
            ace_type, mask, sid = (
                acl.GetAce(index)[0][0],
                acl.GetAce(index)[1],
                acl.GetAce(index)[2],
            )
            sid = win32security.ConvertSidToStringSid(sid)
            if ace_type != win32security.ACCESS_ALLOWED_ACE_TYPE:
                raise ValueError
            if sid not in privileged_sids and (sid != owner or mask & ~read_mask):
                raise ValueError
    except Exception:
        raise ClientError(
            "Session descriptor has unsafe or unreadable Windows permissions."
        ) from None


def read_descriptor(path: Path, owner: str) -> dict | None:
    reject_link(path)
    if not path.exists():
        return None
    try:
        info = path.stat()
        if info.st_size > 4096:
            raise ValueError
        verify_descriptor_permissions(path, owner)
        value = json.loads(path.read_text(encoding="utf-8"))
        if (
            not isinstance(value, dict)
            or type(value.get("protocol_version")) is not int
            or value.get("protocol_version") != 1
            or value.get("owner") != owner
            or type(value.get("port")) is not int
            or not 1 <= value["port"] <= 65535
            or not isinstance(value.get("token"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", value["token"])
            or not isinstance(value.get("generation"), str)
            or not re.fullmatch(r"[a-f0-9]{32}", value["generation"])
        ):
            raise ValueError
        return value
    except (ValueError, OSError):
        raise ClientError(
            "Session descriptor is invalid or unreadable; do not trust saved process IDs."
        ) from None


class LifetimeLock:
    def __init__(self, path: Path):
        reject_link(path)
        self.handle = path.open("a+b")
        try:
            if os.name == "nt":
                import msvcrt

                self.handle.seek(0)
                if not self.handle.read(1):
                    self.handle.write(b"\0")
                    self.handle.flush()
                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.handle.close()
            raise ClientError("Another supervisor already owns this account's runtime.") from None

    def close(self):
        if not self.handle.closed:
            if os.name == "nt":
                import msvcrt

                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
            self.handle.close()
