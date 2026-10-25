"""Native owned-process adapters. Never terminate a PID from discovery metadata."""

from __future__ import annotations

import asyncio
import os
import subprocess
from pathlib import Path

import psutil

from .errors import ClientError


class OwnedProcess:
    def __init__(self, process: psutil.Process, *, popen=None, pipe=None, job=None):
        self.process, self.popen, self.pipe, self.job = process, popen, pipe, job
        self.created = process.create_time()

    def alive(self) -> bool:
        try:
            return (
                self.process.is_running()
                and self.process.create_time() == self.created
                and self.process.status() != psutil.STATUS_ZOMBIE
            )
        except psutil.Error:
            return False

    def owns_peer(self, port: int) -> bool:
        try:
            return self.alive() and any(
                connection.laddr.port == port
                for connection in self.process.net_connections(kind="tcp")
                if connection.laddr
            )
        except psutil.Error:
            return False

    async def stop(self):
        if self.alive():
            try:
                self.process.terminate()
                await asyncio.to_thread(self.process.wait, 5)
            except psutil.TimeoutExpired:
                if self.alive():
                    self.process.kill()
                    await asyncio.to_thread(self.process.wait, 5)
            except psutil.NoSuchProcess:
                pass
        if self.popen:
            await asyncio.to_thread(self.popen.wait)
        if self.pipe:
            self.pipe.Close()
            self.pipe = None
        if self.job:
            self.job.Close()
            self.job = None


def windows_startup_message(workdir: Path, args: list[str]) -> bytes:
    # The upstream service requires three NUL-delimited UTF-16 strings in one write.
    return (str(workdir) + "\0" + subprocess.list2cmdline(args) + "\0\0").encode("utf-16-le")


def parse_service_reply(raw: bytes) -> int:
    try:
        parts = raw.decode("utf-16-le").strip("\0\r\n").splitlines()
        if len(parts) < 3 or int(parts[0], 16) != 0 or parts[2].strip() != "Process ID":
            raise ValueError
        pid = int(parts[1], 16)
        if pid <= 0:
            raise ValueError
        return pid
    except (ValueError, UnicodeError):
        raise ClientError(
            "OpenVPN Interactive Service rejected startup. Check driver, service and account authorization."
        ) from None


def launch(
    binary: Path, args: list[str], directory: Path, *, owner: str | None = None
) -> OwnedProcess:
    if os.name != "nt":
        info = binary.stat()
        trusted_owners = {0, int(owner)} if owner is not None else {0}
        if info.st_uid not in trusted_owners or info.st_mode & 0o022:
            raise ClientError(
                "Elevated OpenVPN executable must belong to root/the originating account and not be group/world writable."
            )
        environment = {k: v for k, v in os.environ.items() if k in {"PATH", "LANG", "LC_ALL"}}
        popen = subprocess.Popen(
            [str(binary), *args],
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=directory,
            close_fds=True,
            env=environment,
        )
        return OwnedProcess(psutil.Process(popen.pid), popen=popen)
    import win32api
    import win32con
    import win32file
    import win32job
    import win32pipe

    pipe = job = None
    try:
        # The service always uses its configured binary, so verify it agrees with doctor.
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\OpenVPN") as key:
            try:
                configured = Path(winreg.QueryValueEx(key, "exe_path")[0])
            except OSError:
                configured = Path(winreg.QueryValueEx(key, "")[0]) / "bin/openvpn.exe"
        if not os.path.samefile(configured, binary):
            raise ClientError(
                "Selected executable differs from the Interactive Service executable."
            )
        pipe_name = r"\\.\pipe\openvpn\service"
        win32pipe.WaitNamedPipe(pipe_name, 5000)
        pipe = win32file.CreateFile(
            pipe_name,
            win32con.GENERIC_READ | win32con.GENERIC_WRITE,
            0,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_OVERLAPPED,
            None,
        )
        win32pipe.SetNamedPipeHandleState(pipe, win32pipe.PIPE_READMODE_MESSAGE, None, None)

        def io(operation):
            import pywintypes

            overlap = pywintypes.OVERLAPPED()
            overlap.hEvent = win32event.CreateEvent(None, True, False, None)
            try:
                result = operation(overlap)
                if (
                    win32event.WaitForSingleObject(overlap.hEvent, 10000)
                    != win32event.WAIT_OBJECT_0
                ):
                    win32file.CancelIoEx(pipe, overlap)
                    raise ClientError("Interactive Service startup timed out.")
                count = win32file.GetOverlappedResult(pipe, overlap, False)
                return result, count
            finally:
                overlap.hEvent.Close()

        import win32event

        io(
            lambda overlap: win32file.WriteFile(
                pipe, windows_startup_message(directory, args), overlap
            )
        )
        buffer = win32file.AllocateReadBuffer(4096)
        _, count = io(lambda overlap: win32file.ReadFile(pipe, buffer, overlap))
        pid = parse_service_reply(bytes(buffer[:count]))
        process = psutil.Process(pid)
        if not os.path.samefile(process.exe(), binary):
            raise ClientError("Interactive Service returned an unexpected executable.")
        # Management stays held until the child is assigned to a kill-on-close job.
        job = win32job.CreateJobObject(None, None)
        info = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
        info["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, info)
        handle = win32api.OpenProcess(
            win32con.PROCESS_SET_QUOTA
            | win32con.PROCESS_TERMINATE
            | win32con.PROCESS_QUERY_INFORMATION,
            False,
            pid,
        )
        try:
            win32job.AssignProcessToJobObject(job, handle)
        finally:
            handle.Close()
        return OwnedProcess(process, pipe=pipe, job=job)
    except ClientError:
        if pipe:
            pipe.Close()
        if job:
            job.Close()
        raise
    except Exception:
        if pipe:
            pipe.Close()
        if job:
            job.Close()
        raise ClientError(
            "Interactive Service startup failed; check installation and privileges."
        ) from None
