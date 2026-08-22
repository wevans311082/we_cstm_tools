"""Detached `va snap --listen` daemon: PID file, liveness checks, auto-reload.

A thread dies with the CLI process, so the hotkey listener runs as a real detached
child instead. Every va command can then cheaply check the PID file and restart it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from va_workspace.core.state import utc_now
from va_workspace.util import log

PID_FILE = Path("06-logs") / "snap-listener.json"
LOG_FILE = Path("06-logs") / "snap-listener.log"
_STILL_ACTIVE = 259


@dataclass
class DaemonInfo:
    pid: int
    hotkey: str
    started: str

    def describe(self) -> str:
        return f"pid {self.pid}, hotkey {self.hotkey}, since {self.started}"


def pid_file(engagement: Path) -> Path:
    return engagement / PID_FILE


def log_file(engagement: Path) -> Path:
    return engagement / LOG_FILE


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            ok = kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
            return bool(ok) and code.value == _STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _is_ours(pid: int) -> bool:
    """Guard against PID reuse by checking the command line where the OS exposes it."""
    cmdline = Path(f"/proc/{pid}/cmdline")
    if not cmdline.is_file():
        return True
    try:
        text = cmdline.read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="replace")
    except OSError:
        return True
    return "va_workspace" in text or "va" in text.split()


def _read(engagement: Path) -> DaemonInfo | None:
    path = pid_file(engagement)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return DaemonInfo(
            pid=int(data["pid"]),
            hotkey=str(data.get("hotkey", "")),
            started=str(data.get("started", "")),
        )
    except (OSError, ValueError, KeyError):
        return None


def _write(engagement: Path, info: DaemonInfo) -> None:
    path = pid_file(engagement)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"pid": info.pid, "hotkey": info.hotkey, "started": info.started}, indent=2),
        encoding="utf-8",
    )


def _clear(engagement: Path) -> None:
    pid_file(engagement).unlink(missing_ok=True)


def status(engagement: Path) -> DaemonInfo | None:
    """Return the running daemon, clearing the PID file if it is stale."""
    info = _read(engagement)
    if info is None:
        return None
    if _pid_alive(info.pid) and _is_ours(info.pid):
        return info
    _clear(engagement)
    return None


def was_started(engagement: Path) -> bool:
    """True when a PID file exists, i.e. the operator asked for a listener at some point."""
    return pid_file(engagement).is_file()


def start(engagement: Path, hotkey: str) -> DaemonInfo | None:
    """Spawn a detached listener. Returns None if the child failed to stay up."""
    running = status(engagement)
    if running is not None:
        return running
    logs = log_file(engagement)
    logs.parent.mkdir(parents=True, exist_ok=True)
    argv = [
        sys.executable,
        "-m",
        "va_workspace",
        "--no-snap-check",
        "snap",
        "--listen",
        "--foreground",
        "--hotkey",
        hotkey,
        "--out",
        str(engagement.expanduser().resolve()),  # the child inherits a different cwd
    ]
    creationflags = 0
    extra: dict[str, object] = {}
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000008  # DETACHED_PROCESS
    else:
        extra["start_new_session"] = True
    with logs.open("ab") as handle:
        handle.write(f"\n=== {utc_now()} starting listener ({hotkey}) ===\n".encode())
        try:
            proc = subprocess.Popen(  # noqa: S603 - argv list, shell=False
                argv,
                stdout=handle,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                close_fds=True,
                creationflags=creationflags,
                **extra,  # type: ignore[arg-type]
            )
        except OSError as exc:
            log.warn(f"snap listener failed to spawn: {exc}")
            return None
    try:
        proc.wait(timeout=0.75)
    except subprocess.TimeoutExpired:
        pass
    else:
        log.warn(f"snap listener exited immediately (see {logs})")
        return None
    info = DaemonInfo(pid=proc.pid, hotkey=hotkey, started=utc_now())
    _write(engagement, info)
    return info


def stop(engagement: Path) -> bool:
    info = status(engagement)
    if info is None:
        _clear(engagement)
        return False
    if os.name == "nt":
        subprocess.run(  # noqa: S603
            ["taskkill", "/PID", str(info.pid), "/F"],
            capture_output=True,
            check=False,
        )
    else:
        import signal

        try:
            os.kill(info.pid, signal.SIGTERM)
        except OSError as exc:
            log.warn(f"could not stop listener {info.pid}: {exc}")
            return False
    for _ in range(10):
        if not _pid_alive(info.pid):
            break
        time.sleep(0.1)
    _clear(engagement)
    return True


def ensure(engagement: Path, hotkey: str, *, autostart: bool) -> tuple[DaemonInfo | None, str]:
    """Check the listener and reload it if it died. Returns (info, action)."""
    had_pidfile = was_started(engagement)
    running = status(engagement)
    if running is not None:
        if running.hotkey != hotkey and autostart:
            stop(engagement)
            return start(engagement, hotkey), "rebound"
        return running, "running"
    if not autostart and not had_pidfile:
        return None, "idle"
    info = start(engagement, hotkey)
    if info is None:
        return None, "failed"
    return info, "reloaded" if had_pidfile else "started"
