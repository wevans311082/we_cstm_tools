"""Safe subprocess wrappers. Never uses shell=True."""

from __future__ import annotations

import shutil
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import IO


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.error


def _decode_optional(data: str | bytes | None) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data


def which(binary: str) -> Path | None:
    found = shutil.which(binary)
    return Path(found) if found else None


def run_command(
    argv: list[str],
    *,
    timeout: int,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> CommandResult:
    """Run an external binary with a timeout. argv must be a list (no shell)."""
    bad = _argv_error(argv)
    if bad is not None:
        return bad
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except FileNotFoundError as exc:
        return CommandResult(
            argv=list(argv),
            returncode=-1,
            stdout="",
            stderr="",
            error=f"binary not found: {exc}",
        )
    except subprocess.TimeoutExpired as exc:
        stdout = _decode_optional(exc.stdout)
        stderr = _decode_optional(exc.stderr)
        return CommandResult(
            argv=list(argv),
            returncode=-1,
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
            error=f"timed out after {timeout}s",
        )
    except OSError as exc:
        return CommandResult(
            argv=list(argv),
            returncode=-1,
            stdout="",
            stderr="",
            error=str(exc),
        )
    return CommandResult(
        argv=list(argv),
        returncode=int(completed.returncode),
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )


def _argv_error(argv: list[str]) -> CommandResult | None:
    if not argv:
        return CommandResult(argv=[], returncode=-1, stdout="", stderr="", error="empty argv")
    if any(not isinstance(item, str) or item == "" for item in argv):
        return CommandResult(
            argv=list(argv),
            returncode=-1,
            stdout="",
            stderr="",
            error="argv items must be non-empty strings",
        )
    return None


def _drain(stream: IO[str], sink: list[str], on_line: Callable[[str], None] | None) -> None:
    with stream:
        for line in stream:
            sink.append(line)
            if on_line is not None:
                try:
                    on_line(line.rstrip("\n"))
                except Exception:  # a broken progress display must not kill the scan
                    pass


def run_command_streamed(
    argv: list[str],
    *,
    timeout: int,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    on_stdout: Callable[[str], None] | None = None,
    on_stderr: Callable[[str], None] | None = None,
) -> CommandResult:
    """Like run_command, but hands each output line to a callback as it arrives."""
    bad = _argv_error(argv)
    if bad is not None:
        return bad
    try:
        proc = subprocess.Popen(  # noqa: S603 - argv list, shell=False
            argv,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            shell=False,
        )
    except FileNotFoundError as exc:
        return CommandResult(
            argv=list(argv),
            returncode=-1,
            stdout="",
            stderr="",
            error=f"binary not found: {exc}",
        )
    except OSError as exc:
        return CommandResult(argv=list(argv), returncode=-1, stdout="", stderr="", error=str(exc))

    out_lines: list[str] = []
    err_lines: list[str] = []
    readers = [
        threading.Thread(target=_drain, args=(proc.stdout, out_lines, on_stdout), daemon=True),
        threading.Thread(target=_drain, args=(proc.stderr, err_lines, on_stderr), daemon=True),
    ]
    for reader in readers:
        reader.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout or None)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait()
        raise
    finally:
        for reader in readers:
            reader.join(timeout=10)

    return CommandResult(
        argv=list(argv),
        returncode=int(proc.returncode),
        stdout="".join(out_lines),
        stderr="".join(err_lines),
        timed_out=timed_out,
        error=f"timed out after {timeout}s" if timed_out else "",
    )


def run_interactive(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> int:
    """Run a binary attached to the operator's terminal. Output is not captured."""
    bad = _argv_error(argv)
    if bad is not None:
        raise ValueError(bad.error)
    completed = subprocess.run(  # noqa: S603 - argv list, shell=False
        argv,
        cwd=cwd,
        env=env,
        check=False,
        shell=False,
    )
    return int(completed.returncode)


def binary_version(binary: str, timeout: int = 15) -> str:
    """Best-effort version string for the tooling appendix."""
    path = which(binary)
    if path is None:
        return "missing"
    for flag in ("--version", "-V", "-v"):
        result = run_command([str(path), flag], timeout=timeout)
        text = (result.stdout or result.stderr).strip()
        if result.ok and text:
            return text.splitlines()[0][:200]
        if text and not result.timed_out:
            return text.splitlines()[0][:200]
    return str(path)
