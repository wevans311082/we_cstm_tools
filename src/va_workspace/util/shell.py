"""Safe subprocess wrappers. Never uses shell=True."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


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
