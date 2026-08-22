from __future__ import annotations

import sys

from va_workspace.util.progress import parse_percent
from va_workspace.util.shell import run_command, run_command_streamed


def test_run_command_timeout() -> None:
    result = run_command([sys.executable, "-c", "import time; time.sleep(5)"], timeout=1)
    assert result.timed_out
    assert result.returncode != 0


def test_run_command_ok() -> None:
    result = run_command([sys.executable, "-c", "print('ok')"], timeout=10)
    assert result.ok
    assert "ok" in result.stdout


def test_run_command_streamed_emits_lines() -> None:
    seen: list[str] = []
    result = run_command_streamed(
        [sys.executable, "-c", "print('a'); print('b')"],
        timeout=10,
        on_stdout=seen.append,
    )
    assert result.ok
    assert seen == ["a", "b"]
    assert result.stdout.splitlines() == ["a", "b"]


def test_run_command_streamed_timeout_kills_process() -> None:
    result = run_command_streamed(
        [sys.executable, "-c", "import time; time.sleep(30)"], timeout=1
    )
    assert result.timed_out
    assert "timed out" in result.error


def test_parse_nmap_percent() -> None:
    line = "SYN Stealth Scan Timing: About 42.13% done; ETC: 14:03 (0:01:12 remaining)"
    assert parse_percent(line) == 42.13
    assert parse_percent("Nmap scan report for 10.0.0.1") is None
