from __future__ import annotations

import sys

from va_workspace.util.shell import run_command


def test_run_command_timeout() -> None:
    result = run_command([sys.executable, "-c", "import time; time.sleep(5)"], timeout=1)
    assert result.timed_out
    assert result.returncode != 0


def test_run_command_ok() -> None:
    result = run_command([sys.executable, "-c", "print('ok')"], timeout=10)
    assert result.ok
    assert "ok" in result.stdout
