from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from va_workspace.core.nmap_runner import ScanPlatformError, require_linux_scan


def test_require_linux_scan_passes_on_linux() -> None:
    with patch.object(sys, "platform", "linux"):
        # Should not raise
        require_linux_scan()


def test_require_linux_scan_raises_on_windows() -> None:
    with patch.object(sys, "platform", "win32"):
        with pytest.raises(ScanPlatformError, match="Linux"):
            require_linux_scan()


def test_require_linux_scan_raises_on_darwin() -> None:
    with patch.object(sys, "platform", "darwin"):
        with pytest.raises(ScanPlatformError):
            require_linux_scan()
