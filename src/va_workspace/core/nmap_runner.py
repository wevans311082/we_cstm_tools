"""Run Nmap on Linux. Unsupported as a live scanner on Windows."""

from __future__ import annotations

import sys
from pathlib import Path

from va_workspace.config.profiles import build_nmap_argv
from va_workspace.constants import Intensity, NmapPhase
from va_workspace.core.state import save_state, utc_now
from va_workspace.models import EngagementState
from va_workspace.util import log
from va_workspace.util.shell import run_command, which

SCAN_UNSUPPORTED = "va scan (live Nmap) is supported on Kali/Linux. Use va ingest on this OS."


class ScanPlatformError(RuntimeError):
    """Raised when live Nmap is requested on a non-Linux OS."""


def require_linux_scan() -> None:
    if not sys.platform.startswith("linux"):
        raise ScanPlatformError(SCAN_UNSUPPORTED)


def nmap_output_stem(engagement_dir: Path) -> Path:
    return engagement_dir / "05-raw" / "nmap" / "scan"


def run_nmap(state: EngagementState, extra_args: list[str]) -> Path:
    require_linux_scan()
    nmap = which("nmap")
    if nmap is None:
        raise FileNotFoundError("nmap is not on PATH. Run: sudo apt install nmap")
    stem = nmap_output_stem(state.path)
    stem.parent.mkdir(parents=True, exist_ok=True)
    argv, notes = build_nmap_argv(
        nmap_path=str(nmap),
        output_stem=str(stem),
        targets=state.targets,
        excludes=state.excludes,
        intensity=Intensity(state.intensity),
        extra_args=extra_args,
    )
    for note in notes:
        log.warn(note)
    log.info("nmap: " + " ".join(argv))
    state.nmap.status = NmapPhase.RUNNING
    state.nmap.output_stem = str(stem)
    state.nmap.started = utc_now()
    state.nmap.error = ""
    save_state(state)

    from va_workspace.config.profiles import nmap_profile

    profile = nmap_profile(Intensity(state.intensity))
    result = run_command(argv, timeout=profile.nmap_timeout)
    xml_path = Path(str(stem) + ".xml")
    if result.timed_out:
        state.nmap.status = NmapPhase.FAILED
        state.nmap.error = result.error
        state.nmap.finished = utc_now()
        save_state(state)
        raise TimeoutError(result.error)
    if not xml_path.is_file():
        state.nmap.status = NmapPhase.FAILED
        state.nmap.error = result.stderr or result.error or "nmap produced no XML"
        state.nmap.finished = utc_now()
        save_state(state)
        raise RuntimeError(state.nmap.error)
    state.nmap.status = NmapPhase.COMPLETE
    state.nmap.finished = utc_now()
    save_state(state)
    return xml_path
