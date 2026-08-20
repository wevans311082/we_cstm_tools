"""Run Nmap on Linux in resumable phases. Unsupported as a live scanner on Windows."""

from __future__ import annotations

import sys
from pathlib import Path

from va_workspace.config.profiles import (
    build_discovery_argv,
    build_scripts_argv,
    build_tcp_argv,
    build_udp_argv,
    is_privileged,
    nmap_profile,
)
from va_workspace.constants import Intensity, Mode, NmapPhase
from va_workspace.core.nmap_parser import merge_hosts, parse_nmap_xml
from va_workspace.core.state import save_state, utc_now
from va_workspace.models import EngagementState, Host
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


def _stem(engagement_dir: Path, name: str) -> Path:
    return engagement_dir / "05-raw" / "nmap" / name


def _xml(stem: Path) -> Path:
    return Path(str(stem) + ".xml")


def _run_argv(state: EngagementState, argv: list[str], stem: Path, timeout: int) -> Path:
    log.info("nmap: " + " ".join(argv))
    result = run_command(argv, timeout=timeout)
    xml_path = _xml(stem)
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
    return xml_path


def _live_targets(state: EngagementState, discovery_xml: Path | None) -> list[str]:
    if discovery_xml is None or not discovery_xml.is_file():
        return list(state.targets)
    hosts = parse_nmap_xml(discovery_xml)
    live = [h.ip for h in hosts if h.status == "up"]
    if not live:
        log.warn("discovery found no live hosts; falling back to original targets")
        return list(state.targets)
    live_file = state.path / "05-raw" / "nmap" / "live.txt"
    live_file.write_text("\n".join(live) + "\n", encoding="utf-8")
    log.info(f"discovery: {len(live)} live host(s)")
    return live


def run_nmap_pipeline(
    state: EngagementState,
    extra_args: list[str],
    *,
    resume: bool = False,
    skip_host_discovery: bool = False,
) -> list[Path]:
    """Phases A discovery, B TCP, C UDP, D NSE. Returns XML paths to merge."""
    require_linux_scan()
    nmap = which("nmap")
    if nmap is None:
        raise FileNotFoundError("nmap is not on PATH. Run: sudo apt install nmap")
    intensity = Intensity(state.intensity)
    mode = Mode(state.mode)
    profile = nmap_profile(intensity)
    nmap_path = str(nmap)
    raw = state.path / "05-raw" / "nmap"
    raw.mkdir(parents=True, exist_ok=True)
    xmls: list[Path] = []

    state.nmap.status = NmapPhase.RUNNING
    state.nmap.output_stem = str(nmap_output_stem(state.path))
    if not state.nmap.started:
        state.nmap.started = utc_now()
    state.nmap.skip_host_discovery = skip_host_discovery
    save_state(state)

    discovery_xml: Path | None = None
    if skip_host_discovery:
        state.nmap.discovery = "skipped"
        save_state(state)
    elif (
        resume
        and state.nmap.discovery == "complete"
        and _xml(_stem(state.path, "discovery")).is_file()
    ):
        discovery_xml = _xml(_stem(state.path, "discovery"))
        log.info("resume: discovery complete")
    else:
        stem = _stem(state.path, "discovery")
        argv = build_discovery_argv(
            nmap_path=nmap_path,
            output_stem=str(stem),
            targets=state.targets,
            excludes=state.excludes,
            intensity=intensity,
        )
        discovery_xml = _run_argv(state, argv, stem, profile.nmap_timeout)
        state.nmap.discovery = "complete"
        save_state(state)
        xmls.append(discovery_xml)

    if discovery_xml and discovery_xml not in xmls and discovery_xml.is_file():
        xmls.append(discovery_xml)

    targets = _live_targets(state, discovery_xml)

    tcp_xml = _xml(_stem(state.path, "tcp"))
    if resume and state.nmap.tcp == "complete" and tcp_xml.is_file():
        log.info("resume: tcp complete")
        xmls.append(tcp_xml)
    else:
        stem = _stem(state.path, "tcp")
        argv, notes = build_tcp_argv(
            nmap_path=nmap_path,
            output_stem=str(stem),
            targets=targets,
            excludes=state.excludes,
            intensity=intensity,
            extra_args=extra_args,
        )
        for note in notes:
            log.warn(note)
        tcp_xml = _run_argv(state, argv, stem, profile.nmap_timeout)
        state.nmap.tcp = "complete"
        save_state(state)
        xmls.append(tcp_xml)

    udp_xml = _xml(_stem(state.path, "udp"))
    udp_argv, udp_notes = build_udp_argv(
        nmap_path=nmap_path,
        output_stem=str(_stem(state.path, "udp")),
        targets=targets,
        excludes=state.excludes,
        intensity=intensity,
    )
    if not udp_argv:
        for note in udp_notes:
            log.warn(note)
        state.nmap.udp = "skipped"
        save_state(state)
    elif resume and state.nmap.udp == "complete" and udp_xml.is_file():
        log.info("resume: udp complete")
        xmls.append(udp_xml)
    else:
        udp_xml = _run_argv(state, udp_argv, _stem(state.path, "udp"), profile.nmap_timeout)
        state.nmap.udp = "complete"
        save_state(state)
        xmls.append(udp_xml)

    parsed: list[list[Host]] = []
    for path in xmls:
        if path.is_file() and path.name != "discovery.xml":
            parsed.append(parse_nmap_xml(path))
    merged = merge_hosts(*parsed) if parsed else []
    open_ports = sorted({p.number for h in merged for p in h.open_ports})
    script_xml = _xml(_stem(state.path, "scripts"))
    if resume and state.nmap.scripts == "complete" and script_xml.is_file():
        log.info("resume: nse complete")
        xmls.append(script_xml)
    else:
        argv, notes = build_scripts_argv(
            nmap_path=nmap_path,
            output_stem=str(_stem(state.path, "scripts")),
            targets=targets,
            excludes=state.excludes,
            intensity=intensity,
            mode=mode,
            ports=open_ports,
            extra_args=[],
            privileged=is_privileged(),
        )
        if not argv:
            for note in notes:
                log.warn(note)
            state.nmap.scripts = "skipped"
            save_state(state)
        else:
            for note in notes:
                log.warn(note)
            script_xml = _run_argv(
                state, argv, _stem(state.path, "scripts"), profile.nmap_timeout
            )
            state.nmap.scripts = "complete"
            save_state(state)
            xmls.append(script_xml)

    # Compatibility alias used by ingest resume
    scan_xml = _xml(nmap_output_stem(state.path))
    if tcp_xml.is_file() and tcp_xml.resolve() != scan_xml.resolve():
        scan_xml.write_bytes(tcp_xml.read_bytes())

    state.nmap.status = NmapPhase.COMPLETE
    state.nmap.finished = utc_now()
    save_state(state)
    return [path for path in xmls if path.is_file()]


def run_nmap(state: EngagementState, extra_args: list[str]) -> Path:
    """Back-compat: run the pipeline and return the tcp/scan XML."""
    xmls = run_nmap_pipeline(state, extra_args, resume=False)
    scan = _xml(nmap_output_stem(state.path))
    if scan.is_file():
        return scan
    for path in xmls:
        if path.name.endswith(".xml"):
            return path
    raise RuntimeError("nmap produced no XML")
