"""Run Nmap on Linux in resumable phases. Unsupported as a live scanner on Windows."""

from __future__ import annotations

import sys
from collections.abc import Callable
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
from va_workspace.core.live_feed import LiveFeed
from va_workspace.core.nmap_parser import merge_hosts, parse_nmap_xml
from va_workspace.core.state import save_state, utc_now
from va_workspace.models import EngagementState, Host
from va_workspace.util import log
from va_workspace.util.progress import phase_progress
from va_workspace.util.shell import run_command_streamed, which

SCAN_UNSUPPORTED = "va scan (live Nmap) is supported on Kali/Linux. Use va ingest on this OS."
STATS_INTERVAL = "5s"

# Called with (phase name, xml paths so far) once each phase produces usable XML.
PhaseHook = Callable[[str, list[Path]], None]


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


def _with_progress_flags(argv: list[str]) -> list[str]:
    """Force periodic `Timing: About x% done` lines so the progress bar can advance."""
    out = list(argv)
    if "--stats-every" in out:
        idx = out.index("--stats-every")
        if idx + 1 < len(out):
            out[idx + 1] = STATS_INTERVAL
    else:
        out[1:1] = ["--stats-every", STATS_INTERVAL]
    if not any(item.startswith("-v") for item in out):
        out.insert(1, "-v")
    return out


def _fail(state: EngagementState, message: str) -> None:
    state.nmap.status = NmapPhase.FAILED
    state.nmap.error = message
    state.nmap.finished = utc_now()
    save_state(state)


def _run_argv(
    state: EngagementState, argv: list[str], stem: Path, timeout: int, *, label: str
) -> Path:
    argv = _with_progress_flags(argv)
    log.info("nmap: " + " ".join(argv))
    live = LiveFeed(state.path, label)

    with phase_progress(label) as bar:

        def on_line(line: str) -> None:
            live.feed(line)
            bar(line)

        result = run_command_streamed(argv, timeout=timeout, on_stdout=on_line)
    xml_path = _xml(stem)
    if result.timed_out:
        log.error(f"{label}: {result.error} ({live.summary()})")
        _fail(state, result.error)
        raise TimeoutError(result.error)
    if not xml_path.is_file():
        message = result.stderr.strip() or result.error or "nmap produced no XML"
        log.error(f"{label} failed (exit {result.returncode}): {message}")
        _fail(state, message)
        raise RuntimeError(message)
    if result.returncode != 0:
        log.warn(f"{label}: nmap exited {result.returncode}; using partial XML")
    for line in result.stderr.splitlines():
        if line.strip():
            log.warn(f"nmap: {line.strip()}")
    log.success(f"{label}: complete — {live.summary()} → {xml_path.name}")
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
    on_phase: PhaseHook | None = None,
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

    def phase_done(name: str) -> None:
        if on_phase is None:
            return
        try:
            on_phase(name, [path for path in xmls if path.is_file()])
        except Exception as exc:  # partial results must never abort the scan
            log.warn(f"incremental write after {name} failed: {exc}")

    state.nmap.status = NmapPhase.RUNNING
    state.nmap.output_stem = str(nmap_output_stem(state.path))
    if not state.nmap.started:
        state.nmap.started = utc_now()
    state.nmap.skip_host_discovery = skip_host_discovery
    save_state(state)
    log.info(
        f"scan starting: {len(state.targets)} target spec(s), intensity={intensity}, "
        f"mode={mode}, timeout={profile.nmap_timeout}s per phase"
    )

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
        discovery_xml = _run_argv(
            state, argv, stem, profile.nmap_timeout, label="nmap host discovery"
        )
        state.nmap.discovery = "complete"
        save_state(state)
        xmls.append(discovery_xml)

    if discovery_xml and discovery_xml not in xmls and discovery_xml.is_file():
        xmls.append(discovery_xml)

    targets = _live_targets(state, discovery_xml)
    phase_done("discovery")

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
        tcp_xml = _run_argv(state, argv, stem, profile.nmap_timeout, label="nmap TCP scan")
        state.nmap.tcp = "complete"
        save_state(state)
        xmls.append(tcp_xml)
    phase_done("tcp")

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
        udp_xml = _run_argv(
            state,
            udp_argv,
            _stem(state.path, "udp"),
            profile.nmap_timeout,
            label="nmap UDP scan",
        )
        state.nmap.udp = "complete"
        save_state(state)
        xmls.append(udp_xml)
    phase_done("udp")

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
                state,
                argv,
                _stem(state.path, "scripts"),
                profile.nmap_timeout,
                label="nmap NSE scripts",
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
