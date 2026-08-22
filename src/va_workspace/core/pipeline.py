"""Scan and ingest pipelines (CLI compositor helpers)."""

from __future__ import annotations

import shutil
from pathlib import Path

from va_workspace.config.load import load_tool_mappings
from va_workspace.constants import NmapPhase
from va_workspace.core.leads import write_leads
from va_workspace.core.nmap_parser import filter_reportable, merge_hosts, parse_nmap_xml
from va_workspace.core.nmap_runner import nmap_output_stem, run_nmap_pipeline
from va_workspace.core.orchestrator import run_jobs
from va_workspace.core.state import save_state
from va_workspace.core.vault import write_host_notes, write_operator_docs, write_overview
from va_workspace.core.visualizer import write_canvas, write_service_chart
from va_workspace.models import EngagementState
from va_workspace.util import log


def ingest_xmls(
    state: EngagementState,
    xml_paths: list[Path],
    *,
    copy_primary: bool = True,
    mark_complete: bool = True,
) -> None:
    existing = [path.expanduser().resolve() for path in xml_paths if path.is_file()]
    if not existing:
        raise FileNotFoundError("no nmap xml to ingest")
    dest_dir = state.path / "05-raw" / "nmap"
    dest_dir.mkdir(parents=True, exist_ok=True)
    parsed = [parse_nmap_xml(path) for path in existing]
    hosts = merge_hosts(*parsed) if len(parsed) > 1 else parsed[0]
    hosts, skipped = filter_reportable(hosts)
    if skipped:
        log.info(f"skipped {skipped} down host(s) with no open ports")
    if copy_primary:
        dest = dest_dir / "scan.xml"
        src = existing[0]
        if src.resolve() != dest.resolve():
            shutil.copy2(src, dest)
    state.hosts = hosts
    state.nmap.output_stem = str(nmap_output_stem(state.path))
    if mark_complete:
        state.nmap.status = NmapPhase.COMPLETE
        if state.nmap.tcp == "pending":
            state.nmap.tcp = "complete"
            state.nmap.scripts = "complete"
            state.nmap.discovery = "skipped"
            state.nmap.udp = "skipped"
    save_state(state)
    write_host_notes(state)
    write_overview(state)
    write_operator_docs(state)
    write_canvas(state)
    chart = write_service_chart(state)
    if chart:
        log.info(f"wrote {chart}")
    from va_workspace.core.nse_leads import write_nse_leads

    nse_leads = write_nse_leads(state)
    if nse_leads:
        log.info(f"wrote {nse_leads} NSE lead note(s)")
    if mark_complete:
        log.success(f"ingested {len(hosts)} host(s) into {state.path}")


def _partial_ingest(state: EngagementState, phase: str, xmls: list[Path]) -> None:
    """Write what we know so far into the vault so hosts appear before the scan ends."""
    usable = [path for path in xmls if path.is_file()]
    if not usable:
        return
    ingest_xmls(state, usable, copy_primary=False, mark_complete=False)
    open_ports = sum(len(host.open_ports) for host in state.hosts)
    log.success(
        f"{phase} written to vault: {len(state.hosts)} host(s), {open_ports} open port(s)"
    )


def ingest_xml(state: EngagementState, xml_path: Path, *, copy_raw: bool = True) -> None:
    ingest_xmls(state, [xml_path], copy_primary=copy_raw)


def run_enum(state: EngagementState) -> None:
    tools = load_tool_mappings()
    run_jobs(state, tools)
    leads = write_leads(state)
    if leads:
        log.info(f"wrote {leads} lead note(s)")
    write_overview(state)
    write_operator_docs(state)
    save_state(state)


def run_scan(
    state: EngagementState,
    extra_args: list[str],
    *,
    resume: bool,
    skip_host_discovery: bool = False,
    enum: bool = True,
) -> None:
    xml_path = Path(str(nmap_output_stem(state.path)) + ".xml")
    if resume and state.nmap.status == NmapPhase.COMPLETE and xml_path.is_file():
        log.info("resume: nmap already complete, re-parsing XML")
        extras = [
            state.path / "05-raw" / "nmap" / name
            for name in ("discovery.xml", "tcp.xml", "udp.xml", "scripts.xml", "scan.xml")
        ]
        present = [path for path in extras if path.is_file()]
        ingest_xmls(state, present or [xml_path], copy_primary=False)
    else:
        xmls = run_nmap_pipeline(
            state,
            extra_args,
            resume=resume,
            skip_host_discovery=skip_host_discovery or state.nmap.skip_host_discovery,
            on_phase=lambda phase, paths: _partial_ingest(state, phase, paths),
        )
        ingest_xmls(state, xmls, copy_primary=True)
    if enum:
        run_enum(state)
