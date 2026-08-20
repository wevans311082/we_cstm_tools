"""Scan and ingest pipelines (CLI compositor helpers)."""

from __future__ import annotations

import shutil
from pathlib import Path

from va_workspace.config.load import load_tool_mappings
from va_workspace.constants import NmapPhase
from va_workspace.core.leads import write_leads
from va_workspace.core.nmap_parser import parse_nmap_xml
from va_workspace.core.nmap_runner import nmap_output_stem, run_nmap
from va_workspace.core.orchestrator import run_jobs
from va_workspace.core.state import save_state
from va_workspace.core.vault import write_host_notes, write_operator_docs, write_overview
from va_workspace.core.visualizer import write_canvas, write_service_chart
from va_workspace.models import EngagementState
from va_workspace.util import log


def ingest_xml(state: EngagementState, xml_path: Path, *, copy_raw: bool = True) -> None:
    xml_path = xml_path.expanduser().resolve()
    dest_dir = state.path / "05-raw" / "nmap"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / "scan.xml"
    if copy_raw:
        if xml_path.resolve() != dest.resolve():
            shutil.copy2(xml_path, dest)
        xml_path = dest
    hosts = parse_nmap_xml(xml_path)
    state.hosts = hosts
    state.nmap.status = NmapPhase.COMPLETE
    state.nmap.output_stem = str(nmap_output_stem(state.path))
    save_state(state)
    write_host_notes(state)
    write_overview(state)
    write_operator_docs(state)
    write_canvas(state)
    chart = write_service_chart(state)
    if chart:
        log.info(f"wrote {chart}")
    log.success(f"ingested {len(hosts)} host(s) into {state.path}")


def run_enum(state: EngagementState) -> None:
    tools = load_tool_mappings()
    run_jobs(state, tools)
    leads = write_leads(state)
    if leads:
        log.info(f"wrote {leads} searchsploit lead note(s)")
    write_overview(state)
    write_operator_docs(state)
    save_state(state)


def run_scan(state: EngagementState, extra_args: list[str], *, resume: bool) -> None:
    xml_path = Path(str(nmap_output_stem(state.path)) + ".xml")
    if resume and state.nmap.status == NmapPhase.COMPLETE and xml_path.is_file():
        log.info("resume: nmap already complete, re-parsing XML")
        ingest_xml(state, xml_path, copy_raw=False)
    else:
        xml_path = run_nmap(state, extra_args)
        ingest_xml(state, xml_path, copy_raw=False)
    run_enum(state)
