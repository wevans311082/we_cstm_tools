"""Searchsploit leads — never findings."""

from __future__ import annotations

import json
from pathlib import Path

from va_workspace.core.vault import render
from va_workspace.models import EngagementState, Host, Port
from va_workspace.util import log
from va_workspace.util.shell import run_command, which


def _query(port: Port) -> str | None:
    product = port.product.strip()
    version = port.version.strip()
    if not product:
        return None
    if version:
        return f"{product} {version}"
    return product


def write_leads(state: EngagementState) -> int:
    from va_workspace.core.nse_leads import write_nse_leads

    nse_count = write_nse_leads(state)
    if nse_count:
        log.info(f"wrote {nse_count} NSE lead note(s)")
    from va_workspace.core.python_leads import write_python_leads

    py_count = write_python_leads(state)
    if py_count:
        log.info(f"wrote {py_count} Python-probe lead note(s)")
    nse_count += py_count
    binary = which("searchsploit")
    if binary is None:
        log.warn("searchsploit not on PATH — skipping exploit leads (sudo apt install exploitdb)")
        return nse_count
    written = 0
    for host in state.hosts:
        for port in host.open_ports:
            query = _query(port)
            if query is None:
                continue
            result = run_command(
                [str(binary), "--json", "--disable-colour", query],
                timeout=60,
            )
            body = result.stdout.strip()
            if not body:
                continue
            pretty = _format_json(body)
            if not pretty:
                continue
            dest = _lead_path(state, host, port)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(
                render(
                    "lead.md.j2",
                    state=state,
                    host=host,
                    product=port.product,
                    version=port.version,
                    service=port.service,
                    port=port.number,
                    protocol=port.protocol,
                    body=pretty,
                    mode=str(state.mode),
                    template="",
                ),
                encoding="utf-8",
            )
            written += 1
    return nse_count + written


def _lead_path(state: EngagementState, host: Host, port: Port) -> Path:
    slug = f"{host.slug}-{port.protocol}{port.number}"
    return state.path / "04-leads" / f"{slug}.md"


def _format_json(raw: str) -> str:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return raw[:8000]
    exploits = data.get("RESULTS_EXPLOIT") or data.get("RESULTS_SHELLCODE") or []
    if not exploits:
        return ""
    lines = []
    for item in exploits[:25]:
        title = item.get("Title") or item.get("title") or ""
        path = item.get("Path") or item.get("path") or ""
        lines.append(f"- {title} ({path})")
    return "\n".join(lines)
