"""Promote interesting NSE output to unverified leads."""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib.resources import files

import yaml

from va_workspace.core.vault import render
from va_workspace.models import EngagementState, Host


@dataclass(frozen=True)
class LeadRule:
    id: str
    script: str
    pattern: str
    title: str
    template: str


def load_lead_rules() -> list[LeadRule]:
    raw = files("va_workspace.config").joinpath("lead_rules.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(raw) or {}
    rules: list[LeadRule] = []
    for item in data.get("rules") or []:
        rules.append(
            LeadRule(
                id=str(item["id"]),
                script=str(item["script"]),
                pattern=str(item.get("pattern") or "."),
                title=str(item["title"]),
                template=str(item.get("template") or ""),
            )
        )
    return rules


def match_leads(host: Host, rules: list[LeadRule] | None = None) -> list[dict[str, str]]:
    rules = rules if rules is not None else load_lead_rules()
    hits: list[dict[str, str]] = []
    seen: set[str] = set()
    for port, script in host.all_scripts():
        for rule in rules:
            if script.id != rule.script:
                continue
            if not re.search(rule.pattern, script.output or "", re.IGNORECASE | re.DOTALL):
                continue
            key = f"{rule.id}:{host.ip}:{port.number if port else 0}"
            if key in seen:
                continue
            seen.add(key)
            hits.append(
                {
                    "rule_id": rule.id,
                    "title": rule.title,
                    "template": rule.template,
                    "script": script.id,
                    "body": script.output[:8000],
                    "host": host.ip,
                    "port": str(port.number) if port else "",
                    "protocol": port.protocol if port else "",
                    "service": port.service if port else "",
                }
            )
    return hits


def write_nse_leads(state: EngagementState) -> int:
    rules = load_lead_rules()
    written = 0
    folder = state.path / "04-leads"
    folder.mkdir(parents=True, exist_ok=True)
    for host in state.hosts:
        for hit in match_leads(host, rules):
            dest = folder / f"nse-{hit['rule_id']}-{host.slug}-{hit['port'] or 'host'}.md"
            dest.write_text(
                render(
                    "lead.md.j2",
                    state=state,
                    host=host,
                    product=hit["title"],
                    version=hit["script"],
                    service=hit["service"] or hit["script"],
                    port=hit["port"] or "-",
                    protocol=hit["protocol"] or "host",
                    body=hit["body"],
                    mode=str(state.mode),
                    template=hit["template"],
                ),
                encoding="utf-8",
            )
            written += 1
    return written
