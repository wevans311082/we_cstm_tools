"""Operator-authored findings."""

from __future__ import annotations

import re
from pathlib import Path

from va_workspace.constants import FindingStatus
from va_workspace.core.cvss import base_score, severity_from_score
from va_workspace.core.state import save_state, utc_now
from va_workspace.core.vault import list_finding_files, write_finding_note
from va_workspace.models import EngagementState, Finding

_ID_RE = re.compile(r"^F-(\d+)")


def next_finding_id(state: EngagementState) -> str:
    highest = 0
    for item in state.findings:
        match = _ID_RE.match(item)
        if match:
            highest = max(highest, int(match.group(1)))
    for path in list_finding_files(state):
        match = _ID_RE.match(path.name)
        if match:
            highest = max(highest, int(match.group(1)))
    return f"F-{highest + 1:03d}"


def add_finding(
    state: EngagementState,
    *,
    title: str,
    cvss_vector: str,
    hosts: list[str],
    ports: list[str],
    description: str = "",
    short_term_fix: str = "",
    strategic_fix: str = "",
    evidence: list[str] | None = None,
    status: FindingStatus = FindingStatus.DRAFT,
) -> tuple[Finding, Path]:
    score = base_score(cvss_vector)
    finding = Finding(
        id=next_finding_id(state),
        title=title,
        cvss_vector=cvss_vector.strip(),
        cvss_score=score,
        severity=severity_from_score(score),
        status=status,
        hosts=hosts,
        ports=ports,
        evidence=list(evidence or []),
        short_term_fix=short_term_fix,
        strategic_fix=strategic_fix,
        description=description,
        created=utc_now(),
    )
    path = write_finding_note(state, finding)
    if finding.id not in state.findings:
        state.findings.append(finding.id)
    save_state(state)
    return finding, path


def parse_finding_frontmatter(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    marker = text.find("---")
    if marker == -1:
        return {}
    rest = text[marker + 3 :]
    end = rest.find("\n---")
    block = rest[:end] if end != -1 else rest
    data: dict[str, str] = {}
    for line in block.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip().strip('"')
    return data
