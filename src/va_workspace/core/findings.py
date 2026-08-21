"""Operator-authored findings."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

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
    template_id: str = "",
) -> tuple[Finding, Path]:
    if template_id:
        from va_workspace.core.templates import get_template

        tmpl = get_template(template_id)
        title = title or tmpl.title
        cvss_vector = cvss_vector or tmpl.cvss
        description = description or tmpl.description
        short_term_fix = short_term_fix or tmpl.short_term
        strategic_fix = strategic_fix or tmpl.strategic
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
    """Extract YAML frontmatter from a finding note as a flat string dict."""
    text = path.read_text(encoding="utf-8")
    # Skip the leading managed-header comment if present
    start = text.find("---")
    if start == -1:
        return {}
    rest = text[start + 3 :]
    end = rest.find("\n---")
    block = rest[:end] if end != -1 else rest
    try:
        parsed: Any = yaml.safe_load(block)
    except yaml.YAMLError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {k: str(v) for k, v in parsed.items() if not isinstance(v, dict | list)}


def _safe_float(value: str) -> float:
    """Convert a string to float, returning 0.0 on invalid/corrupted values."""
    try:
        return float(value)
    except (ValueError, TypeError):
        return 0.0


def load_finding(path: Path) -> Finding | None:
    """Reconstruct a Finding dataclass from a note's YAML frontmatter."""
    meta = parse_finding_frontmatter(path)
    fid = meta.get("id", "")
    if not fid:
        return None
    try:
        status = FindingStatus(meta.get("status", FindingStatus.DRAFT))
    except ValueError:
        status = FindingStatus.DRAFT
    return Finding(
        id=fid,
        title=meta.get("title", ""),
        cvss_vector=meta.get("cvss_vector", ""),
        cvss_score=_safe_float(meta.get("cvss_score", "0.0")),
        severity=meta.get("severity", "none"),
        status=status,
        hosts=[],
        ports=[],
        evidence=[],
        short_term_fix="",
        strategic_fix="",
        description="",
        created=meta.get("created", ""),
    )


def edit_finding(
    state: EngagementState,
    finding_id: str,
    *,
    title: str | None = None,
    cvss_vector: str | None = None,
    hosts: list[str] | None = None,
    ports: list[str] | None = None,
    status: FindingStatus | None = None,
) -> tuple[Finding, Path]:
    """Update fields on an existing finding note and save state."""
    files = list_finding_files(state)
    matched = next((p for p in files if p.name.startswith(finding_id + "-")), None)
    if matched is None:
        raise FileNotFoundError(f"finding {finding_id} not found in vault")
    existing = load_finding(matched)
    if existing is None:
        raise ValueError(f"could not parse frontmatter from {matched}")

    updated = Finding(
        id=existing.id,
        title=title if title is not None else existing.title,
        cvss_vector=(cvss_vector.strip() if cvss_vector is not None else existing.cvss_vector),
        cvss_score=existing.cvss_score,
        severity=existing.severity,
        status=status if status is not None else existing.status,
        hosts=hosts if hosts is not None else existing.hosts,
        ports=ports if ports is not None else existing.ports,
        evidence=existing.evidence,
        short_term_fix=existing.short_term_fix,
        strategic_fix=existing.strategic_fix,
        description=existing.description,
        created=existing.created,
    )
    if cvss_vector is not None:
        updated.cvss_score = base_score(updated.cvss_vector)
        updated.severity = severity_from_score(updated.cvss_score)

    path = write_finding_note(state, updated)
    # If the title changed the slug, write_finding_note created a new file.
    # Remove the old one to avoid stale duplicates.
    if path.resolve() != matched.resolve() and matched.is_file():
        matched.unlink()
    save_state(state)
    return updated, path
