"""Finding template library."""

from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files

import yaml


@dataclass(frozen=True)
class FindingTemplate:
    id: str
    title: str
    cvss: str
    description: str
    short_term: str
    strategic: str


def load_finding_templates() -> dict[str, FindingTemplate]:
    raw = files("va_workspace.config").joinpath("finding_templates.yaml").read_text(
        encoding="utf-8"
    )
    data = yaml.safe_load(raw) or {}
    templates: dict[str, FindingTemplate] = {}
    for tid, body in (data.get("templates") or {}).items():
        templates[str(tid)] = FindingTemplate(
            id=str(tid),
            title=str(body.get("title", tid)),
            cvss=str(body.get("cvss", "")).strip(),
            description=str(body.get("description", "")).strip(),
            short_term=str(body.get("short_term", "")).strip(),
            strategic=str(body.get("strategic", "")).strip(),
        )
    return templates


def get_template(template_id: str) -> FindingTemplate:
    templates = load_finding_templates()
    if template_id not in templates:
        known = ", ".join(sorted(templates))
        raise KeyError(f"unknown template '{template_id}'. Known: {known}")
    return templates[template_id]
