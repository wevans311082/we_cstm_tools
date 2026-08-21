"""Create and render the Obsidian engagement vault."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from va_workspace.constants import MANAGED_HEADER
from va_workspace.core.state import utc_now
from va_workspace.models import EngagementState, Finding, Host

REPORT_FILES: tuple[str, ...] = (
    "01-cover-and-people.md",
    "02-executive-summary.md",
    "03-background-scope-context.md",
    "04-methodology.md",
    "05-findings-index.md",
    "06-conclusions.md",
    "07-appendix-tooling.md",
)

NARRATIVE_REPORT = {
    "01-cover-and-people.md",
    "02-executive-summary.md",
    "03-background-scope-context.md",
    "04-methodology.md",
    "06-conclusions.md",
}


def jinja_env() -> Environment:
    env = Environment(
        loader=PackageLoader("va_workspace", "templates"),
        autoescape=select_autoescape(enabled_extensions=("html",)),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.globals["managed"] = MANAGED_HEADER

    def _clip(text: str, limit: int = 2000) -> str:
        if len(text) <= limit:
            return text
        return text[:limit] + "\n… truncated; full NSE is in 05-raw/nmap"

    env.filters["clip"] = _clip
    return env


def default_vault_root() -> Path:
    return Path.home() / "va-engagements"


def is_engagement_dir(path: Path) -> bool:
    return (path / "state.json").is_file() or (path / "engagement.md").is_file()


def host_dir(state: EngagementState, host: Host) -> Path:
    return state.path / "02-hosts" / host.slug


def render(name: str, **context: Any) -> str:
    return jinja_env().get_template(name).render(**context)


def write_file(path: Path, content: str, *, overwrite: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file() and not overwrite:
        return
    path.write_text(content, encoding="utf-8")


def is_managed(path: Path) -> bool:
    if not path.is_file():
        return True
    first = path.read_text(encoding="utf-8", errors="replace")[:80]
    return MANAGED_HEADER in first


def ensure_tree(state: EngagementState) -> None:
    root = state.path
    for relative in (
        "00-report",
        "01-overview/attachments",
        "02-hosts",
        "03-findings",
        "04-leads",
        "05-raw/nmap",
        "05-raw/tools",
        "06-logs/screenshots",
        "08-pre-engagement",
        "09-attachments/screenshots",
        ".obsidian",
    ):
        (root / relative).mkdir(parents=True, exist_ok=True)
    app_json = root / ".obsidian" / "app.json"
    if not app_json.is_file():
        app_json.write_text(
            '{\n  "legacyEditor": false,\n  "livePreview": true\n}\n',
            encoding="utf-8",
        )


def write_operator_docs(state: EngagementState, *, force: bool = False) -> None:
    ctx = _ctx(state)
    write_file(state.path / "engagement.md", render("engagement.md.j2", **ctx), overwrite=force)
    write_file(state.path / "scope.md", render("scope.md.j2", **ctx), overwrite=force)
    write_file(
        state.path / "rules-of-engagement.md",
        render("roe.md.j2", **ctx),
        overwrite=force,
    )
    write_file(
        state.path / "08-pre-engagement" / "checklist.md",
        render("pre_engagement.md.j2", **ctx),
        overwrite=force,
    )
    for name in REPORT_FILES:
        dest = state.path / "00-report" / name
        overwrite = name not in NARRATIVE_REPORT
        if name in NARRATIVE_REPORT and dest.is_file() and not force:
            continue
        if name == "05-findings-index.md" or name == "07-appendix-tooling.md":
            overwrite = True
        write_file(dest, render(f"report/{name}.j2", **ctx), overwrite=overwrite or force)


def write_overview(state: EngagementState) -> None:
    ctx = _ctx(state)
    write_file(
        state.path / "01-overview" / "dashboard.md",
        render("dashboard.md.j2", **ctx),
        overwrite=True,
    )
    write_file(
        state.path / "01-overview" / "network-overview.md",
        render("overview.md.j2", **ctx),
        overwrite=True,
    )
    from va_workspace.core.posture import write_posture_notes

    write_posture_notes(state)


def write_host_notes(state: EngagementState) -> None:
    for host in state.hosts:
        directory = host_dir(state, host)
        for sub in ("services", "info", "loot", "evidence"):
            (directory / sub).mkdir(parents=True, exist_ok=True)
        ctx = _ctx(state) | {"host": host}
        write_file(directory / "host.md", render("host.md.j2", **ctx), overwrite=True)


def write_finding_note(state: EngagementState, finding: Finding) -> Path:
    slug = _slug(finding.title)
    dest = state.path / "03-findings" / f"{finding.id}-{slug}.md"
    ctx = _ctx(state) | {"finding": finding}
    write_file(dest, render("finding.md.j2", **ctx), overwrite=True)
    return dest


def list_finding_files(state: EngagementState) -> list[Path]:
    folder = state.path / "03-findings"
    if not folder.is_dir():
        return []
    return sorted(folder.glob("F-*.md"))


def _slug(title: str) -> str:
    chars: list[str] = []
    for char in title.lower():
        if char.isalnum():
            chars.append(char)
        elif chars and chars[-1] != "-":
            chars.append("-")
    slug = "".join(chars).strip("-")
    return slug[:48] or "finding"


def _ctx(state: EngagementState) -> dict[str, Any]:
    up_hosts = [h for h in state.hosts if h.status == "up"]
    return {
        "state": state,
        "hosts": state.hosts,
        "up_hosts": up_hosts,
        "now": utc_now(),
        "client": state.client or "unspecified",
        "mode": str(state.mode),
        "intensity": str(state.intensity),
        "targets": state.targets,
        "excludes": state.excludes,
        "testers": state.testers,
        "classification": state.classification,
        "finding_ids": state.findings,
        "job_count": len(state.jobs),
        "complete_jobs": sum(1 for j in state.jobs if str(j.status) == "complete"),
    }
