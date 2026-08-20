"""Resolve and bootstrap engagement directories."""

from __future__ import annotations

from datetime import date
from pathlib import Path

from va_workspace import __version__
from va_workspace.constants import Intensity, Mode
from va_workspace.core.doctor import collect_doctor, version_snapshot
from va_workspace.core.state import save_state, try_load_state, utc_now
from va_workspace.core.vault import (
    default_vault_root,
    ensure_tree,
    is_engagement_dir,
    write_operator_docs,
)
from va_workspace.models import EngagementState
from va_workspace.util import log
from va_workspace.util.log import set_file_log


def slug_client(client: str) -> str:
    cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in client).strip("-")
    return cleaned or "scan"


def default_out_dir(client: str) -> Path:
    return default_vault_root() / f"{slug_client(client)}-{date.today().isoformat()}"


def resolve_engagement_dir(out: Path | None, cwd: Path) -> Path | None:
    if out is not None:
        return out
    if is_engagement_dir(cwd):
        return cwd
    return None


def bootstrap(
    *,
    path: Path,
    client: str,
    mode: Mode,
    intensity: Intensity,
    targets: list[str],
    excludes: list[str],
    testers: list[str],
    classification: str,
    resume: bool,
) -> EngagementState:
    path = path.expanduser().resolve()
    existing = try_load_state(path) if resume or is_engagement_dir(path) else None
    if existing is not None and resume:
        set_file_log(path / "06-logs" / "va.log")
        if targets:
            existing.targets = targets
        if excludes:
            existing.excludes = excludes
        existing.mode = mode
        existing.intensity = intensity
        save_state(existing)
        return existing

    state = existing or EngagementState(
        path=path,
        client=client,
        mode=mode,
        intensity=intensity,
        targets=targets,
        excludes=excludes,
        testers=testers,
        classification=classification,
        va_version=__version__,
        created=utc_now(),
    )
    if not resume:
        state.client = client or state.client
        state.mode = mode
        state.intensity = intensity
        if targets:
            state.targets = targets
        if excludes:
            state.excludes = excludes
        if testers:
            state.testers = testers
        state.classification = classification or state.classification
        state.va_version = __version__
    state.binary_versions = version_snapshot(collect_doctor())
    ensure_tree(state)
    set_file_log(path / "06-logs" / "va.log")
    write_operator_docs(state, force=existing is None)
    save_state(state)
    return state


def maybe_warn_check_metadata(state: EngagementState) -> None:
    if state.mode != Mode.CHECK:
        return
    missing: list[str] = []
    if not state.client or state.client.startswith("scan"):
        missing.append("client")
    if not state.testers:
        missing.append("testers")
    if not state.targets:
        missing.append("scope/targets")
    if missing:
        log.warn(
            "CHECK mode: engagement metadata is thin ("
            + ", ".join(missing)
            + "). Run va init and fill engagement.md / scope.md."
        )
