"""Atomic engagement state.json load/save."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from va_workspace.models import EngagementState

STATE_FILENAME = "state.json"


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def state_path(engagement_dir: Path) -> Path:
    return engagement_dir / STATE_FILENAME


def load_state(engagement_dir: Path) -> EngagementState:
    path = state_path(engagement_dir)
    data = json.loads(path.read_text(encoding="utf-8"))
    state = EngagementState.from_dict(data)
    state.path = engagement_dir
    return state


def save_state(state: EngagementState) -> None:
    state.updated = utc_now()
    path = state_path(state.path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state.to_dict(), indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def try_load_state(engagement_dir: Path) -> EngagementState | None:
    path = state_path(engagement_dir)
    if not path.is_file():
        return None
    return load_state(engagement_dir)
