from __future__ import annotations

from pathlib import Path

from va_workspace.constants import Intensity, JobStatus, Mode
from va_workspace.core.state import load_state, save_state
from va_workspace.models import EngagementState, Job


def test_roundtrip(tmp_path: Path) -> None:
    state = EngagementState(
        path=tmp_path,
        client="acme",
        mode=Mode.CHECK,
        intensity=Intensity.STEALTH,
        targets=["10.0.0.0/24"],
        jobs=[
            Job(
                id="whatweb:10.0.0.1:tcp:80",
                tool_id="whatweb",
                host="10.0.0.1",
                port=80,
                status=JobStatus.COMPLETE,
            )
        ],
    )
    save_state(state)
    loaded = load_state(tmp_path)
    assert loaded.client == "acme"
    assert loaded.mode is Mode.CHECK
    assert loaded.jobs[0].status is JobStatus.COMPLETE
    assert loaded.targets == ["10.0.0.0/24"]
