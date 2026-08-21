from __future__ import annotations

from pathlib import Path

from va_workspace.constants import JobStatus
from va_workspace.core.orchestrator import merge_jobs
from va_workspace.models import EngagementState, Job


def _job(job_id: str, status: JobStatus = JobStatus.PENDING) -> Job:
    j = Job(id=job_id, tool_id="whatweb", host="10.0.0.1", port=80)
    j.status = status
    return j


def test_merge_jobs_appends_new(tmp_path: Path) -> None:
    state = EngagementState(path=tmp_path)
    state.jobs = [_job("a"), _job("b")]
    new_jobs = [_job("b"), _job("c")]
    merge_jobs(state, new_jobs)
    ids = [j.id for j in state.jobs]
    assert ids.count("b") == 1  # no duplicate
    assert "c" in ids  # new job appended


def test_merge_jobs_interrupted_becomes_failed(tmp_path: Path) -> None:
    state = EngagementState(path=tmp_path)
    state.jobs = [_job("x", JobStatus.RUNNING)]
    merge_jobs(state, [_job("x")])
    job = next(j for j in state.jobs if j.id == "x")
    assert job.status == JobStatus.FAILED


def test_merge_jobs_complete_job_unchanged(tmp_path: Path) -> None:
    state = EngagementState(path=tmp_path)
    state.jobs = [_job("done", JobStatus.COMPLETE)]
    merge_jobs(state, [_job("done")])
    job = next(j for j in state.jobs if j.id == "done")
    # A completed job is not touched by merge
    assert job.status == JobStatus.COMPLETE
