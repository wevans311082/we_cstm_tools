"""Resume-aware, bounded secondary-tool dispatcher."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import yaml

from va_workspace.config.load import ToolMapping
from va_workspace.config.profiles import nmap_profile
from va_workspace.constants import (
    MARKDOWN_EMBED_LIMIT,
    SECLISTS_WEB_LOUD,
    SECLISTS_WEB_SMALL,
    SNMP_COMMUNITY_LISTS,
    Intensity,
    JobStatus,
)
from va_workspace.core.plugins import (
    PluginError,
    first_existing,
    interpolate_argv,
    plan_jobs,
    port_matches,
    url_for,
)
from va_workspace.core.state import save_state
from va_workspace.core.vault import host_dir
from va_workspace.models import EngagementState, Host, Job, Port
from va_workspace.util import log
from va_workspace.util.progress import job_progress
from va_workspace.util.scope import url_in_scope
from va_workspace.util.shell import run_command, which


def snapshot_mappings(state: EngagementState, tools: list[ToolMapping]) -> None:
    payload = {
        "mode": str(state.mode),
        "intensity": str(state.intensity),
        "tools": [tool.id for tool in tools],
    }
    dest = state.path / "run-config.snapshot.yaml"
    dest.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def merge_jobs(state: EngagementState, planned: list[Job]) -> None:
    existing = {job.id: job for job in state.jobs}
    for job in planned:
        if job.id not in existing:
            state.jobs.append(job)
        elif existing[job.id].status == JobStatus.RUNNING:
            existing[job.id].status = JobStatus.FAILED
            existing[job.id].skip_reason = "interrupted (will retry once)"


def _tool_by_id(tools: list[ToolMapping], tool_id: str) -> ToolMapping | None:
    for tool in tools:
        if tool.id == tool_id:
            return tool
    return None


def _port(host: Host, number: int, protocol: str) -> Port | None:
    for port in host.ports:
        if port.number == number and port.protocol == protocol:
            return port
    return None


def _outfile(state: EngagementState, host: Host, tool: ToolMapping, port: Port) -> Path:
    folder = host_dir(state, host) / tool.output
    folder.mkdir(parents=True, exist_ok=True)
    raw_dir = state.path / "05-raw" / "tools" / tool.id / host.slug
    raw_dir.mkdir(parents=True, exist_ok=True)
    if tool.id == "gowitness":
        return folder
    return raw_dir / f"{port.protocol}-{port.number}.txt"


def _truncate(text: str) -> str:
    if len(text.encode("utf-8")) <= MARKDOWN_EMBED_LIMIT:
        return text
    encoded = text.encode("utf-8")[:MARKDOWN_EMBED_LIMIT]
    return encoded.decode("utf-8", errors="ignore") + "\n\n_truncated; full output in 05-raw/_\n"


def _run_one(
    state: EngagementState,
    job: Job,
    tools: list[ToolMapping],
    intensity: Intensity,
) -> Job:
    tool = _tool_by_id(tools, job.tool_id)
    host = state.host_by_ip(job.host)
    if tool is None or host is None or job.port is None:
        job.status = JobStatus.SKIPPED
        job.skip_reason = "missing tool or host"
        return job
    port = _port(host, job.port, job.protocol)
    if port is None or not port_matches(tool, port):
        job.status = JobStatus.SKIPPED
        job.skip_reason = "port no longer matches"
        return job
    import sys

    if tool.python_module:
        binary_path = sys.executable
    else:
        found = which(tool.binary)
        if found is None:
            job.status = JobStatus.SKIPPED
            job.skip_reason = f"{tool.binary} not on PATH"
            hint = f" ({tool.install_hint})" if tool.install_hint else ""
            log.warn(f"{tool.id}: {job.skip_reason}{hint}")
            return job
        binary_path = str(found)

    wordlist = None
    wordlist_loud = None
    if tool.wordlist_kind == "web":
        wordlist = first_existing(SECLISTS_WEB_SMALL)
        wordlist_loud = first_existing(SECLISTS_WEB_LOUD)
    elif tool.wordlist_kind == "snmp":
        wordlist = first_existing(SNMP_COMMUNITY_LISTS)
        wordlist_loud = wordlist
    elif tool.wordlist_kind:
        wordlist = first_existing(SNMP_COMMUNITY_LISTS)
    if tool.wordlist_kind and wordlist is None:
        job.status = JobStatus.SKIPPED
        job.skip_reason = f"wordlist missing for {tool.id}"
        log.warn(job.skip_reason + " — install seclists")
        return job

    template = tool.argv.get(str(intensity), [])
    outfile = _outfile(state, host, tool, port)
    try:
        extra = interpolate_argv(
            template,
            host=host,
            port=port,
            outfile=outfile,
            wordlist=wordlist,
            wordlist_loud=wordlist_loud,
        )
        if tool.python_module:
            argv = [binary_path, "-m", tool.python_module, *extra]
        else:
            argv = [binary_path, *extra]
    except PluginError as exc:
        job.status = JobStatus.SKIPPED
        job.skip_reason = str(exc)
        return job

    if tool.match.http_only:
        url = url_for(host, port)
        if not url_in_scope(url, state.targets, state.excludes):
            job.status = JobStatus.SKIPPED
            job.skip_reason = "url off-scope"
            return job

    log.info(f"job {job.id}: {' '.join(argv)}")
    result = run_command(argv, timeout=tool.timeout_seconds)
    raw_name = f"{port.protocol}-{port.number}.txt"
    raw_path = state.path / "05-raw" / "tools" / tool.id / host.slug / raw_name
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_body = result.stdout + (("\n" + result.stderr) if result.stderr else "")
    raw_path.write_text(raw_body, encoding="utf-8", errors="replace")
    note = host_dir(state, host) / tool.output / f"{tool.id}-{port.protocol}{port.number}.md"
    note.parent.mkdir(parents=True, exist_ok=True)
    note.write_text(
        "\n".join(
            [
                "<!-- va:managed -->",
                f"# {tool.id} — {host.ip}:{port.number}",
                "",
                f"`{' '.join(argv)}`",
                "",
                "```",
                _truncate(raw_body or result.error or "_no output_"),
                "```",
                "",
            ]
        ),
        encoding="utf-8",
    )
    job.paths = [str(raw_path), str(note)]
    if result.timed_out:
        job.status = JobStatus.FAILED
        job.skip_reason = result.error
    elif result.returncode != 0 and not raw_body:
        job.status = JobStatus.FAILED
        job.skip_reason = result.error or f"exit {result.returncode}"
    else:
        job.status = JobStatus.COMPLETE
    return job


def run_jobs(state: EngagementState, tools: list[ToolMapping]) -> None:
    intensity = Intensity(state.intensity)
    planned = plan_jobs(
        hosts=state.hosts,
        tools=tools,
        intensity=intensity,
        targets=state.targets,
        excludes=state.excludes,
    )
    merge_jobs(state, planned)
    snapshot_mappings(state, tools)
    save_state(state)

    pending = [
        job
        for job in state.jobs
        if job.status in {JobStatus.PENDING, JobStatus.FAILED}
    ]
    if not pending:
        log.info("no secondary jobs to run")
        return

    profile = nmap_profile(intensity)
    log.info(f"running {len(pending)} secondary jobs with {profile.workers} workers")

    def _wrapped(job: Job) -> Job:
        if job.status == JobStatus.FAILED:
            if job.retries >= 1:
                job.status = JobStatus.SKIPPED
                job.skip_reason = "failed after retry"
                return job
            job.retries += 1
        if profile.delay_seconds:
            time.sleep(profile.delay_seconds)
        job.status = JobStatus.RUNNING
        return _run_one(state, job, tools, intensity)

    lock = threading.Lock()
    failed = 0
    with (
        job_progress("secondary enum", len(pending)) as advance,
        ThreadPoolExecutor(max_workers=profile.workers) as pool,
    ):
        futures = {pool.submit(_wrapped, job): job for job in pending}
        for future in as_completed(futures):
            finished = future.result()
            with lock:
                for idx, job in enumerate(state.jobs):
                    if job.id == finished.id:
                        state.jobs[idx] = finished
                        break
                save_state(state)
                if finished.status == JobStatus.FAILED:
                    failed += 1
                advance(f"{finished.tool_id} {finished.host} [{finished.status}]")
    if failed:
        log.warn(f"secondary enum: {failed} job(s) failed (see 05-raw/tools)")
    log.success(f"secondary enum: {len(pending) - failed}/{len(pending)} job(s) ok")
