"""Live progress reporting for long-running scans and enumeration jobs."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from va_workspace.util import log

# nmap --stats-every: "SYN Stealth Scan Timing: About 42.13% done; ETC: 14:03 (0:01:12 remaining)"
_PERCENT = re.compile(r"About\s+([0-9.]+)%\s+done")
_REMAINING = re.compile(r"\(([^)]*?)\s+remaining\)")
_NOISE = ("Starting Nmap", "Nmap scan report", "Host is up", "Read data files")


def _columns() -> list[TextColumn | BarColumn | SpinnerColumn | TaskProgressColumn]:
    return [
        SpinnerColumn(style="cyan"),
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=28),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        TextColumn("[dim]{task.fields[detail]}"),
    ]


def parse_percent(line: str) -> float | None:
    match = _PERCENT.search(line)
    return float(match.group(1)) if match else None


@contextmanager
def phase_progress(label: str, *, total: float = 100.0) -> Iterator[Callable[[str], None]]:
    """Yield a line consumer that drives a live spinner/bar for one scan phase.

    Falls back to periodic log lines when stderr is not a terminal (CI, piped output).
    """
    if not log.console.is_terminal:
        last = 0.0

        def plain(line: str) -> None:
            nonlocal last
            percent = parse_percent(line)
            if percent is not None and percent - last >= 5.0:
                last = percent
                log.info(f"{label}: {percent:.0f}%")

        log.info(f"{label}: running")
        yield plain
        log.info(f"{label}: done")
        return

    with Progress(*_columns(), console=log.console, transient=False) as progress:
        task = progress.add_task(label, total=total, detail="starting")

        def feed(line: str) -> None:
            text = line.strip()
            if not text or text.startswith(_NOISE):
                return
            percent = parse_percent(text)
            remaining = _REMAINING.search(text)
            detail = f"ETA {remaining.group(1)}" if remaining else text[:60]
            if percent is None:
                progress.update(task, detail=detail)
            else:
                progress.update(task, completed=percent, detail=detail)

        try:
            yield feed
        finally:
            progress.update(task, completed=total, detail="done")


@contextmanager
def job_progress(label: str, total: int) -> Iterator[Callable[[str], None]]:
    """Yield an advance callback (called once per finished unit) for N discrete jobs."""
    if not log.console.is_terminal:
        done = 0

        def plain(detail: str) -> None:
            nonlocal done
            done += 1
            log.info(f"{label}: {done}/{total} {detail}")

        yield plain
        return

    with Progress(*_columns(), console=log.console, transient=False) as progress:
        task = progress.add_task(label, total=float(total), detail="")

        def advance(detail: str) -> None:
            progress.update(task, advance=1, detail=detail[:60])

        yield advance
