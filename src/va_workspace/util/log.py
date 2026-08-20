"""Rich console logging plus optional engagement file log."""

from __future__ import annotations

from datetime import UTC
from pathlib import Path

from rich.console import Console

from va_workspace.constants import LEGAL_BANNER

console = Console(stderr=True)
stdout = Console()
_file_log: Path | None = None


def set_file_log(path: Path | None) -> None:
    global _file_log
    _file_log = path
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)


def _write_file(level: str, message: str) -> None:
    if _file_log is None:
        return
    from datetime import datetime

    stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    with _file_log.open("a", encoding="utf-8") as handle:
        handle.write(f"{stamp} [{level}] {message}\n")


def debug(message: str, *, verbose: bool = False) -> None:
    _write_file("DEBUG", message)
    if verbose:
        console.print(f"[dim]{message}[/dim]")


def info(message: str) -> None:
    _write_file("INFO", message)
    console.print(message)


def warn(message: str) -> None:
    _write_file("WARN", message)
    console.print(f"[yellow]{message}[/yellow]")


def error(message: str) -> None:
    _write_file("ERROR", message)
    console.print(f"[red]{message}[/red]")


def success(message: str) -> None:
    _write_file("INFO", message)
    console.print(f"[green]{message}[/green]")


def legal_banner() -> None:
    info(LEGAL_BANNER)
