"""Packaged CSTM/CHECK operator notes (from ca_misc_scripts/docs/cstm)."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path


def notes_dir() -> Path:
    return Path(str(files("va_workspace").joinpath("notes")))


def list_notes() -> list[Path]:
    directory = notes_dir()
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.glob("*.md") if p.name != "README.md")


def read_note(name: str) -> Path:
    directory = notes_dir()
    direct = directory / name
    if direct.is_file():
        return direct
    if not name.endswith(".md"):
        matches = list(directory.glob(f"*{name}*.md"))
        if len(matches) == 1:
            return matches[0]
        if matches:
            raise FileNotFoundError(
                "ambiguous note name; matches: " + ", ".join(p.name for p in matches)
            )
    raise FileNotFoundError(f"no note matching {name!r} in {directory}")
