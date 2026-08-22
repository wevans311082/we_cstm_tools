"""Load named NSE packs and resolve custom va-*.nse Lua plus stock names."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from importlib.resources import files
from pathlib import Path

import yaml

from va_workspace.constants import Intensity, Mode

# Nmap aborts the whole script engine if any one --script name is unknown, so we
# check names against the local script.db before handing the list over.
_SCRIPT_DB_CANDIDATES: tuple[Path, ...] = (
    Path("/usr/share/nmap/scripts/script.db"),
    Path("/usr/local/share/nmap/scripts/script.db"),
    Path("/opt/homebrew/share/nmap/scripts/script.db"),
    Path("/opt/local/share/nmap/scripts/script.db"),
    Path(r"C:\Program Files (x86)\Nmap\scripts\script.db"),
    Path(r"C:\Program Files\Nmap\scripts\script.db"),
)
_DB_ENTRY = re.compile(r'filename\s*=\s*"([^"]+?)\.nse"')
# Categories and wildcards are resolved by nmap itself, not by script.db lookup.
_CATEGORIES = frozenset(
    {
        "all",
        "auth",
        "broadcast",
        "brute",
        "default",
        "discovery",
        "dos",
        "exploit",
        "external",
        "fuzzer",
        "intrusive",
        "malware",
        "safe",
        "version",
        "vuln",
    }
)


def script_db_path() -> Path | None:
    env = os.environ.get("NMAPDIR")
    if env:
        candidate = Path(env) / "scripts" / "script.db"
        if candidate.is_file():
            return candidate
    for candidate in _SCRIPT_DB_CANDIDATES:
        if candidate.is_file():
            return candidate
    return None


@lru_cache(maxsize=1)
def installed_stock_scripts() -> frozenset[str]:
    """Script names this machine's nmap actually has. Empty when script.db is missing."""
    path = script_db_path()
    if path is None:
        return frozenset()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return frozenset()
    return frozenset(_DB_ENTRY.findall(text))


def _is_known(name: str) -> bool:
    installed = installed_stock_scripts()
    if not installed:
        return True
    if name in _CATEGORIES or "*" in name:
        return True
    return name in installed


def _pack_data() -> dict[str, list[str]]:
    raw = files("va_workspace.config").joinpath("nse_packs.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(raw) or {}
    return {str(key): [str(item) for item in (data.get(key) or [])] for key in data}


def packaged_nse_dir() -> Path:
    return Path(str(files("va_workspace").joinpath("nse")))


def list_custom_nse() -> list[Path]:
    directory = packaged_nse_dir()
    if not directory.is_dir():
        return []
    return sorted(directory.glob("va-*.nse"))


def custom_nse_names(mode: Mode, intensity: Intensity) -> list[str]:
    packs = _pack_data()
    ordered: list[str] = []
    seen: set[str] = set()

    def _add(names: list[str]) -> None:
        for name in names:
            if name not in seen:
                seen.add(name)
                ordered.append(name)

    _add(packs.get("custom_stealth", []))
    if intensity in {Intensity.STANDARD, Intensity.LOUD}:
        _add(packs.get("custom_standard", []))
    if intensity is Intensity.LOUD:
        _add(packs.get("custom_loud", []))
    return ordered


def custom_nse_paths(mode: Mode, intensity: Intensity) -> list[str]:
    directory = packaged_nse_dir()
    paths: list[str] = []
    for name in custom_nse_names(mode, intensity):
        candidate = directory / f"{name}.nse"
        if candidate.is_file():
            paths.append(str(candidate.resolve()))
    return paths


def nse_scripts(mode: Mode, intensity: Intensity) -> list[str]:
    """Stock Nmap script names (not filesystem paths)."""
    packs = _pack_data()
    ordered: list[str] = []
    seen: set[str] = set()

    def _add(names: list[str]) -> None:
        for name in names:
            if name not in seen:
                seen.add(name)
                ordered.append(name)

    _add(packs.get("stealth", []))
    if intensity in {Intensity.STANDARD, Intensity.LOUD}:
        _add(packs.get("standard", []))
    if intensity is Intensity.LOUD:
        _add(packs.get("loud", []))
        if mode in {Mode.LAB, Mode.INTERNAL}:
            _add(packs.get("lab_loud_extra", []))
    if mode is Mode.CHECK:
        banned = set(packs.get("never_check", []))
        return [name for name in ordered if name not in banned]
    return ordered


@dataclass
class NseSelection:
    custom: list[str] = field(default_factory=list)
    stock: list[str] = field(default_factory=list)
    dropped: list[str] = field(default_factory=list)
    missing_custom: list[str] = field(default_factory=list)

    @property
    def arg(self) -> str:
        return ",".join([*self.custom, *self.stock])

    def notes(self) -> list[str]:
        out: list[str] = []
        if self.dropped:
            out.append(
                f"NSE: skipped {len(self.dropped)} script(s) this nmap does not have: "
                + ", ".join(sorted(self.dropped))
            )
        if self.missing_custom:
            out.append("NSE: missing packaged Lua: " + ", ".join(sorted(self.missing_custom)))
        return out


def nse_selection(mode: Mode, intensity: Intensity) -> NseSelection:
    """Resolve the script list, dropping stock names the local nmap cannot resolve."""
    selection = NseSelection()
    directory = packaged_nse_dir()
    for name in custom_nse_names(mode, intensity):
        candidate = directory / f"{name}.nse"
        if candidate.is_file():
            selection.custom.append(str(candidate.resolve()))
        else:
            selection.missing_custom.append(name)
    for name in nse_scripts(mode, intensity):
        if _is_known(name):
            selection.stock.append(name)
        else:
            selection.dropped.append(name)
    return selection


def nse_script_arg(mode: Mode, intensity: Intensity) -> str:
    return nse_selection(mode, intensity).arg


def unknown_stock_scripts() -> list[str]:
    """Every stock name in the packs that this machine's nmap does not provide."""
    packs = _pack_data()
    names: set[str] = set()
    for key in ("stealth", "standard", "loud", "lab_loud_extra", "never_check"):
        names.update(packs.get(key, []))
    return sorted(name for name in names if not _is_known(name))
