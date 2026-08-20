"""Load named NSE packs and resolve custom va-*.nse Lua plus stock names."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

import yaml

from va_workspace.constants import Intensity, Mode


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


def nse_script_arg(mode: Mode, intensity: Intensity) -> str:
    custom = custom_nse_paths(mode, intensity)
    stock = nse_scripts(mode, intensity)
    return ",".join([*custom, *stock])
