"""Load named NSE packs and resolve scripts for mode + intensity."""

from __future__ import annotations

from importlib.resources import files

import yaml

from va_workspace.constants import Intensity, Mode


def _pack_data() -> dict[str, list[str]]:
    raw = files("va_workspace.config").joinpath("nse_packs.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(raw) or {}
    return {str(key): [str(item) for item in (data.get(key) or [])] for key in data}


def nse_scripts(mode: Mode, intensity: Intensity) -> list[str]:
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


def nse_script_arg(scripts: list[str]) -> str:
    return ",".join(scripts)
