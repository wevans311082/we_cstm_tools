"""Load and validate YAML tool mappings."""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml

from va_workspace.constants import FORBIDDEN_ARGV_PLACEHOLDERS, USER_CONFIG_DIRNAME, Intensity


@dataclass
class ToolMatch:
    ports: list[int] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    tunnel_ssl: bool = False
    http_only: bool = False


@dataclass
class ToolMapping:
    id: str
    binary: str
    match: ToolMatch
    min_intensity: Intensity
    timeout_seconds: int = 300
    output: str = "services"
    argv: dict[str, list[str]] = field(default_factory=dict)
    wordlist_kind: str | None = None
    install_hint: str = ""


def user_config_dir() -> Path:
    return Path.home() / ".config" / USER_CONFIG_DIRNAME


def packaged_mappings_path() -> Path:
    return Path(str(files("va_workspace.config").joinpath("tool_mappings.yaml")))


def _require_no_secrets(argv: list[str], tool_id: str) -> None:
    joined = " ".join(argv).lower()
    for token in FORBIDDEN_ARGV_PLACEHOLDERS:
        if token in joined:
            raise ValueError(
                f"tool {tool_id} argv contains forbidden placeholder {token}; "
                "authenticated scanning is not supported in v1"
            )


def _parse_mapping(raw: dict[str, Any]) -> ToolMapping:
    tool_id = str(raw["id"])
    match_raw = raw.get("match") or {}
    argv_raw = raw.get("argv") or {}
    argv: dict[str, list[str]] = {}
    for intensity in Intensity:
        items = argv_raw.get(str(intensity), [])
        if items is None:
            items = []
        if not isinstance(items, list) or not all(isinstance(i, str) for i in items):
            raise ValueError(f"tool {tool_id} argv.{intensity} must be a list of strings")
        _require_no_secrets(items, tool_id)
        argv[str(intensity)] = list(items)
    protocols = [str(p).lower() for p in match_raw.get("protocols", [])]
    return ToolMapping(
        id=tool_id,
        binary=str(raw["binary"]),
        match=ToolMatch(
            ports=[int(p) for p in match_raw.get("ports", [])],
            services=[str(s).lower() for s in match_raw.get("services", [])],
            protocols=protocols,
            tunnel_ssl=bool(match_raw.get("tunnel_ssl", False)),
            http_only=bool(match_raw.get("http_only", False)),
        ),
        min_intensity=Intensity(str(raw.get("min_intensity", Intensity.STEALTH))),
        timeout_seconds=int(raw.get("timeout_seconds", 300)),
        output=str(raw.get("output", "services")),
        argv=argv,
        wordlist_kind=raw.get("wordlist_kind"),
        install_hint=str(raw.get("install_hint", "")),
    )


def _index_by_id(tools: list[ToolMapping]) -> dict[str, ToolMapping]:
    return {tool.id: tool for tool in tools}


def load_tool_mappings(override: Path | None = None) -> list[ToolMapping]:
    packaged = packaged_mappings_path().read_text(encoding="utf-8")
    data = yaml.safe_load(packaged) or {}
    tools = [_parse_mapping(item) for item in data.get("tools", [])]
    by_id = _index_by_id(tools)

    path = override if override is not None else user_config_dir() / "tool_mappings.yaml"
    if path.is_file():
        extra = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for item in extra.get("tools", []):
            parsed = _parse_mapping(item)
            by_id[parsed.id] = parsed
    return list(by_id.values())
