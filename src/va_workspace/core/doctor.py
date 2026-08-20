"""Environment checks for Kali binaries and plugin YAML."""

from __future__ import annotations

from dataclasses import dataclass

from va_workspace.config.load import ToolMapping, load_tool_mappings
from va_workspace.constants import (
    INSTALL_HINTS,
    REQUIRED_BINARIES,
    SECLISTS_WEB_LOUD,
    SECLISTS_WEB_SMALL,
    SNMP_COMMUNITY_LISTS,
)
from va_workspace.core.plugins import first_existing
from va_workspace.util.shell import binary_version, which


@dataclass
class BinaryCheck:
    name: str
    required: bool
    present: bool
    version: str
    hint: str


@dataclass
class DoctorReport:
    checks: list[BinaryCheck]
    wordlists: dict[str, str]
    mapping_count: int
    mapping_error: str = ""

    @property
    def required_missing(self) -> list[BinaryCheck]:
        return [c for c in self.checks if c.required and not c.present]


def collect_doctor() -> DoctorReport:
    mapping_error = ""
    tools: list[ToolMapping] = []
    try:
        tools = load_tool_mappings()
    except (OSError, ValueError) as exc:
        mapping_error = str(exc)

    names: list[tuple[str, bool]] = [(name, True) for name in REQUIRED_BINARIES]
    seen = {name for name, _ in names}
    for tool in tools:
        if tool.python_module:
            continue
        if tool.binary not in seen:
            names.append((tool.binary, False))
            seen.add(tool.binary)
    if "searchsploit" not in seen:
        names.append(("searchsploit", False))

    checks: list[BinaryCheck] = []
    for name, required in names:
        path = which(name)
        hint = INSTALL_HINTS.get(name, "")
        for tool in tools:
            if tool.binary == name and tool.install_hint:
                hint = tool.install_hint
                break
        checks.append(
            BinaryCheck(
                name=name,
                required=required,
                present=path is not None,
                version=binary_version(name) if path else "missing",
                hint=hint,
            )
        )

    wordlists = {
        "web_small": str(first_existing(SECLISTS_WEB_SMALL) or "missing (apt install seclists)"),
        "web_loud": str(first_existing(SECLISTS_WEB_LOUD) or "missing (apt install seclists)"),
        "snmp": str(first_existing(SNMP_COMMUNITY_LISTS) or "missing (apt install seclists)"),
    }
    return DoctorReport(
        checks=checks,
        wordlists=wordlists,
        mapping_count=len(tools),
        mapping_error=mapping_error,
    )


def version_snapshot(report: DoctorReport) -> dict[str, str]:
    return {check.name: check.version for check in report.checks if check.present}
