"""Shared constants and enumerations."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

APP_NAME = "va-workspace"
CLI_NAME = "va"
DEFAULT_VAULT_ROOT = "va-engagements"
USER_CONFIG_DIRNAME = "va-workspace"
MANAGED_HEADER = "<!-- va:managed -->"
MARKDOWN_EMBED_LIMIT = 512 * 1024
LEGAL_BANNER = (
    "AUTHORISED USE ONLY. va-workspace is an operator aid for scoped, authorised "
    "vulnerability assessment (including CHECK ITHCs). You are responsible for Rules "
    "of Engagement, scope, and applicable law. This tool is not NCSC-endorsed."
)

REQUIRED_BINARIES: tuple[str, ...] = ("nmap",)

INSTALL_HINTS: dict[str, str] = {
    "nmap": "sudo apt install nmap",
    "whatweb": "sudo apt install whatweb",
    "sslscan": "sudo apt install sslscan",
    "feroxbuster": "sudo apt install feroxbuster",
    "gowitness": "sudo apt install gowitness",
    "netexec": "pipx install netexec",
    "nxc": "pipx install netexec",
    "onesixtyone": "sudo apt install onesixtyone",
    "snmpwalk": "sudo apt install snmp",
    "searchsploit": "sudo apt install exploitdb",
}

SECLISTS_WEB_SMALL: tuple[Path, ...] = (
    Path("/usr/share/seclists/Discovery/Web-Content/common.txt"),
    Path("/usr/share/wordlists/dirb/common.txt"),
    Path("/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"),
)
SECLISTS_WEB_LOUD: tuple[Path, ...] = (
    Path("/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"),
    Path("/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"),
    Path("/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"),
)
SNMP_COMMUNITY_LISTS: tuple[Path, ...] = (
    Path("/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt"),
    Path("/usr/share/wordlists/metasploit/snmp_default_pass.txt"),
)

FORBIDDEN_ARGV_PLACEHOLDERS: tuple[str, ...] = ("{user}", "{password}", "{pass}", "{creds}")


class Mode(StrEnum):
    CHECK = "check"
    LAB = "lab"
    INTERNAL = "internal"


class Intensity(StrEnum):
    STEALTH = "stealth"
    STANDARD = "standard"
    LOUD = "loud"


class JobStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    FAILED = "failed"
    COMPLETE = "complete"
    SKIPPED = "skipped"


class FindingStatus(StrEnum):
    DRAFT = "draft"
    CONFIRMED = "confirmed"
    RETEST = "retest"
    CLOSED = "closed"


class NmapPhase(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


DEFAULT_INTENSITY: dict[Mode, Intensity] = {
    Mode.CHECK: Intensity.STEALTH,
    Mode.LAB: Intensity.STANDARD,
    Mode.INTERNAL: Intensity.STANDARD,
}

PROFILE_WORKERS: dict[Intensity, int] = {
    Intensity.STEALTH: 2,
    Intensity.STANDARD: 4,
    Intensity.LOUD: 8,
}

PROFILE_DELAY_SECONDS: dict[Intensity, float] = {
    Intensity.STEALTH: 1.0,
    Intensity.STANDARD: 0.2,
    Intensity.LOUD: 0.0,
}
