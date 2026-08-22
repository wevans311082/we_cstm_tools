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
    "enum4linux-ng": "sudo apt install enum4linux-ng",
    "ldapsearch": "sudo apt install ldap-utils",
    "testssl.sh": "sudo apt install testssl.sh",
    "ike-scan": "sudo apt install ike-scan",
    "maim": "sudo apt install maim xclip",
    "grim": "sudo apt install grim slurp wl-clipboard",
    "xclip": "sudo apt install xclip",
    "notify-send": "sudo apt install libnotify-bin",
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
    Mode.CHECK: Intensity.STANDARD,
    Mode.LAB: Intensity.STANDARD,
    Mode.INTERNAL: Intensity.STANDARD,
}

PROFILE_WORKERS: dict[Intensity, int] = {
    Intensity.STEALTH: 2,
    Intensity.STANDARD: 8,
    Intensity.LOUD: 16,
}

PROFILE_DELAY_SECONDS: dict[Intensity, float] = {
    Intensity.STEALTH: 1.0,
    Intensity.STANDARD: 0.0,
    Intensity.LOUD: 0.0,
}

PROFILE_MAX_RATE: dict[Intensity, int] = {
    Intensity.STEALTH: 300,
    Intensity.STANDARD: 5000,
    Intensity.LOUD: 20000,
}

# --min-rate is the single biggest nmap speed lever; stealth deliberately has none.
PROFILE_MIN_RATE: dict[Intensity, int | None] = {
    Intensity.STEALTH: None,
    Intensity.STANDARD: 1000,
    Intensity.LOUD: 5000,
}

PROFILE_MAX_RETRIES: dict[Intensity, int] = {
    Intensity.STEALTH: 2,
    Intensity.STANDARD: 1,
    Intensity.LOUD: 1,
}

# Stops one unresponsive host stalling the whole phase.
PROFILE_HOST_TIMEOUT: dict[Intensity, str | None] = {
    Intensity.STEALTH: None,
    Intensity.STANDARD: "15m",
    Intensity.LOUD: "20m",
}

SCRIPT_TIMEOUT = "30s"

INTERESTING_PORTS: frozenset[int] = frozenset(
    {
        21,
        23,
        25,
        53,
        69,
        88,
        111,
        135,
        137,
        139,
        161,
        389,
        445,
        500,
        502,
        623,
        1433,
        1521,
        1723,
        2049,
        2375,
        3306,
        3389,
        4786,
        5432,
        5555,
        5601,
        5672,
        5900,
        5985,
        6379,
        6443,
        8009,
        8291,
        8443,
        9200,
        10250,
        11211,
        27017,
        50070,
    }
)
