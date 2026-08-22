"""Mode and intensity profiles for Nmap and job scheduling."""

from __future__ import annotations

import re
from dataclasses import dataclass

from va_workspace.config.nse import nse_script_arg
from va_workspace.constants import (
    DEFAULT_INTENSITY,
    PROFILE_DELAY_SECONDS,
    PROFILE_HOST_TIMEOUT,
    PROFILE_MAX_RATE,
    PROFILE_MAX_RETRIES,
    PROFILE_MIN_RATE,
    PROFILE_WORKERS,
    SCRIPT_TIMEOUT,
    Intensity,
    Mode,
)


@dataclass(frozen=True)
class NmapProfile:
    intensity: Intensity
    tcp_ports: list[str]
    udp_top_ports: int | None
    timing: str
    version_intensity: int
    os_detect: bool
    workers: int
    delay_seconds: float
    nmap_timeout: int
    max_rate: int
    max_retries: int
    script_timeout: str
    min_rate: int | None = None
    host_timeout: str | None = None


def intensity_or_default(mode: Mode, intensity: Intensity | None) -> Intensity:
    if intensity is not None:
        return intensity
    return DEFAULT_INTENSITY[mode]


def nmap_profile(intensity: Intensity) -> NmapProfile:
    if intensity is Intensity.STEALTH:
        # Slow and quiet: opt in with --intensity stealth for fragile or monitored networks.
        return NmapProfile(
            intensity=intensity,
            tcp_ports=["--top-ports", "1000"],
            udp_top_ports=None,
            timing="-T2",
            version_intensity=2,
            os_detect=False,
            workers=PROFILE_WORKERS[intensity],
            delay_seconds=PROFILE_DELAY_SECONDS[intensity],
            nmap_timeout=6 * 60 * 60,
            max_rate=PROFILE_MAX_RATE[intensity],
            max_retries=PROFILE_MAX_RETRIES[intensity],
            script_timeout=SCRIPT_TIMEOUT,
            min_rate=PROFILE_MIN_RATE[intensity],
            host_timeout=PROFILE_HOST_TIMEOUT[intensity],
        )
    if intensity is Intensity.STANDARD:
        # Default: fast. Top 3000 TCP ports covers real services without paying for -p-.
        return NmapProfile(
            intensity=intensity,
            tcp_ports=["--top-ports", "3000"],
            udp_top_ports=20,
            timing="-T4",
            version_intensity=5,
            os_detect=True,
            workers=PROFILE_WORKERS[intensity],
            delay_seconds=PROFILE_DELAY_SECONDS[intensity],
            nmap_timeout=6 * 60 * 60,
            max_rate=PROFILE_MAX_RATE[intensity],
            max_retries=PROFILE_MAX_RETRIES[intensity],
            script_timeout=SCRIPT_TIMEOUT,
            min_rate=PROFILE_MIN_RATE[intensity],
            host_timeout=PROFILE_HOST_TIMEOUT[intensity],
        )
    return NmapProfile(
        intensity=intensity,
        tcp_ports=["-p-"],
        udp_top_ports=100,
        timing="-T4",
        version_intensity=7,
        os_detect=True,
        workers=PROFILE_WORKERS[intensity],
        delay_seconds=PROFILE_DELAY_SECONDS[intensity],
        nmap_timeout=12 * 60 * 60,
        max_rate=PROFILE_MAX_RATE[intensity],
        max_retries=PROFILE_MAX_RETRIES[intensity],
        script_timeout=SCRIPT_TIMEOUT,
        min_rate=PROFILE_MIN_RATE[intensity],
        host_timeout=PROFILE_HOST_TIMEOUT[intensity],
    )


# Operator nmap switches replace the profile's equivalents rather than stacking with them.
_EXACT_GROUPS: dict[str, frozenset[str]] = {
    "-F": frozenset({"ports"}),
    "--top-ports": frozenset({"ports"}),
    "--exclude-ports": frozenset({"ports"}),
    "--max-rate": frozenset({"rate"}),
    "--min-rate": frozenset({"rate"}),
    "--max-retries": frozenset({"retries"}),
    "-sV": frozenset({"version"}),
    "--version-intensity": frozenset({"version"}),
    "--version-all": frozenset({"version"}),
    "--version-light": frozenset({"version"}),
    "-O": frozenset({"os"}),
    "--osscan-guess": frozenset({"os"}),
    "--osscan-limit": frozenset({"os"}),
    "-sC": frozenset({"scripts"}),
    "--script": frozenset({"scripts"}),
    "--script-args": frozenset({"scripts"}),
    "--script-args-file": frozenset({"scripts"}),
    "--script-timeout": frozenset({"scripts"}),
    "--host-timeout": frozenset({"hosttimeout"}),
    "--scan-delay": frozenset({"delay"}),
    "--max-scan-delay": frozenset({"delay"}),
    "-A": frozenset({"version", "os", "scripts"}),
}
_SCAN_TYPES = frozenset({"-sS", "-sT", "-sA", "-sW", "-sM", "-sN", "-sF", "-sX", "-sY", "-sZ"})
_VALUE_FLAGS = frozenset(
    {
        "-p",
        "--top-ports",
        "--exclude-ports",
        "--max-rate",
        "--min-rate",
        "--max-retries",
        "--version-intensity",
        "--script",
        "--script-args",
        "--script-args-file",
        "--script-timeout",
        "--host-timeout",
        "--scan-delay",
        "--max-scan-delay",
    }
)
# We own the output files; the pipeline cannot parse results without them.
_PROTECTED_OUTPUT = frozenset({"-oA", "-oX", "-oN", "-oG", "-oS", "--resume", "--stylesheet"})
_TIMING = re.compile(r"^-T[0-5]$")


def _groups_for(token: str) -> frozenset[str]:
    if token in _EXACT_GROUPS:
        return _EXACT_GROUPS[token]
    if token in _SCAN_TYPES:
        return frozenset({"scantype"})
    if _TIMING.match(token):
        return frozenset({"timing"})
    if token.startswith("-P"):
        return frozenset({"discovery"})
    if token.startswith("-p"):
        return frozenset({"ports"})
    return frozenset()


def apply_overrides(base: list[str], extra: list[str]) -> tuple[list[str], list[str]]:
    """Merge operator nmap args into a profile argv, dropping the flags they replace."""
    notes: list[str] = []
    cleaned: list[str] = []
    skip_value = False
    for token in extra:
        if skip_value:
            skip_value = False
            continue
        if token in _PROTECTED_OUTPUT:
            notes.append(f"ignored {token}: va manages nmap output files")
            skip_value = token != "--resume"
            continue
        cleaned.append(token)

    touched: set[str] = set()
    for token in cleaned:
        touched |= _groups_for(token)
    if not touched:
        return [*base, *cleaned], notes

    merged: list[str] = []
    index = 0
    while index < len(base):
        token = base[index]
        if _groups_for(token) & touched:
            notes.append(f"override: profile {token} replaced by --nmap-args")
            index += 2 if token in _VALUE_FLAGS and index + 1 < len(base) else 1
            continue
        merged.append(token)
        index += 1
    return [*merged, *cleaned], notes


def is_privileged() -> bool:
    try:
        import os

        geteuid = getattr(os, "geteuid", None)
        if geteuid is None:
            return False
        return int(geteuid()) == 0
    except OSError:
        return False


def _scan_type(root: bool) -> tuple[str, list[str]]:
    if root:
        return "-sS", []
    return "-sT", ["not root: using TCP connect scan (-sT) instead of SYN (-sS)"]


def build_nmap_argv(
    *,
    nmap_path: str,
    output_stem: str,
    targets: list[str],
    excludes: list[str],
    intensity: Intensity,
    extra_args: list[str],
    privileged: bool | None = None,
    mode: Mode = Mode.LAB,
    include_scripts: bool = True,
    skip_os_detect: bool = False,
    skip_udp: bool = False,
) -> tuple[list[str], list[str]]:
    """Return (argv, notes describing privilege fallbacks). Combined TCP+UDP+NSE."""
    profile = nmap_profile(intensity)
    notes: list[str] = []
    root = is_privileged() if privileged is None else privileged
    scan, scan_notes = _scan_type(root)
    notes.extend(scan_notes)

    argv: list[str] = [
        nmap_path,
        scan,
        profile.timing,
        "-sV",
        "--version-intensity",
        str(profile.version_intensity),
        "--reason",
        "--stats-every",
        "30s",
        "--max-retries",
        str(profile.max_retries),
        "--max-rate",
        str(profile.max_rate),
    ]
    if profile.min_rate:
        argv.extend(["--min-rate", str(profile.min_rate)])
    if profile.host_timeout:
        argv.extend(["--host-timeout", profile.host_timeout])
    argv.extend(profile.tcp_ports)

    if profile.os_detect and not skip_os_detect:
        if root:
            argv.append("-O")
        else:
            notes.append("not root: skipping OS detection (-O)")

    if include_scripts:
        script_arg = nse_script_arg(mode, intensity)
        if script_arg:
            argv.extend(
                [
                    "--script",
                    script_arg,
                    "--script-timeout",
                    profile.script_timeout,
                ]
            )

    if profile.udp_top_ports and not skip_udp:
        if root:
            argv.extend(["-sU", "--top-ports", str(profile.udp_top_ports)])
        else:
            notes.append("not root: skipping UDP scan")

    if excludes:
        argv.extend(["--exclude", ",".join(excludes)])

    argv.extend(["-oA", output_stem])
    argv, override_notes = apply_overrides(argv, extra_args)
    notes.extend(override_notes)
    argv.extend(targets)
    return argv, notes


def build_discovery_argv(
    *,
    nmap_path: str,
    output_stem: str,
    targets: list[str],
    excludes: list[str],
    intensity: Intensity,
) -> list[str]:
    profile = nmap_profile(intensity)
    argv = [
        nmap_path,
        "-sn",
        profile.timing,
        "--reason",
        "--max-rate",
        str(profile.max_rate),
    ]
    if profile.min_rate:
        argv.extend(["--min-rate", str(profile.min_rate)])
    if profile.host_timeout:
        argv.extend(["--host-timeout", profile.host_timeout])
    argv.extend(["-oA", output_stem])
    if excludes:
        argv.extend(["--exclude", ",".join(excludes)])
    argv.extend(targets)
    return argv


def build_tcp_argv(
    *,
    nmap_path: str,
    output_stem: str,
    targets: list[str],
    excludes: list[str],
    intensity: Intensity,
    extra_args: list[str],
    privileged: bool | None = None,
) -> tuple[list[str], list[str]]:
    return build_nmap_argv(
        nmap_path=nmap_path,
        output_stem=output_stem,
        targets=targets,
        excludes=excludes,
        intensity=intensity,
        extra_args=extra_args,
        privileged=privileged,
        include_scripts=False,
        skip_udp=True,
    )


def build_udp_argv(
    *,
    nmap_path: str,
    output_stem: str,
    targets: list[str],
    excludes: list[str],
    intensity: Intensity,
    extra_args: list[str] | None = None,
    privileged: bool | None = None,
) -> tuple[list[str], list[str]]:
    profile = nmap_profile(intensity)
    notes: list[str] = []
    root = is_privileged() if privileged is None else privileged
    if not root:
        return [], ["not root: skipping UDP scan"]
    if not profile.udp_top_ports:
        return [], ["stealth: UDP scan off"]
    argv = [
        nmap_path,
        "-sU",
        "-sV",
        "--version-intensity",
        str(profile.version_intensity),
        profile.timing,
        "--top-ports",
        str(profile.udp_top_ports),
        "--reason",
        "--max-rate",
        str(profile.max_rate),
        "--max-retries",
        str(profile.max_retries),
    ]
    if profile.min_rate:
        argv.extend(["--min-rate", str(profile.min_rate)])
    if profile.host_timeout:
        argv.extend(["--host-timeout", profile.host_timeout])
    argv.extend(["-oA", output_stem])
    if excludes:
        argv.extend(["--exclude", ",".join(excludes)])
    argv, override_notes = apply_overrides(argv, extra_args or [])
    notes.extend(override_notes)
    argv.extend(targets)
    return argv, notes


def build_scripts_argv(
    *,
    nmap_path: str,
    output_stem: str,
    targets: list[str],
    excludes: list[str],
    intensity: Intensity,
    mode: Mode,
    ports: list[int],
    extra_args: list[str],
    privileged: bool | None = None,
) -> tuple[list[str], list[str]]:
    profile = nmap_profile(intensity)
    script_arg = nse_script_arg(mode, intensity)
    if not script_arg or not ports:
        return [], ["no NSE scripts or no open ports"]
    notes: list[str] = []
    root = is_privileged() if privileged is None else privileged
    scan, scan_notes = _scan_type(root)
    notes.extend(scan_notes)
    port_spec = ",".join(str(p) for p in sorted(set(ports)))
    argv = [
        nmap_path,
        scan,
        "-sV",
        profile.timing,
        "-p",
        port_spec,
        "--script",
        script_arg,
        "--script-timeout",
        profile.script_timeout,
        "--reason",
        "--max-rate",
        str(profile.max_rate),
    ]
    if profile.host_timeout:
        argv.extend(["--host-timeout", profile.host_timeout])
    argv.extend(["-oA", output_stem])
    if excludes:
        argv.extend(["--exclude", ",".join(excludes)])
    argv, override_notes = apply_overrides(argv, extra_args)
    notes.extend(override_notes)
    argv.extend(targets)
    return argv, notes
