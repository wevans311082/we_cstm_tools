"""Mode and intensity profiles for Nmap and job scheduling."""

from __future__ import annotations

from dataclasses import dataclass

from va_workspace.constants import (
    DEFAULT_INTENSITY,
    PROFILE_DELAY_SECONDS,
    PROFILE_WORKERS,
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
    default_scripts: bool
    workers: int
    delay_seconds: float
    nmap_timeout: int


def intensity_or_default(mode: Mode, intensity: Intensity | None) -> Intensity:
    if intensity is not None:
        return intensity
    return DEFAULT_INTENSITY[mode]


def nmap_profile(intensity: Intensity) -> NmapProfile:
    if intensity is Intensity.STEALTH:
        return NmapProfile(
            intensity=intensity,
            tcp_ports=["--top-ports", "1000"],
            udp_top_ports=None,
            timing="-T2",
            version_intensity=2,
            os_detect=False,
            default_scripts=False,
            workers=PROFILE_WORKERS[intensity],
            delay_seconds=PROFILE_DELAY_SECONDS[intensity],
            nmap_timeout=6 * 60 * 60,
        )
    if intensity is Intensity.STANDARD:
        return NmapProfile(
            intensity=intensity,
            tcp_ports=["-p-"],
            udp_top_ports=20,
            timing="-T3",
            version_intensity=7,
            os_detect=True,
            default_scripts=True,
            workers=PROFILE_WORKERS[intensity],
            delay_seconds=PROFILE_DELAY_SECONDS[intensity],
            nmap_timeout=12 * 60 * 60,
        )
    return NmapProfile(
        intensity=intensity,
        tcp_ports=["-p-"],
        udp_top_ports=100,
        timing="-T4",
        version_intensity=9,
        os_detect=True,
        default_scripts=True,
        workers=PROFILE_WORKERS[intensity],
        delay_seconds=PROFILE_DELAY_SECONDS[intensity],
        nmap_timeout=12 * 60 * 60,
    )


def is_privileged() -> bool:
    try:
        import os

        geteuid = getattr(os, "geteuid", None)
        if geteuid is None:
            return False
        return int(geteuid()) == 0
    except OSError:
        return False


def build_nmap_argv(
    *,
    nmap_path: str,
    output_stem: str,
    targets: list[str],
    excludes: list[str],
    intensity: Intensity,
    extra_args: list[str],
    privileged: bool | None = None,
) -> tuple[list[str], list[str]]:
    """Return (argv, notes describing privilege fallbacks)."""
    profile = nmap_profile(intensity)
    notes: list[str] = []
    root = is_privileged() if privileged is None else privileged

    argv: list[str] = [nmap_path]
    if root:
        argv.append("-sS")
    else:
        argv.append("-sT")
        notes.append("not root: using TCP connect scan (-sT) instead of SYN (-sS)")

    argv.extend([profile.timing, "-sV", "--version-intensity", str(profile.version_intensity)])
    argv.extend(profile.tcp_ports)

    if profile.os_detect:
        if root:
            argv.append("-O")
        else:
            notes.append("not root: skipping OS detection (-O)")

    if profile.default_scripts:
        argv.extend(["--script", "default"])

    if profile.udp_top_ports:
        if root:
            argv.extend(["-sU", "--top-ports", str(profile.udp_top_ports)])
        else:
            notes.append("not root: skipping UDP scan")

    if excludes:
        argv.extend(["--exclude", ",".join(excludes)])

    argv.extend(["-oA", output_stem])
    argv.extend(extra_args)
    argv.extend(targets)
    return argv, notes
