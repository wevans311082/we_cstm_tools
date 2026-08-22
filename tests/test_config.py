from __future__ import annotations

from pathlib import Path

import pytest

from va_workspace.config.load import load_tool_mappings
from va_workspace.config.profiles import build_nmap_argv, intensity_or_default, nmap_profile
from va_workspace.constants import Intensity, Mode


def test_packaged_mappings_load() -> None:
    tools = load_tool_mappings()
    ids = {t.id for t in tools}
    assert {
        "whatweb",
        "sslscan",
        "feroxbuster",
        "gowitness",
        "netexec-smb",
        "netexec-ldap",
        "netexec-winrm",
        "onesixtyone",
        "snmpwalk",
        "enum4linux-ng",
        "ldapsearch",
        "testssl",
        "ike-scan",
        "netexec-ms17",
        "py-smb-unauth",
        "py-tls-versions",
        "py-vpn-portals",
        "py-ldap-anon",
        "py-http-intel",
        "py-postgres",
        "py-oracle-tns",
    } <= ids
    smb = next(t for t in tools if t.id == "py-smb-unauth")
    assert smb.python_module == "va_workspace.tools.smb_unauth"
    ferox = next(t for t in tools if t.id == "feroxbuster")
    assert ferox.min_intensity is Intensity.STANDARD
    assert ferox.argv[str(Intensity.STEALTH)] == []


def test_override_rejects_creds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = tmp_path / "tool_mappings.yaml"
    cfg.write_text(
        """
tools:
  - id: evil
    binary: netexec
    min_intensity: stealth
    match:
      ports: [445]
    argv:
      stealth: ["smb", "{host}", "-u", "{user}", "-p", "{password}"]
      standard: []
      loud: []
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="forbidden placeholder"):
        load_tool_mappings(override=cfg)


def test_nmap_fallback_unprivileged() -> None:
    argv, notes = build_nmap_argv(
        nmap_path="nmap",
        output_stem="/tmp/scan",
        targets=["10.0.0.0/24"],
        excludes=["10.0.0.1"],
        intensity=Intensity.STANDARD,
        extra_args=["--max-retries", "2"],
        privileged=False,
    )
    assert "-sT" in argv
    assert "-sS" not in argv
    assert "-O" not in argv
    assert "-sU" not in argv
    assert "--exclude" in argv
    assert "-oA" in argv
    assert "--max-retries" in argv
    assert "--max-rate" in argv
    assert "--reason" in argv
    assert any("connect" in n for n in notes)


def test_default_intensity() -> None:
    assert intensity_or_default(Mode.CHECK, None) is Intensity.STANDARD
    assert intensity_or_default(Mode.LAB, None) is Intensity.STANDARD
    assert intensity_or_default(Mode.CHECK, Intensity.LOUD) is Intensity.LOUD
    assert intensity_or_default(Mode.CHECK, Intensity.STEALTH) is Intensity.STEALTH


def test_default_profile_is_fast() -> None:
    fast = nmap_profile(Intensity.STANDARD)
    slow = nmap_profile(Intensity.STEALTH)
    assert fast.timing == "-T4"
    assert fast.tcp_ports == ["--top-ports", "3000"]
    assert fast.min_rate and fast.min_rate > 0
    assert fast.host_timeout
    assert fast.max_retries < slow.max_retries
    assert fast.max_rate > slow.max_rate
    assert slow.min_rate is None
    assert slow.timing == "-T2"


def test_overrides_replace_profile_flags() -> None:
    argv, notes = build_nmap_argv(
        nmap_path="nmap",
        output_stem="/tmp/scan",
        targets=["10.0.0.0/24"],
        excludes=[],
        intensity=Intensity.STANDARD,
        extra_args=["-T5", "-p-", "--min-rate", "10000"],
        privileged=True,
    )
    assert "-T4" not in argv
    assert "-T5" in argv
    assert "--top-ports" not in argv
    assert "-p-" in argv
    assert argv.count("--min-rate") == 1
    assert argv[argv.index("--min-rate") + 1] == "10000"
    assert argv[-1] == "10.0.0.0/24"
    assert any("replaced" in note for note in notes)


def test_overrides_leave_untouched_flags_alone() -> None:
    argv, _ = build_nmap_argv(
        nmap_path="nmap",
        output_stem="/tmp/scan",
        targets=["10.0.0.1"],
        excludes=[],
        intensity=Intensity.STANDARD,
        extra_args=["--open"],
        privileged=True,
    )
    assert "--open" in argv
    assert "-T4" in argv
    assert "--top-ports" in argv


def test_overrides_cannot_hijack_output_files() -> None:
    argv, notes = build_nmap_argv(
        nmap_path="nmap",
        output_stem="/tmp/scan",
        targets=["10.0.0.1"],
        excludes=[],
        intensity=Intensity.STANDARD,
        extra_args=["-oA", "/tmp/evil", "--open"],
        privileged=True,
    )
    assert argv.count("-oA") == 1
    assert "/tmp/evil" not in argv
    assert argv[argv.index("-oA") + 1] == "/tmp/scan"
    assert "--open" in argv
    assert any("va manages nmap output" in note for note in notes)
