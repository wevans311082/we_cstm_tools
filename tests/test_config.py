from __future__ import annotations

from pathlib import Path

import pytest

from va_workspace.config.load import load_tool_mappings
from va_workspace.config.profiles import build_nmap_argv, intensity_or_default
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
    assert intensity_or_default(Mode.CHECK, None) is Intensity.STEALTH
    assert intensity_or_default(Mode.LAB, None) is Intensity.STANDARD
    assert intensity_or_default(Mode.CHECK, Intensity.LOUD) is Intensity.LOUD
