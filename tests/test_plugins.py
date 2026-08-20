from __future__ import annotations

from va_workspace.config.load import load_tool_mappings
from va_workspace.constants import Intensity
from va_workspace.core.nmap_parser import parse_nmap_xml
from va_workspace.core.plugins import plan_jobs
from va_workspace.util.scope import is_in_scope, url_in_scope


def test_scope() -> None:
    targets = ["10.10.10.0/24", "web01.lab.local"]
    assert is_in_scope("10.10.10.5", targets, [])
    assert not is_in_scope("10.10.10.5", targets, ["10.10.10.5"])
    assert not is_in_scope("8.8.8.8", targets, [])
    assert url_in_scope("https://10.10.10.8/admin", targets, [])
    assert not url_in_scope("https://evil.example/", targets, [])


def test_plan_jobs_intensity_and_scope(nmap_xml) -> None:  # type: ignore[no-untyped-def]
    hosts = parse_nmap_xml(nmap_xml)
    tools = load_tool_mappings()
    targets = ["10.10.10.0/24"]
    stealth = plan_jobs(
        hosts=hosts, tools=tools, intensity=Intensity.STEALTH, targets=targets, excludes=[]
    )
    ids = {j.tool_id for j in stealth}
    assert "whatweb" in ids
    assert "netexec-smb" in ids
    assert "feroxbuster" not in ids
    assert "gowitness" not in ids
    assert "snmpwalk" not in ids

    standard = plan_jobs(
        hosts=hosts, tools=tools, intensity=Intensity.STANDARD, targets=targets, excludes=[]
    )
    standard_ids = {j.tool_id for j in standard}
    assert "feroxbuster" in standard_ids
    assert "gowitness" in standard_ids
    assert "netexec-ldap" not in standard_ids  # no ldap ports in fixture
    assert "onesixtyone" in standard_ids

    loud = plan_jobs(
        hosts=hosts, tools=tools, intensity=Intensity.LOUD, targets=targets, excludes=[]
    )
    assert any(j.tool_id == "snmpwalk" for j in loud)

    excluded = plan_jobs(
        hosts=hosts,
        tools=tools,
        intensity=Intensity.STANDARD,
        targets=targets,
        excludes=["10.10.10.5"],
    )
    assert all(j.host != "10.10.10.5" for j in excluded)
