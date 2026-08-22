from __future__ import annotations

from pathlib import Path

import pytest

from va_workspace.core.nmap_parser import (
    NmapParseError,
    filter_reportable,
    is_reportable,
    parse_nmap_xml,
)
from va_workspace.models import Host, Port


def test_parse_mixed_lab(nmap_xml: Path) -> None:
    hosts = parse_nmap_xml(nmap_xml)
    assert [h.ip for h in hosts] == ["10.10.10.5", "10.10.10.8", "10.10.10.9"]
    dc = hosts[0]
    assert dc.primary_hostname == "dc01.lab.local"
    assert dc.os.startswith("Microsoft Windows Server 2019")
    assert 445 in dc.open_port_numbers
    assert 3389 not in dc.open_port_numbers
    smb = next(p for p in dc.ports if p.number == 445)
    assert smb.service == "microsoft-ds"
    https = next(p for p in dc.ports if p.number == 443)
    assert https.is_tls
    assert https.is_http
    assert any(s.id == "smb-os-discovery" for s in dc.host_scripts)
    web = hosts[1]
    apache = next(p for p in web.ports if p.number == 80)
    assert apache.product == "Apache httpd"
    assert apache.version.startswith("2.4.52")
    snmp = next(p for p in web.ports if p.number == 161)
    assert snmp.protocol == "udp"
    assert hosts[2].status == "down"


def test_parse_rejects_garbage(tmp_path: Path) -> None:
    junk = tmp_path / "not.xml"
    junk.write_text("<root/>", encoding="utf-8")
    with pytest.raises(NmapParseError):
        parse_nmap_xml(junk)


def test_parse_still_returns_down_hosts(nmap_xml: Path) -> None:
    """The parser stays faithful to the XML; filtering is an ingest decision."""
    hosts = parse_nmap_xml(nmap_xml)
    assert any(h.status == "down" for h in hosts)


def test_down_host_with_no_ports_is_not_reportable() -> None:
    assert not is_reportable(Host(ip="10.0.0.9", status="down"))


def test_up_host_with_no_open_ports_is_kept() -> None:
    """A live host with everything filtered is still a real result."""
    assert is_reportable(Host(ip="10.0.0.5", status="up"))


def test_down_host_that_still_has_ports_is_kept() -> None:
    host = Host(
        ip="10.0.0.7",
        status="down",
        ports=[Port(number=80, protocol="tcp", state="open")],
    )
    assert is_reportable(host)


def test_filter_reportable_counts_drops(nmap_xml: Path) -> None:
    hosts = parse_nmap_xml(nmap_xml)
    kept, dropped = filter_reportable(hosts)

    assert dropped == 1
    assert [h.ip for h in kept] == ["10.10.10.5", "10.10.10.8"]
    assert all(h.status != "down" or h.ports for h in kept)
