from __future__ import annotations

from pathlib import Path

import pytest

from va_workspace.core.nmap_parser import NmapParseError, parse_nmap_xml


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
