"""Parse Nmap XML into Host models using stdlib ElementTree."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from va_workspace.models import Host, NseScript, Port


class NmapParseError(ValueError):
    """Raised when XML is not usable Nmap output."""


def _text(element: ET.Element | None, attr: str, default: str = "") -> str:
    if element is None:
        return default
    return element.get(attr, default) or default


def _scripts(parent: ET.Element) -> list[NseScript]:
    results: list[NseScript] = []
    for script in parent.findall("script"):
        script_id = script.get("id") or ""
        output = script.get("output") or ""
        if script_id:
            results.append(NseScript(id=script_id, output=output.strip()))
    return results


def parse_nmap_xml(path: Path) -> list[Host]:
    if not path.is_file():
        raise NmapParseError(f"nmap xml not found: {path}")
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        raise NmapParseError(f"invalid nmap xml: {exc}") from exc
    root = tree.getroot()
    if root.tag != "nmaprun":
        raise NmapParseError(f"root element is <{root.tag}>, expected <nmaprun>")

    hosts: list[Host] = []
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        status = _text(status_el, "state", "unknown")
        ip = ""
        for addr in host_el.findall("address"):
            addr_type = addr.get("addrtype", "")
            if addr_type in {"ipv4", "ipv6"}:
                ip = addr.get("addr") or ""
                if addr_type == "ipv4":
                    break
        if not ip:
            continue
        hostnames = [
            hn.get("name") or ""
            for hn in host_el.findall("./hostnames/hostname")
            if hn.get("name")
        ]
        os_name = ""
        osmatch = host_el.find("./os/osmatch")
        if osmatch is not None:
            os_name = osmatch.get("name") or ""
        ports: list[Port] = []
        for port_el in host_el.findall("./ports/port"):
            try:
                number = int(port_el.get("portid", ""))
            except ValueError:
                continue
            service_el = port_el.find("service")
            state_el = port_el.find("state")
            ports.append(
                Port(
                    number=number,
                    protocol=(port_el.get("protocol") or "tcp").lower(),
                    state=_text(state_el, "state", "unknown"),
                    service=_text(service_el, "name"),
                    product=_text(service_el, "product"),
                    version=_text(service_el, "version"),
                    extra_info=_text(service_el, "extrainfo"),
                    tunnel=_text(service_el, "tunnel"),
                    scripts=_scripts(port_el),
                )
            )
        hostscript_el = host_el.find("hostscript")
        host_scripts = _scripts(hostscript_el) if hostscript_el is not None else []
        hosts.append(
            Host(
                ip=ip,
                status=status,
                hostnames=hostnames,
                os=os_name,
                ports=ports,
                host_scripts=host_scripts,
            )
        )
    return hosts
