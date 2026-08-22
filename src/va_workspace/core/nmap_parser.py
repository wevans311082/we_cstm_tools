"""Parse Nmap XML into Host models using stdlib ElementTree."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from va_workspace.models import Host, NseScript, Port


class NmapParseError(ValueError):
    """Raised when XML is not usable Nmap output."""


def _text(element: ET.Element | None, attr: str, default: str = "") -> str:
    if element is None:
        return default
    return element.get(attr, default) or default


def _script_data(element: ET.Element) -> dict[str, Any]:
    result: dict[str, Any] = {}
    unnamed: list[Any] = []
    for child in list(element):
        if child.tag == "elem":
            key = child.get("key")
            value = (child.text or "").strip()
            if key:
                result[key] = value
            else:
                unnamed.append(value)
        elif child.tag == "table":
            key = child.get("key")
            parsed = _script_data(child)
            if key:
                result[key] = parsed
            else:
                unnamed.append(parsed)
    if unnamed:
        result["_items"] = unnamed
    return result


def _scripts(parent: ET.Element) -> list[NseScript]:
    results: list[NseScript] = []
    for script in parent.findall("script"):
        script_id = script.get("id") or ""
        output = script.get("output") or ""
        if script_id:
            results.append(
                NseScript(id=script_id, output=output.strip(), data=_script_data(script))
            )
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


def merge_hosts(*groups: list[Host]) -> list[Host]:
    """Merge hosts from several Nmap XML parses (tcp / udp / scripts)."""
    by_ip: dict[str, Host] = {}
    order: list[str] = []
    for group in groups:
        for host in group:
            if host.ip not in by_ip:
                by_ip[host.ip] = Host(
                    ip=host.ip,
                    status=host.status,
                    hostnames=list(host.hostnames),
                    os=host.os,
                    ports=[],
                    host_scripts=[],
                )
                order.append(host.ip)
            current = by_ip[host.ip]
            if host.status == "up":
                current.status = "up"
            for name in host.hostnames:
                if name not in current.hostnames:
                    current.hostnames.append(name)
            if len(host.os) > len(current.os):
                current.os = host.os
            port_index = {(p.protocol, p.number): p for p in current.ports}
            for port in host.ports:
                key = (port.protocol, port.number)
                if key not in port_index:
                    current.ports.append(port)
                    port_index[key] = port
                    continue
                existing = port_index[key]
                if port.state == "open":
                    existing.state = "open"
                if port.service and not existing.service:
                    existing.service = port.service
                if port.product:
                    existing.product = port.product
                if port.version:
                    existing.version = port.version
                if port.tunnel:
                    existing.tunnel = port.tunnel
                seen_ids = {s.id for s in existing.scripts}
                for script in port.scripts:
                    if script.id not in seen_ids:
                        existing.scripts.append(script)
                        seen_ids.add(script.id)
            seen_host = {s.id for s in current.host_scripts}
            for script in host.host_scripts:
                if script.id not in seen_host:
                    current.host_scripts.append(script)
                    seen_host.add(script.id)
    return [by_ip[ip] for ip in order]


def is_reportable(host: Host) -> bool:
    """False for addresses nmap only listed because -v echoes down hosts."""
    return host.status == "up" or bool(host.ports)


def filter_reportable(hosts: list[Host]) -> tuple[list[Host], int]:
    """Drop down hosts with nothing to show. Returns (kept, dropped count)."""
    kept = [host for host in hosts if is_reportable(host)]
    return kept, len(hosts) - len(kept)
