"""Host role inference from open ports."""

from __future__ import annotations

from va_workspace.constants import INTERESTING_PORTS
from va_workspace.models import Host, Port


def infer_role(host: Host) -> str:
    ports = set(host.open_port_numbers)
    if 445 in ports and (88 in ports or 389 in ports):
        return "domain-controller"
    if 25 in ports or 587 in ports or 465 in ports:
        return "mail"
    if 1433 in ports or 3306 in ports or 5432 in ports or 27017 in ports:
        return "database"
    if 2375 in ports or 6443 in ports or 10250 in ports:
        return "container-platform"
    if 161 in ports and not (80 in ports or 443 in ports or 22 in ports):
        return "network-device"
    if 3389 in ports or (22 in ports and 445 in ports):
        return "jump-host"
    if 80 in ports or 443 in ports or 8080 in ports or 8443 in ports:
        return "web"
    if 22 in ports:
        return "unix-host"
    return "unknown"


def interesting_ports(host: Host) -> list[Port]:
    return [p for p in host.ports if p.number in INTERESTING_PORTS]
