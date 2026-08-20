"""Target parsing helpers."""

from __future__ import annotations

import ipaddress
from pathlib import Path


def load_target_args(value: str) -> list[str]:
    """Return one or more target tokens from a CIDR/IP/hostname or a file of those."""
    path = Path(value)
    if path.is_file():
        lines: list[str] = []
        for raw in path.read_text(encoding="utf-8").splitlines():
            item = raw.strip()
            if not item or item.startswith("#"):
                continue
            lines.append(item)
        if not lines:
            raise ValueError(f"target file is empty: {path}")
        return lines
    return [value]


def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def parse_network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
