"""In-scope / out-of-scope checks for secondary tools."""

from __future__ import annotations

from urllib.parse import urlparse

from va_workspace.util.net import parse_ip, parse_network


def _matches_token(host: str, token: str) -> bool:
    ip = parse_ip(host)
    network = parse_network(token)
    token_ip = parse_ip(token)
    if ip is not None and network is not None:
        return ip in network
    if ip is not None and token_ip is not None:
        return ip == token_ip
    return host.lower().rstrip(".") == token.lower().rstrip(".")


def is_in_scope(host: str, targets: list[str], excludes: list[str]) -> bool:
    if any(_matches_token(host, item) for item in excludes):
        return False
    if not targets:
        return False
    return any(_matches_token(host, item) for item in targets)


def host_from_url(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return host.strip("[]")


def url_in_scope(url: str, targets: list[str], excludes: list[str]) -> bool:
    host = host_from_url(url)
    if not host:
        return False
    return is_in_scope(host, targets, excludes)
