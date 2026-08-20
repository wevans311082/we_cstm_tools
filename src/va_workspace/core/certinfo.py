"""Fetch a TLS certificate with the stdlib (Windows-friendly)."""

from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime
from typing import Any


def fetch_cert(host: str, port: int = 443, timeout: float = 8.0) -> dict[str, Any]:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
    if not cert:
        raise RuntimeError("empty certificate")
    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
    sans = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
    return {
        "host": host,
        "port": port,
        "subject": subject.get("commonName", str(subject)),
        "issuer": issuer.get("commonName", str(issuer)),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "expired": not_after < datetime.now(UTC).replace(tzinfo=None),
        "sans": sans,
    }
