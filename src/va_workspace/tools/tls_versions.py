"""Probe which TLS protocol versions a listener accepts (stdlib ssl)."""

from __future__ import annotations

import socket
import ssl
import warnings
from typing import Any

from va_workspace.tools._common import emit, probe_parser

_VERSIONS = (
    ("TLSv1.0", "TLSv1"),
    ("TLSv1.1", "TLSv1_1"),
    ("TLSv1.2", "TLSv1_2"),
    ("TLSv1.3", "TLSv1_3"),
)


def try_version(host: str, port: int, name: str, attr: str, timeout: float) -> str:
    enum = getattr(ssl.TLSVersion, attr, None)
    if enum is None:
        return "unsupported-client"
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = enum
            ctx.maximum_version = enum
    except (ValueError, OSError):
        return "unsupported-client"
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.version() or name
    except (ssl.SSLError, OSError, TimeoutError, ConnectionError):
        return "no"


def probe(host: str, port: int, timeout: float = 6.0) -> dict[str, Any]:
    accepted: list[str] = []
    detail: dict[str, str] = {}
    for label, attr in _VERSIONS:
        result = try_version(host, port, label, attr, timeout)
        detail[label] = result
        if result not in {"no", "unsupported-client"}:
            accepted.append(label)
    legacy = [v for v in accepted if v in {"TLSv1.0", "TLSv1.1"}]
    return {
        "probe": "tls_versions",
        "host": host,
        "port": port,
        "accepted": accepted,
        "legacy": legacy,
        "legacy_tls": "yes" if legacy else "no",
        "detail": detail,
    }


def main() -> None:
    args = probe_parser("TLS version probe").parse_args()
    emit(args.out, probe(args.host, args.port, args.timeout))


if __name__ == "__main__":
    main()
