"""Anonymous LDAP bind + RootDSE naming contexts (no extra deps)."""

from __future__ import annotations

import socket
from typing import Any

from va_workspace.tools._common import emit, probe_parser


def _ber_len(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    if n < 256:
        return bytes([0x81, n])
    return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])


def _seq(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(payload)) + payload


def _bind_anon() -> bytes:
    # LDAPMessage: messageId 1, BindRequest version 3, empty DN, simple ""
    inner = _seq(0x02, b"\x03") + _seq(0x04, b"") + _seq(0x80, b"")
    bind = _seq(0x60, inner)
    msg = _seq(0x02, b"\x01") + bind
    return _seq(0x30, msg)


def _search_rootdse() -> bytes:
    # messageId 2, SearchRequest base "", scope base, present objectClass
    msgid = _seq(0x02, b"\x02")
    base = _seq(0x04, b"")
    scope = _seq(0x0A, b"\x00")  # ENUMERATED baseObject
    deref = _seq(0x0A, b"\x00")
    slimit = _seq(0x02, b"\x00")
    tlimit = _seq(0x02, b"\x00")
    types_only = b"\x01\x01\x00"
    filt = _seq(0x87, b"objectClass")  # present
    attrs = _seq(
        0x30,
        _seq(0x04, b"namingContexts")
        + _seq(0x04, b"defaultNamingContext")
        + _seq(0x04, b"dnsHostName")
        + _seq(0x04, b"ldapServiceName")
        + _seq(0x04, b"vendorName"),
    )
    search = _seq(0x63, base + scope + deref + slimit + tlimit + types_only + filt + attrs)
    return _seq(0x30, msgid + search)


def probe(host: str, port: int = 389, timeout: float = 6.0) -> dict[str, Any]:
    out: dict[str, Any] = {
        "probe": "ldap_anon",
        "host": host,
        "port": port,
        "anonymous_bind": "no",
        "rootdse": "no",
    }
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(_bind_anon())
            data = sock.recv(4096)
            if b"\x61" in data:  # BindResponse
                out["anonymous_bind"] = "yes"
            sock.sendall(_search_rootdse())
            data2 = sock.recv(8192)
    except OSError as exc:
        out["error"] = str(exc)
        return out
    blob = data2.decode("latin-1", errors="replace")
    if "namingContexts" in blob or "DC=" in blob or "dc=" in blob:
        out["rootdse"] = "yes"
    out["raw_len"] = len(data2)
    # crude extract of DC= fragments
    if "DC=" in data2.decode("utf-8", errors="ignore") or "dc=" in blob:
        out["looks_like_ad"] = "yes"
    return out


def main() -> None:
    args = probe_parser("Anonymous LDAP bind").parse_args()
    emit(args.out, probe(args.host, args.port, args.timeout))


if __name__ == "__main__":
    main()
