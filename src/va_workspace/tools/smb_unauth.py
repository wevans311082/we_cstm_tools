"""Unauth SMB2 negotiate: dialects and signing flags (no creds)."""

from __future__ import annotations

import socket
import struct
from typing import Any

from va_workspace.tools._common import emit, probe_parser

DIALECTS = (0x0202, 0x0210, 0x0300, 0x0302, 0x0311)
_DIALECT_NAME = {
    0x0202: "SMB 2.0.2",
    0x0210: "SMB 2.1",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
}


def _smb2_negotiate() -> bytes:
    header = bytearray(64)
    header[0:4] = b"\xfeSMB"
    struct.pack_into("<H", header, 4, 64)  # StructureSize
    struct.pack_into("<H", header, 12, 0)  # Command SMB2 NEGOTIATE
    struct.pack_into("<H", header, 14, 1)  # Credits
    struct.pack_into("<Q", header, 24, 1)  # MessageId
    body = bytearray()
    body += struct.pack("<H", 36)  # StructureSize
    body += struct.pack("<H", len(DIALECTS))
    body += struct.pack("<H", 0x01)  # signing enabled advertised
    body += b"\x00\x00"
    body += struct.pack("<I", 0)
    body += b"\x00" * 16  # ClientGuid
    body += struct.pack("<I", 0)
    body += struct.pack("<I", 0)
    for dialect in DIALECTS:
        body += struct.pack("<H", dialect)
    nb = struct.pack(">I", len(header) + len(body))
    return nb + header + body


def probe(host: str, port: int = 445, timeout: float = 6.0) -> dict[str, Any]:
    out: dict[str, Any] = {
        "probe": "smb_unauth",
        "host": host,
        "port": port,
        "smb2": "no",
        "signing_enabled": "",
        "signing_required": "",
        "dialect": "",
        "smbv1_hint": "unknown",
    }
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(_smb2_negotiate())
            data = sock.recv(4096)
    except OSError as exc:
        out["error"] = str(exc)
        return out
    if len(data) < 4 + 64 + 4:
        out["error"] = "short-response"
        return out
    payload = data[4:]
    if payload[0:4] != b"\xfeSMB":
        if payload[0:4] == b"\xffSMB":
            out["smbv1_hint"] = "yes"
        out["error"] = "not-smb2"
        return out
    # SMB2 header 64, Negotiate response StructureSize at 64
    if len(payload) < 64 + 8:
        out["error"] = "truncated"
        return out
    dialect = struct.unpack_from("<H", payload, 64 + 4)[0]
    secmode = struct.unpack_from("<H", payload, 64 + 2)[0]
    out["smb2"] = "yes"
    out["dialect"] = _DIALECT_NAME.get(dialect, hex(dialect))
    out["signing_enabled"] = "yes" if secmode & 0x01 else "no"
    out["signing_required"] = "yes" if secmode & 0x02 else "no"
    out["smbv1_hint"] = "no"
    return out


def main() -> None:
    args = probe_parser("SMB2 unauth negotiate").parse_args()
    emit(args.out, probe(args.host, args.port, args.timeout))


if __name__ == "__main__":
    main()
