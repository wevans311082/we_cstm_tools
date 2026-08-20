"""Oracle TNS ping / version (no login)."""

from __future__ import annotations

import socket
from typing import Any

from va_workspace.tools._common import emit, probe_parser


def probe(host: str, port: int = 1521, timeout: float = 6.0) -> dict[str, Any]:
    out: dict[str, Any] = {
        "probe": "oracle_tns",
        "host": host,
        "port": port,
        "tns": "no",
        "version": "",
    }
    # TNS connect with (CONNECT_DATA=(COMMAND=version))
    connect = (
        "(CONNECT_DATA=(COMMAND=version))\x00"
    )
    payload = connect.encode("ascii")
    # Packet: length, checksum 0, type 1 connect, flags 0, header checksum 0
    length = 8 + len(payload)
    header = length.to_bytes(2, "big") + b"\x00\x00\x01\x00\x00\x00"
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(header + payload)
            data = sock.recv(2048)
    except OSError as exc:
        out["error"] = str(exc)
        return out
    if not data:
        return out
    out["tns"] = "yes"
    text = data.decode("latin-1", errors="replace")
    out["banner"] = text[:300]
    if "TNS" in text or "Oracle" in text or len(data) > 8:
        out["oracle"] = "yes"
    return out


def main() -> None:
    args = probe_parser("Oracle TNS version ping").parse_args()
    emit(args.out, probe(args.host, args.port, args.timeout))


if __name__ == "__main__":
    main()
