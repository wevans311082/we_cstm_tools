"""PostgreSQL unauth: startup packet, record auth request type (no password)."""

from __future__ import annotations

import socket
import struct
from typing import Any

from va_workspace.tools._common import emit, probe_parser

_AUTH = {
    0: "trust",
    3: "cleartext",
    5: "md5",
    10: "sasl",
}


def probe(host: str, port: int = 5432, timeout: float = 6.0) -> dict[str, Any]:
    out: dict[str, Any] = {
        "probe": "postgres",
        "host": host,
        "port": port,
        "postgres": "no",
        "auth": "",
        "trust": "no",
    }
    user = b"user\x00va\x00database\x00postgres\x00\x00"
    body = struct.pack("!I", 196608) + user  # protocol 3.0
    pkt = struct.pack("!I", len(body) + 4) + body
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(pkt)
            data = sock.recv(1024)
    except OSError as exc:
        out["error"] = str(exc)
        return out
    if not data:
        return out
    out["postgres"] = "yes"
    if data[0:1] == b"R" and len(data) >= 9:
        code = struct.unpack_from("!I", data, 5)[0]
        out["auth"] = _AUTH.get(code, str(code))
        if code == 0:
            out["trust"] = "yes"
    elif data[0:1] == b"E":
        out["auth"] = "error"
    return out


def main() -> None:
    args = probe_parser("Postgres unauth startup").parse_args()
    emit(args.out, probe(args.host, args.port, args.timeout))


if __name__ == "__main__":
    main()
