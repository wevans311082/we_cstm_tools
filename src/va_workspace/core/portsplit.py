"""Split an Nmap-style port expression into chunks (from nsplit.py)."""

from __future__ import annotations


def parse_ports_expr(expr: str) -> list[int]:
    ports: set[int] = set()
    expr = expr.strip()
    if not expr or expr == "-":
        return list(range(1, 65536)) if expr == "-" else []
    for part in expr.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end or start < 1 or end > 65535:
                raise ValueError(f"invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            number = int(part)
            if number < 1 or number > 65535:
                raise ValueError(f"invalid port: {part}")
            ports.add(number)
    return sorted(ports)


def ports_to_expr(ports: list[int]) -> str:
    if not ports:
        return ""
    ranges: list[str] = []
    start = prev = ports[0]
    for port in ports[1:]:
        if port == prev + 1:
            prev = port
            continue
        ranges.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = port
    ranges.append(str(start) if start == prev else f"{start}-{prev}")
    return ",".join(ranges)


def split_ports(expr: str, parts: int) -> list[str]:
    ports = parse_ports_expr(expr)
    if parts <= 1 or not ports:
        return [ports_to_expr(ports)]
    size = (len(ports) + parts - 1) // parts
    return [ports_to_expr(ports[i : i + size]) for i in range(0, len(ports), size)]
