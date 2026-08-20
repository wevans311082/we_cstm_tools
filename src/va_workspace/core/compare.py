"""Retest diff between two engagement vaults."""

from __future__ import annotations

from va_workspace.constants import MANAGED_HEADER
from va_workspace.core.vault import _write
from va_workspace.models import EngagementState, Host


def _port_set(host: Host) -> set[tuple[str, int, str]]:
    return {(p.protocol, p.number, p.state) for p in host.open_ports}


def compare_states(current: EngagementState, previous: EngagementState) -> str:
    cur = {h.ip: h for h in current.hosts}
    prev = {h.ip: h for h in previous.hosts}
    new_hosts = sorted(set(cur) - set(prev))
    gone_hosts = sorted(set(prev) - set(cur))
    both = sorted(set(cur) & set(prev))
    new_ports: list[str] = []
    closed_ports: list[str] = []
    for ip in both:
        a = _port_set(cur[ip])
        b = _port_set(prev[ip])
        for proto, num, state in sorted(a - b):
            new_ports.append(f"{ip} {num}/{proto} ({state})")
        for proto, num, state in sorted(b - a):
            closed_ports.append(f"{ip} {num}/{proto} ({state})")
    lines = [
        MANAGED_HEADER,
        "---",
        "tags: [retest, compare]",
        "---",
        "",
        "# Retest diff",
        "",
        f"Current: `{current.path}` ({current.client})",
        f"Previous: `{previous.path}` ({previous.client})",
        "",
        f"- Hosts only in current: {', '.join(new_hosts) or '_none_'}",
        f"- Hosts only in previous: {', '.join(gone_hosts) or '_none_'}",
        "",
        "## New open ports",
        "",
    ]
    lines.extend([f"- `{item}`" for item in new_ports] or ["- _none_"])
    lines.extend(["", "## Open ports no longer seen", ""])
    lines.extend([f"- `{item}`" for item in closed_ports] or ["- _none_"])
    lines.extend(
        [
            "",
            f"Findings now: {len(current.findings)}; then: {len(previous.findings)}",
            "",
        ]
    )
    return "\n".join(lines) + "\n"


def write_compare(current: EngagementState, previous: EngagementState) -> None:
    _write(
        current.path / "01-overview" / "retest-diff.md",
        compare_states(current, previous),
        overwrite=True,
    )
