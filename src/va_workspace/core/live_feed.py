"""Turn raw nmap stdout into live operator feedback and an on-disk running log.

Nmap with -v announces hosts and open ports as it finds them, long before the XML
is complete. We surface those immediately instead of waiting for the phase to end.
"""

from __future__ import annotations

import re
from pathlib import Path

from va_workspace.core.state import utc_now
from va_workspace.util import log

LIVE_NOTE = Path("01-overview") / "live-scan.md"

_OPEN_PORT = re.compile(
    r"Discovered open port (?P<port>\d+)/(?P<proto>tcp|udp) on (?P<ip>[0-9a-fA-F.:]+)"
)
_HOST_REPORT = re.compile(r"Nmap scan report for (?P<name>\S+)(?: \((?P<ip>[0-9a-fA-F.:]+)\))?")
_SERVICE = re.compile(r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+open\s+(?P<service>\S+)(?P<rest>.*)$")
_HOST_DONE = re.compile(r"Completed .* against (?P<ip>[0-9a-fA-F.:]+)")


class LiveFeed:
    """Consumes nmap stdout lines; logs discoveries and appends them to the vault."""

    def __init__(self, engagement: Path, phase: str) -> None:
        self.phase = phase
        self.note = engagement / LIVE_NOTE
        self.note.parent.mkdir(parents=True, exist_ok=True)
        if not self.note.is_file():
            self.note.write_text(
                "# Live scan feed\n\nAppended while `va scan` runs. "
                "Superseded by the host notes.\n\n",
                encoding="utf-8",
            )
        self._seen_ports: set[tuple[str, str]] = set()
        self._seen_hosts: set[str] = set()
        self._current_host = ""
        self.ports_found = 0
        self.hosts_found = 0

    def _append(self, text: str) -> None:
        with self.note.open("a", encoding="utf-8") as handle:
            handle.write(text + "\n")

    def host(self, ip: str) -> None:
        if not ip or ip in self._seen_hosts:
            return
        self._seen_hosts.add(ip)
        self.hosts_found += 1
        self._append(f"- {utc_now()} [{self.phase}] host up `{ip}`")
        log.info(f"[cyan]host up[/cyan] {ip}")

    def port(self, ip: str, port: str, proto: str, service: str = "") -> None:
        key = (ip, f"{port}/{proto}")
        if key in self._seen_ports:
            return
        self._seen_ports.add(key)
        self.ports_found += 1
        suffix = f" {service}" if service else ""
        self._append(f"- {utc_now()} [{self.phase}] `{ip}` **{port}/{proto}** open{suffix}")
        log.info(f"[green]open[/green] {ip}:{port}/{proto}{suffix}")

    def feed(self, line: str) -> None:
        text = line.strip()
        if not text:
            return
        match = _OPEN_PORT.search(text)
        if match:
            self.port(match["ip"], match["port"], match["proto"])
            return
        match = _HOST_REPORT.search(text)
        if match:
            self._current_host = match["ip"] or match["name"]
            self.host(self._current_host)
            return
        match = _SERVICE.match(text)
        if match and self._current_host:
            self.port(self._current_host, match["port"], match["proto"], match["service"].strip())
            return
        match = _HOST_DONE.search(text)
        if match:
            self.host(match["ip"])

    def summary(self) -> str:
        return f"{self.hosts_found} host(s), {self.ports_found} open port(s) seen live"
