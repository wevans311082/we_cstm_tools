"""Match YAML tools to open ports and interpolate argv."""

from __future__ import annotations

from pathlib import Path

from va_workspace.config.load import ToolMapping
from va_workspace.constants import Intensity
from va_workspace.models import Host, Job, Port
from va_workspace.util.scope import is_in_scope, url_in_scope


class PluginError(ValueError):
    """Invalid plugin interpolation or match."""


def intensity_rank(value: Intensity) -> int:
    return {Intensity.STEALTH: 0, Intensity.STANDARD: 1, Intensity.LOUD: 2}[value]


def first_existing(candidates: tuple[Path, ...]) -> Path | None:
    for path in candidates:
        if path.is_file():
            return path
    return None


def port_matches(tool: ToolMapping, port: Port) -> bool:
    if not port.is_open:
        return False
    match = tool.match
    if match.protocols and port.protocol not in match.protocols:
        return False
    if match.http_only and not port.is_http:
        return False
    if match.tunnel_ssl and not port.is_tls:
        if port.number not in match.ports:
            return False
        # TLS-ish port numbers still match even without tunnel flag
    port_ok = port.number in match.ports if match.ports else False
    service_ok = False
    if match.services:
        service = port.service.lower()
        service_ok = any(token in service or service == token for token in match.services)
    if match.ports or match.services:
        return port_ok or service_ok
    return False


def interpolate_argv(
    template: list[str],
    *,
    host: Host,
    port: Port,
    outfile: Path,
    wordlist: Path | None,
    wordlist_loud: Path | None,
    community: str = "public",
) -> list[str]:
    url_pattern = port.url
    url = url_pattern.format(host=host.ip) if url_pattern else f"http://{host.ip}:{port.number}"
    mapping = {
        "{host}": host.ip,
        "{port}": str(port.number),
        "{url}": url,
        "{outfile}": str(outfile),
        "{wordlist}": str(wordlist) if wordlist else "",
        "{wordlist_loud}": str(wordlist_loud or wordlist or ""),
        "{community}": community,
    }
    rendered: list[str] = []
    for item in template:
        value = item
        for token, replacement in mapping.items():
            value = value.replace(token, replacement)
        if "{user}" in value.lower() or "{password}" in value.lower():
            raise PluginError("refusing to interpolate credential placeholders")
        rendered.append(value)
    if any(part == "" for part in rendered):
        raise PluginError("empty argv item after interpolation (missing wordlist?)")
    return rendered


def url_for(host: Host, port: Port) -> str:
    pattern = port.url
    if pattern:
        return pattern.format(host=host.ip)
    scheme = "https" if port.is_tls else "http"
    return f"{scheme}://{host.ip}:{port.number}"


def job_id(tool_id: str, host: Host, port: Port) -> str:
    return f"{tool_id}:{host.ip}:{port.protocol}:{port.number}"


def plan_jobs(
    *,
    hosts: list[Host],
    tools: list[ToolMapping],
    intensity: Intensity,
    targets: list[str],
    excludes: list[str],
) -> list[Job]:
    jobs: list[Job] = []
    for host in hosts:
        if host.status != "up":
            continue
        if not is_in_scope(host.ip, targets, excludes):
            continue
        for port in host.open_ports:
            for tool in tools:
                if intensity_rank(intensity) < intensity_rank(tool.min_intensity):
                    continue
                template = tool.argv.get(str(intensity), [])
                if not template:
                    continue
                if not port_matches(tool, port):
                    continue
                if tool.match.http_only:
                    url = url_for(host, port)
                    if not url_in_scope(url, targets, excludes):
                        continue
                jobs.append(
                    Job(
                        id=job_id(tool.id, host, port),
                        tool_id=tool.id,
                        host=host.ip,
                        port=port.number,
                        protocol=port.protocol,
                    )
                )
    # stable unique
    seen: set[str] = set()
    unique: list[Job] = []
    for job in jobs:
        if job.id in seen:
            continue
        seen.add(job.id)
        unique.append(job)
    return unique
