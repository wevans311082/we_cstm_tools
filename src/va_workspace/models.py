"""Typed domain models for hosts, jobs, findings, and engagement state."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from va_workspace.constants import FindingStatus, Intensity, JobStatus, Mode, NmapPhase


@dataclass
class NseScript:
    id: str
    output: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> NseScript:
        return cls(id=str(data.get("id", "")), output=str(data.get("output", "")))


@dataclass
class Port:
    number: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    tunnel: str = ""
    scripts: list[NseScript] = field(default_factory=list)

    @property
    def is_open(self) -> bool:
        return self.state == "open"

    @property
    def is_http(self) -> bool:
        name = self.service.lower()
        if self.number in {80, 443, 8080, 8443, 8000, 8888, 3000}:
            return self.is_open
        return self.is_open and any(
            token in name for token in ("http", "https", "ssl/http", "http-proxy")
        )

    @property
    def is_tls(self) -> bool:
        if self.tunnel.lower() == "ssl":
            return True
        name = self.service.lower()
        return "ssl" in name or "https" in name or self.number in {443, 8443, 636, 5986}

    @property
    def url(self) -> str | None:
        if not self.is_http:
            return None
        scheme = "https" if self.is_tls else "http"
        default = 443 if scheme == "https" else 80
        if self.number == default:
            return f"{scheme}://{{host}}"
        return f"{scheme}://{{host}}:{self.number}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "number": self.number,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "extra_info": self.extra_info,
            "tunnel": self.tunnel,
            "scripts": [s.to_dict() for s in self.scripts],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Port:
        scripts = [NseScript.from_dict(s) for s in data.get("scripts", [])]
        return cls(
            number=int(data["number"]),
            protocol=str(data.get("protocol", "tcp")),
            state=str(data.get("state", "")),
            service=str(data.get("service", "")),
            product=str(data.get("product", "")),
            version=str(data.get("version", "")),
            extra_info=str(data.get("extra_info", "")),
            tunnel=str(data.get("tunnel", "")),
            scripts=scripts,
        )


@dataclass
class Host:
    ip: str
    status: str = "up"
    hostnames: list[str] = field(default_factory=list)
    os: str = ""
    ports: list[Port] = field(default_factory=list)
    host_scripts: list[NseScript] = field(default_factory=list)

    @property
    def primary_hostname(self) -> str:
        return self.hostnames[0] if self.hostnames else ""

    @property
    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.is_open]

    @property
    def open_port_numbers(self) -> list[int]:
        return [p.number for p in self.open_ports]

    @property
    def service_names(self) -> list[str]:
        names: list[str] = []
        for port in self.open_ports:
            label = port.service or f"{port.protocol}/{port.number}"
            if label not in names:
                names.append(label)
        return names

    @property
    def slug(self) -> str:
        return self.ip.replace(":", "_")

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "status": self.status,
            "hostnames": list(self.hostnames),
            "os": self.os,
            "ports": [p.to_dict() for p in self.ports],
            "host_scripts": [s.to_dict() for s in self.host_scripts],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Host:
        return cls(
            ip=str(data["ip"]),
            status=str(data.get("status", "up")),
            hostnames=list(data.get("hostnames", [])),
            os=str(data.get("os", "")),
            ports=[Port.from_dict(p) for p in data.get("ports", [])],
            host_scripts=[NseScript.from_dict(s) for s in data.get("host_scripts", [])],
        )


@dataclass
class Job:
    id: str
    tool_id: str
    host: str
    port: int | None = None
    protocol: str = "tcp"
    status: JobStatus = JobStatus.PENDING
    skip_reason: str = ""
    paths: list[str] = field(default_factory=list)
    retries: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tool_id": self.tool_id,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "status": str(self.status),
            "skip_reason": self.skip_reason,
            "paths": list(self.paths),
            "retries": self.retries,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Job:
        return cls(
            id=str(data["id"]),
            tool_id=str(data["tool_id"]),
            host=str(data["host"]),
            port=data.get("port"),
            protocol=str(data.get("protocol", "tcp")),
            status=JobStatus(str(data.get("status", JobStatus.PENDING))),
            skip_reason=str(data.get("skip_reason", "")),
            paths=list(data.get("paths", [])),
            retries=int(data.get("retries", 0)),
        )


@dataclass
class Finding:
    id: str
    title: str
    cvss_vector: str
    cvss_score: float
    severity: str
    status: FindingStatus = FindingStatus.DRAFT
    hosts: list[str] = field(default_factory=list)
    ports: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    short_term_fix: str = ""
    strategic_fix: str = ""
    description: str = ""
    created: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "status": str(self.status),
            "hosts": list(self.hosts),
            "ports": list(self.ports),
            "evidence": list(self.evidence),
            "short_term_fix": self.short_term_fix,
            "strategic_fix": self.strategic_fix,
            "description": self.description,
            "created": self.created,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            id=str(data["id"]),
            title=str(data.get("title", "")),
            cvss_vector=str(data.get("cvss_vector", "")),
            cvss_score=float(data.get("cvss_score", 0.0)),
            severity=str(data.get("severity", "none")),
            status=FindingStatus(str(data.get("status", FindingStatus.DRAFT))),
            hosts=list(data.get("hosts", [])),
            ports=list(data.get("ports", [])),
            evidence=list(data.get("evidence", [])),
            short_term_fix=str(data.get("short_term_fix", "")),
            strategic_fix=str(data.get("strategic_fix", "")),
            description=str(data.get("description", "")),
            created=str(data.get("created", "")),
        )


@dataclass
class NmapState:
    status: NmapPhase = NmapPhase.PENDING
    output_stem: str = ""
    started: str = ""
    finished: str = ""
    pid: int | None = None
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": str(self.status),
            "output_stem": self.output_stem,
            "started": self.started,
            "finished": self.finished,
            "pid": self.pid,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> NmapState:
        return cls(
            status=NmapPhase(str(data.get("status", NmapPhase.PENDING))),
            output_stem=str(data.get("output_stem", "")),
            started=str(data.get("started", "")),
            finished=str(data.get("finished", "")),
            pid=data.get("pid"),
            error=str(data.get("error", "")),
        )


@dataclass
class EngagementState:
    path: Path
    client: str = ""
    mode: Mode = Mode.LAB
    intensity: Intensity = Intensity.STANDARD
    targets: list[str] = field(default_factory=list)
    excludes: list[str] = field(default_factory=list)
    testers: list[str] = field(default_factory=list)
    classification: str = "OFFICIAL"
    va_version: str = ""
    binary_versions: dict[str, str] = field(default_factory=dict)
    nmap: NmapState = field(default_factory=NmapState)
    hosts: list[Host] = field(default_factory=list)
    jobs: list[Job] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    legal_banner_shown: bool = False
    created: str = ""
    updated: str = ""

    def host_by_ip(self, ip: str) -> Host | None:
        for host in self.hosts:
            if host.ip == ip:
                return host
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "client": self.client,
            "mode": str(self.mode),
            "intensity": str(self.intensity),
            "targets": list(self.targets),
            "excludes": list(self.excludes),
            "testers": list(self.testers),
            "classification": self.classification,
            "va_version": self.va_version,
            "binary_versions": dict(self.binary_versions),
            "nmap": self.nmap.to_dict(),
            "hosts": [h.to_dict() for h in self.hosts],
            "jobs": [j.to_dict() for j in self.jobs],
            "findings": list(self.findings),
            "legal_banner_shown": self.legal_banner_shown,
            "created": self.created,
            "updated": self.updated,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EngagementState:
        return cls(
            path=Path(str(data["path"])),
            client=str(data.get("client", "")),
            mode=Mode(str(data.get("mode", Mode.LAB))),
            intensity=Intensity(str(data.get("intensity", Intensity.STANDARD))),
            targets=list(data.get("targets", [])),
            excludes=list(data.get("excludes", [])),
            testers=list(data.get("testers", [])),
            classification=str(data.get("classification", "OFFICIAL")),
            va_version=str(data.get("va_version", "")),
            binary_versions=dict(data.get("binary_versions", {})),
            nmap=NmapState.from_dict(data.get("nmap", {})),
            hosts=[Host.from_dict(h) for h in data.get("hosts", [])],
            jobs=[Job.from_dict(j) for j in data.get("jobs", [])],
            findings=list(data.get("findings", [])),
            legal_banner_shown=bool(data.get("legal_banner_shown", False)),
            created=str(data.get("created", "")),
            updated=str(data.get("updated", "")),
        )
