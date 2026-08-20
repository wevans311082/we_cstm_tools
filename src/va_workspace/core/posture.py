"""Generated TLS / SMB / certificate / attack-surface overview notes."""

from __future__ import annotations

import re
from dataclasses import dataclass

from va_workspace.constants import INTERESTING_PORTS, MANAGED_HEADER
from va_workspace.core.roles import infer_role
from va_workspace.core.vault import _write
from va_workspace.models import EngagementState, Host, Port

_WEAK_TLS = re.compile(
    r"(SSLv2|SSLv3|TLSv1\.0|RC4|DES|3DES|NULL-MD5|EXPORT|broken)",
    re.IGNORECASE,
)


@dataclass
class CertRow:
    host: str
    port: int
    subject: str
    issuer: str
    not_after: str
    bits: str


def _script_output(host: Host, script_id: str) -> list[tuple[Port | None, str]]:
    rows: list[tuple[Port | None, str]] = []
    for port, script in host.all_scripts():
        if script.id == script_id and script.output:
            rows.append((port, script.output))
    return rows


def parse_cert(output: str) -> dict[str, str]:
    def grab(label: str) -> str:
        match = re.search(rf"{label}:\s*(.+)", output)
        return match.group(1).strip() if match else ""

    return {
        "subject": grab("Subject"),
        "issuer": grab("Issuer"),
        "not_after": grab("Not valid after"),
        "bits": grab("Public Key bits"),
    }


def collect_certs(state: EngagementState) -> list[CertRow]:
    rows: list[CertRow] = []
    for host in state.hosts:
        for port, output in _script_output(host, "ssl-cert"):
            parsed = parse_cert(output)
            rows.append(
                CertRow(
                    host=host.ip,
                    port=port.number if port else 0,
                    subject=parsed["subject"],
                    issuer=parsed["issuer"],
                    not_after=parsed["not_after"],
                    bits=parsed["bits"],
                )
            )
    return rows


def tls_findings(state: EngagementState) -> list[tuple[str, int, str]]:
    hits: list[tuple[str, int, str]] = []
    for host in state.hosts:
        for port, output in _script_output(host, "ssl-enum-ciphers"):
            if _WEAK_TLS.search(output):
                snippet = ", ".join(sorted({m.group(0) for m in _WEAK_TLS.finditer(output)}))
                hits.append((host.ip, port.number if port else 0, snippet))
    return hits


def smb_rows(state: EngagementState) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for host in state.hosts:
        signing = ""
        protocols = ""
        shares = ""
        for _port, output in _script_output(host, "smb-security-mode"):
            signing = output.splitlines()[0][:200]
        for _port, output in _script_output(host, "smb2-security-mode"):
            if not signing:
                signing = output.splitlines()[0][:200]
        for _port, output in _script_output(host, "smb-protocols"):
            protocols = output.replace("\n", "; ")[:240]
        for _port, output in _script_output(host, "smb-enum-shares"):
            shares = output.replace("\n", "; ")[:240]
        if signing or protocols or shares:
            rows.append(
                {
                    "host": host.ip,
                    "hostname": host.primary_hostname,
                    "signing": signing,
                    "protocols": protocols,
                    "shares": shares,
                }
            )
    return rows


def attack_surface_rows(state: EngagementState) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for host in state.hosts:
        interesting = [
            p for p in host.ports if p.number in INTERESTING_PORTS and p.state == "open"
        ]
        if not interesting:
            continue
        rows.append(
            {
                "host": host.ip,
                "hostname": host.primary_hostname,
                "role": infer_role(host),
                "ports": ", ".join(f"{p.number}/{p.protocol}" for p in interesting),
                "services": ", ".join(
                    sorted({p.service or str(p.number) for p in interesting})
                ),
            }
        )
    return rows


def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    if not rows:
        lines.append("| " + " | ".join(["_none_"] + [""] * (len(headers) - 1)) + " |")
        return "\n".join(lines)
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def write_posture_notes(state: EngagementState) -> None:
    mode = str(state.mode)
    certs = collect_certs(state)
    tls = tls_findings(state)
    smb = smb_rows(state)
    surface = attack_surface_rows(state)

    cert_md = "\n".join(
        [
            MANAGED_HEADER,
            "---",
            f"tags: [certs, {mode}]",
            "---",
            "",
            "# Certificate inventory",
            "",
            _md_table(
                ["Host", "Port", "Subject", "Not after", "Key bits"],
                [
                    [
                        f"[[02-hosts/{c.host}/host|{c.host}]]",
                        str(c.port),
                        c.subject.replace("|", "/"),
                        c.not_after,
                        c.bits,
                    ]
                    for c in certs
                ],
            ),
            "",
            "Out-of-scope SAN hostnames belong on [[scope]] or as a limitation.",
            "",
        ]
    )
    tls_md = "\n".join(
        [
            MANAGED_HEADER,
            "---",
            f"tags: [tls, {mode}]",
            "---",
            "",
            "# TLS posture",
            "",
            _md_table(
                ["Host", "Port", "Weak indicators"],
                [
                    [f"[[02-hosts/{h}/host|{h}]]", str(p), ind]
                    for h, p, ind in tls
                ],
            ),
            "",
            "Promote with `va finding add --template weak-ciphers` after sslscan/testssl.",
            "",
            "[[01-overview/certs]]",
            "",
        ]
    )
    smb_md = "\n".join(
        [
            MANAGED_HEADER,
            "---",
            f"tags: [smb, {mode}]",
            "---",
            "",
            "# SMB posture",
            "",
            _md_table(
                ["Host", "Hostname", "Signing", "Protocols", "Shares"],
                [
                    [
                        f"[[02-hosts/{r['host']}/host|{r['host']}]]",
                        r["hostname"],
                        r["signing"].replace("|", "/"),
                        r["protocols"].replace("|", "/"),
                        r["shares"].replace("|", "/"),
                    ]
                    for r in smb
                ],
            ),
            "",
            "Templates: `smb-signing`, `smbv1`, `smb-null`, `ms17-010`.",
            "",
        ]
    )
    surface_md = "\n".join(
        [
            MANAGED_HEADER,
            "---",
            f"tags: [attack-surface, {mode}]",
            "---",
            "",
            "# Attack surface",
            "",
            "Interesting ports only (admin, data stores, directory, remote access, ICS).",
            "",
            _md_table(
                ["Host", "Role", "Ports", "Services"],
                [
                    [
                        f"[[02-hosts/{r['host']}/host|{r['host']}]]",
                        r["role"],
                        r["ports"],
                        r["services"],
                    ]
                    for r in surface
                ],
            ),
            "",
        ]
    )
    overview = state.path / "01-overview"
    _write(overview / "certs.md", cert_md, overwrite=True)
    _write(overview / "tls.md", tls_md, overwrite=True)
    _write(overview / "smb.md", smb_md, overwrite=True)
    _write(overview / "attack-surface.md", surface_md, overwrite=True)
