"""Turn bundled Python probe JSON into unverified leads."""

from __future__ import annotations

import json

from va_workspace.core.vault import render
from va_workspace.models import EngagementState, Host

_RULES = (
    ("tls_versions", lambda d: d.get("legacy_tls") == "yes", "Legacy TLS accepted", "tls10"),
    (
        "smb_unauth",
        lambda d: d.get("signing_required") == "no" and d.get("smb2") == "yes",
        "SMB signing not required",
        "smb-signing",
    ),
    ("vpn_portals", lambda d: d.get("portal") == "yes", "SSL VPN / published portal", "vpn-portal"),
    ("ldap_anon", lambda d: d.get("anonymous_bind") == "yes", "Anonymous LDAP bind", "ldap-anon"),
    ("http_intel", lambda d: d.get("swagger") == "yes", "OpenAPI/Swagger exposed", "swagger"),
    ("http_intel", lambda d: d.get("graphql") == "yes", "GraphQL introspection", "graphql"),
    ("http_intel", lambda d: d.get("dirlisting") == "yes", "HTTP directory listing", "dirlisting"),
    ("http_intel", lambda d: d.get("open_proxy") == "yes", "Open HTTP proxy", "open-proxy"),
    ("postgres", lambda d: d.get("trust") == "yes", "PostgreSQL trust auth", "postgres-trust"),
    ("oracle_tns", lambda d: d.get("tns") == "yes", "Oracle TNS exposed", "oracle-tns"),
)


def write_python_leads(state: EngagementState) -> int:
    root = state.path / "05-raw" / "tools"
    if not root.is_dir():
        return 0
    written = 0
    folder = state.path / "04-leads"
    folder.mkdir(parents=True, exist_ok=True)
    for path in root.rglob("*.txt"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        if not isinstance(data, dict) or "probe" not in data:
            continue
        host = state.host_by_ip(str(data.get("host", "")))
        if host is None:
            host = Host(ip=str(data.get("host") or "unknown"))
        for probe, pred, title, template in _RULES:
            if data.get("probe") != probe or not pred(data):
                continue
            dest = folder / f"py-{probe}-{host.slug}-{data.get('port', '0')}.md"
            dest.write_text(
                render(
                    "lead.md.j2",
                    state=state,
                    host=host,
                    product=title,
                    version=probe,
                    service=probe,
                    port=str(data.get("port") or "-"),
                    protocol="tcp",
                    body=json.dumps(data, indent=2)[:8000],
                    mode=str(state.mode),
                    template=template,
                ),
                encoding="utf-8",
            )
            written += 1
    return written
