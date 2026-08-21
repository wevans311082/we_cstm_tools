from __future__ import annotations

from pathlib import Path

from va_workspace.config.nse import (
    custom_nse_names,
    list_custom_nse,
    nse_script_arg,
    nse_scripts,
    packaged_nse_dir,
)
from va_workspace.constants import Intensity, Mode
from va_workspace.core.compare import compare_states
from va_workspace.core.nmap_parser import merge_hosts, parse_nmap_xml
from va_workspace.core.nse_leads import flatten_script, match_leads
from va_workspace.core.roles import infer_role
from va_workspace.core.templates import get_template, load_finding_templates
from va_workspace.models import EngagementState, Host, NseScript, Port


def test_custom_lua_scripts_shipped() -> None:
    files = list_custom_nse()
    names = {path.name for path in files}
    assert packaged_nse_dir().is_dir()
    assert "va-http-posture.nse" in names
    assert "va-smb-posture.nse" in names
    assert "va-ssh-posture.nse" in names
    assert len(files) >= 60
    for path in files:
        text = path.read_text(encoding="utf-8")
        assert "categories" in text
        assert "action" in text


def test_custom_pack_and_script_arg() -> None:
    stealth = custom_nse_names(Mode.CHECK, Intensity.STEALTH)
    standard = custom_nse_names(Mode.CHECK, Intensity.STANDARD)
    assert "va-http-posture" in stealth
    assert "va-kerberos-info" in stealth
    assert "va-http-cors" in stealth
    assert "va-ad-unauth" not in stealth
    assert "va-ad-unauth" in standard
    assert "va-http-backup" in custom_nse_names(Mode.LAB, Intensity.LOUD)
    arg = nse_script_arg(Mode.CHECK, Intensity.STEALTH)
    assert "va-http-posture.nse" in arg
    assert "ssl-cert" in arg


def test_nse_packs_accumulate_and_check_strips() -> None:
    stealth = nse_scripts(Mode.CHECK, Intensity.STEALTH)
    standard = nse_scripts(Mode.CHECK, Intensity.STANDARD)
    loud_check = nse_scripts(Mode.CHECK, Intensity.LOUD)
    loud_lab = nse_scripts(Mode.LAB, Intensity.LOUD)
    assert "ssl-cert" in stealth
    assert "http-title" in stealth
    assert "http-headers" not in stealth
    assert "http-headers" in standard
    assert "ssl-enum-ciphers" in standard
    assert "ssl-heartbleed" in loud_check
    assert "smb-vuln-ms17-010" in loud_check
    assert "http-slowloris-check" not in loud_check
    assert "http-slowloris-check" in loud_lab
    assert "http-sql-injection" in loud_lab
    assert stealth == nse_scripts(Mode.LAB, Intensity.STEALTH)


def test_parse_nse_and_roles(nmap_xml: Path) -> None:
    hosts = parse_nmap_xml(nmap_xml)
    dc = hosts[0]
    assert infer_role(dc) == "domain-controller"
    smb = next(p for p in dc.ports if p.number == 445)
    assert any(s.id == "smb-security-mode" for s in smb.scripts)
    titles = {hit["title"] for hit in match_leads(dc)}
    assert "SMB signing not required" in titles
    assert "SMBv1 offered" in titles
    assert "HTTP TRACE enabled" in titles
    assert "Weak TLS configuration" in titles
    web = hosts[1]
    ftp_titles = {hit["title"] for hit in match_leads(web)}
    assert "Anonymous FTP" in ftp_titles


def test_merge_hosts() -> None:
    a = Host(ip="10.0.0.1", status="up", ports=[Port(80, "tcp", "open", service="http")])
    b = Host(
        ip="10.0.0.1",
        status="up",
        os="Linux",
        ports=[Port(80, "tcp", "open", service="http", product="nginx")],
    )
    merged = merge_hosts([a], [b])
    assert len(merged) == 1
    assert merged[0].os == "Linux"
    assert merged[0].ports[0].product == "nginx"


def test_flatten_script_includes_table_keys() -> None:
    script = NseScript(
        id="va-http-cors",
        output="",
        data={"cors": "wildcard", "acao": "*"},
    )
    text = flatten_script(script)
    assert "cors: wildcard" in text
    host = Host(
        ip="10.0.0.1",
        ports=[Port(443, "tcp", "open", scripts=[script])],
    )
    titles = {hit["title"] for hit in match_leads(host)}
    assert "Permissive CORS" in titles


def test_templates_exist() -> None:
    templates = load_finding_templates()
    assert "smb-signing" in templates
    assert "heartbleed" in templates
    assert "docker-api" in templates
    assert "jdwp-open" in templates
    tmpl = get_template("ms17-010")
    assert tmpl.cvss.startswith("CVSS:3.1/")


def test_compare_states(tmp_path: Path) -> None:
    prev = EngagementState(
        path=tmp_path / "old",
        client="acme",
        hosts=[Host(ip="10.0.0.1", ports=[Port(22, "tcp", "open")])],
    )
    cur = EngagementState(
        path=tmp_path / "new",
        client="acme",
        hosts=[
            Host(ip="10.0.0.1", ports=[Port(22, "tcp", "open"), Port(80, "tcp", "open")]),
            Host(ip="10.0.0.2", ports=[Port(443, "tcp", "open")]),
        ],
    )
    text = compare_states(cur, prev)
    assert "10.0.0.2" in text
    assert "80/tcp" in text


def test_compare_port_closed(tmp_path: Path) -> None:
    """A port that was open in the previous engagement but is now closed appears in the diff."""
    prev = EngagementState(
        path=tmp_path / "old",
        client="acme",
        hosts=[Host(ip="10.0.0.1", ports=[Port(22, "tcp", "open"), Port(8080, "tcp", "open")])],
    )
    cur = EngagementState(
        path=tmp_path / "new",
        client="acme",
        hosts=[Host(ip="10.0.0.1", ports=[Port(22, "tcp", "open"), Port(8080, "tcp", "closed")])],
    )
    text = compare_states(cur, prev)
    # 8080 changed state — should appear in "ports no longer seen" (open→closed)
    assert "8080" in text


def test_compare_new_and_gone_host(tmp_path: Path) -> None:
    prev = EngagementState(
        path=tmp_path / "old",
        client="acme",
        hosts=[Host(ip="10.0.0.1"), Host(ip="10.0.0.3")],
    )
    cur = EngagementState(
        path=tmp_path / "new",
        client="acme",
        hosts=[Host(ip="10.0.0.1"), Host(ip="10.0.0.2")],
    )
    text = compare_states(cur, prev)
    assert "10.0.0.2" in text  # new host
    assert "10.0.0.3" in text  # gone host


def test_compare_no_change(tmp_path: Path) -> None:
    state = EngagementState(
        path=tmp_path / "vault",
        client="acme",
        hosts=[Host(ip="10.0.0.1", ports=[Port(22, "tcp", "open")])],
    )
    text = compare_states(state, state)
    assert "_none_" in text  # no new/closed ports


def test_compare_finding_diff(tmp_path: Path) -> None:
    prev = EngagementState(
        path=tmp_path / "old",
        client="acme",
        findings=["F-001", "F-002"],
    )
    cur = EngagementState(
        path=tmp_path / "new",
        client="acme",
        findings=["F-001", "F-003"],
    )
    text = compare_states(cur, prev)
    assert "F-003" in text  # added
    assert "F-002" in text  # removed
