from __future__ import annotations

from pathlib import Path

import pytest

from va_workspace.config.load import load_tool_mappings
from va_workspace.constants import Intensity
from va_workspace.core.nmap_parser import parse_nmap_xml
from va_workspace.core.plugins import PluginError, interpolate_argv, plan_jobs
from va_workspace.models import Host, Port
from va_workspace.util.scope import is_in_scope, url_in_scope


def test_scope() -> None:
    targets = ["10.10.10.0/24", "web01.lab.local"]
    assert is_in_scope("10.10.10.5", targets, [])
    assert not is_in_scope("10.10.10.5", targets, ["10.10.10.5"])
    assert not is_in_scope("8.8.8.8", targets, [])
    assert url_in_scope("https://10.10.10.8/admin", targets, [])
    assert not url_in_scope("https://evil.example/", targets, [])


def test_plan_jobs_intensity_and_scope(nmap_xml) -> None:  # type: ignore[no-untyped-def]
    hosts = parse_nmap_xml(nmap_xml)
    tools = load_tool_mappings()
    targets = ["10.10.10.0/24"]
    stealth = plan_jobs(
        hosts=hosts, tools=tools, intensity=Intensity.STEALTH, targets=targets, excludes=[]
    )
    ids = {j.tool_id for j in stealth}
    assert "whatweb" in ids
    assert "netexec-smb" in ids
    assert "feroxbuster" not in ids
    assert "gowitness" not in ids
    assert "snmpwalk" not in ids

    standard = plan_jobs(
        hosts=hosts, tools=tools, intensity=Intensity.STANDARD, targets=targets, excludes=[]
    )
    standard_ids = {j.tool_id for j in standard}
    assert "feroxbuster" in standard_ids
    assert "gowitness" in standard_ids
    assert "netexec-ldap" not in standard_ids  # no ldap ports in fixture
    assert "onesixtyone" in standard_ids

    loud = plan_jobs(
        hosts=hosts, tools=tools, intensity=Intensity.LOUD, targets=targets, excludes=[]
    )
    assert any(j.tool_id == "snmpwalk" for j in loud)

    excluded = plan_jobs(
        hosts=hosts,
        tools=tools,
        intensity=Intensity.STANDARD,
        targets=targets,
        excludes=["10.10.10.5"],
    )
    assert all(j.host != "10.10.10.5" for j in excluded)


def _host_and_port(
    ip: str = "10.0.0.1", port_num: int = 80, svc: str = "http"
) -> tuple[Host, Port]:
    port = Port(port_num, "tcp", "open", service=svc)
    host = Host(ip=ip, ports=[port])
    return host, port


def test_interpolate_argv_basic(tmp_path: Path) -> None:
    host, port = _host_and_port()
    out = tmp_path / "out.txt"
    result = interpolate_argv(
        ["{host}", "{port}", "{outfile}"],
        host=host,
        port=port,
        outfile=out,
        wordlist=None,
        wordlist_loud=None,
    )
    assert result == [host.ip, str(port.number), str(out)]


def test_interpolate_argv_url_http(tmp_path: Path) -> None:
    host, port = _host_and_port(port_num=80, svc="http")
    result = interpolate_argv(
        ["{url}"],
        host=host,
        port=port,
        outfile=tmp_path / "o.txt",
        wordlist=None,
        wordlist_loud=None,
    )
    assert result[0].startswith("http://")
    assert "443" not in result[0]


def test_interpolate_argv_url_https(tmp_path: Path) -> None:
    port = Port(443, "tcp", "open", service="https", tunnel="ssl")
    host = Host(ip="10.0.0.1", ports=[port])
    result = interpolate_argv(
        ["{url}"],
        host=host,
        port=port,
        outfile=tmp_path / "o.txt",
        wordlist=None,
        wordlist_loud=None,
    )
    assert result[0].startswith("https://")
    # Default HTTPS port — no port number in URL
    assert ":443" not in result[0]


def test_interpolate_argv_forbidden_user(tmp_path: Path) -> None:
    host, port = _host_and_port()
    with pytest.raises(PluginError, match="credential"):
        interpolate_argv(
            ["{host}", "{user}"],
            host=host,
            port=port,
            outfile=tmp_path / "o.txt",
            wordlist=None,
            wordlist_loud=None,
        )


def test_interpolate_argv_forbidden_pass(tmp_path: Path) -> None:
    host, port = _host_and_port()
    with pytest.raises(PluginError, match="credential"):
        interpolate_argv(
            ["{host}", "{pass}"],
            host=host,
            port=port,
            outfile=tmp_path / "o.txt",
            wordlist=None,
            wordlist_loud=None,
        )


def test_interpolate_argv_forbidden_creds(tmp_path: Path) -> None:
    host, port = _host_and_port()
    with pytest.raises(PluginError, match="credential"):
        interpolate_argv(
            ["{creds}"],
            host=host,
            port=port,
            outfile=tmp_path / "o.txt",
            wordlist=None,
            wordlist_loud=None,
        )


def test_interpolate_argv_empty_after_missing_wordlist(tmp_path: Path) -> None:
    host, port = _host_and_port()
    with pytest.raises(PluginError, match="empty"):
        interpolate_argv(
            ["{wordlist}"],
            host=host,
            port=port,
            outfile=tmp_path / "o.txt",
            wordlist=None,  # no wordlist → empty string → raises
            wordlist_loud=None,
        )
