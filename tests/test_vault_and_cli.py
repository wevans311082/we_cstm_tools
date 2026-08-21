from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from va_workspace.cli import app
from va_workspace.constants import MANAGED_HEADER
from va_workspace.core.cvss import base_score

runner = CliRunner()


def test_doctor_exits_when_nmap_missing() -> None:
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code in {0, 1}
    assert "va doctor" in result.stdout or "nmap" in result.stdout + result.stderr


def test_ingest_and_finding(tmp_path: Path, nmap_xml: Path) -> None:
    out = tmp_path / "vault"
    result = runner.invoke(
        app,
        ["ingest", str(nmap_xml), "--out", str(out), "--client", "acme", "--mode", "check"],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    assert (out / "engagement.md").is_file()
    assert (out / "state.json").is_file()
    assert (out / "00-report" / "01-cover-and-people.md").is_file()
    host_note = out / "02-hosts" / "10.10.10.5" / "host.md"
    assert host_note.is_file()
    text = host_note.read_text(encoding="utf-8")
    assert MANAGED_HEADER in text
    assert "10.10.10.5" in text
    assert "domain-controller" in text
    assert (out / "01-overview" / "network.canvas").is_file()
    assert (out / "01-overview" / "attachments" / "services-bar.png").is_file()
    assert (out / "01-overview" / "attack-surface.md").is_file()
    assert (out / "01-overview" / "tls.md").is_file()
    assert (out / "01-overview" / "smb.md").is_file()
    assert (out / "01-overview" / "certs.md").is_file()
    assert (out / "01-overview" / "nse-results.md").is_file()
    leads = list((out / "04-leads").glob("nse-*.md"))
    assert leads
    dashboard = (out / "01-overview" / "dashboard.md").read_text(encoding="utf-8")
    assert "dataview" in dashboard

    add = runner.invoke(
        app,
        [
            "finding",
            "add",
            "--out",
            str(out),
            "--title",
            "Anonymous SMB share",
            "--cvss",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "--hosts",
            "10.10.10.5",
            "--ports",
            "445/tcp",
            "--description",
            "Null session enumerated share list.",
            "--short-term",
            "Disable guest / null sessions.",
            "--strategic",
            "Hardening GPO; remove leftover shares.",
        ],
    )
    assert add.exit_code == 0, add.stdout + add.stderr
    score = base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
    listed = runner.invoke(app, ["finding", "list", "--out", str(out)])
    assert listed.exit_code == 0
    assert "F-001" in listed.stdout
    listed_l = listed.stdout.lower()
    assert str(score) in listed.stdout or "medium" in listed_l or "low" in listed_l

    templated = runner.invoke(
        app,
        ["finding", "add", "--out", str(out), "--template", "smb-signing", "--hosts", "10.10.10.5"],
    )
    assert templated.exit_code == 0, templated.stdout + templated.stderr
    listed2 = runner.invoke(app, ["finding", "list", "--out", str(out)])
    assert "F-002" in listed2.stdout

    status = runner.invoke(app, ["status", "--out", str(out)])
    assert status.exit_code == 0
    assert "acme" in status.stdout
    assert "check" in status.stdout


def test_init(tmp_path: Path) -> None:
    out = tmp_path / "init-vault"
    result = runner.invoke(
        app,
        ["init", "--client", "labnet", "--mode", "lab", "--out", str(out), "--tester", "Wayne"],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    assert (out / "rules-of-engagement.md").is_file()
    assert (out / "08-pre-engagement" / "checklist.md").is_file()
    cover = (out / "00-report" / "01-cover-and-people.md").read_text(encoding="utf-8")
    assert "Wayne" in cover


def test_scan_refuses_non_linux(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", "10.0.0.1", "--out", str(tmp_path / "scan-out")])
    # CliRunner mixes stderr into output by default; use .output (not .stderr)
    combined = result.output
    assert result.exit_code != 0
    assert "Linux" in combined or "nmap" in combined.lower() or "TARGET" in combined
