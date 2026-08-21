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


def test_scan_dry_run(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["scan", "10.0.0.1", "--dry-run", "--mode", "lab", "--intensity", "stealth"]
    )
    assert result.exit_code == 0, result.output
    assert "Dry run" in result.output
    assert "nmap" in result.output.lower()


def test_finding_edit(tmp_path: Path, nmap_xml: Path) -> None:
    out = tmp_path / "vault-edit"
    runner.invoke(
        app,
        ["ingest", str(nmap_xml), "--out", str(out), "--client", "acme"],
    )
    runner.invoke(
        app,
        [
            "finding", "add", "--out", str(out),
            "--title", "Initial title",
            "--cvss", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "--hosts", "10.10.10.5",
        ],
    )
    edit = runner.invoke(
        app,
        [
            "finding", "edit", "F-001", "--out", str(out),
            "--title", "Updated title",
            "--status", "confirmed",
        ],
    )
    assert edit.exit_code == 0, edit.output
    assert "updated" in edit.output.lower() or "F-001" in edit.output
    finding_file = next((out / "03-findings").glob("F-001-*.md"))
    text = finding_file.read_text(encoding="utf-8")
    assert "Updated title" in text
    assert "confirmed" in text


def test_finding_add_from_lead(tmp_path: Path, nmap_xml: Path) -> None:
    out = tmp_path / "vault-lead"
    runner.invoke(
        app,
        ["ingest", str(nmap_xml), "--out", str(out), "--client", "acme"],
    )
    # Create a minimal lead note
    lead_note = out / "04-leads" / "test-lead.md"
    lead_note.parent.mkdir(parents=True, exist_ok=True)
    lead_note.write_text(
        "<!-- va:managed -->\n"
        "---\n"
        'tags: [lead, unverified, lab]\n'
        'host: "10.10.10.5"\n'
        'product: "Apache httpd"\n'
        'version: "2.4.52"\n'
        "---\n\n# Lead\n",
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        [
            "finding", "add", "--out", str(out),
            "--from-lead", str(lead_note),
            "--cvss", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        ],
    )
    assert result.exit_code == 0, result.output
    files = list((out / "03-findings").glob("F-*.md"))
    assert files
    text = files[0].read_text(encoding="utf-8")
    assert "Apache" in text or "10.10.10.5" in text


def test_status_severity_bar(tmp_path: Path, nmap_xml: Path) -> None:
    out = tmp_path / "vault-sev"
    runner.invoke(
        app,
        ["ingest", str(nmap_xml), "--out", str(out), "--client", "acme"],
    )
    runner.invoke(
        app,
        [
            "finding", "add", "--out", str(out),
            "--title", "Test finding",
            "--cvss", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "--hosts", "10.10.10.5",
        ],
    )
    status = runner.invoke(app, ["status", "--out", str(out)])
    assert status.exit_code == 0
    # Severity bar should appear somewhere in the output
    assert "critical" in status.output or "■" in status.output
