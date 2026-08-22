from __future__ import annotations

from pathlib import Path

from va_workspace.core.portsplit import parse_ports_expr, ports_to_expr, split_ports
from va_workspace.core.snap import capture_region, import_latest_picture, snap_status
from va_workspace.tools.smb_unauth import probe as smb_probe
from va_workspace.tools.tls_versions import probe as tls_probe


def test_snap_status_reports_missing_backend(monkeypatch: object) -> None:
    from va_workspace.core import snap as snap_mod

    monkeypatch.setattr(snap_mod, "detect_capture_backend", lambda: None)  # type: ignore[attr-defined]
    monkeypatch.setattr(snap_mod, "detect_clipboard_backend", lambda: None)  # type: ignore[attr-defined]
    status = snap_status()
    assert not status.ready
    assert not status.listening
    assert any("screenshot backend" in hint for hint in status.hints())
    assert "missing" in status.summary()


def test_live_feed_records_hosts_and_ports(tmp_path: Path) -> None:
    from va_workspace.core.live_feed import LIVE_NOTE, LiveFeed

    feed = LiveFeed(tmp_path, "nmap TCP scan")
    feed.feed("Nmap scan report for host.example (10.0.0.5)")
    feed.feed("Discovered open port 443/tcp on 10.0.0.5")
    feed.feed("Discovered open port 443/tcp on 10.0.0.5")  # duplicate is ignored
    feed.feed("80/tcp   open  http    nginx 1.24")
    feed.feed("Read data files from: /usr/share/nmap")

    assert feed.hosts_found == 1
    assert feed.ports_found == 2
    body = (tmp_path / LIVE_NOTE).read_text(encoding="utf-8")
    assert "10.0.0.5" in body
    assert "**443/tcp** open" in body
    assert "**80/tcp** open http" in body


def test_smb_unauth_probe_handles_refused() -> None:
    result = smb_probe("127.0.0.1", 1, timeout=0.3)
    assert result["probe"] == "smb_unauth"
    assert "error" in result or result["smb2"] == "no"


def test_tls_probe_refused() -> None:
    result = tls_probe("127.0.0.1", 1, timeout=0.3)
    assert result["probe"] == "tls_versions"
    assert result["legacy_tls"] == "no"


def test_port_split() -> None:
    ports = parse_ports_expr("80,443,8000-8002")
    assert ports == [80, 443, 8000, 8001, 8002]
    assert ports_to_expr(ports) == "80,443,8000-8002"
    chunks = split_ports("1-10", 2)
    assert len(chunks) == 2
    assert parse_ports_expr("-")[0] == 1
    assert parse_ports_expr("-")[-1] == 65535


def test_grab_imports_latest(tmp_path: Path) -> None:
    pictures = tmp_path / "Pictures"
    pictures.mkdir()
    (pictures / "old.png").write_bytes(b"old")
    newest = pictures / "new.png"
    newest.write_bytes(b"\x89PNG\r\n")
    newest.touch()
    vault = tmp_path / "vault"
    vault.mkdir()
    result = import_latest_picture(
        engagement=vault, name="login-page", pictures=pictures
    )
    assert result.status == "ok"
    assert result.path is not None
    assert result.path.parent.name == "screenshots"
    assert "login-page" in result.path.name
    diary = (vault / "06-logs" / "diary.md").read_text(encoding="utf-8")
    assert "login-page" in diary or "screenshot" in diary


def test_snap_cancel_is_not_an_error(tmp_path: Path, monkeypatch: object) -> None:
    from va_workspace.core import snap as snap_mod

    monkeypatch.setattr(snap_mod, "detect_capture_backend", lambda: "maim")

    class FakeProc:
        returncode = 1
        stdout = b""
        stderr = b"selection cancelled"

    monkeypatch.setattr(snap_mod, "_run", lambda *a, **k: FakeProc())
    result = capture_region(engagement=tmp_path, clipboard=False)
    assert result.status == "cancel"
