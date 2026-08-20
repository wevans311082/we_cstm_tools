from __future__ import annotations

from pathlib import Path

from va_workspace.core.portsplit import parse_ports_expr, ports_to_expr, split_ports
from va_workspace.core.snap import capture_region, import_latest_picture


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
