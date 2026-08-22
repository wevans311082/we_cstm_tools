from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from va_workspace.cli import app
from va_workspace.core.transcript import (
    TRANSCRIPT_DIR,
    build_argv,
    find_transcript,
    list_transcripts,
    parse_tsv,
    paths_for,
    strip_ansi,
    write_command_log,
    write_rcfile,
)

runner = CliRunner()


def test_transcript_without_out_resolves_its_options(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: the no-subcommand path used to pass OptionInfo defaults through as values."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["--no-snap-check", "transcript"])

    assert not isinstance(result.exception, TypeError)
    assert "unsupported operand" not in result.output
    # tmp_path is not an engagement directory, so this is the expected rejection.
    assert result.exit_code == 2


def test_transcript_start_matches_the_bare_invocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    bare = runner.invoke(app, ["--no-snap-check", "transcript"])
    explicit = runner.invoke(app, ["--no-snap-check", "transcript", "start"])

    assert bare.exit_code == explicit.exit_code == 2
    assert not isinstance(bare.exception, TypeError)
    assert not isinstance(explicit.exception, TypeError)


def test_transcript_list_reports_empty_vault(tmp_path: Path) -> None:
    result = runner.invoke(app, ["--no-snap-check", "transcript", "list", "--out", str(tmp_path)])

    assert not isinstance(result.exception, TypeError)
    assert result.exit_code == 1


def _session(tmp_path: Path, name: str = "demo"):
    session = paths_for(tmp_path, name)
    session.raw.write_text("terminal output\n", encoding="utf-8")
    return session


def test_paths_land_under_the_vault(tmp_path: Path) -> None:
    session = paths_for(tmp_path, "recon phase/1")
    assert session.raw.parent == tmp_path / TRANSCRIPT_DIR
    assert session.raw.name.endswith(".raw.log")
    assert session.commands.name.endswith(".commands.md")
    assert "recon-phase-1" in session.name


def test_strip_ansi_cleans_terminal_control_codes() -> None:
    raw = "\x1b[1;32mroot@kali\x1b[0m:~# ls\r\nfile\r\n"
    assert strip_ansi(raw) == "root@kali:~# ls\nfile\n"


def test_parse_tsv_ignores_malformed_rows(tmp_path: Path) -> None:
    session = _session(tmp_path)
    session.tsv.write_text(
        "2026-08-22T10:00:00Z\t0\t/root\tnmap -sV 10.0.0.1\n"
        "junk line without tabs\n"
        "2026-08-22T10:01:00Z\t1\t/root\tcat missing\n",
        encoding="utf-8",
    )
    rows = parse_tsv(session.tsv)
    assert len(rows) == 2
    assert rows[0][3] == "nmap -sV 10.0.0.1"
    assert rows[1][1] == "1"


def test_command_log_groups_by_directory(tmp_path: Path) -> None:
    session = _session(tmp_path)
    session.tsv.write_text(
        "2026-08-22T10:00:00Z\t0\t/root\tnmap -sV 10.0.0.1\n"
        "2026-08-22T10:01:00Z\t0\t/root\twhoami\n"
        "2026-08-22T10:02:00Z\t2\t/tmp\tls /nope\n",
        encoding="utf-8",
    )
    count = write_command_log(session, tmp_path)
    body = session.commands.read_text(encoding="utf-8")

    assert count == 3
    assert body.count("### `/root`") == 1
    assert body.count("### `/tmp`") == 1
    assert "`nmap -sV 10.0.0.1`" in body
    assert "<!-- exit 2 -->" in body
    assert "06-logs/transcripts" in body


def test_command_log_handles_empty_session(tmp_path: Path) -> None:
    session = _session(tmp_path)
    assert write_command_log(session, tmp_path) == 0
    assert "_No commands captured._" in session.commands.read_text(encoding="utf-8")


def test_rcfile_installs_prompt_hook(tmp_path: Path) -> None:
    session = paths_for(tmp_path, "hooked")
    write_rcfile(session, tmp_path)
    body = session.rcfile.read_text(encoding="utf-8")

    assert 'export VA_CMD_LOG="' + str(session.tsv) + '"' in body
    assert "PROMPT_COMMAND=" in body
    assert "__va_capture" in body
    assert '. "$HOME/.bashrc"' in body
    assert "HISTCONTROL=ignorespace" in body
    assert "__VA_PRIMED" in body
    assert "PROMPT_COMMAND+=(__va_capture)" in body


def test_build_argv_wraps_bash_in_script(tmp_path: Path) -> None:
    session = paths_for(tmp_path, "demo")
    recorder = Path("/usr/bin/script")
    argv = build_argv(recorder, session, None)
    assert argv[0] == str(recorder)
    assert "-q" in argv and "-f" in argv
    assert argv[-1] == str(session.raw)
    assert str(session.rcfile) in argv[argv.index("-c") + 1]


def test_build_argv_records_a_single_command(tmp_path: Path) -> None:
    session = paths_for(tmp_path, "oneshot")
    argv = build_argv(Path("/usr/bin/script"), session, "nmap -sV 10.0.0.1")
    inner = argv[argv.index("-c") + 1]
    assert "nmap -sV 10.0.0.1" in inner
    assert "-i -c" in inner


def test_list_and_find_transcripts(tmp_path: Path) -> None:
    _session(tmp_path, "alpha")
    _session(tmp_path, "beta")
    sessions = list_transcripts(tmp_path)
    assert len(sessions) == 2

    found = find_transcript(tmp_path, "beta")
    assert "beta" in found.name
    with pytest.raises(FileNotFoundError):
        find_transcript(tmp_path, "gamma")
