"""Record a shell session into the vault: raw typescript plus a clean command log.

`script(1)` captures everything on the terminal (the raw log). A PROMPT_COMMAND hook
in the recorded bash writes one tab-separated row per command entered at the prompt,
which becomes the command log. Recording starts when the shell starts and ends on exit.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from va_workspace.core.state import utc_now
from va_workspace.util import log
from va_workspace.util.shell import which

TRANSCRIPT_DIR = Path("06-logs") / "transcripts"
_ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|[\x00-\x08\x0b\x0c\x0e-\x1f]")

# Installed into the recorded shell; one row per prompt-entered command.
_HOOK = r"""
# --- va transcript hook ---
__VA_LAST_NUM=""
__VA_PRIMED=""
__va_capture() {
  local __va_status=$?
  local HISTTIMEFORMAT=
  local __va_raw
  __va_raw=$(builtin history 1)
  if [[ $__va_raw =~ ^[[:space:]]*([0-9]+)[[:space:]]+(.*)$ ]]; then
    local __va_num="${BASH_REMATCH[1]}"
    local __va_cmd="${BASH_REMATCH[2]}"
    if [[ -z $__VA_PRIMED ]]; then
      # First prompt: whatever is in history predates the recording.
      __VA_PRIMED=1
      __VA_LAST_NUM="$__va_num"
      return $__va_status
    fi
    if [[ -n $__va_cmd && $__va_num != "$__VA_LAST_NUM" ]]; then
      printf '%s\t%s\t%s\t%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$__va_status" "$PWD" "$__va_cmd" \
        >> "$VA_CMD_LOG"
      __VA_LAST_NUM="$__va_num"
    fi
  fi
  return $__va_status
}
if declare -p PROMPT_COMMAND 2>/dev/null | grep -q 'declare -a'; then
  PROMPT_COMMAND+=(__va_capture)
else
  PROMPT_COMMAND="__va_capture${PROMPT_COMMAND:+; $PROMPT_COMMAND}"
fi
PS1="(va-rec) $PS1"
# --- end va transcript hook ---
"""


@dataclass
class Transcript:
    name: str
    raw: Path
    commands: Path
    tsv: Path
    rcfile: Path

    def exists(self) -> bool:
        return self.raw.is_file()


class TranscriptError(RuntimeError):
    """Raised when the host cannot record a shell session."""


def transcript_dir(engagement: Path) -> Path:
    path = engagement / TRANSCRIPT_DIR
    path.mkdir(parents=True, exist_ok=True)
    return path


def _slug(name: str | None) -> str:
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    if not name:
        return stamp
    clean = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in name).strip("-")
    return f"{stamp}_{clean}" if clean else stamp


def paths_for(engagement: Path, name: str | None) -> Transcript:
    base = transcript_dir(engagement)
    slug = _slug(name)
    return Transcript(
        name=slug,
        raw=base / f"{slug}.raw.log",
        commands=base / f"{slug}.commands.md",
        tsv=base / f"{slug}.commands.tsv",
        rcfile=base / f".{slug}.bashrc",
    )


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text.replace("\r\n", "\n"))


def require_recorder() -> Path:
    if not sys.platform.startswith("linux") and sys.platform != "darwin":
        raise TranscriptError("va transcript records a bash session; use Kali/Linux")
    binary = which("script")
    if binary is None:
        raise TranscriptError("script(1) not found. Run: sudo apt install bsdutils util-linux")
    if which("bash") is None:
        raise TranscriptError("bash not found on PATH")
    return binary


def write_rcfile(session: Transcript, engagement: Path) -> Path:
    session.rcfile.write_text(
        "\n".join(
            [
                "[ -f /etc/bash.bashrc ] && . /etc/bash.bashrc",
                '[ -f "$HOME/.bashrc" ] && . "$HOME/.bashrc"',
                f'export VA_CMD_LOG="{session.tsv}"',
                f'export VA_ENGAGEMENT="{engagement}"',
                f'export VA_TRANSCRIPT="{session.name}"',
                # ignorespace keeps the deliberate "prefix with a space to hide it" escape hatch.
                "export HISTCONTROL=ignorespace",
                "shopt -s histappend 2>/dev/null",
                _HOOK,
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return session.rcfile


def build_argv(recorder: Path, session: Transcript, shell_command: str | None) -> list[str]:
    inner = f'bash --rcfile "{session.rcfile}" -i'
    if shell_command:
        inner = f'bash --rcfile "{session.rcfile}" -i -c {shell_command!r}'
    return [str(recorder), "-q", "-f", "-c", inner, str(session.raw)]


def parse_tsv(path: Path) -> list[tuple[str, str, str, str]]:
    if not path.is_file():
        return []
    rows: list[tuple[str, str, str, str]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split("\t", 3)
        if len(parts) == 4:
            rows.append((parts[0], parts[1], parts[2], parts[3]))
    return rows


def write_command_log(session: Transcript, engagement: Path) -> int:
    """Render the tab-separated capture into an Obsidian-friendly command log."""
    rows = parse_tsv(session.tsv)
    raw_rel = session.raw.relative_to(engagement).as_posix()
    lines = [
        f"# Command log — {session.name}",
        "",
        f"Raw terminal capture: `{raw_rel}`",
        f"Commands recorded: {len(rows)}",
        "",
        "> Commands typed with a leading space are not recorded here, but their",
        "> output still appears in the raw capture.",
        "",
    ]
    if not rows:
        lines.append("_No commands captured._")
    last_cwd = ""
    for stamp, status, cwd, command in rows:
        if cwd != last_cwd:
            lines.extend(["", f"### `{cwd}`", ""])
            last_cwd = cwd
        marker = "" if status == "0" else f"  <!-- exit {status} -->"
        lines.append(f"- `{stamp}` `{command}`{marker}")
    session.commands.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(rows)


def append_diary(engagement: Path, session: Transcript, count: int) -> None:
    diary = engagement / "06-logs" / "diary.md"
    diary.parent.mkdir(parents=True, exist_ok=True)
    rel = session.commands.relative_to(engagement).as_posix()
    with diary.open("a", encoding="utf-8") as handle:
        handle.write(f"- {utc_now()} transcript {session.name} ({count} command(s))\n")
        handle.write(f"  [[{rel}]]\n")


def list_transcripts(engagement: Path) -> list[Transcript]:
    base = engagement / TRANSCRIPT_DIR
    if not base.is_dir():
        return []
    sessions: list[Transcript] = []
    for raw in sorted(base.glob("*.raw.log")):
        name = raw.name.removesuffix(".raw.log")
        sessions.append(
            Transcript(
                name=name,
                raw=raw,
                commands=base / f"{name}.commands.md",
                tsv=base / f"{name}.commands.tsv",
                rcfile=base / f".{name}.bashrc",
            )
        )
    return sessions


def find_transcript(engagement: Path, name: str) -> Transcript:
    sessions = list_transcripts(engagement)
    matches = [s for s in sessions if s.name == name] or [s for s in sessions if name in s.name]
    if not matches:
        raise FileNotFoundError(f"no transcript matching {name!r}")
    return matches[-1]


def record(engagement: Path, name: str | None, *, shell_command: str | None = None) -> Transcript:
    """Run a recorded interactive bash. Blocks until the operator exits the shell."""
    from va_workspace.util.shell import run_interactive

    recorder = require_recorder()
    session = paths_for(engagement, name)
    write_rcfile(session, engagement)
    session.tsv.touch()
    argv = build_argv(recorder, session, shell_command)

    env = dict(os.environ)
    env["VA_CMD_LOG"] = str(session.tsv)
    env["VA_ENGAGEMENT"] = str(engagement)

    log.info(f"recording shell → {session.raw}")
    log.info("everything typed here is logged. type `exit` to stop recording.")
    try:
        run_interactive(argv, env=env)
    finally:
        count = write_command_log(session, engagement)
        append_diary(engagement, session, count)
        session.rcfile.unlink(missing_ok=True)
    return session
