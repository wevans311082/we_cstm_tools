"""Evidence snapper: region screenshot → vault, clipboard, Obsidian wikilink.

Fixes vs the old scrptn.py:
- Esc/cancel on maim is not treated as a hard error (nonzero + no file).
- Overlapping hotkeys cannot spawn a second selector (lock).
- notify-send failure does not fail the capture.
- X11 (maim) and Wayland (grim+slurp) both work.
- Files land in the engagement vault, not a hardcoded Documents folder.
- Optional host folder + diary wikilink.
"""

from __future__ import annotations

import os
import subprocess
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from va_workspace.core.engagement import resolve_engagement_dir
from va_workspace.core.state import utc_now
from va_workspace.util import log
from va_workspace.util.shell import which

_BUSY = threading.Lock()


@dataclass
class CaptureResult:
    status: str  # ok | cancel | error
    path: Path | None
    message: str


def detect_capture_backend() -> str | None:
    wayland = bool(os.environ.get("WAYLAND_DISPLAY")) or (
        os.environ.get("XDG_SESSION_TYPE") == "wayland"
    )
    if wayland and which("grim") and which("slurp"):
        return "grim"
    if which("maim"):
        return "maim"
    if which("gnome-screenshot"):
        return "gnome"
    if which("scrot"):
        return "scrot"
    return None


def detect_clipboard_backend() -> str | None:
    wayland = bool(os.environ.get("WAYLAND_DISPLAY")) or (
        os.environ.get("XDG_SESSION_TYPE") == "wayland"
    )
    if wayland and which("wl-copy"):
        return "wl-copy"
    if which("xclip"):
        return "xclip"
    return None


def screenshot_dir(engagement: Path, host: str | None) -> Path:
    if host:
        dest = engagement / "02-hosts" / host.replace(":", "_") / "evidence"
    else:
        dest = engagement / "06-logs" / "screenshots"
    dest.mkdir(parents=True, exist_ok=True)
    return dest


def _run(argv: list[str], *, stdin: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        argv,
        input=stdin,
        capture_output=True,
        check=False,
    )


def _capture_to(dest: Path, backend: str) -> CaptureResult:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        dest.unlink()

    if backend == "maim":
        proc = _run(["maim", "-s", "-u", str(dest)])
    elif backend == "grim":
        slurp = _run(["slurp"])
        if slurp.returncode != 0 or not slurp.stdout.strip():
            return CaptureResult("cancel", None, "region select cancelled")
        geom = slurp.stdout.decode("utf-8", errors="replace").strip()
        proc = _run(["grim", "-g", geom, str(dest)])
    elif backend == "gnome":
        proc = _run(["gnome-screenshot", "-a", "-f", str(dest)])
    elif backend == "scrot":
        proc = _run(["scrot", "-s", str(dest)])
    else:
        return CaptureResult("error", None, f"unknown backend {backend}")

    exists = dest.is_file() and dest.stat().st_size > 0
    if proc.returncode != 0 and not exists:
        # maim/slurp/scrot exit 1 on Esc — that is cancel, not failure
        return CaptureResult("cancel", None, "screenshot cancelled")
    if not exists:
        return CaptureResult("error", None, "screenshot produced an empty file")
    return CaptureResult("ok", dest, "captured")


def copy_png_to_clipboard(path: Path) -> str | None:
    backend = detect_clipboard_backend()
    if backend is None:
        return "no clipboard tool (install xclip or wl-copy)"
    data = path.read_bytes()
    if backend == "xclip":
        proc = _run(
            ["xclip", "-selection", "clipboard", "-t", "image/png"],
            stdin=data,
        )
    else:
        proc = _run(["wl-copy", "-t", "image/png"], stdin=data)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout).decode("utf-8", errors="replace")[:200]
        return err or "clipboard failed"
    return None


def notify(title: str, body: str) -> None:
    binary = which("notify-send")
    if binary is None:
        return
    _run([str(binary), title, body])


def _stamp_name(name: str | None) -> str:
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    if name:
        slug = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in name).strip("-")
        return f"{stamp}_{slug}.png"
    return f"evidence_{stamp}.png"


def append_wikilink(engagement: Path, rel: str, caption: str) -> None:
    diary = engagement / "06-logs" / "diary.md"
    diary.parent.mkdir(parents=True, exist_ok=True)
    with diary.open("a", encoding="utf-8") as handle:
        handle.write(f"- {utc_now()} screenshot {caption}\n")
        handle.write(f"  ![[{rel}]]\n")
    gallery = engagement / "06-logs" / "screenshots.md"
    if not gallery.is_file():
        gallery.write_text("# Screenshots\n\n", encoding="utf-8")
    with gallery.open("a", encoding="utf-8") as handle:
        handle.write(f"![[{rel}]]\n\n*{caption}*\n\n")


def capture_region(
    *,
    engagement: Path,
    name: str | None = None,
    host: str | None = None,
    clipboard: bool = True,
) -> CaptureResult:
    backend = detect_capture_backend()
    if backend is None:
        return CaptureResult(
            "error",
            None,
            "no screenshot backend (install maim on X11, or grim+slurp on Wayland)",
        )
    dest = screenshot_dir(engagement, host) / _stamp_name(name)
    if not _BUSY.acquire(blocking=False):
        return CaptureResult("error", None, "capture already in progress")
    try:
        result = _capture_to(dest, backend)
        if result.status != "ok" or result.path is None:
            return result
        if clipboard:
            clip_err = copy_png_to_clipboard(result.path)
            if clip_err:
                log.warn(f"clipboard: {clip_err}")
        rel = result.path.relative_to(engagement).as_posix()
        append_wikilink(engagement, rel, name or result.path.name)
        notify("va snap", f"Saved {result.path.name}")
        result.message = f"saved {result.path}"
        return result
    finally:
        _BUSY.release()


def import_latest_picture(
    *,
    engagement: Path,
    name: str | None,
    host: str | None = None,
    pictures: Path | None = None,
) -> CaptureResult:
    folder = pictures or (Path.home() / "Pictures")
    if not folder.is_dir():
        return CaptureResult("error", None, f"no pictures folder: {folder}")
    candidates = [
        p
        for p in folder.iterdir()
        if p.is_file() and p.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp"}
    ]
    if not candidates:
        return CaptureResult("error", None, f"no images in {folder}")
    latest = max(candidates, key=lambda p: p.stat().st_mtime)
    dest = screenshot_dir(engagement, host) / _stamp_name(name or latest.stem)
    dest.write_bytes(latest.read_bytes())
    rel = dest.relative_to(engagement).as_posix()
    append_wikilink(engagement, rel, name or dest.name)
    copy_png_to_clipboard(dest)
    notify("va grab", f"Imported {dest.name}")
    return CaptureResult("ok", dest, f"imported {latest.name} → {dest}")


def resolve_vault(out: Path | None) -> Path | None:
    return resolve_engagement_dir(out, Path.cwd())


def listen_hotkey(engagement: Path, hotkey: str) -> None:
    try:
        from pynput import keyboard  # type: ignore[import-untyped]
    except ImportError as exc:
        raise RuntimeError(
            "hotkey listener needs pynput: pipx inject va-workspace pynput"
        ) from exc

    def on_activate() -> None:
        thread = threading.Thread(
            target=_hotkey_capture,
            args=(engagement,),
            daemon=True,
        )
        thread.start()

    log.info(f"va snap listening for {hotkey}  → {engagement}")
    log.info("Ctrl+C to stop")
    try:
        with keyboard.GlobalHotKeys({hotkey: on_activate}) as listener:
            listener.join()
    except KeyboardInterrupt:
        log.info("stopped")


def _hotkey_capture(engagement: Path) -> None:
    result = capture_region(engagement=engagement)
    if result.status == "ok":
        log.success(result.message)
    elif result.status == "cancel":
        log.warn("cancelled")
    else:
        log.error(result.message)
