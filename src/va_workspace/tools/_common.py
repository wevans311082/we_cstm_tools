"""Shared CLI helpers for probe modules."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def probe_parser(description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--out", default="-")
    parser.add_argument("--timeout", type=float, default=6.0)
    return parser


def emit(path: str, payload: dict[str, Any]) -> None:
    text = json.dumps(payload, indent=2, default=str) + "\n"
    if path in {"", "-"}:
        print(text, end="")
        return
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")
