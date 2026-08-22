from __future__ import annotations

import re
import tomllib
from importlib import metadata
from pathlib import Path

import pytest

from va_workspace import __version__

PEP440 = re.compile(r"^\d+\.\d+\.\d+(?:[-.]?(?:a|b|rc|dev|post)\d+)?$")
PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_version_is_pep440() -> None:
    assert PEP440.match(__version__), f"{__version__!r} is not a bumpable release version"


def test_pyproject_takes_its_version_from_the_package() -> None:
    """Version must live in exactly one place or pipx upgrade sees a stale number."""
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    project = data["project"]

    assert "version" not in project, "hard-coded version in pyproject will drift from __init__"
    assert "version" in project.get("dynamic", [])
    assert data["tool"]["setuptools"]["dynamic"]["version"] == {"attr": "va_workspace.__version__"}


def test_installed_distribution_matches_source() -> None:
    """Catches an editable install left pointing at an older build."""
    try:
        installed = metadata.version("va-workspace")
    except metadata.PackageNotFoundError:
        pytest.skip("va-workspace is not installed in this environment")
    assert installed == __version__
