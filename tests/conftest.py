from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def nmap_xml() -> Path:
    return FIXTURES / "nmap" / "mixed-lab.xml"
