from __future__ import annotations

import pytest

from va_workspace.core.cvss import CvssError, base_score, severity_from_score


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", 6.5),
        ("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_known_vectors(vector: str, score: float) -> None:
    assert base_score(vector) == score


def test_severity() -> None:
    assert severity_from_score(9.8) == "critical"
    assert severity_from_score(7.5) == "high"
    assert severity_from_score(5.0) == "medium"
    assert severity_from_score(2.0) == "low"
    assert severity_from_score(0.0) == "none"


def test_rejects_v2() -> None:
    with pytest.raises(CvssError):
        base_score("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P")
