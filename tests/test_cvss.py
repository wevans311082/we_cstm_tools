from __future__ import annotations

import pytest

from va_workspace.core.cvss import CvssError, base_score, severity_from_score


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        # Original four vectors
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", 6.5),
        ("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        # Additional FIRST NVD reference vectors
        # S:C with low Impact — boundary around the roundup
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N", 7.2),
        # High severity boundary (8.9 → high, 9.0 → critical)
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.0),
        # Medium boundary (6.9)
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L", 6.3),
        # Low boundary (2.5) — local, high complexity, low privilege
        ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", 2.5),
        # Adjacent network vector
        ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.8),
        # Physical vector
        ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 6.8),
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


def test_severity_boundaries() -> None:
    # Inclusive upper bounds per CVSS spec
    assert severity_from_score(3.9) == "low"
    assert severity_from_score(4.0) == "medium"
    assert severity_from_score(6.9) == "medium"
    assert severity_from_score(7.0) == "high"
    assert severity_from_score(8.9) == "high"
    assert severity_from_score(9.0) == "critical"
    assert severity_from_score(10.0) == "critical"


def test_rejects_v2() -> None:
    with pytest.raises(CvssError):
        base_score("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P")


def test_rejects_truncated_vector() -> None:
    with pytest.raises(CvssError):
        base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")


def test_rejects_invalid_metric_value() -> None:
    with pytest.raises(CvssError):
        base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
