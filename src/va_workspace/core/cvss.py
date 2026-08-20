"""CVSS v3.1 base score calculator (FIRST specification)."""

from __future__ import annotations

import math
import re

_VECTOR_RE = re.compile(
    r"^CVSS:3\.1"
    r"/AV:(?P<AV>[NALP])"
    r"/AC:(?P<AC>[LH])"
    r"/PR:(?P<PR>[NLH])"
    r"/UI:(?P<UI>[NR])"
    r"/S:(?P<S>[UC])"
    r"/C:(?P<C>[NLH])"
    r"/I:(?P<I>[NLH])"
    r"/A:(?P<A>[NLH])"
    r"$"
)

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}


class CvssError(ValueError):
    """Invalid CVSS 3.1 vector."""


def roundup(value: float) -> float:
    """CVSS 3.1 roundup from the FIRST specification."""
    if value <= 0:
        return 0.0
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000.0
    return (math.floor(int_input / 10_000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    cleaned = vector.strip().upper().replace(" ", "")
    match = _VECTOR_RE.match(cleaned)
    if not match:
        raise CvssError(
            "CVSS vector must look like CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )
    return match.groupdict()


def base_score(vector: str) -> float:
    metrics = parse_vector(vector)
    iss = 1 - (
        (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
    )
    if metrics["S"] == "U":
        impact = 6.42 * iss
        pr = _PR_UNCHANGED[metrics["PR"]]
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        pr = _PR_CHANGED[metrics["PR"]]
    exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr * _UI[metrics["UI"]]
    if impact <= 0:
        return 0.0
    if metrics["S"] == "U":
        return roundup(min(impact + exploitability, 10))
    return roundup(min(1.08 * (impact + exploitability), 10))


def severity_from_score(score: float) -> str:
    if score == 0:
        return "none"
    if score <= 3.9:
        return "low"
    if score <= 6.9:
        return "medium"
    if score <= 8.9:
        return "high"
    return "critical"
