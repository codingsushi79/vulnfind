"""CVSS base-score calculation (v3.x exact, v2 exact, v4 approximated)."""

from __future__ import annotations

import math
from typing import Dict, Optional


def _parse(vector: str) -> Dict[str, str]:
    parts = {}
    for chunk in vector.split("/"):
        if ":" in chunk:
            k, v = chunk.split(":", 1)
            parts[k] = v
    return parts


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> Optional[float]:
    m = _parse(vector)
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
        ac = {"L": 0.77, "H": 0.44}[m["AC"]]
        ui = {"N": 0.85, "R": 0.62}[m["UI"]]
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        c, i, a = cia[m["C"]], cia[m["I"]], cia[m["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def cvss2_score(vector: str) -> Optional[float]:
    m = _parse(vector)
    try:
        av = {"L": 0.395, "A": 0.646, "N": 1.0}[m["AV"]]
        ac = {"H": 0.35, "M": 0.61, "L": 0.71}[m["AC"]]
        au = {"M": 0.45, "S": 0.56, "N": 0.704}[m["Au"]]
        cia = {"N": 0.0, "P": 0.275, "C": 0.660}
        c, i, a = cia[m["C"]], cia[m["I"]], cia[m["A"]]
    except KeyError:
        return None
    impact = 10.41 * (1 - (1 - c) * (1 - i) * (1 - a))
    exploitability = 20 * av * ac * au
    f = 0 if impact == 0 else 1.176
    return round((0.6 * impact + 0.4 * exploitability - 1.5) * f, 1)


def cvss4_estimate(vector: str) -> Optional[float]:
    """Rough CVSS v4 estimate. The real algorithm needs large lookup tables;
    this keeps the ordering sensible for triage (network + high impact = high)."""
    m = _parse(vector)
    if "AV" not in m:
        return None
    impact = {"H": 3, "L": 1, "N": 0}
    base = max(impact.get(m.get(k, "N"), 0) for k in ("VC", "VI", "VA"))
    sub = max(impact.get(m.get(k, "N"), 0) for k in ("SC", "SI", "SA"))
    score = 2.0 + base * 1.8 + sub * 0.4
    score += {"N": 1.2, "A": 0.6, "L": 0.0, "P": -1.0}.get(m["AV"], 0)
    score += 0.5 if m.get("AC") == "L" else -0.5
    score += {"N": 0.8, "L": 0.0, "H": -0.8}.get(m.get("PR", "N"), 0)
    score += {"N": 0.4, "P": -0.2, "A": -0.5}.get(m.get("UI", "N"), 0)
    if base == 0 and sub == 0:
        return 0.0
    return round(max(0.1, min(score, 10.0)), 1)


def score_vector(vector: str) -> Optional[float]:
    vector = vector.strip()
    if vector.startswith("CVSS:3"):
        return cvss3_score(vector)
    if vector.startswith("CVSS:4"):
        return cvss4_estimate(vector)
    if "Au:" in vector:
        return cvss2_score(vector)
    try:
        return float(vector)
    except ValueError:
        return None
