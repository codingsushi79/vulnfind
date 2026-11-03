"""Threat-intel enrichment and prioritisation.

- CISA KEV: CVEs known to be exploited in the wild (federal patch mandate list).
- FIRST EPSS: probability a CVE is exploited in the next 30 days.
Both are free, keyless public feeds, cached for 24h in ~/.cache/vulnfind.
"""

from __future__ import annotations

import json
import os
import time
import urllib.request
from typing import Dict, Iterable, List, Optional

from . import __version__
from .models import Finding, Severity
from .osv import _cache_dir

KEV_URL = os.environ.get("VULNFIND_KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
EPSS_URL = os.environ.get("VULNFIND_EPSS_URL", "https://api.first.org/data/v1/epss")
TTL = 24 * 3600


def _cache_file(name: str) -> str:
    return os.path.join(os.path.dirname(_cache_dir()), name)


def _fetch_json(url: str, timeout: float = 30) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": f"vulnfind/{__version__}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def load_kev(use_cache: bool = True) -> Dict[str, dict]:
    path = _cache_file("kev.json")
    if use_cache and os.path.isfile(path) and time.time() - os.path.getmtime(path) < TTL:
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            pass
    data = _fetch_json(KEV_URL, timeout=60)
    kev = {v["cveID"]: {"date_added": v.get("dateAdded"), "name": v.get("vulnerabilityName"),
                        "ransomware": v.get("knownRansomwareCampaignUse") == "Known", "due": v.get("dueDate"),
                        "action": v.get("requiredAction")}
           for v in data.get("vulnerabilities", []) if v.get("cveID")}
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(kev, fh)
    except OSError:
        pass
    return kev


def load_epss(cves: Iterable[str], use_cache: bool = True) -> Dict[str, dict]:
    path = _cache_file("epss.json")
    cache: Dict[str, dict] = {}
    if use_cache and os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as fh:
                cache = json.load(fh)
        except (OSError, ValueError):
            cache = {}
    now = time.time()
    wanted = sorted(set(cves))
    missing = [c for c in wanted if c not in cache or now - cache[c].get("fetched", 0) > TTL]
    for i in range(0, len(missing), 80):
        chunk = missing[i:i + 80]
        data = _fetch_json(f"{EPSS_URL}?cve={','.join(chunk)}&limit=100")
        got = {row["cve"]: row for row in data.get("data", [])}
        for c in chunk:
            row = got.get(c)
            cache[c] = {"epss": float(row["epss"]), "percentile": float(row["percentile"]), "fetched": now} if row else {"epss": None, "fetched": now}
    if missing and use_cache:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(cache, fh)
        except OSError:
            pass
    return {c: cache[c] for c in wanted if cache.get(c, {}).get("epss") is not None}


def enrich(findings: List[Finding], use_cache: bool = True, warnings: Optional[List[str]] = None) -> None:
    deps = [f for f in findings if f.category in ("dependency", "web") and f.extra.get("aliases")]
    cves = {a for f in deps for a in f.extra.get("aliases", []) if a.startswith("CVE-")}
    if not cves:
        return
    try:
        kev = load_kev(use_cache)
    except Exception as e:  # network/parse problems must never break a scan
        kev = {}
        if warnings is not None:
            warnings.append(f"CISA KEV lookup failed ({e.__class__.__name__}); exploited-in-the-wild flags unavailable.")
    try:
        epss = load_epss(cves, use_cache)
    except Exception as e:
        epss = {}
        if warnings is not None:
            warnings.append(f"EPSS lookup failed ({e.__class__.__name__}); exploit-probability scores unavailable.")
    for f in deps:
        ids = [a for a in f.extra.get("aliases", []) if a.startswith("CVE-")]
        hit = next(({**kev[c], "cve": c} for c in ids if c in kev), None)
        if hit:
            f.extra["kev"] = hit
            f.severity = Severity.CRITICAL
        scores = [epss[c] for c in ids if c in epss]
        if scores:
            best = max(scores, key=lambda s: s["epss"])
            f.extra["epss"] = round(best["epss"], 5)
            f.extra["epss_percentile"] = round(best["percentile"], 4)


SEV_BASE = {Severity.CRITICAL: 70, Severity.HIGH: 50, Severity.MEDIUM: 30, Severity.LOW: 12, Severity.INFO: 2}


def prioritise(findings: List[Finding]) -> None:
    """0-100 'fix this first' score combining severity, exploitation evidence and reachability."""
    for f in findings:
        score = SEV_BASE[f.severity]
        x = f.extra
        if x.get("kev"):
            score += 25
        if x.get("epss") is not None:
            score += round(x["epss"] * 30)
        if f.category == "dependency":
            if x.get("fixed"):
                score += 3
            if x.get("imported") is False and x.get("direct") is not True:
                score -= 15
            if x.get("dev"):
                score -= 10
            if x.get("direct"):
                score += 4
        if x.get("confidence") == "high":
            score += 10
        elif x.get("confidence") == "medium":
            score += 5
        if x.get("history"):
            score -= 5
        if "test/example" in str(x.get("context", "")):
            score -= 10
        x["priority"] = max(0, min(100, score))
