"""Client for the OSV.dev vulnerability database (aggregates GitHub Advisories, NVD CVEs,
PyPA, RustSec, Go vulndb, RubySec and more). Free, no API key required."""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import __version__
from .cvss import score_vector
from .models import Package, Severity

API = os.environ.get("VULNFIND_OSV_API", "https://api.osv.dev/v1")
BATCH_SIZE = 1000
CACHE_TTL = 24 * 3600


class OSVError(RuntimeError):
    pass


def _cache_dir() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "vulnfind", "osv")


def _post(url: str, payload: dict, timeout: float) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={
        "Content-Type": "application/json", "User-Agent": f"vulnfind/{__version__}"})
    return _send(req, timeout)


def _get(url: str, timeout: float) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": f"vulnfind/{__version__}"})
    return _send(req, timeout)


def _send(req: urllib.request.Request, timeout: float, retries: int = 3) -> dict:
    last: Optional[Exception] = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            last = e
            if e.code < 500 and e.code != 429:
                break
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            last = e
        time.sleep(0.5 * (2 ** attempt))
    raise OSVError(f"OSV request failed ({req.full_url}): {last}")


class OSVClient:
    def __init__(self, use_cache: bool = True, timeout: float = 30.0, workers: int = 16):
        self.use_cache = use_cache
        self.timeout = timeout
        self.workers = workers

    # -- cache -------------------------------------------------------------
    def _cache_path(self, vuln_id: str) -> str:
        return os.path.join(_cache_dir(), re.sub(r"[^A-Za-z0-9._-]", "_", vuln_id) + ".json")

    def _cached(self, vuln_id: str, modified: Optional[str]) -> Optional[dict]:
        if not self.use_cache:
            return None
        path = self._cache_path(vuln_id)
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return None
        if modified and data.get("modified") == modified:
            return data
        if time.time() - os.path.getmtime(path) < CACHE_TTL:
            return data
        return None

    def _store(self, vuln_id: str, data: dict) -> None:
        if not self.use_cache:
            return
        try:
            os.makedirs(_cache_dir(), exist_ok=True)
            tmp = self._cache_path(vuln_id) + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            os.replace(tmp, self._cache_path(vuln_id))
        except OSError:
            pass

    # -- API ---------------------------------------------------------------
    def query(self, packages: Sequence[Package]) -> Dict[Tuple[str, str, str], List[dict]]:
        """Return {(ecosystem, name, version): [full vuln records]}."""
        unique = sorted({(p.ecosystem, p.name, p.version) for p in packages})
        hits: Dict[Tuple[str, str, str], List[Tuple[str, Optional[str]]]] = {}
        for start in range(0, len(unique), BATCH_SIZE):
            chunk = unique[start:start + BATCH_SIZE]
            queries = [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]
            pending = list(range(len(chunk)))
            while pending:
                resp = _post(f"{API}/querybatch", {"queries": [queries[i] for i in pending]}, self.timeout)
                results = resp.get("results") or []
                next_round = []
                for i, res in zip(pending, results):
                    for v in res.get("vulns") or []:
                        hits.setdefault(chunk[i], []).append((v["id"], v.get("modified")))
                    if res.get("next_page_token"):
                        queries[i]["page_token"] = res["next_page_token"]
                        next_round.append(i)
                pending = next_round

        ids = {vid: mod for refs in hits.values() for vid, mod in refs}
        details = self.fetch(ids)
        return {k: [details[vid] for vid, _ in refs if vid in details] for k, refs in hits.items()}

    def fetch(self, ids: Dict[str, Optional[str]]) -> Dict[str, dict]:
        out: Dict[str, dict] = {}
        missing = []
        for vid, mod in ids.items():
            cached = self._cached(vid, mod)
            if cached:
                out[vid] = cached
            else:
                missing.append(vid)

        def one(vid: str) -> Tuple[str, Optional[dict]]:
            try:
                return vid, _get(f"{API}/vulns/{vid}", self.timeout)
            except OSVError:
                return vid, None

        if missing:
            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                for vid, data in pool.map(one, missing):
                    if data:
                        self._store(vid, data)
                        out[vid] = data
        return out


# ------------------------------------------------------------------ helpers

def _vkey(version: str) -> Tuple:
    """Sort key: numeric release, then pre-release (< release) or post-release (> release)."""
    v = version.strip().lstrip("vV")
    m = re.match(r"^(\d+(?:\.\d+)*)(.*)$", v)
    if not m:
        return ((), 1, ((1, 0, v),))
    nums = tuple(int(x) for x in m.group(1).split("."))
    while len(nums) > 1 and nums[-1] == 0:
        nums = nums[:-1]  # 1.0 == 1.0.0
    rest = m.group(2)
    if not rest or rest.startswith("+"):
        return (nums, 1, ())
    rest = rest.lstrip(".-_")
    phase = 2 if re.match(r"(?i)post|p\d|r\d|patch|pl", rest) else 0
    parts = tuple((0, int(p), "") if p.isdigit() else (1, 0, p.lower()) for p in re.split(r"[.\-_+]", rest) if p)
    return (nums, phase, parts)


def version_lt(a: str, b: str) -> bool:
    try:
        return _vkey(a) < _vkey(b)
    except TypeError:
        return a < b


def _norm(name: str, ecosystem: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def fixed_versions(vuln: dict, pkg: Package) -> List[str]:
    fixed = []
    for aff in vuln.get("affected") or []:
        p = aff.get("package") or {}
        if p.get("ecosystem", "").split(":")[0] != pkg.ecosystem or _norm(p.get("name", ""), pkg.ecosystem) != _norm(pkg.name, pkg.ecosystem):
            continue
        for rng in aff.get("ranges") or []:
            if rng.get("type") == "GIT":
                continue
            for ev in rng.get("events") or []:
                if "fixed" in ev and ev["fixed"] not in fixed:
                    fixed.append(ev["fixed"])
    return sorted(fixed, key=_vkey)


def best_fix(vuln: dict, pkg: Package) -> Optional[str]:
    """Smallest fixed version that is newer than the installed one."""
    candidates = [f for f in fixed_versions(vuln, pkg) if version_lt(pkg.version, f)]
    releases = [c for c in candidates if re.fullmatch(r"v?\d+(?:\.\d+)*", c)]
    return (releases or candidates or [None])[0]


def severity_of(vuln: dict) -> Tuple[Severity, Optional[float], Optional[str]]:
    """(severity, cvss score, vector) using CVSS when present, else the database's own rating."""
    best: Optional[Tuple[float, str]] = None
    entries = list(vuln.get("severity") or [])
    for aff in vuln.get("affected") or []:
        entries += aff.get("severity") or []
    for entry in entries:
        score = score_vector(str(entry.get("score", "")))
        if score is not None and (best is None or score > best[0]):
            best = (score, entry.get("score"))
    db = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(db, str):
        try:
            sev = Severity.parse(db)
            return sev, best[0] if best else None, best[1] if best else None
        except ValueError:
            pass
    for aff in vuln.get("affected") or []:
        eco = (aff.get("ecosystem_specific") or {}).get("severity")
        if isinstance(eco, str):
            try:
                return Severity.parse(eco), best[0] if best else None, best[1] if best else None
            except ValueError:
                pass
    if best:
        return max(Severity.from_score(best[0]), Severity.LOW), best[0], best[1]
    # Malicious-package advisories carry no CVSS but are always critical.
    if vuln.get("id", "").startswith("MAL-"):
        return Severity.CRITICAL, None, None
    return Severity.MEDIUM, None, None


def aliases(vuln: dict) -> List[str]:
    ids = [vuln["id"]] + list(vuln.get("aliases") or [])
    cves = [i for i in ids if i.startswith("CVE-")]
    others = [i for i in ids if not i.startswith("CVE-")]
    return list(dict.fromkeys(cves + others))


def dedupe(vulns: Iterable[dict]) -> List[dict]:
    """The same issue often appears as GHSA + PYSEC + CVE records; keep one."""
    seen = set()
    out = []
    for v in sorted(vulns, key=lambda v: (not v["id"].startswith("GHSA"), v["id"])):
        ids = set(aliases(v))
        if ids & seen:
            continue
        seen |= ids
        out.append(v)
    return out
