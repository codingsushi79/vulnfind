"""Package health and license intelligence from deps.dev (Google's Open Source Insights).

- deprecated versions (with the maintainer's reason)
- abandoned packages (no release for years; OpenSSF Scorecard "Maintained" = 0)
- license compliance against the project's own license
- upgrade impact: breaking-change notes from GitHub releases for major bumps (used by `vulnfind fix`)
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import __version__
from .models import Finding, Package, Severity as S
from .osv import _cache_dir, _vkey

API = os.environ.get("VULNFIND_DEPSDEV_URL", "https://api.deps.dev/v3")
SYSTEMS = {"npm": "NPM", "PyPI": "PYPI", "Go": "GO", "Maven": "MAVEN", "crates.io": "CARGO", "NuGet": "NUGET"}
TTL = 24 * 3600


def _get(url: str, timeout: float = 20) -> Optional[dict]:
    path = os.path.join(os.path.dirname(_cache_dir()), "depsdev", re.sub(r"[^A-Za-z0-9._-]", "_", url[len(API):])[:200] + ".json")
    if os.path.isfile(path) and time.time() - os.path.getmtime(path) < TTL:
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            pass
    req = urllib.request.Request(url, headers={"User-Agent": f"vulnfind/{__version__}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        data = {} if e.code == 404 else None
    except (urllib.error.URLError, OSError, ValueError):
        data = None
    if data is not None:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
        except OSError:
            pass
    return data


def _q(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def package_info(eco: str, name: str) -> Optional[dict]:
    return _get(f"{API}/systems/{SYSTEMS[eco]}/packages/{_q(name)}")


def version_info(eco: str, name: str, version: str) -> Optional[dict]:
    v = version if eco != "Go" else ("v" + version if not version.startswith("v") else version)
    return _get(f"{API}/systems/{SYSTEMS[eco]}/packages/{_q(name)}/versions/{_q(v)}")


def project_info(project_id: str) -> Optional[dict]:
    return _get(f"{API}/projects/{_q(project_id)}")


def source_repo(vinfo: Optional[dict]) -> Optional[str]:
    for p in (vinfo or {}).get("relatedProjects") or []:
        if p.get("relationType") == "SOURCE_REPO":
            return p["projectKey"]["id"]
    return None


# ---------------------------------------------------------------- licenses

STRONG_NETWORK = re.compile(r"\b(?:AGPL|SSPL|OSL-3|EUPL)", re.I)
STRONG = re.compile(r"\b(?<!L)GPL", re.I)
WEAK = re.compile(r"\b(?:LGPL|MPL|EPL|CDDL|CPL)", re.I)
PERMISSIVE = re.compile(r"\b(?:MIT|BSD|Apache|ISC|Zlib|Unlicense|0BSD|CC0|WTFPL|PSF|Python|BlueOak|Artistic)", re.I)


def classify(expr: str) -> str:
    """network | strong | weak | permissive | unknown for an SPDX-ish expression (OR picks the friendliest option)."""
    if not expr or expr.lower() in ("non-standard", "unknown", "noassertion", "none"):
        return "unknown"
    options = re.split(r"\s+OR\s+", expr.replace("(", "").replace(")", ""))
    order = ["permissive", "weak", "strong", "network", "unknown"]
    best = "unknown"
    for opt in options:
        parts = re.split(r"\s+AND\s+", opt)
        worst = "permissive"
        for p in parts:
            c = "network" if STRONG_NETWORK.search(p) else "weak" if WEAK.search(p) else "strong" if STRONG.search(p) \
                else "permissive" if PERMISSIVE.search(p) else "unknown"
            if order.index(c) > order.index(worst):
                worst = c
        if order.index(worst) < order.index(best):
            best = worst
    return best


def project_license(root: str) -> Tuple[str, str]:
    """(license name, class) of the scanned project itself."""
    try:
        with open(os.path.join(root, "package.json"), encoding="utf-8") as fh:
            lic = json.load(fh).get("license")
            if isinstance(lic, str) and lic:
                return lic, classify(lic)
    except (OSError, ValueError):
        pass
    for name in ("pyproject.toml", "Cargo.toml"):
        try:
            with open(os.path.join(root, name), encoding="utf-8") as fh:
                m = re.search(r'(?m)^license\s*=\s*(?:\{\s*text\s*=\s*)?"([^"]+)"', fh.read())
                if m:
                    return m.group(1), classify(m.group(1))
        except OSError:
            pass
    for name in sorted(os.listdir(root)) if os.path.isdir(root) else []:
        if re.match(r"(?i)^(?:licen[cs]e|copying)(?:\.\w+)?$", name):
            try:
                with open(os.path.join(root, name), encoding="utf-8", errors="replace") as fh:
                    head = fh.read(3000)
            except OSError:
                continue
            for pat, lic in ((r"GNU AFFERO", "AGPL-3.0"), (r"GNU LESSER", "LGPL"), (r"GNU GENERAL PUBLIC", "GPL"),
                             (r"Mozilla Public License", "MPL-2.0"), (r"Apache License", "Apache-2.0"),
                             (r"Permission is hereby granted, free of charge", "MIT"), (r"Redistribution and use in source", "BSD"),
                             (r"This is free and unencumbered", "Unlicense"), (r"ISC License", "ISC")):
                if re.search(pat, head, re.I):
                    return lic, classify(lic)
            return "custom (" + name + ")", "unknown"
    return "none found (treated as proprietary)", "proprietary"


# ---------------------------------------------------------------- findings

def _years_since(iso: str) -> float:
    try:
        dt = datetime.strptime(iso[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return 0.0
    return (datetime.now(timezone.utc) - dt).days / 365.25


def intel_findings(packages: Sequence[Package], root: str, include_transitive: bool = False,
                   workers: int = 8, progress=None) -> Tuple[List[Finding], List[str]]:
    warnings: List[str] = []
    chosen: Dict[Tuple[str, str, str], Package] = {}
    for p in packages:
        if p.ecosystem not in SYSTEMS or p.name == "stdlib":
            continue
        if not include_transitive and p.direct is False:
            continue
        chosen.setdefault((p.ecosystem, p.name, p.version), p)
    if not chosen:
        return [], warnings
    proj_name, proj_class = project_license(root)

    def fetch(key):
        eco, name, version = key
        return key, package_info(eco, name), version_info(eco, name, version)

    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for res in pool.map(fetch, list(chosen)):
            results.append(res)
            if progress is not None:
                progress.advance(1, res[0][1])
    if all(pi is None and vi is None for _, pi, vi in results):
        warnings.append("deps.dev unreachable: package health and license checks skipped.")
        return [], warnings

    projects: Dict[str, Optional[dict]] = {}
    repos = {source_repo(vi) for _, _, vi in results if source_repo(vi)}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for rid, info in zip(repos, pool.map(project_info, repos)):
            projects[rid] = info

    out: List[Finding] = []
    for (eco, name, version), pinfo, vinfo in results:
        pkg = chosen[(eco, name, version)]
        base = dict(package=name, version=version, ecosystem=eco, direct=pkg.direct, dev=pkg.dev, aliases=[])
        # deprecated by the maintainer?
        if vinfo and vinfo.get("isDeprecated"):
            reason = (vinfo.get("deprecatedReason") or "").strip()
            out.append(Finding("DEP-DEPRECATED", f"Deprecated package: {name} {version}", S.MEDIUM, "dependency", pkg.source, pkg.line,
                               snippet=f"{name}@{version}", description=f"The maintainers have deprecated this version"
                               + (f": \"{reason[:200]}\"" if reason else ".") + " It will not receive security fixes.",
                               fix="Move to the replacement the maintainers recommend, or a maintained alternative.",
                               cwe="CWE-1104", extra=dict(base)))
        # abandoned?
        if pinfo and pinfo.get("versions"):
            last = max((v.get("publishedAt") or "" for v in pinfo["versions"]), default="")
            years = _years_since(last) if last else 0
            repo = source_repo(vinfo)
            maintained = None
            for c in ((projects.get(repo) or {}).get("scorecard") or {}).get("checks") or []:
                if c.get("name") == "Maintained":
                    maintained = c.get("score")
            if years >= 2 and pkg.direct is not False:
                sev = S.MEDIUM if (years >= 4 or maintained == 0) else S.LOW
                out.append(Finding("DEP-UNMAINTAINED", f"Possibly abandoned: {name} (last release {years:.0f} years ago)", sev,
                                   "dependency", pkg.source, pkg.line, snippet=f"{name}@{version}",
                                   description=f"No new version since {last[:10]}"
                                   + (f"; OpenSSF Scorecard 'Maintained' = {maintained}/10" if maintained is not None else "")
                                   + ". Unmaintained packages don't get fixes for newly found vulnerabilities.",
                                   fix="Plan a migration to an actively maintained alternative.", cwe="CWE-1104",
                                   extra=dict(base, last_release=last[:10], maintained_score=maintained, repo=repo)))
        # license
        if pkg.dev:
            continue  # dev-only tools aren't distributed
        licenses = (vinfo or {}).get("licenses") or []
        expr = " AND ".join(licenses) if licenses else ""
        cls = classify(expr) if vinfo is not None else None
        if cls is None:
            continue
        conflict = None
        if cls == "network" and proj_class not in ("network",):
            conflict = (S.HIGH, f"{expr} requires releasing your source code to anyone who uses your software, even over a network.")
        elif cls == "strong" and proj_class not in ("strong", "network"):
            conflict = (S.MEDIUM, f"{expr} is copyleft: distributing software that includes it generally requires releasing your "
                        "code under the GPL.")
        elif cls == "unknown":
            conflict = (S.LOW, "No recognised license is declared, which legally means no permission to use or redistribute it.")
        if conflict:
            out.append(Finding("LICENSE-" + {"network": "NETWORK-COPYLEFT", "strong": "COPYLEFT", "unknown": "UNKNOWN"}[cls],
                               f"License {'conflict' if cls != 'unknown' else 'missing'}: {name} ({expr or 'none'})", conflict[0],
                               "license", pkg.source, pkg.line, snippet=f"{name}@{version}",
                               description=conflict[1] + f" Your project license: {proj_name}.",
                               fix="Check with your legal policy; replace the dependency or isolate it (separate process/service)"
                               if cls != "unknown" else "Ask upstream to add a license, or replace the package.",
                               cwe=None, extra=dict(base, license=expr or None, project_license=proj_name)))
    return out, warnings


# ---------------------------------------------------------------- upgrade impact (major bumps)

BREAKING = re.compile(r"(?i)\b(?:breaking|backwards?[- ]incompatible|no longer|removed|drop(?:ped)? support|deprecat|renamed|now requires|minimum (?:node|python))")


def upgrade_notes(eco: str, name: str, old: str, new: str, limit: int = 8) -> Tuple[Optional[str], List[str]]:
    """(compare URL, breaking-change lines) using the package's GitHub releases."""
    if eco not in SYSTEMS:
        return None, []
    repo = source_repo(version_info(eco, name, new) or version_info(eco, name, old))
    if not repo or not repo.startswith("github.com/"):
        return None, []
    owner_repo = repo[len("github.com/"):]
    compare = f"https://github.com/{owner_repo}/compare/v{old}...v{new}"
    headers = {"User-Agent": f"vulnfind/{__version__}", "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(f"https://api.github.com/repos/{owner_repo}/releases?per_page=100", headers=headers)
        with urllib.request.urlopen(req, timeout=20) as resp:
            releases = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError):
        return compare, []
    notes: List[str] = []
    if not any((r.get("body") or "").strip() for r in releases if isinstance(r, dict)):
        return compare, _changelog_notes(owner_repo, old, new, headers, limit)
    for rel in releases:
        tag = re.sub(r"^[^\d]*", "", rel.get("tag_name") or "")
        if not tag:
            continue
        try:
            if not (_vkey(old) < _vkey(tag) <= _vkey(new)):
                continue
        except TypeError:
            continue
        for line in (rel.get("body") or "").splitlines():
            line = re.sub(r"^[\s*\-#>]+", "", line).strip()
            if BREAKING.search(line) and 15 < len(line) < 220:
                notes.append(f"{tag}: {line}")
                if len(notes) >= limit:
                    return compare, notes
    return compare, notes


def _changelog_notes(owner_repo: str, old: str, new: str, headers: Dict[str, str], limit: int) -> List[str]:
    """Fallback for projects that keep notes in CHANGELOG.md instead of GitHub releases."""
    text = ""
    for name in ("CHANGELOG.md", "HISTORY.md", "CHANGES.md", "History.md"):
        try:
            req = urllib.request.Request(f"https://raw.githubusercontent.com/{owner_repo}/HEAD/{name}",
                                         headers={"User-Agent": headers["User-Agent"]})
            with urllib.request.urlopen(req, timeout=20) as resp:
                text = resp.read(800_000).decode("utf-8", "replace")
                break
        except (urllib.error.URLError, OSError):
            continue
    notes: List[str] = []
    current: Optional[str] = None
    for line in text.splitlines():
        head = re.match(r"^\s*(?:#+|\[)\s*\[?v?(\d+\.\d+(?:\.\d+)?)", line)
        if head:
            current = head.group(1)
            continue
        if not current:
            continue
        try:
            in_range = _vkey(old) < _vkey(current) <= _vkey(new)
        except TypeError:
            in_range = False
        clean = re.sub(r"^[\s*\-#>]+", "", line).strip()
        if in_range and BREAKING.search(clean) and 15 < len(clean) < 220:
            notes.append(f"{current}: {clean}")
            if len(notes) >= limit:
                break
    return notes
