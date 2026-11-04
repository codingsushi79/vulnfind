"""Dependency scanning: parse manifests/lockfiles, look up every package in OSV.dev."""

from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .. import osv, reach
from ..depgraph import declared_names
from ..manifests import NPM_LOCKS, parse_requirements, parser_for
from ..models import Finding, Package, Severity
from ..walker import SourceFile


def is_manifest(f: SourceFile) -> bool:
    if parser_for(f.name):
        return True
    parent = f.rel.rsplit("/", 2)[-2] if "/" in f.rel else ""
    return parent.lower() == "requirements" and f.ext in (".txt", ".in")


def collect_packages(files: Sequence[SourceFile], warnings: List[str]) -> Tuple[List[Package], List[str]]:
    by_dir: Dict[str, Set[str]] = {}
    for f in files:
        by_dir.setdefault(os.path.dirname(f.rel), set()).add(f.name)

    packages: List[Package] = []
    used: List[str] = []
    for f in files:
        siblings = by_dir.get(os.path.dirname(f.rel), set())
        if f.name == "package.json" and siblings & NPM_LOCKS:
            continue  # the lockfile has exact versions
        parser = parser_for(f.name)
        if parser is None:
            parser = parse_requirements
        try:
            found = parser(f.text(), f.rel)
        except Exception as e:  # malformed manifest shouldn't kill the scan
            warnings.append(f"could not parse {f.rel}: {e.__class__.__name__}: {e}")
            continue
        if found:
            used.append(f.rel)
            if any(p.direct is None for p in found):
                declared = declared_names(f.path, found[0].ecosystem)
                if declared is not None:
                    norm = (lambda n: re.sub(r"[-_.]+", "-", n).lower()) if found[0].ecosystem == "PyPI" else (lambda n: n)
                    for p in found:
                        if p.direct is None:
                            p.direct = norm(p.name) in declared
                elif f.name == "package.json" or parser_for(f.name) in (parse_requirements,) or f.name.endswith(("pom.xml", "proj", ".config")):
                    for p in found:
                        p.direct = True if p.direct is None else p.direct
            packages.extend(found)
    return packages, used


def upgrade_cmd(ecosystem: str) -> str:
    """Command template for an ecosystem; distro ecosystems look like "Debian:12"."""
    return UPGRADE_CMD.get(ecosystem) or UPGRADE_CMD.get(ecosystem.split(":")[0], "upgrade {name} to {fix}")


UPGRADE_CMD = {
    "Debian": "rebuild on an updated base image or `apt-get install --only-upgrade` the {name} binaries (fixed in {fix})",
    "Ubuntu": "rebuild on an updated base image or `apt-get install --only-upgrade` the {name} binaries (fixed in {fix})",
    "Alpine": "apk upgrade {name}  (fixed in {fix}), or rebuild on a newer alpine tag",
    "AlmaLinux": "dnf update {name}  (fixed in {fix})",
    "Rocky Linux": "dnf update {name}  (fixed in {fix})",
    "npm": "npm install {name}@{fix}",
    "PyPI": 'pip install "{name}>={fix}"',
    "Go": "go get {name}@v{fix}",
    "crates.io": "cargo update -p {name} --precise {fix}",
    "RubyGems": "bundle update {name} (needs >= {fix})",
    "Packagist": "composer require {name}:^{fix}",
    "Maven": "set {name} to <version>{fix}</version>",
    "NuGet": "dotnet add package {name} --version {fix}",
    "Pub": "dart pub upgrade {name} (needs >= {fix})",
    "Hex": "mix deps.update {name} (needs >= {fix})",
}


def _clean(text: str, limit: int = 700) -> str:
    text = re.sub(r"\s+", " ", re.sub(r"[#*`>]+", "", text or "")).strip()
    return text if len(text) <= limit else text[:limit].rsplit(" ", 1)[0] + "..."


def build_findings(packages: Sequence[Package], results: Dict[Tuple[str, str, str], List[dict]],
                   ignored: Set[str]) -> Tuple[List[Finding], int]:
    findings: List[Finding] = []
    suppressed = 0
    for pkg in packages:
        vulns = osv.dedupe(results.get((pkg.ecosystem, pkg.name, pkg.version), []))
        for v in vulns:
            ids = osv.aliases(v)
            if ignored & {i.upper() for i in ids}:
                suppressed += 1
                continue
            sev, score, vector = osv.severity_of(v)
            fix = osv.best_fix(v, pkg)
            summary = v.get("summary") or _clean(v.get("details", ""), 90) or f"Vulnerability in {pkg.name}"
            desc = _clean(v.get("details") or summary)
            if pkg.approximate:
                desc = f"(Version inferred from a range in {os.path.basename(pkg.source)}; add a lockfile for exact results.) " + desc
            refs = [f"https://osv.dev/vulnerability/{v['id']}"]
            for r in v.get("references") or []:
                if r.get("type") in ("ADVISORY", "FIX", "REPORT", "WEB") and r.get("url") not in refs:
                    refs.append(r["url"])
                if len(refs) >= 4:
                    break
            if fix:
                fix_text = f"Upgrade {pkg.name} {pkg.version} -> {fix}:  " + upgrade_cmd(pkg.ecosystem).format(name=pkg.name, fix=fix)
            elif v["id"].startswith("MAL-"):
                fix_text = f"Remove {pkg.name} immediately - it is a known malicious package. Rotate any credentials on machines that installed it."
            else:
                fix_text = "No fixed version published yet. Consider an alternative package or mitigate per the advisory."
            cwes = (v.get("database_specific") or {}).get("cwe_ids") or []
            findings.append(Finding(
                rule_id=ids[0], title=summary.strip().rstrip("."), severity=sev, category="dependency",
                file=pkg.source, line=pkg.line, snippet=f"{pkg.name}@{pkg.version}",
                description=desc, fix=fix_text, cwe=cwes[0] if cwes else None, references=refs,
                extra={"package": pkg.name, "version": pkg.version, "ecosystem": pkg.ecosystem, "fixed": fix,
                       "aliases": ids, "cvss": score, "vector": vector, "dev": pkg.dev, "purl": pkg.purl,
                       "direct": pkg.direct, "via": pkg.via, "imported": pkg.imported,
                       "vulnerable_symbols": reach.symbols_for(v, pkg.name, pkg.ecosystem),
                       "symbol_source": reach.symbol_source(v) or "text",
                       "published": v.get("published", "")[:10] or None},
            ))
    return findings, suppressed


def scan(files: Sequence[SourceFile], ignored: Set[str], warnings: List[str], offline: bool = False,
         use_cache: bool = True, client: Optional[osv.OSVClient] = None, progress=None, packages=None, used=None):
    if packages is None:
        packages, used = collect_packages(files, warnings)
    if offline or not packages:
        return packages, used, [], 0
    client = client or osv.OSVClient(use_cache=use_cache)
    try:
        results = client.query(packages, progress) if progress is not None else client.query(packages)
    except osv.OSVError as e:
        warnings.append(f"dependency CVE lookup failed - {e}. Re-run with network access or use --offline.")
        return packages, used, [], 0
    findings, suppressed = build_findings(packages, results, ignored)
    return packages, used, findings, suppressed
