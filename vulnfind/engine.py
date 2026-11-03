"""Runs every scanner over a folder and returns a ScanResult."""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional, Set

from .models import Finding, ScanResult, Severity
from .scanners import code, deps, files, iac, is_suppressed, secrets
from .walker import IgnoreConfig, git_tracked, walk

ALL_SCANNERS = ("deps", "secrets", "code", "config", "files")
MAX_TEXT_SIZE = 2 * 1024 * 1024
_TEST_PATH = re.compile(r"(?:^|/)(?:tests?|__tests__|spec|specs|fixtures?|testdata|examples?|samples?|mocks?|docs?)(?:/|$)|(?:_test|\.test|\.spec|_spec)\.\w+$", re.I)


@dataclass
class ScanOptions:
    scanners: Iterable[str] = ALL_SCANNERS
    excludes: List[str] = field(default_factory=list)
    use_gitignore: bool = True
    include_vendor: bool = False
    offline: bool = False
    use_cache: bool = True
    min_severity: Severity = Severity.INFO
    baseline: Optional[str] = None
    include_dev: bool = True
    downgrade_tests: bool = True
    progress: Optional[Callable[[str], None]] = None


def load_baseline(path: str) -> Set[str]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    items = data.get("findings", data) if isinstance(data, dict) else data
    return {i["fingerprint"] if isinstance(i, dict) else str(i) for i in items}


def scan(root: str, opts: ScanOptions) -> ScanResult:
    started = time.time()
    root = os.path.abspath(root)
    enabled = set(opts.scanners)
    result = ScanResult(root=root, scanners=[s for s in ALL_SCANNERS if s in enabled])
    ignore = IgnoreConfig.load(root)
    tracked = git_tracked(root) if "files" in enabled else None
    progress = opts.progress or (lambda msg: None)

    manifests = []
    raw: List[Finding] = []
    for f in walk(root, ignore, opts.excludes, opts.use_gitignore, opts.include_vendor):
        result.files_scanned += 1
        if result.files_scanned % 250 == 0:
            progress(f"scanned {result.files_scanned} files...")
        is_manifest = "deps" in enabled and deps.is_manifest(f) and f.size <= 50 * MAX_TEXT_SIZE
        if is_manifest:
            manifests.append(f)
        if "files" in enabled:
            raw.extend(files.scan(f, tracked))
        if f.size > MAX_TEXT_SIZE or f.size == 0 or f.is_binary():
            continue
        found: List[Finding] = []
        if "secrets" in enabled:
            found.extend(secrets.scan(f))
        if "code" in enabled:
            found.extend(code.scan(f))
        if "config" in enabled:
            found.extend(iac.scan(f))
        if found:
            lines = f.text().splitlines()
            for fnd in found:
                if fnd.line and is_suppressed(lines, fnd.line, fnd.rule_id):
                    result.suppressed += 1
                    continue
                if opts.downgrade_tests and fnd.category in ("code", "secret") and _TEST_PATH.search(f.rel):
                    fnd.severity = fnd.severity.lowered()
                    fnd.extra["context"] = "test/example file (severity lowered)"
                raw.append(fnd)
        if not is_manifest:
            f._text = None  # release memory

    if "deps" in enabled and manifests:
        progress(f"checking dependencies from {len(manifests)} manifest(s) against OSV.dev...")
        packages, used, dep_findings, dep_suppressed = deps.scan(
            manifests, ignore.vulns, result.warnings, opts.offline, opts.use_cache)
        result.packages = packages
        result.manifests = used
        result.suppressed += dep_suppressed
        if not opts.include_dev:
            dep_findings = [d for d in dep_findings if not d.extra.get("dev")]
        raw.extend(dep_findings)
        if opts.offline and packages:
            result.warnings.append(f"--offline: {len(packages)} packages inventoried but not checked for CVEs.")

    baseline = load_baseline(opts.baseline) if opts.baseline else set()
    for fnd in raw:
        if fnd.rule_id.upper() in ignore.rules:
            result.suppressed += 1
        elif fnd.severity < opts.min_severity:
            result.below_threshold += 1
        elif baseline and fnd.fingerprint in baseline:
            result.suppressed += 1
        else:
            result.findings.append(fnd)

    order = {c: i for i, c in enumerate(("dependency", "secret", "code", "config", "file"))}
    result.findings.sort(key=lambda x: (-x.severity, order.get(x.category, 9), x.file, x.line or 0))
    result.duration = time.time() - started
    return result
