"""Runs every scanner over a folder and returns a ScanResult."""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from . import depgraph, enrich, reach
from .models import Finding, ScanResult, Severity
from .progress import NULL, Progress
from .scanners import code, deps, files, iac, is_suppressed, routes, run_rules, secrets
from .walker import IgnoreConfig, SourceFile, git_tracked, walk

ALL_SCANNERS = ("deps", "secrets", "code", "config", "files")
MAX_TEXT_SIZE = 2 * 1024 * 1024
PARALLEL_THRESHOLD = 150
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
    deep: bool = True  # taint / data-flow analysis
    history: bool = False  # scan git history for secrets
    history_depth: Optional[int] = None
    enrich: bool = True  # CISA KEV + EPSS
    jobs: int = 0  # 0 = auto
    only: Optional[Set[str]] = None  # restrict to these relative paths (diff mode)
    staged: bool = False  # read file contents from the git index (pre-commit)
    custom_rules: List = field(default_factory=list)  # user-defined Rule objects (customrules.load)
    health: bool = True  # deps.dev: deprecated/abandoned packages + license compliance
    health_transitive: bool = False  # also check transitive dependencies (slower)
    progress: Progress = NULL


def load_baseline(path: str) -> Set[str]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    items = data.get("findings", data) if isinstance(data, dict) else data
    return {i["fingerprint"] if isinstance(i, dict) else str(i) for i in items}


# ---------------------------------------------------------------- per-file content scanning (runs in workers)

def _staged_text(root: str, rel: str) -> Optional[str]:
    try:
        out = subprocess.run(["git", "-C", root, "show", f":{rel}"], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.decode("utf-8", "replace") if out.returncode == 0 else None


def scan_content(f: SourceFile, enabled: Set[str], deep: bool, downgrade: bool,
                 custom: Sequence = (), py_project=None) -> Tuple[List[Finding], int, dict]:
    """Run the text scanners on one file. Returns (findings, suppressed count, {"imports", "routes"})."""
    found: List[Finding] = []
    for rule in custom:
        found.extend(run_rules([rule], f, getattr(rule, "category", "code")))
    if "secrets" in enabled:
        found.extend(secrets.scan(f))
    if "code" in enabled:
        found.extend(code.scan(f, deep, py_project))
    if "config" in enabled:
        found.extend(iac.scan(f))
    meta = {"imports": depgraph.extract_imports(f.ext, f.text()) if "deps" in enabled else None,
            "routes": routes.routes_for(f.text(), f.rel, f.path[: -len(f.rel)] if f.path.endswith(f.rel) else None)
            if "code" in enabled else []}
    kept: List[Finding] = []
    suppressed = 0
    if found:
        lines = f.text().splitlines()
        for fnd in found:
            if fnd.line and is_suppressed(lines, fnd.line, fnd.rule_id):
                suppressed += 1
                continue
            if downgrade and fnd.category in ("code", "secret") and _TEST_PATH.search(f.rel):
                fnd.severity = fnd.severity.lowered()
                fnd.extra["context"] = "test/example file (severity lowered)"
            kept.append(fnd)
    return kept, suppressed, meta


def _scan_batch(batch: List[Tuple[str, str, int]], enabled: Set[str], deep: bool, downgrade: bool, staged_root: Optional[str],
                custom: Sequence = (), py_project=None):
    out = []
    for path, rel, size in batch:
        f = SourceFile(path, rel, size)
        if staged_root:
            text = _staged_text(staged_root, rel)
            if text is None or "\0" in text[:8192]:
                continue
            f._text, f._binary = text, False
        try:
            out.append((rel,) + scan_content(f, enabled, deep, downgrade, custom, py_project))
        except Exception as e:  # one weird file must not abort the whole scan
            out.append((rel, [], 0, {}, f"{e.__class__.__name__}: {e}"))
    return out


# ---------------------------------------------------------------- main entry

def scan(root: str, opts: ScanOptions) -> ScanResult:
    started = time.time()
    root = os.path.abspath(root)
    enabled = set(opts.scanners)
    result = ScanResult(root=root, scanners=[s for s in ALL_SCANNERS if s in enabled])
    ignore = IgnoreConfig.load(root)
    p = opts.progress

    # 1. discover
    p.stage("Discovering files")
    all_files = list(walk(root, ignore, opts.excludes, opts.use_gitignore, opts.include_vendor, opts.only))
    result.files_scanned = len(all_files)
    p.done(f"Found {len(all_files)} files to scan")
    tracked = git_tracked(root) if "files" in enabled else None

    raw: List[Finding] = []
    manifests = []
    content_files: List[SourceFile] = []
    for f in all_files:
        if "deps" in enabled and deps.is_manifest(f) and f.size <= 50 * MAX_TEXT_SIZE:
            manifests.append(f)
        if "files" in enabled:
            raw.extend(files.scan(f, tracked))
        if f.size > MAX_TEXT_SIZE or f.size == 0 or (not opts.staged and f.is_binary()):
            continue
        content_files.append(f)

    # 2. content scanning (parallel for larger trees)
    imports: Dict[str, Set[str]] = {}
    import_files: Dict[Tuple[str, str], List[str]] = {}
    if enabled & {"secrets", "code", "config", "deps"} and content_files:
        py_project = None
        py_files = [f for f in content_files if f.ext == ".py"]
        if opts.deep and "code" in enabled and len(py_files) > 1 and not opts.staged:
            from .scanners import taint_python
            p.stage("Building cross-file data-flow summaries", total=len(py_files))
            pairs = []
            for f in py_files:
                pairs.append((f.rel, f.text()))
                f._text = None
                p.advance(1)
            py_project = taint_python.build_project(pairs)
            del pairs
            p.done(f"Summarised {sum(len(v) for v in py_project.values())} functions across {len(py_project)} Python modules")
        p.stage("Analysing code, secrets & config", total=len(content_files))
        staged_root = root if opts.staged else None
        jobs = opts.jobs or min(8, os.cpu_count() or 1)
        batches = [[(f.path, f.rel, f.size) for f in content_files[i:i + 40]] for i in range(0, len(content_files), 40)]

        def consume(rows) -> None:
            for row in rows:
                rel, found, suppressed, meta = row[:4]
                if len(row) > 4:
                    result.warnings.append(f"skipped {rel}: {row[4]}")
                raw.extend(found)
                result.suppressed += suppressed
                imps = (meta or {}).get("imports")
                result.routes.extend((meta or {}).get("routes") or [])
                if imps:
                    imports.setdefault(imps[0], set()).update(imps[1])
                    for name in imps[1]:
                        import_files.setdefault((imps[0], name), []).append(rel)
            p.advance(len(rows), rows[-1][0] if rows else None)

        def serial() -> None:
            for b in batches:
                consume(_scan_batch(b, enabled, opts.deep, opts.downgrade_tests, staged_root, opts.custom_rules, py_project))

        if jobs > 1 and len(content_files) >= PARALLEL_THRESHOLD:
            try:
                with ProcessPoolExecutor(max_workers=jobs) as pool:
                    futures = [pool.submit(_scan_batch, b, enabled, opts.deep, opts.downgrade_tests, staged_root, opts.custom_rules,
                                           py_project) for b in batches]
                    for fut in as_completed(futures):
                        consume(fut.result())
            except (OSError, RuntimeError, ImportError):
                # Process pools can be unavailable (sandboxes, frozen apps): fall back to serial.
                raw.clear()
                imports.clear()
                import_files.clear()
                result.routes.clear()
                p.set_total(len(content_files))
                serial()
        else:
            serial()
        if result.routes:
            no_auth = routes.missing_auth_findings(result.routes)
            for fnd in no_auth:  # honour inline suppressions on the route line
                try:
                    with open(os.path.join(root, fnd.file), encoding="utf-8", errors="replace") as fh:
                        src_lines = fh.read().splitlines()
                except OSError:
                    src_lines = []
                if is_suppressed(src_lines, fnd.line, fnd.rule_id):
                    result.suppressed += 1
                else:
                    raw.append(fnd)
            routes.annotate_flows(raw, result.routes)
        n_flows = sum(1 for x in raw if x.extra.get("flow"))
        p.done(f"Analysed {len(content_files)} files" + (f" · {n_flows} confirmed data flows" if n_flows else ""))

    # 3. git history
    if opts.history and "secrets" in enabled and not opts.only:
        from .scanners import history
        total = history.count_commits(root, opts.history_depth)
        if total:
            p.stage("Scanning git history for secrets", total=total)
            hist = history.scan(root, opts.history_depth, on_commit=lambda h: p.advance(1, h))
            raw.extend(hist)
            result.commits_scanned = total
            p.done(f"Scanned {total} commit{'s' if total != 1 else ''} · {len(hist)} secret(s) only in history")
        else:
            result.warnings.append("--history: not a git repository (or no commits); history scan skipped.")

    # 4. dependencies
    if "deps" in enabled and manifests:
        p.stage("Reading dependency manifests", total=len(manifests))
        packages, used = deps.collect_packages(manifests, result.warnings)
        for pkg in packages:
            pkg.imported = depgraph.is_imported(pkg, imports)
        p.done(f"Inventoried {len(packages)} packages from {len(used)} manifest(s)")
        online = bool(packages) and not opts.offline
        if online:
            p.stage(f"Checking {len(packages)} packages against OSV.dev")
        _, _, dep_findings, dep_suppressed = deps.scan(
            manifests, ignore.vulns, result.warnings, opts.offline, opts.use_cache,
            progress=p if online else None, packages=packages, used=used)
        if online:
            p.done(f"Found {len(dep_findings)} known vulnerabilities")
        result.packages, result.manifests = packages, used
        result.suppressed += dep_suppressed
        reach.annotate(dep_findings, root, import_files)
        dep_findings += depgraph.typosquat_findings(packages)
        dep_findings += depgraph.hygiene_findings(manifests, used)
        dep_findings += depgraph.install_script_findings(manifests, root)
        if opts.health and online:
            scope = [p for p in packages if opts.health_transitive or p.direct is not False]
            p.stage("Checking package health & licenses (deps.dev)", total=len({(x.ecosystem, x.name, x.version) for x in scope}) or None)
            from . import depintel
            health, warns = depintel.intel_findings(packages, root, opts.health_transitive, progress=p)
            result.warnings += warns
            dep_findings += health
            p.done(f"Package health & licenses checked · {len(health)} issue(s)")
        if not opts.include_dev:
            dep_findings = [d for d in dep_findings if not d.extra.get("dev")]
        if opts.enrich and online and any(d.rule_id.startswith(("CVE-", "GHSA-")) for d in dep_findings):
            p.stage("Enriching with CISA KEV & EPSS exploit data")
            enrich.enrich(dep_findings, opts.use_cache, result.warnings)
            kev = sum(1 for d in dep_findings if d.extra.get("kev"))
            p.done(f"Threat intel applied · {kev} actively exploited in the wild" if kev else "Threat intel applied")
        raw.extend(dep_findings)
        if opts.offline and packages:
            result.warnings.append(f"--offline: {len(packages)} packages inventoried but not checked for CVEs.")

    # 5. filter, prioritise, sort
    if opts.baseline:
        baseline = load_baseline(opts.baseline)
    elif os.path.isfile(os.path.join(root, ".vulnfind-baseline.json")):  # triage decisions committed with the project
        baseline = load_baseline(os.path.join(root, ".vulnfind-baseline.json"))
    else:
        baseline = set()
    for fnd in raw:
        if fnd.rule_id.upper() in ignore.rules:
            result.suppressed += 1
        elif fnd.severity < opts.min_severity:
            result.below_threshold += 1
        elif baseline and fnd.fingerprint in baseline:
            result.suppressed += 1
        else:
            result.findings.append(fnd)
    enrich.prioritise(result.findings)

    order = {c: i for i, c in enumerate(("dependency", "secret", "code", "config", "file"))}
    result.findings.sort(key=lambda x: (-x.severity, -x.extra.get("priority", 0), order.get(x.category, 9), x.file, x.line or 0))
    result.duration = time.time() - started
    return result
