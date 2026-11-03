"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from typing import Any, Dict, List, Optional

from . import __version__
from .engine import ALL_SCANNERS, ScanOptions, scan
from .models import ScanResult, Severity
from .progress import Progress
from .reporters import FORMATTERS, format_for_path
from .reporters.terminal import SEV_TEXT, Style, render, render_multi, use_color

COMMANDS = ("scan", "sbom", "rules", "explain", "init", "hook", "ci", "compare", "watch", "fix", "cache")
FORMATS = ["table", "json", "sarif", "markdown", "html", "sbom", "github", "junit", "csv"]

EPILOG = """examples:
  vulnfind                              scan the current folder
  vulnfind ~/code/app -v                full descriptions, data flows, references, every CVE
  vulnfind ~/code/*                     scan many projects, one summary table
  vulnfind --history                    also find secrets that were deleted but live on in git history
  vulnfind --diff origin/main           only report issues in files changed vs main (PRs)
  vulnfind --staged                     scan what is staged for commit (pre-commit)
  vulnfind -o report.html -o out.sarif  write an interactive HTML report and SARIF
  vulnfind -f json | jq .summary        machine-readable output (also: sarif github junit csv markdown sbom)
  vulnfind --notify https://hooks.slack.com/...   post a summary to Slack / Discord / Teams / any webhook
  vulnfind fix --apply                  upgrade vulnerable dependencies automatically
  vulnfind watch                        re-scan on every save
  vulnfind hook install                 block commits that add secrets
  vulnfind ci github                    generate a GitHub Actions workflow
  vulnfind compare old.json new.json    what got introduced / fixed between two scans

configuration: .vulnfind.json in the scanned folder (`vulnfind init`), overridden by flags.
suppress inline with:  # vulnfind:ignore [RULE-ID]   ·   project-wide: .vulnfindignore
exit codes: 0 = clean, 1 = findings at/above --fail-on, 2 = error
"""

BUILTIN_DEFAULTS: Dict[str, Any] = {
    "scanners": ",".join(ALL_SCANNERS), "skip": "", "fail_on": "high", "min_severity": "low", "exclude": [],
    "output": [], "offline": False, "no_cache": False, "no_dev": False, "no_test_downgrade": False, "baseline": None,
    "history": False, "history_depth": None, "no_deep": False, "no_enrich": False, "jobs": 0, "notify": [],
    "notify_always": False, "include_vendor": False, "no_gitignore": False, "limit": 0, "format": None,
}


def _err(msg: str) -> int:
    print(f"vulnfind: error: {msg}", file=sys.stderr)
    return 2


# ---------------------------------------------------------------- argument parsing

def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--exclude", action="append", default=None, metavar="GLOB", help="skip paths matching a gitignore-style glob. Repeatable")
    p.add_argument("--no-gitignore", action="store_true", default=None, help="also scan files ignored by .gitignore")
    p.add_argument("--include-vendor", action="store_true", default=None, help="also scan vendor/ and node_modules/")
    p.add_argument("--no-color", dest="color", action="store_false", default=None, help="disable colours")
    p.add_argument("--color", dest="color", action="store_true", help="force colours")
    p.add_argument("--no-progress", action="store_true", help="no live progress display")
    p.add_argument("-q", "--quiet", action="store_true", help="no terminal report (exit code / files only)")
    p.add_argument("--config", metavar="FILE", help="config file (default: .vulnfind.json in the scanned folder)")


def _add_scan_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("paths", nargs="*", default=["."], metavar="PATH", help="folder(s) to scan (default: current directory)")
    _add_common(p)
    g = p.add_argument_group("output")
    g.add_argument("-f", "--format", choices=FORMATS, default=None, help="stdout format (default: table)")
    g.add_argument("-o", "--output", action="append", default=None, metavar="FILE",
                   help="write a report; format from extension: .json .sarif .html .md .xml(junit) .csv .cdx.json(sbom). Repeatable")
    g.add_argument("-v", "--verbose", action="store_true", help="descriptions, references, full data flows, every CVE")
    g.add_argument("--limit", type=int, default=None, metavar="N", help="show at most N findings per section")
    g = p.add_argument_group("what to scan")
    g.add_argument("--scanners", default=None, metavar="LIST", help=f"comma list: {','.join(ALL_SCANNERS)} (default: all)")
    g.add_argument("--skip", default=None, metavar="LIST", help="comma list of scanners to skip")
    g.add_argument("--history", action="store_true", default=None, help="also scan every commit in git history for secrets")
    g.add_argument("--history-depth", type=int, default=None, metavar="N", help="only the newest N commits")
    g.add_argument("--diff", metavar="REF", help="only files changed since REF (merge-base), plus uncommitted/untracked files")
    g.add_argument("--staged", action="store_true", help="only files staged for commit, scanning the staged content")
    g.add_argument("--no-deep", action="store_true", default=None, help="skip data-flow (taint) analysis (faster)")
    g.add_argument("--no-test-downgrade", action="store_true", default=None, help="keep full severity in tests/, examples/, docs/ …")
    g = p.add_argument_group("dependencies")
    g.add_argument("--offline", action="store_true", default=None, help="no network: inventory dependencies but skip CVE lookups")
    g.add_argument("--no-enrich", action="store_true", default=None, help="skip CISA KEV / EPSS exploit intelligence")
    g.add_argument("--no-cache", action="store_true", default=None, help="ignore the local advisory cache")
    g.add_argument("--no-dev", action="store_true", default=None, help="ignore vulnerabilities in dev-only dependencies")
    g = p.add_argument_group("gating & automation")
    g.add_argument("--min-severity", default=None, metavar="LEVEL", help="hide findings below LEVEL (default: low)")
    g.add_argument("--fail-on", default=None, metavar="LEVEL", help="exit 1 if a finding is at/above LEVEL, or 'none' (default: high)")
    g.add_argument("--baseline", metavar="FILE", default=None, help="hide findings recorded in a baseline file")
    g.add_argument("--write-baseline", metavar="FILE", help="record current findings to FILE")
    g.add_argument("--notify", action="append", default=None, metavar="URL", help="POST a summary to a webhook (Slack/Discord/Teams/JSON). Repeatable")
    g.add_argument("--notify-always", action="store_true", default=None, help="notify even when nothing reaches --fail-on")
    g.add_argument("--quiet-ok", action="store_true", help="print nothing unless a finding reaches --fail-on (hooks, cron)")
    g.add_argument("-j", "--jobs", type=int, default=None, metavar="N", help="worker processes (default: auto)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnfind",
        description="Find vulnerabilities in a project: known CVEs in dependencies (with exploit intel), leaked secrets "
                    "(incl. git history), data-flow analysis of insecure code, IaC/CI misconfigurations and sensitive files.",
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"vulnfind {__version__}")
    sub = parser.add_subparsers(dest="command")
    _add_scan_args(sub.add_parser("scan", help="scan folder(s) (default command)", epilog=EPILOG,
                                  formatter_class=argparse.RawDescriptionHelpFormatter))

    sb = sub.add_parser("sbom", help="generate a CycloneDX SBOM of all dependencies")
    sb.add_argument("path", nargs="?", default=".")
    sb.add_argument("-o", "--output", action="append", default=[], metavar="FILE")
    sb.add_argument("--offline", action="store_true", help="omit the vulnerability section")
    _add_common(sb)

    r = sub.add_parser("rules", help="list built-in rules")
    r.add_argument("--category", choices=["secret", "code", "config", "file", "dependency"])
    r.add_argument("--json", action="store_true")
    e = sub.add_parser("explain", help="explain a rule or advisory")
    e.add_argument("rule_id")
    i = sub.add_parser("init", help="create .vulnfind.json and .vulnfindignore")
    i.add_argument("path", nargs="?", default=".")

    h = sub.add_parser("hook", help="install/remove the git pre-commit hook")
    h.add_argument("action", choices=["install", "uninstall", "status"])
    h.add_argument("path", nargs="?", default=".")
    h.add_argument("--fail-on", default="high", metavar="LEVEL")

    c = sub.add_parser("ci", help="generate CI configuration")
    c.add_argument("provider", choices=["github", "gitlab", "pre-commit"])
    c.add_argument("path", nargs="?", default=".")
    c.add_argument("--install", default="git+https://github.com/codingsushi79/vulnfind",
                   help="pip install spec for vulnfind in CI (default: %(default)s)")
    c.add_argument("--write", action="store_true", help="write the file into the project instead of printing it")

    cmp_ = sub.add_parser("compare", help="diff two JSON reports: new vs fixed findings")
    cmp_.add_argument("old")
    cmp_.add_argument("new")
    cmp_.add_argument("-f", "--format", choices=["table", "json", "markdown"], default="table")
    cmp_.add_argument("--fail-on", default="high", metavar="LEVEL", help="exit 1 if a NEW finding is at/above LEVEL, or 'none'")
    cmp_.add_argument("--no-color", dest="color", action="store_false", default=None)

    wt = sub.add_parser("watch", help="re-scan changed files continuously")
    wt.add_argument("path", nargs="?", default=".")
    wt.add_argument("--interval", type=float, default=1.5, metavar="SECONDS")
    _add_common(wt)

    fx = sub.add_parser("fix", help="upgrade vulnerable dependencies (dry run unless --apply)")
    fx.add_argument("path", nargs="?", default=".")
    fx.add_argument("--apply", action="store_true", help="write the changes")
    fx.add_argument("--no-major", action="store_true", help="skip upgrades that cross a major version")
    _add_common(fx)

    ca = sub.add_parser("cache", help="manage the advisory cache")
    ca.add_argument("action", choices=["info", "clear"])
    return parser


# ---------------------------------------------------------------- helpers

def _merge_config(args: argparse.Namespace, root: str) -> Dict[str, Any]:
    from .automation import find_config, load_config
    cfg: Dict[str, Any] = {}
    path = find_config(root, getattr(args, "config", None))
    if path:
        cfg = load_config(path)
    merged = {}
    for key, default in BUILTIN_DEFAULTS.items():
        val = getattr(args, key, None)
        merged[key] = val if val is not None else cfg.get(key, default)
    merged["_config_path"] = path
    return merged


def _parse_sev(value: str, name: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError:
        raise ValueError(f"{name}: unknown severity {value!r} (use info, low, medium, high, critical)")


def _options(o: Dict[str, Any], args: argparse.Namespace, root: str, progress: Progress) -> ScanOptions:
    wanted = {s.strip() for s in str(o["scanners"]).split(",") if s.strip()}
    if "dependencies" in wanted:
        wanted.add("deps")
    skip = {s.strip() for s in str(o["skip"]).split(",") if s.strip()}
    unknown = (wanted | skip) - set(ALL_SCANNERS) - {"dependencies"}
    if unknown:
        raise ValueError(f"unknown scanner(s): {', '.join(sorted(unknown))}. Choose from {', '.join(ALL_SCANNERS)}")
    only = None
    if getattr(args, "staged", False) or getattr(args, "diff", None):
        from . import gitutil
        only = gitutil.staged_files(root) if args.staged else gitutil.changed_files(root, args.diff)
        if only is None:
            raise ValueError("--staged/--diff need a git repository" + (f" and a valid ref ({args.diff})" if getattr(args, "diff", None) else ""))
    return ScanOptions(
        scanners=[s for s in ALL_SCANNERS if s in wanted and s not in skip],
        excludes=list(o["exclude"]), use_gitignore=not o["no_gitignore"], include_vendor=o["include_vendor"],
        offline=o["offline"], use_cache=not o["no_cache"], min_severity=_parse_sev(o["min_severity"], "--min-severity"),
        baseline=o["baseline"], include_dev=not o["no_dev"], downgrade_tests=not o["no_test_downgrade"],
        deep=not o["no_deep"], history=o["history"], history_depth=o["history_depth"], enrich=not o["no_enrich"],
        jobs=o["jobs"] or 0, only=only, staged=bool(getattr(args, "staged", False)), progress=progress,
    )


def _write_outputs(paths: List[str], results: List[ScanResult], fmt: Optional[str], quiet: bool, color) -> None:
    st = Style(use_color(sys.stderr, color))
    for path in paths:
        out_fmt = format_for_path(path) or (fmt if fmt and fmt != "table" else None)
        if not out_fmt:
            raise ValueError(f"can't infer report format for {path}; use .json/.sarif/.html/.md/.xml/.csv or --format")
        if len(results) > 1:
            if out_fmt != "json":
                raise ValueError("with several paths only .json reports can be written")
            text = "[" + ",\n".join(FORMATTERS["json"](r) for r in results) + "]"
        else:
            text = FORMATTERS[out_fmt](results[0])
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        if not quiet:
            print(st(f"  wrote {out_fmt} report → {path}", "green"), file=sys.stderr)


# ---------------------------------------------------------------- commands

def cmd_scan(args: argparse.Namespace) -> int:
    roots = []
    for p in args.paths:
        root = os.path.abspath(os.path.expanduser(p))
        if not os.path.isdir(root):
            return _err(f"not a directory: {p}")
        roots.append(root)
    try:
        o = _merge_config(args, roots[0])
        fail_on = None if str(o["fail_on"]).lower() == "none" else _parse_sev(o["fail_on"], "--fail-on")
    except (ValueError, OSError) as e:
        return _err(str(e))
    fmt = o["format"] or "table"
    if len(roots) > 1 and fmt not in ("table", "json"):
        return _err("scanning several paths supports --format table or json")

    progress = Progress(enabled=not (args.no_progress or args.quiet), color=args.color is not False)
    results: List[ScanResult] = []
    try:
        for root in roots:
            if len(roots) > 1:
                progress.log(Style(progress.color)(f"▸ {os.path.basename(root) or root}", "bold"))
            opts = _options(o, args, root, progress)
            results.append(scan(root, opts))
    except (OSError, ValueError) as e:
        progress.close()
        return _err(str(e))
    except KeyboardInterrupt:
        progress.close()
        raise
    progress.close()

    failing = fail_on is not None and any(f.severity >= fail_on for r in results for f in r.findings)
    if args.quiet_ok and not failing:
        args.quiet = True
    if fmt == "table":
        if not args.quiet:
            if len(results) == 1:
                render(results[0], sys.stdout, args.color, args.verbose, o["limit"])
            else:
                render_multi(results, sys.stdout, args.color)
    elif len(results) > 1:
        sys.stdout.write("[" + ",\n".join(FORMATTERS["json"](r) for r in results) + "]\n")
    else:
        sys.stdout.write(FORMATTERS[fmt](results[0]) + "\n")

    try:
        _write_outputs(list(o["output"]), results, o["format"], args.quiet, args.color)
    except (ValueError, OSError) as e:
        return _err(str(e))

    if args.write_baseline:
        with open(args.write_baseline, "w", encoding="utf-8") as fh:
            json.dump({"tool": "vulnfind", "version": __version__, "findings": [
                {"fingerprint": f.fingerprint, "rule_id": f.rule_id, "file": f.file, "title": f.title}
                for r in results for f in r.findings]}, fh, indent=2)
        if not args.quiet:
            print(f"  baseline with {sum(len(r.findings) for r in results)} findings written to {args.write_baseline}", file=sys.stderr)
        return 0

    if o["notify"]:
        from .automation import notify
        for url in o["notify"]:
            for r in results:
                if not o["notify_always"] and not (fail_on is not None and any(f.severity >= fail_on for f in r.findings)):
                    continue
                ok, info = notify(url, r)
                if not args.quiet or not ok:
                    host = url.split("/")[2] if "://" in url else url
                    print(f"  notify {host}: {'sent' if ok else 'FAILED'} ({info})", file=sys.stderr)
    return 1 if failing else 0


def cmd_sbom(args: argparse.Namespace) -> int:
    root = os.path.abspath(os.path.expanduser(args.path))
    if not os.path.isdir(root):
        return _err(f"not a directory: {args.path}")
    progress = Progress(enabled=not (args.no_progress or args.quiet or not args.output))
    opts = ScanOptions(scanners=["deps"], excludes=args.exclude or [], use_gitignore=not args.no_gitignore,
                       include_vendor=bool(args.include_vendor), offline=args.offline, progress=progress)
    result = scan(root, opts)
    progress.close()
    doc = FORMATTERS["sbom"](result)
    if args.output:
        for path in args.output:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(doc)
        if not args.quiet:
            print(f"SBOM: {len(result.packages)} packages from {len(result.manifests)} manifests → {', '.join(args.output)}", file=sys.stderr)
    else:
        print(doc)
    return 0


def _all_rules():
    from .scanners.code import CODE_RULES
    from .scanners.files import SENSITIVE
    from .scanners.iac import CONFIG_RULES
    from .scanners.secrets import SECRET_RULES
    from .scanners.taint_js import SINKS
    from .scanners.taint_python import CLASSES
    rows = []
    for cat, rules in (("secret", SECRET_RULES), ("code", CODE_RULES), ("config", CONFIG_RULES)):
        for r in rules:
            rows.append({"id": r.id, "category": cat, "severity": r.severity.label, "title": r.title,
                         "description": r.description, "fix": r.fix, "cwe": r.cwe,
                         "applies_to": list(r.exts) + list(r.names) + list(r.paths)})
    for vc in CLASSES.values():
        rows.append({"id": vc.rule_id, "category": "code", "severity": vc.severity.label, "title": f"{vc.title} (data flow)",
                     "description": f"Python taint analysis: untrusted input (request data, route parameters, CLI input) traced "
                                    f"through assignments and helper functions into a {vc.title.lower()} sink.",
                     "fix": vc.fix, "cwe": vc.cwe, "applies_to": [".py"]})
    seen_js = set()
    for s in SINKS:
        if s.rule_id in seen_js:
            continue
        seen_js.add(s.rule_id)
        rows.append({"id": s.rule_id, "category": "code", "severity": s.severity.label, "title": f"{s.title} (data flow)",
                     "description": f"JavaScript/TypeScript taint tracking: request/URL data traced through variables into a "
                                    f"{s.title.lower()} sink.", "fix": s.fix, "cwe": s.cwe, "applies_to": [".js", ".ts", ".jsx", ".tsx"]})
    structural = [
        ("DOCKER-LATEST-TAG", "config", "LOW", "Base image not pinned", "Dockerfile FROM without a tag/digest, or :latest."),
        ("DOCKER-ROOT-USER", "config", "MEDIUM", "Container runs as root", "Final Dockerfile stage has no non-root USER."),
        ("DOCKER-NO-HEALTHCHECK", "config", "INFO", "No HEALTHCHECK defined", "Dockerfile without HEALTHCHECK."),
        ("DOCKER-NO-DOCKERIGNORE", "config", "MEDIUM", "COPY . without .dockerignore", "The whole build context (.env, .git, keys) is copied into the image."),
        ("CONTAINER-DANGEROUS-CAP", "config", "HIGH", "Dangerous capability added", "SYS_ADMIN, NET_ADMIN, ALL … under cap_add / capabilities.add."),
        ("GHA-PWN-REQUEST", "config", "CRITICAL", "pull_request_target checks out untrusted PR code", "Privileged workflow runs attacker code."),
        ("GHA-SELF-HOSTED-PR", "config", "MEDIUM", "Self-hosted runner on pull requests", "Fork PRs can run code on your own machines."),
        ("RUNTIME-EOL", "config", "MEDIUM", "End-of-life runtime", "Python/Node/PHP/Ruby/Go version past end of security support."),
        ("FILE-WORLD-WRITABLE", "file", "MEDIUM", "World-writable file", "Any local user may modify the file."),
        ("DEP-TYPOSQUAT", "dependency", "HIGH", "Possible typosquat", "Dependency name one edit away from a popular package."),
        ("DEP-NO-LOCKFILE", "dependency", "LOW", "No lockfile", "package.json without a committed lockfile."),
        ("DEP-UNPINNED", "dependency", "LOW", "Unpinned requirements", "requirements.txt entries without exact versions."),
    ]
    for rid, cat, sev, title, desc in structural:
        rows.append({"id": rid, "category": cat, "severity": sev, "title": title, "description": desc, "fix": "", "cwe": None, "applies_to": []})
    seen = set()
    for glob, rid, title, sev, desc in SENSITIVE:
        if rid not in seen:
            seen.add(rid)
            rows.append({"id": rid, "category": "file", "severity": sev.label, "title": title, "description": desc,
                         "fix": "Remove it from the repository and rotate its contents.", "cwe": "CWE-538", "applies_to": [glob]})
    return rows


def cmd_rules(args: argparse.Namespace) -> int:
    rows = [r for r in _all_rules() if not args.category or r["category"] == args.category]
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    st = Style(use_color(sys.stdout))
    sev_color = {"CRITICAL": "magenta", "HIGH": "bred", "MEDIUM": "yellow", "LOW": "blue", "INFO": "grey"}
    current = None
    for r in rows:
        if r["category"] != current:
            current = r["category"]
            print("\n" + st(current.upper(), "bold", "under"))
        print(f"  {st(r['id'].ljust(28), 'bold')} {st(r['severity'].ljust(9), sev_color[r['severity']])} {r['title']}")
    print(f"\n{len(rows)} rules, plus CVE lookups (OSV.dev + CISA KEV + EPSS) for npm, PyPI, Go, crates.io, RubyGems, "
          "Packagist, Maven, NuGet, Pub and Hex\n")
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    rid = args.rule_id.upper()
    for r in _all_rules():
        if r["id"] == rid:
            st = Style(use_color(sys.stdout))
            print(f"\n{st(r['id'], 'bold')}  {r['severity']}  ({r['category']})\n{st(r['title'], 'bold')}\n")
            print(r["description"])
            if r["fix"]:
                print("\n" + st("Fix: ", "green") + r["fix"])
            if r["cwe"]:
                print(f"\n{r['cwe']}: https://cwe.mitre.org/data/definitions/{r['cwe'].split('-')[-1]}.html")
            if r["applies_to"]:
                print("Applies to: " + ", ".join(r["applies_to"]))
            print(f"\nSuppress inline:   # vulnfind:ignore {r['id']}\nSuppress globally: echo 'rule:{r['id']}' >> .vulnfindignore\n")
            return 0
    if rid.startswith(("CVE-", "GHSA-", "PYSEC-", "GO-", "RUSTSEC-", "OSV-", "MAL-")):
        from . import osv
        try:
            v = osv.OSVClient().fetch({rid: None}).get(rid)
        except Exception:
            v = None
        if not v:
            print(f"{rid}: see https://osv.dev/vulnerability/{rid}")
            return 0
        sev, score, vector = osv.severity_of(v)
        print(f"\n{rid}  {sev.label}" + (f"  CVSS {score}" if score else "") + f"\n{v.get('summary', '')}\n")
        print((v.get("details") or "")[:1500])
        pkgs = sorted({f"{a['package']['ecosystem']}/{a['package']['name']}" for a in v.get("affected", []) if a.get("package")})
        if pkgs:
            print("\nAffected: " + ", ".join(pkgs[:10]))
        print(f"\nhttps://osv.dev/vulnerability/{rid}\n")
        return 0
    return _err(f"unknown rule {args.rule_id!r} (see `vulnfind rules`)")


INIT_IGNORE = """# vulnfind ignore file
# Paths use .gitignore syntax:
#   docs/
#   **/*.min.js
#
# Disable a rule everywhere:
#   rule:PY-REQUESTS-NO-TIMEOUT
#
# Accept a specific advisory (CVE, GHSA, ...) - add a reason!
#   vuln:CVE-2023-12345   # not reachable: we never parse untrusted YAML
"""


def cmd_init(args: argparse.Namespace) -> int:
    from .automation import DEFAULT_CONFIG
    created = []
    cfg_path = os.path.join(args.path, ".vulnfind.json")
    if not os.path.exists(cfg_path):
        cfg = {"$comment": "vulnfind settings; command-line flags override these. Run `vulnfind --help` for all options."}
        cfg.update(DEFAULT_CONFIG)
        with open(cfg_path, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2)
            fh.write("\n")
        created.append(cfg_path)
    ign_path = os.path.join(args.path, ".vulnfindignore")
    if not os.path.exists(ign_path):
        with open(ign_path, "w", encoding="utf-8") as fh:
            fh.write(INIT_IGNORE)
        created.append(ign_path)
    for p in created:
        print(f"created {p}")
    if not created:
        print("nothing to do: .vulnfind.json and .vulnfindignore already exist")
    print("next: `vulnfind hook install` (pre-commit) and `vulnfind ci github --write` (CI)")
    return 0


def cmd_hook(args: argparse.Namespace) -> int:
    from . import gitutil
    root = os.path.abspath(args.path)
    try:
        if args.action == "install":
            path = gitutil.install_hook(root, args.fail_on)
            print(f"installed pre-commit hook → {path}\ncommits are now scanned for secrets & high-risk code (bypass once with --no-verify)")
            if not shutil.which("vulnfind"):
                print("warning: `vulnfind` is not on PATH, so the hook will skip scanning", file=sys.stderr)
        elif args.action == "uninstall":
            path = gitutil.uninstall_hook(root)
            print(f"removed vulnfind from {path}" if path else "no vulnfind hook installed")
        else:
            d = gitutil.hooks_dir(root)
            path = os.path.join(d, "pre-commit") if d else None
            on = False
            if path and os.path.exists(path):
                with open(path, encoding="utf-8", errors="replace") as fh:
                    on = gitutil.HOOK_MARK in fh.read()
            print(f"pre-commit hook: {'installed' if on else 'not installed'}" + (f" ({path})" if on else ""))
    except (RuntimeError, OSError) as e:
        return _err(str(e))
    return 0


def cmd_ci(args: argparse.Namespace) -> int:
    from . import automation
    text = {"github": lambda: automation.github_workflow(args.install), "gitlab": lambda: automation.gitlab_job(args.install),
            "pre-commit": automation.precommit_config}[args.provider]()
    if not args.write:
        print(text)
        return 0
    target = {"github": os.path.join(".github", "workflows", "vulnfind.yml"), "gitlab": "vulnfind.gitlab-ci.yml",
              "pre-commit": ".pre-commit-config.vulnfind.yaml"}[args.provider]
    path = os.path.join(args.path, target)
    if os.path.exists(path):
        return _err(f"{path} already exists")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"wrote {path}")
    if args.provider == "gitlab":
        print("add to .gitlab-ci.yml:  include: { local: vulnfind.gitlab-ci.yml }")
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    from .automation import compare, load_report
    try:
        diff = compare(load_report(args.old), load_report(args.new))
    except (OSError, ValueError, KeyError) as e:
        return _err(f"could not read reports: {e} (create them with `vulnfind -o report.json`)")
    fail_on = None if args.fail_on.lower() == "none" else Severity.parse(args.fail_on)
    if args.format == "json":
        print(json.dumps({"new": diff["new"], "fixed": diff["fixed"], "unchanged": len(diff["unchanged"])}, indent=2))
    elif args.format == "markdown":
        out = [f"### vulnfind: {len(diff['new'])} new, {len(diff['fixed'])} fixed, {len(diff['unchanged'])} unchanged", ""]
        for label, key in (("New", "new"), ("Fixed", "fixed")):
            if diff[key]:
                out.append(f"**{label}**\n")
                out += [f"- `{f['severity']}` {f['title']} — `{f['file']}{':' + str(f['line']) if f.get('line') else ''}`" for f in diff[key]]
                out.append("")
        print("\n".join(out))
    else:
        st = Style(use_color(sys.stdout, args.color))
        print("\n  " + st(f"{len(diff['new'])} new", "bold", "bred") + "  ·  " + st(f"{len(diff['fixed'])} fixed", "bold", "green")
              + "  ·  " + st(f"{len(diff['unchanged'])} unchanged", "grey") + "\n")
        for sign, key, color in (("+", "new", "bred"), ("-", "fixed", "green")):
            for f in diff[key]:
                sev = Severity.parse(f["severity"])
                loc = f"{f['file']}:{f['line']}" if f.get("line") else f["file"]
                print(f"  {st(sign, color, 'bold')} {st(f['severity'].ljust(8), *SEV_TEXT[sev])} {f['title']}  {st(loc, 'cyan')}")
        print()
    return 1 if fail_on is not None and any(Severity.parse(f["severity"]) >= fail_on for f in diff["new"]) else 0


def cmd_watch(args: argparse.Namespace) -> int:
    from . import automation
    from .walker import IgnoreConfig, walk
    root = os.path.abspath(os.path.expanduser(args.path))
    if not os.path.isdir(root):
        return _err(f"not a directory: {args.path}")
    st = Style(use_color(sys.stdout, args.color))
    try:
        o = _merge_config(args, root)
    except (ValueError, OSError) as e:
        return _err(str(e))
    progress = Progress(enabled=not args.no_progress)
    base_opts = _options(o, args, root, progress)
    first = scan(root, base_opts)
    progress.close()
    render(first, sys.stdout, args.color, False, 10)
    current = {}
    for f in first.findings:
        current.setdefault(f.file, {})[f.fingerprint] = f
    print(st(f"  watching {root} for changes (Ctrl-C to stop)…\n", "cyan"), flush=True)
    ignore = IgnoreConfig.load(root)

    def list_files():
        return list(walk(root, ignore, base_opts.excludes, base_opts.use_gitignore, base_opts.include_vendor))

    def on_change(changed: set) -> None:
        from .scanners.deps import is_manifest
        from .walker import SourceFile
        manifest_changed = any(is_manifest(SourceFile("", rel, 0)) for rel in changed)
        scanners = [s for s in base_opts.scanners if s != "deps" or manifest_changed]
        opts = ScanOptions(**{**base_opts.__dict__, "only": set(changed), "scanners": scanners, "progress": Progress(False),
                              "history": False})
        res = scan(root, opts)
        stamp = time.strftime("%H:%M:%S")
        new_by_file: Dict[str, Dict[str, Any]] = {}
        for f in res.findings:
            new_by_file.setdefault(f.file, {})[f.fingerprint] = f
        added = removed = 0
        files_touched = set(changed) | ({f.file for f in res.findings if f.category == "dependency"} if manifest_changed else set())
        for rel in sorted(files_touched):
            before, after = current.get(rel, {}), new_by_file.get(rel, {})
            for fp, f in after.items():
                if fp not in before:
                    added += 1
                    print(f"  {st(stamp, 'grey')} {st('+', 'bred', 'bold')} {st(f.severity.label.ljust(8), *SEV_TEXT[f.severity])} "
                          f"{f.title}  {st(f.location, 'cyan')}")
            for fp, f in before.items():
                if fp not in after:
                    removed += 1
                    print(f"  {st(stamp, 'grey')} {st('✔', 'green', 'bold')} {st('resolved', 'green')}  {f.title}  {st(f.location, 'grey')}")
            current[rel] = after
        if not added and not removed:
            print(f"  {st(stamp, 'grey')} {st('·', 'grey')} {len(changed)} file(s) changed, no new issues")
        total = sum(len(v) for v in current.values())
        print(st(f"           {total} open findings", "grey"), flush=True)

    try:
        automation.watch(root, list_files, on_change, args.interval)
    except KeyboardInterrupt:
        print("\nstopped watching")
    return 0


def cmd_fix(args: argparse.Namespace) -> int:
    from . import fixer
    root = os.path.abspath(os.path.expanduser(args.path))
    if not os.path.isdir(root):
        return _err(f"not a directory: {args.path}")
    st = Style(use_color(sys.stdout, args.color))
    progress = Progress(enabled=not (args.no_progress or args.quiet))
    result = scan(root, ScanOptions(scanners=["deps"], excludes=args.exclude or [], use_gitignore=not args.no_gitignore,
                                    include_vendor=bool(args.include_vendor), enrich=False, progress=progress))
    progress.close()
    if args.no_major:
        result.findings = [f for f in result.findings if not (f.extra.get("fixed") and
                           fixer._major(f.extra["fixed"]) != fixer._major(f.extra.get("version", "")))]
    pl = fixer.plan(result)
    if not pl.upgrades:
        unfixed = [f for f in result.findings if f.category == "dependency" and not f.extra.get("fixed")]
        print(st("\n  ✔ Nothing to upgrade", "green", "bold") + (f" ({len(unfixed)} advisories have no fixed release yet)" if unfixed else "") + "\n")
        for msg in result.warnings:
            print(st("  ! " + msg, "yellow"))
        return 0
    print("\n  " + st(f"{len(pl.upgrades)} package upgrade(s) fix {sum(1 for f in result.findings if f.extra.get('fixed'))} advisories", "bold") + "\n")
    for eco, name, old, new, major in pl.upgrades:
        warn = st("  major version: check the changelog", "yellow") if major else ""
        print(f"    {name} {st(old, 'red')} → {st(new, 'green', 'bold')}  {st(eco, 'grey')}{warn}")
    d = fixer.diff(pl, root)
    if d:
        print()
        for line in d.splitlines():
            color = "green" if line.startswith("+") and not line.startswith("+++") else "red" if line.startswith("-") and not line.startswith("---") else "cyan" if line.startswith("@@") else "grey"
            print("    " + st(line, color))
    for n in pl.notes:
        print(st("    note: " + n, "grey"))
    if pl.manual:
        print("\n  " + st("Manual steps", "bold"))
        for m in pl.manual:
            print("    • " + m)
    if args.apply:
        written = fixer.apply(pl)
        print("\n  " + st(f"✔ updated {len(written)} file(s)", "green", "bold"))
        if pl.commands:
            print("  " + st("Now run:", "bold"))
            for c in pl.commands:
                print("    $ " + c)
        print(st("  then re-run `vulnfind` to confirm, and run your tests.", "grey") + "\n")
    else:
        if pl.commands:
            print("\n  " + st("Commands" + (" (after --apply)" if pl.edits else ""), "bold"))
            for c in pl.commands:
                print("    $ " + c)
        print("\n  " + st("Dry run - re-run with --apply to write these changes.", "yellow") + "\n")
    return 0


def cmd_cache(args: argparse.Namespace) -> int:
    from .osv import _cache_dir
    base = os.path.dirname(_cache_dir())
    if args.action == "clear":
        if os.path.isdir(base):
            shutil.rmtree(base)
        print(f"cleared {base}")
        return 0
    size = n = 0
    for dp, _, fns in os.walk(base):
        for fn in fns:
            n += 1
            size += os.path.getsize(os.path.join(dp, fn))
    print(f"{base}: {n} files, {size / 1024:.0f} KB (advisories, CISA KEV, EPSS; refreshed every 24h)")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or (argv[0] not in COMMANDS and argv[0] not in ("-h", "--help", "--version")):
        argv.insert(0, "scan")
    args = build_parser().parse_args(argv)
    handlers = {"scan": cmd_scan, "sbom": cmd_sbom, "rules": cmd_rules, "explain": cmd_explain, "init": cmd_init,
                "hook": cmd_hook, "ci": cmd_ci, "compare": cmd_compare, "watch": cmd_watch, "fix": cmd_fix, "cache": cmd_cache}
    try:
        return handlers[args.command](args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
