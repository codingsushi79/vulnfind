"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import __version__
from .engine import ALL_SCANNERS, ScanOptions, scan
from .models import Severity
from .reporters import EXTENSIONS, FORMATTERS
from .reporters.terminal import Style, render, use_color

COMMANDS = ("scan", "sbom", "rules", "explain", "init")

EPILOG = """examples:
  vulnfind                              scan the current folder
  vulnfind ~/code/app -v                scan a folder, show full descriptions + references
  vulnfind --scanners deps              only check dependencies for CVEs
  vulnfind -o report.html -o out.sarif  write an HTML report and SARIF (GitHub code scanning)
  vulnfind -f json | jq .summary        machine-readable output
  vulnfind --fail-on critical           CI gate: exit 1 only on critical findings
  vulnfind --write-baseline base.json   accept current findings; later: --baseline base.json
  vulnfind sbom -o sbom.json            CycloneDX SBOM of every dependency
  vulnfind rules                        list every built-in rule
  vulnfind explain PY-PICKLE            details for one rule

suppress a finding inline with a comment:  # vulnfind:ignore [RULE-ID]
project-wide ignores go in .vulnfindignore (paths, rule:ID, vuln:CVE-...)
exit codes: 0 = clean, 1 = findings at/above --fail-on, 2 = error
"""


def _severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e))


def _add_scan_args(p: argparse.ArgumentParser, sbom: bool = False) -> None:
    p.add_argument("path", nargs="?", default=".", help="folder to scan (default: current directory)")
    p.add_argument("-o", "--output", action="append", default=[], metavar="FILE",
                   help="write a report file; format comes from the extension (.json .sarif .html .md) or --format. Repeatable")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="skip paths matching a gitignore-style glob. Repeatable")
    p.add_argument("--no-gitignore", action="store_true", help="also scan files ignored by .gitignore")
    p.add_argument("--include-vendor", action="store_true", help="also scan vendor/ and node_modules/")
    p.add_argument("--no-color", dest="color", action="store_false", default=None, help="disable colours")
    p.add_argument("--color", dest="color", action="store_true", help="force colours")
    p.add_argument("-q", "--quiet", action="store_true", help="no terminal report (exit code / files only)")
    if sbom:
        return
    p.add_argument("-f", "--format", choices=["table", "json", "sarif", "markdown", "html", "sbom"], default=None,
                   help="output format for stdout (default: table)")
    p.add_argument("--scanners", default=",".join(ALL_SCANNERS), metavar="LIST",
                   help=f"comma list of scanners to run: {','.join(ALL_SCANNERS)} (default: all)")
    p.add_argument("--skip", default="", metavar="LIST", help="comma list of scanners to skip")
    p.add_argument("--min-severity", type=_severity, default=Severity.LOW, metavar="LEVEL",
                   help="hide findings below LEVEL: info, low, medium, high, critical (default: low)")
    p.add_argument("--fail-on", default="high", metavar="LEVEL",
                   help="exit 1 if any finding is at/above LEVEL, or 'none' (default: high)")
    p.add_argument("--offline", action="store_true", help="do not query OSV.dev (inventory dependencies only)")
    p.add_argument("--no-cache", action="store_true", help="ignore the local advisory cache (~/.cache/vulnfind)")
    p.add_argument("--no-dev", action="store_true", help="ignore vulnerabilities in dev/test-only dependencies")
    p.add_argument("--no-test-downgrade", action="store_true",
                   help="keep full severity for findings in tests/, examples/, fixtures/ ...")
    p.add_argument("--baseline", metavar="FILE", help="hide findings recorded in a baseline file")
    p.add_argument("--write-baseline", metavar="FILE", help="record current findings to FILE (then use --baseline)")
    p.add_argument("--limit", type=int, default=0, metavar="N", help="show at most N findings per section in the terminal")
    p.add_argument("-v", "--verbose", action="store_true", help="show descriptions, references and every CVE")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnfind",
        description="Find vulnerabilities in a project: known CVEs in dependencies (OSV.dev), leaked secrets, "
                    "insecure code, Docker/Kubernetes/Terraform/GitHub Actions misconfigurations and sensitive files.",
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"vulnfind {__version__}")
    sub = parser.add_subparsers(dest="command")
    _add_scan_args(sub.add_parser("scan", help="scan a folder (default command)", epilog=EPILOG,
                                  formatter_class=argparse.RawDescriptionHelpFormatter))
    _add_scan_args(sub.add_parser("sbom", help="generate a CycloneDX SBOM of all dependencies"), sbom=True)
    r = sub.add_parser("rules", help="list built-in rules")
    r.add_argument("--category", choices=["secret", "code", "config", "file"], help="only one category")
    r.add_argument("--json", action="store_true", help="output JSON")
    e = sub.add_parser("explain", help="explain a rule")
    e.add_argument("rule_id")
    i = sub.add_parser("init", help="create a commented .vulnfindignore in a folder")
    i.add_argument("path", nargs="?", default=".")
    return parser


def _progress(enabled: bool):
    if not enabled:
        return None

    def show(msg: str) -> None:
        sys.stderr.write(f"\r\033[2K  \033[90m{msg}\033[0m")
        sys.stderr.flush()
    return show


def _clear_progress(enabled: bool) -> None:
    if enabled:
        sys.stderr.write("\r\033[2K")
        sys.stderr.flush()


def cmd_scan(args: argparse.Namespace) -> int:
    root = os.path.abspath(os.path.expanduser(args.path))
    if not os.path.isdir(root):
        print(f"vulnfind: error: not a directory: {args.path}", file=sys.stderr)
        return 2
    wanted = {s.strip() for s in args.scanners.split(",") if s.strip()}
    if "dependencies" in wanted:
        wanted.add("deps")
    skip = {s.strip() for s in args.skip.split(",") if s.strip()}
    unknown = (wanted | skip) - set(ALL_SCANNERS) - {"dependencies"}
    if unknown:
        print(f"vulnfind: error: unknown scanner(s): {', '.join(sorted(unknown))}. Choose from {', '.join(ALL_SCANNERS)}", file=sys.stderr)
        return 2
    fail_on: Optional[Severity] = None
    if args.fail_on.lower() != "none":
        try:
            fail_on = Severity.parse(args.fail_on)
        except ValueError as e:
            print(f"vulnfind: error: --fail-on: {e}", file=sys.stderr)
            return 2

    show_progress = sys.stderr.isatty() and not args.quiet and (args.format in (None, "table"))
    opts = ScanOptions(
        scanners=[s for s in ALL_SCANNERS if s in wanted and s not in skip],
        excludes=args.exclude, use_gitignore=not args.no_gitignore, include_vendor=args.include_vendor,
        offline=args.offline, use_cache=not args.no_cache, min_severity=args.min_severity,
        baseline=args.baseline, include_dev=not args.no_dev, downgrade_tests=not args.no_test_downgrade,
        progress=_progress(show_progress),
    )
    if show_progress:
        opts.progress("scanning...")
    try:
        result = scan(root, opts)
    except (OSError, ValueError) as e:
        _clear_progress(show_progress)
        print(f"vulnfind: error: {e}", file=sys.stderr)
        return 2
    _clear_progress(show_progress)

    fmt = args.format or "table"
    if fmt == "table":
        if not args.quiet:
            render(result, sys.stdout, args.color, args.verbose, args.limit)
    else:
        sys.stdout.write(FORMATTERS[fmt](result))
        sys.stdout.write("\n")

    for path in args.output:
        ext = os.path.splitext(path)[1].lower()
        out_fmt = args.format if args.format and args.format != "table" and len(args.output) == 1 else EXTENSIONS.get(ext)
        if path.endswith((".cdx.json", "sbom.json")):
            out_fmt = "sbom"
        if not out_fmt:
            print(f"vulnfind: error: can't infer report format for {path}; use .json/.sarif/.html/.md or --format", file=sys.stderr)
            return 2
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(FORMATTERS[out_fmt](result))
        if not args.quiet and fmt == "table":
            st = Style(use_color(sys.stdout, args.color))
            print(st(f"  wrote {out_fmt} report → {path}", "green"))

    if args.write_baseline:
        with open(args.write_baseline, "w", encoding="utf-8") as fh:
            json.dump({"tool": "vulnfind", "version": __version__, "findings": [
                {"fingerprint": f.fingerprint, "rule_id": f.rule_id, "file": f.file, "title": f.title}
                for f in result.findings]}, fh, indent=2)
        if not args.quiet:
            print(f"  baseline with {len(result.findings)} findings written to {args.write_baseline}", file=sys.stderr)
        return 0

    if fail_on is not None and any(f.severity >= fail_on for f in result.findings):
        return 1
    return 0


def cmd_sbom(args: argparse.Namespace) -> int:
    root = os.path.abspath(os.path.expanduser(args.path))
    if not os.path.isdir(root):
        print(f"vulnfind: error: not a directory: {args.path}", file=sys.stderr)
        return 2
    opts = ScanOptions(scanners=["deps"], excludes=args.exclude, use_gitignore=not args.no_gitignore,
                       include_vendor=args.include_vendor, offline=False)
    result = scan(root, opts)
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
    rows = []
    for cat, rules in (("secret", SECRET_RULES), ("code", CODE_RULES), ("config", CONFIG_RULES)):
        for r in rules:
            rows.append({"id": r.id, "category": cat, "severity": r.severity.label, "title": r.title,
                         "description": r.description, "fix": r.fix, "cwe": r.cwe,
                         "applies_to": list(r.exts) + list(r.names) + list(r.paths)})
    structural = [
        ("DOCKER-LATEST-TAG", "config", "LOW", "Base image not pinned", "Dockerfile FROM without a tag/digest, or :latest."),
        ("DOCKER-ROOT-USER", "config", "MEDIUM", "Container runs as root", "Final Dockerfile stage has no non-root USER."),
        ("DOCKER-NO-HEALTHCHECK", "config", "INFO", "No HEALTHCHECK defined", "Dockerfile without HEALTHCHECK."),
        ("CONTAINER-DANGEROUS-CAP", "config", "HIGH", "Dangerous capability added", "SYS_ADMIN, NET_ADMIN, ALL ... under cap_add / capabilities.add."),
        ("GHA-PWN-REQUEST", "config", "CRITICAL", "pull_request_target checks out untrusted PR code", "Privileged workflow runs attacker code."),
        ("RUNTIME-EOL", "config", "MEDIUM", "End-of-life runtime", "Python/Node/PHP/Ruby/Go version past end of security support (Dockerfile, .nvmrc, .python-version, engines)."),
        ("FILE-WORLD-WRITABLE", "file", "MEDIUM", "World-writable file", "Any local user may modify the file."),
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
    print(f"\n{len(rows)} rules, plus CVE lookups for npm, PyPI, Go, crates.io, RubyGems, Packagist, Maven, NuGet, Pub and Hex via OSV.dev\n")
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
                num = r["cwe"].split("-")[-1]
                print(f"\n{r['cwe']}: https://cwe.mitre.org/data/definitions/{num}.html")
            if r["applies_to"]:
                print("Applies to: " + ", ".join(r["applies_to"]))
            print(f"\nSuppress inline:   # vulnfind:ignore {r['id']}\nSuppress globally: echo 'rule:{r['id']}' >> .vulnfindignore\n")
            return 0
    if rid.startswith(("CVE-", "GHSA-", "PYSEC-", "GO-", "RUSTSEC-", "OSV-", "MAL-")):
        print(f"{rid} is an advisory ID - see https://osv.dev/vulnerability/{rid}")
        return 0
    print(f"vulnfind: unknown rule {args.rule_id!r} (see `vulnfind rules`)", file=sys.stderr)
    return 2


INIT_TEMPLATE = """# vulnfind ignore file
# Paths use .gitignore syntax:
#   docs/
#   **/*.min.js
#   tests/fixtures/
#
# Disable a rule everywhere:
#   rule:PY-REQUESTS-NO-TIMEOUT
#
# Accept a specific advisory (CVE, GHSA, ...) - add a reason!
#   vuln:CVE-2023-12345   # not reachable: we never parse untrusted YAML
"""


def cmd_init(args: argparse.Namespace) -> int:
    path = os.path.join(args.path, ".vulnfindignore")
    if os.path.exists(path):
        print(f"{path} already exists", file=sys.stderr)
        return 1
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(INIT_TEMPLATE)
    print(f"created {path}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or (argv[0] not in COMMANDS and argv[0] not in ("-h", "--help", "--version")):
        argv.insert(0, "scan")
    args = build_parser().parse_args(argv)
    handlers = {"scan": cmd_scan, "sbom": cmd_sbom, "rules": cmd_rules, "explain": cmd_explain, "init": cmd_init}
    try:
        return handlers[args.command](args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
