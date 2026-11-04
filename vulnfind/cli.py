"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from typing import Any, Dict, List, Optional

from . import __version__, customrules
from .engine import ALL_SCANNERS, ScanOptions, scan
from .models import ScanResult, Severity
from .progress import Progress
from .reporters import FORMATTERS, format_for_path
from .reporters.terminal import SEV_TEXT, Style, render, render_multi, use_color

COMMANDS = ("scan", "web", "ai", "triage", "bench", "trend", "subdomains", "monitor", "image", "k8s", "cloud", "tfplan", "routes", "update", "sbom", "rules", "explain", "init", "hook", "ci", "compare", "watch", "fix", "cache")
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
  vulnfind https://example.com          scan a website you own (see `vulnfind web --help`)
  vulnfind github.com/owner/repo        clone (shallow) and scan a remote repository
  vulnfind update                       upgrade vulnfind itself

configuration: .vulnfind.json in the scanned folder (`vulnfind init`), overridden by flags.
suppress inline with:  # vulnfind:ignore [RULE-ID]   ·   project-wide: .vulnfindignore
exit codes: 0 = clean, 1 = findings at/above --fail-on, 2 = error
"""

BUILTIN_DEFAULTS: Dict[str, Any] = {
    "scanners": ",".join(ALL_SCANNERS), "skip": "", "fail_on": "high", "min_severity": "low", "exclude": [],
    "output": [], "offline": False, "no_cache": False, "no_dev": False, "no_test_downgrade": False, "baseline": None,
    "history": False, "history_depth": None, "no_deep": False, "no_enrich": False, "jobs": 0, "notify": [],
    "notify_always": False, "include_vendor": False, "no_gitignore": False, "limit": 0, "format": None, "rules": [],
    "no_health": False, "all_deps": False,
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
    p.add_argument("--no-record", action="store_true", help="don't add this scan to the local trend history")


def _add_scan_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("paths", nargs="*", default=["."], metavar="PATH", help="folder(s) to scan (default: current directory)")
    _add_common(p)
    g = p.add_argument_group("output")
    g.add_argument("-f", "--format", choices=FORMATS, default=None, help="stdout format (default: table)")
    g.add_argument("-o", "--output", action="append", default=None, metavar="FILE",
                   help="write a report; format from extension: .json .sarif .html .md .xml(junit) .csv .cdx.json(sbom). Repeatable")
    g.add_argument("-v", "--verbose", action="store_true", help="descriptions, references, full data flows, every CVE")
    g.add_argument("--plain", action="store_true", help="explain findings in plain language for non-security readers")
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
    g.add_argument("--no-health", action="store_true", default=None, help="skip deps.dev package health & license checks")
    g.add_argument("--all-deps", action="store_true", default=None, help="health & license checks for transitive deps too (slower)")
    g = p.add_argument_group("gating & automation")
    g.add_argument("--min-severity", default=None, metavar="LEVEL", help="hide findings below LEVEL (default: low)")
    g.add_argument("--fail-on", default=None, metavar="LEVEL", help="exit 1 if a finding is at/above LEVEL, or 'none' (default: high)")
    g.add_argument("--baseline", metavar="FILE", default=None, help="hide findings recorded in a baseline file")
    g.add_argument("--write-baseline", metavar="FILE", help="record current findings to FILE")
    g.add_argument("--notify", action="append", default=None, metavar="URL", help="POST a summary to a webhook (Slack/Discord/Teams/JSON). Repeatable")
    g.add_argument("--notify-always", action="store_true", default=None, help="notify even when nothing reaches --fail-on")
    g.add_argument("--quiet-ok", action="store_true", help="print nothing unless a finding reaches --fail-on (hooks, cron)")
    g.add_argument("-j", "--jobs", type=int, default=None, metavar="N", help="worker processes (default: auto)")


WEB_EPILOG = """Only scan websites you own or have written permission to test.

default (passive): TLS & certificate, HTTPS redirect, security headers (CSP, HSTS, framing…), cookie flags, CORS,
  HTTP methods, debug/error pages, ~55 exposed-file probes (.git, .env, backups, phpinfo, actuator…),
  mixed content, SRI, JS library CVEs, secrets & source maps in served JS, SPF/DMARC/CAA.
  GET/OPTIONS requests only, rate-limited, same-origin crawl that skips logout/delete-style links.
--active: also sends harmless markers to discovered GET parameters to confirm reflected XSS, SQL errors and
  open redirects (capped by --active-budget; never submits POST forms).

examples:
  vulnfind web https://example.com
  vulnfind https://example.com                 (same thing)
  vulnfind web https://staging.example.com --active -o report.html
  vulnfind web https://app.example.com -H "Authorization: Bearer $TOKEN" --max-pages 80
  vulnfind web https://example.com --fail-on high --quiet-ok --notify https://hooks.slack.com/...
"""


def _add_web_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("urls", nargs="+", metavar="URL", help="site(s) to scan (https:// assumed if omitted)")
    g = p.add_argument_group("scope")
    g.add_argument("--max-pages", type=int, default=30, metavar="N", help="pages to crawl (default: 30; 1 = only the given URL)")
    g.add_argument("--max-requests", type=int, default=600, metavar="N", help="hard cap on requests (default: 600)")
    g.add_argument("--rate", type=float, default=8.0, metavar="RPS", help="requests per second (default: 8)")
    g.add_argument("--timeout", type=float, default=15.0, metavar="SECONDS")
    g.add_argument("-H", "--header", action="append", default=[], metavar="'Name: value'", help="extra request header (auth). Repeatable")
    g.add_argument("--cookie", metavar="'a=1; b=2'", help="Cookie header for authenticated scans")
    g.add_argument("--insecure", action="store_true", help="don't verify TLS certificates for requests")
    g.add_argument("--active", action="store_true", help="enable active probes (XSS, SQL errors, open redirect) - authorised targets only")
    g.add_argument("--active-budget", type=int, default=150, metavar="N", help="max requests for active probes (default: 150)")
    g.add_argument("--login-url", metavar="URL", help="log in through this form before crawling (credentials from env vars)")
    g.add_argument("--login-user-env", default="VULNFIND_USER", metavar="VAR", help="env var holding the username (default: VULNFIND_USER)")
    g.add_argument("--login-pass-env", default="VULNFIND_PASSWORD", metavar="VAR", help="env var holding the password (default: VULNFIND_PASSWORD)")
    g.add_argument("--login-success", metavar="TEXT", help="text that only appears when logged in (verifies the login)")
    g.add_argument("--openapi", metavar="SPEC", help="OpenAPI/Swagger JSON (file or URL): test every GET operation's auth")
    g.add_argument("--browser", action="store_true", help="render JavaScript with headless Chromium (needs Playwright)")
    g = p.add_argument_group("checks")
    g.add_argument("--no-tls", action="store_true", help="skip certificate/protocol checks")
    g.add_argument("--no-paths", action="store_true", help="skip exposed-file probes")
    g.add_argument("--no-js", action="store_true", help="skip JavaScript analysis")
    g.add_argument("--no-dns", action="store_true", help="skip SPF/DMARC/CAA lookups")
    g.add_argument("--offline", action="store_true", help="no third-party lookups (OSV, KEV/EPSS, DNS-over-HTTPS)")
    g.add_argument("--no-cache", action="store_true")
    g.add_argument("--no-enrich", action="store_true", help="skip CISA KEV / EPSS for library CVEs")
    g = p.add_argument_group("output & gating")
    g.add_argument("-f", "--format", choices=FORMATS, default=None)
    g.add_argument("-o", "--output", action="append", default=[], metavar="FILE")
    g.add_argument("-v", "--verbose", action="store_true")
    g.add_argument("--plain", action="store_true", help="explain findings in plain language")
    g.add_argument("--limit", type=int, default=0, metavar="N")
    g.add_argument("--min-severity", default="low", metavar="LEVEL")
    g.add_argument("--fail-on", default="high", metavar="LEVEL")
    g.add_argument("--baseline", metavar="FILE", help="hide findings recorded in a baseline file")
    g.add_argument("--write-baseline", metavar="FILE")
    g.add_argument("--notify", action="append", default=[], metavar="URL")
    g.add_argument("--notify-always", action="store_true")
    g.add_argument("--quiet-ok", action="store_true")
    g.add_argument("--no-progress", action="store_true")
    g.add_argument("-q", "--quiet", action="store_true")
    g.add_argument("--no-color", dest="color", action="store_false", default=None)
    g.add_argument("--color", dest="color", action="store_true")
    g.add_argument("--no-record", action="store_true", help="don't add this scan to the local trend history")


def _add_output_args(p: argparse.ArgumentParser) -> None:
    """Output/gating flags shared by the image, k8s, cloud and tfplan commands."""
    g = p.add_argument_group("output & gating")
    g.add_argument("-f", "--format", choices=FORMATS, default=None)
    g.add_argument("-o", "--output", action="append", default=[], metavar="FILE")
    g.add_argument("-v", "--verbose", action="store_true")
    g.add_argument("--plain", action="store_true", help="explain findings in plain language")
    g.add_argument("--limit", type=int, default=0, metavar="N")
    g.add_argument("--min-severity", default="low", metavar="LEVEL")
    g.add_argument("--fail-on", default="high", metavar="LEVEL")
    g.add_argument("--offline", action="store_true", help="no CVE lookups")
    g.add_argument("--no-cache", action="store_true")
    g.add_argument("--no-enrich", action="store_true")
    g.add_argument("--notify", action="append", default=[], metavar="URL")
    g.add_argument("--notify-always", action="store_true")
    g.add_argument("--quiet-ok", action="store_true")
    g.add_argument("--no-progress", action="store_true")
    g.add_argument("-q", "--quiet", action="store_true")
    g.add_argument("--no-color", dest="color", action="store_false", default=None)
    g.add_argument("--color", dest="color", action="store_true")
    g.add_argument("--no-record", action="store_true", help="don't add this scan to the local trend history")


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

    wb = sub.add_parser("web", help="scan a website (TLS, headers, exposed files, JS libraries, …)", epilog=WEB_EPILOG,
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    _add_web_args(wb)

    sb = sub.add_parser("sbom", help="generate a CycloneDX SBOM of all dependencies")
    sb.add_argument("path", nargs="?", default=".")
    sb.add_argument("-o", "--output", action="append", default=[], metavar="FILE")
    sb.add_argument("--offline", action="store_true", help="omit the vulnerability section")
    _add_common(sb)

    r = sub.add_parser("rules", help="list built-in rules")
    r.add_argument("--category", choices=["secret", "code", "config", "file", "dependency", "web"])
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

    ai = sub.add_parser("ai", help="explain the top findings and draft fixes with Claude (sends code to the Claude API)")
    ai.add_argument("path", nargs="?", default=".")
    ai.add_argument("--top", type=int, default=3, metavar="N", help="how many findings, highest priority first (default: 3)")
    ai.add_argument("--finding", action="append", default=[], metavar="FINGERPRINT", help="explain specific findings (from -f json)")
    ai.add_argument("--report", metavar="FILE.json", help="use an existing JSON report instead of scanning")
    ai.add_argument("--model", default="claude-opus-5-5")
    ai.add_argument("--effort", default="high", choices=["low", "medium", "high", "xhigh", "max"])
    ai.add_argument("-o", "--output", metavar="FILE.md", help="also write the answers to a Markdown file")
    ai.add_argument("--offline", action="store_true", help="skip CVE lookups during the scan")
    ai.add_argument("--no-color", dest="color", action="store_false", default=None)

    tg = sub.add_parser("triage", help="interactively accept / mark false-positive / ignore findings")
    tg.add_argument("path", nargs="?", default=".")
    tg.add_argument("--offline", action="store_true")
    tg.add_argument("--no-color", dest="color", action="store_false", default=None)

    tr = sub.add_parser("trend", help="how a project's findings changed across past scans")
    tr.add_argument("target", nargs="?", default=".", help="folder, URL, image:<ref> or repo URL as it was scanned (default: .)")
    tr.add_argument("--last", type=int, default=20, metavar="N")
    tr.add_argument("-o", "--output", metavar="FILE.html", help="write an interactive chart")
    tr.add_argument("--json", action="store_true")
    tr.add_argument("--list", action="store_true", help="list every target with recorded history")
    tr.add_argument("--no-color", dest="color", action="store_false", default=None)

    be = sub.add_parser("bench", help="measure precision/recall on the built-in labelled corpus")
    be.add_argument("--min-recall", type=float, default=0.0)
    be.add_argument("--min-precision", type=float, default=0.0)
    be.add_argument("-v", "--verbose", action="store_true", help="list every miss and false positive")

    sd = sub.add_parser("subdomains", help="find subdomains via certificate transparency and check for takeovers (your domains only)")
    sd.add_argument("domain")
    sd.add_argument("--max-hosts", type=int, default=300, metavar="N")
    sd.add_argument("--list", action="store_true", help="also print every discovered hostname")
    _add_output_args(sd)

    mo = sub.add_parser("monitor", help="re-scan targets and alert only on changes (for cron)")
    mo.add_argument("targets", nargs="+", metavar="TARGET", help="folder, repo URL, https:// site, or image:<ref>")
    mo.add_argument("--alert-on", default="medium", metavar="LEVEL", help="notify about NEW findings at/above LEVEL (default: medium)")
    mo.add_argument("--state-dir", metavar="DIR", help="where previous results are kept (default: ~/.local/state/vulnfind)")
    mo.add_argument("--print-cron", metavar="SCHEDULE", nargs="?", const="0 7 * * *",
                    help="print a crontab line for this monitor instead of running it")
    _add_output_args(mo)

    im = sub.add_parser("image", help="scan a container image (OS packages, language deps, secrets, config)")
    im.add_argument("images", nargs="+", metavar="IMAGE", help="image reference (nginx:1.25) or a `docker save` tarball")
    im.add_argument("--pull", action="store_true", help="pull the image if it isn't available locally")
    _add_output_args(im)

    k8 = sub.add_parser("k8s", help="read-only security audit of a live Kubernetes cluster (uses kubectl)")
    k8.add_argument("--context", help="kubectl context (default: current)")
    k8.add_argument("-n", "--namespace", help="only this namespace")
    _add_output_args(k8)

    cl = sub.add_parser("cloud", help="read-only audit of an AWS account or GCP project (uses the aws / gcloud CLI)")
    cl.add_argument("provider", choices=["aws", "gcp"])
    cl.add_argument("--profile", help="AWS profile")
    cl.add_argument("--region", help="AWS region (default: from your config)")
    cl.add_argument("--project", help="GCP project id (default: gcloud config)")
    _add_output_args(cl)

    tp = sub.add_parser("tfplan", help="check a Terraform plan (terraform show -json plan.out > plan.json)")
    tp.add_argument("plans", nargs="+", metavar="PLAN_JSON")
    _add_output_args(tp)

    rt = sub.add_parser("routes", help="list HTTP endpoints and whether they require authentication")
    rt.add_argument("path", nargs="?", default=".")
    rt.add_argument("--json", action="store_true")
    rt.add_argument("--unauthenticated", action="store_true", help="only routes without an auth guard")
    rt.add_argument("--no-color", dest="color", action="store_false", default=None)

    up = sub.add_parser("update", help="upgrade vulnfind itself")
    up.add_argument("--check", action="store_true", help="only report whether an update is available")

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
        custom_rules=customrules.load(root, o.get("rules") or []),
        health=not o["no_health"], health_transitive=bool(o["all_deps"]),
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
    from . import remote
    roots = []  # local paths, or repository URLs to clone
    for p in args.paths:
        if remote.is_repo_url(p):
            roots.append(p)
            continue
        root = os.path.abspath(os.path.expanduser(p))
        if not os.path.isdir(root):
            return _err(f"not a directory: {p}")
        roots.append(root)
    try:
        local = next((r for r in roots if not remote.is_repo_url(r)), os.getcwd())
        o = _merge_config(args, local)
        fail_on = None if str(o["fail_on"]).lower() == "none" else _parse_sev(o["fail_on"], "--fail-on")
    except (ValueError, OSError) as e:
        return _err(str(e))
    if len(roots) > 1 and (o["format"] or "table") not in ("table", "json"):
        return _err("scanning several paths supports --format table or json")

    progress = Progress(enabled=not (args.no_progress or args.quiet), color=args.color is not False)
    results: List[ScanResult] = []
    try:
        for root in roots:
            if len(roots) > 1:
                progress.log(Style(progress.color)(f"▸ {os.path.basename(root) or root}", "bold"))
            if remote.is_repo_url(root):
                if getattr(args, "staged", False) or getattr(args, "diff", None):
                    raise ValueError("--staged/--diff only work on local checkouts")
                progress.stage(f"Cloning {root}" + (" (full history)" if o["history"] else " (shallow)"))
                with remote.Clone(root, full_history=bool(o["history"])) as path:
                    progress.done(f"Cloned {root}")
                    res = scan(path, _options(o, args, path, progress))
                res.root = remote.normalise(root)[0]
                results.append(res)
                continue
            opts = _options(o, args, root, progress)
            results.append(scan(root, opts))
    except (OSError, ValueError) as e:
        progress.close()
        return _err(str(e))
    except KeyboardInterrupt:
        progress.close()
        raise
    progress.close()

    return _finish(results, args, o, fail_on)


def _finish(results: List[ScanResult], args: argparse.Namespace, o: Dict[str, Any], fail_on: Optional[Severity]) -> int:
    """Shared tail of every scan command: render, write reports, baseline, notify, exit code."""
    fmt = o["format"] or "table"
    if not getattr(args, "no_record", False):
        from . import history
        for r in results:
            history.record(r)
    failing = fail_on is not None and any(f.severity >= fail_on for r in results for f in r.findings)
    if args.quiet_ok and not failing:
        args.quiet = True
    if fmt == "table":
        if not args.quiet:
            if len(results) == 1:
                render(results[0], sys.stdout, args.color, args.verbose, o["limit"], plain=getattr(args, "plain", False))
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

    if getattr(args, "write_baseline", None):
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


def cmd_web(args: argparse.Namespace) -> int:
    from .engine import load_baseline
    from .web import WebOptions, scan_site
    try:
        fail_on = None if args.fail_on.lower() == "none" else _parse_sev(args.fail_on, "--fail-on")
        min_sev = _parse_sev(args.min_severity, "--min-severity")
    except ValueError as e:
        return _err(str(e))
    headers: Dict[str, str] = {}
    for h in args.header:
        if ":" not in h:
            return _err(f"--header must look like 'Name: value', got {h!r}")
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    if args.cookie:
        headers["Cookie"] = args.cookie
    if len(args.urls) > 1 and (args.format or "table") not in ("table", "json"):
        return _err("scanning several sites supports --format table or json")
    progress = Progress(enabled=not (args.no_progress or args.quiet), color=args.color is not False)
    if not args.quiet:
        st = Style(use_color(sys.stderr, args.color))
        note = "Only scan sites you own or are authorised to test."
        if args.active:
            note += " Active mode sends test payloads to discovered parameters."
        print(st(f"  {note}", "grey"), file=sys.stderr)
    results: List[ScanResult] = []
    try:
        for url in args.urls:
            if len(args.urls) > 1:
                progress.log(Style(progress.color)(f"▸ {url}", "bold"))
            opts = WebOptions(max_pages=max(1, args.max_pages), active=args.active, active_budget=args.active_budget,
                              rate=args.rate, timeout=args.timeout, max_requests=args.max_requests, headers=headers,
                              verify_tls=not args.insecure, tls=not args.no_tls, paths=not args.no_paths, js=not args.no_js,
                              dns=not args.no_dns, offline=args.offline, use_cache=not args.no_cache, enrich=not args.no_enrich,
                              min_severity=min_sev, progress=progress, login_url=args.login_url, login_user_env=args.login_user_env,
                              login_pass_env=args.login_pass_env, login_success=args.login_success, openapi=args.openapi,
                              browser=args.browser)
            results.append(scan_site(url, opts))
    except ValueError as e:
        progress.close()
        return _err(str(e))
    except KeyboardInterrupt:
        progress.close()
        raise
    progress.close()
    if args.baseline:
        try:
            known = load_baseline(args.baseline)
        except (OSError, ValueError, KeyError) as e:
            return _err(f"--baseline: {e}")
        for r in results:
            before = len(r.findings)
            r.findings = [f for f in r.findings if f.fingerprint not in known]
            r.suppressed += before - len(r.findings)
    o = {"format": args.format, "limit": args.limit, "output": args.output, "notify": args.notify, "notify_always": args.notify_always}
    return _finish(results, args, o, fail_on)


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
    from .web import rule_catalog
    for rid, sev, title, desc in rule_catalog():
        rows.append({"id": rid, "category": "web", "severity": sev, "title": title, "description": desc, "fix": "",
                     "cwe": None, "applies_to": ["vulnfind web <url>"]})
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
    from . import depintel
    for eco, name, old, new, major in pl.upgrades:
        warn = st("  major version: check the changelog", "yellow") if major else ""
        print(f"    {name} {st(old, 'red')} → {st(new, 'green', 'bold')}  {st(eco, 'grey')}{warn}")
        if major:
            compare, notes = depintel.upgrade_notes(eco, name, old, new)
            for n in notes:
                print("        " + st("⚠ " + n[:150], "yellow"))
            if compare:
                print("        " + st(compare, "grey"))
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


def cmd_image(args: argparse.Namespace) -> int:
    from .image import scan_image
    try:
        fail_on = None if args.fail_on.lower() == "none" else _parse_sev(args.fail_on, "--fail-on")
    except ValueError as e:
        return _err(str(e))
    progress = Progress(enabled=not (args.no_progress or args.quiet), color=args.color is not False)
    results: List[ScanResult] = []
    try:
        for ref in args.images:
            if len(args.images) > 1:
                progress.log(Style(progress.color)(f"▸ {ref}", "bold"))
            results.append(scan_image(ref, offline=args.offline, use_cache=not args.no_cache, pull=args.pull,
                                      enrich_intel=not args.no_enrich, progress=progress))
    except (ValueError, OSError, KeyError) as e:
        progress.close()
        return _err(str(e))
    progress.close()
    min_sev = _parse_sev(args.min_severity, "--min-severity")
    for r in results:
        r.below_threshold = sum(1 for f in r.findings if f.severity < min_sev)
        r.findings = [f for f in r.findings if f.severity >= min_sev]
    o = {"format": args.format, "limit": args.limit, "output": args.output, "notify": args.notify, "notify_always": args.notify_always}
    return _finish(results, args, o, fail_on)


def _run_infra(args: argparse.Namespace, label: str, fn) -> int:
    try:
        fail_on = None if args.fail_on.lower() == "none" else _parse_sev(args.fail_on, "--fail-on")
        min_sev = _parse_sev(args.min_severity, "--min-severity")
    except ValueError as e:
        return _err(str(e))
    progress = Progress(enabled=not (args.no_progress or args.quiet), color=args.color is not False)
    progress.stage(label)
    try:
        result = fn(progress)
    except (ValueError, OSError) as e:
        progress.close()
        return _err(str(e))
    progress.done(f"{label} · {len(result.findings)} finding(s)")
    progress.close()
    from .enrich import prioritise
    result.below_threshold = sum(1 for f in result.findings if f.severity < min_sev)
    result.findings = [f for f in result.findings if f.severity >= min_sev]
    prioritise(result.findings)
    result.findings.sort(key=lambda f: (-f.severity, -f.extra.get("priority", 0), f.file))
    o = {"format": args.format, "limit": args.limit, "output": args.output, "notify": args.notify, "notify_always": args.notify_always}
    return _finish([result], args, o, fail_on)


def cmd_k8s(args: argparse.Namespace) -> int:
    from .cloud import scan_k8s
    return _run_infra(args, "Auditing Kubernetes cluster (read-only)", lambda p: scan_k8s(args.context, args.namespace))


def cmd_cloud(args: argparse.Namespace) -> int:
    from .cloud import scan_aws, scan_gcp
    if args.provider == "aws":
        return _run_infra(args, "Auditing AWS account (read-only)", lambda p: scan_aws(args.profile, args.region, progress=p))
    return _run_infra(args, "Auditing GCP project (read-only)", lambda p: scan_gcp(args.project, progress=p))


def cmd_tfplan(args: argparse.Namespace) -> int:
    from .cloud import tfplan_findings

    def go(progress):
        result = ScanResult(root=", ".join(args.plans), scanners=["tfplan"])
        for path in args.plans:
            try:
                with open(path, encoding="utf-8") as fh:
                    plan = json.load(fh)
            except (OSError, ValueError) as e:
                raise ValueError(f"{path}: {e} (create it with `terraform show -json plan.out > plan.json`)")
            result.findings += tfplan_findings(plan, path)
            result.files_scanned += 1
        return result
    return _run_infra(args, "Checking Terraform plan", go)


def cmd_ai(args: argparse.Namespace) -> int:
    from . import ai
    from .models import Finding
    root = os.path.abspath(os.path.expanduser(args.path))
    if not os.path.isdir(root):
        return _err(f"not a directory: {args.path}")
    try:
        ai.check_available()  # fail before spending time on a scan
    except ai.AIUnavailable as e:
        return _err(str(e))
    st = Style(use_color(sys.stdout, args.color))
    if args.report:
        try:
            with open(args.report, encoding="utf-8") as fh:
                rows = json.load(fh)["findings"]
        except (OSError, ValueError, KeyError) as e:
            return _err(f"--report: {e}")
        findings = []
        for d in rows:
            f = Finding(d["rule_id"], d["title"], Severity.parse(d["severity"]), d["category"], d["file"], d.get("line"),
                        d.get("column"), d.get("snippet"), d.get("description", ""), d.get("fix"), d.get("cwe"),
                        d.get("references") or [], d.get("extra") or {})
            findings.append(f)
    else:
        progress = Progress(enabled=True, color=args.color is not False)
        o = dict(BUILTIN_DEFAULTS)
        o["offline"] = args.offline
        res = scan(root, _options(o, argparse.Namespace(staged=False, diff=None), root, progress))
        progress.close()
        findings = res.findings
    from .enrich import prioritise
    prioritise(findings)
    if args.finding:
        chosen = [f for f in findings if f.fingerprint in set(args.finding)]
    else:
        chosen = sorted(findings, key=lambda f: -f.extra.get("priority", 0))[:args.top]
    if not chosen:
        print("no matching findings")
        return 0
    print(st(f"  Sending {len(chosen)} finding(s) and nearby source lines to the Claude API ({args.model})…", "grey"), file=sys.stderr)
    out_md = []
    try:
        for f, answer in ai.explain(chosen, root, args.model, args.effort):
            header = f"{f.severity.label} · {f.title} · {f.location}"
            print("\n" + st(header, "bold") + "\n" + answer + "\n")
            out_md.append(f"# {header}\n\n{answer}\n")
    except ai.AIUnavailable as e:
        return _err(str(e))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write("\n".join(out_md))
        print(f"wrote {args.output}", file=sys.stderr)
    return 0


def cmd_triage(args: argparse.Namespace) -> int:
    from . import triage
    root = os.path.abspath(os.path.expanduser(args.path))
    if not os.path.isdir(root):
        return _err(f"not a directory: {args.path}")
    if not sys.stdin.isatty():
        return _err("triage is interactive; run it in a terminal")
    progress = Progress(enabled=True, color=args.color is not False)
    o = dict(BUILTIN_DEFAULTS)
    o["offline"] = args.offline
    result = scan(root, _options(o, argparse.Namespace(staged=False, diff=None), root, progress))
    progress.close()
    from .enrich import prioritise
    prioritise(result.findings)
    st = Style(use_color(sys.stdout, args.color))
    try:
        triage.run(root, result.findings, color=lambda s, c: st(s, c))
    except (KeyboardInterrupt, EOFError):
        print("\nstopped - decisions so far are saved")
    return 0


def cmd_trend(args: argparse.Namespace) -> int:
    from . import history, remote
    if args.list:
        for t in history.targets():
            print(t)
        return 0
    t = args.target
    if remote.is_repo_url(t):
        t = remote.normalise(t)[0]
    elif not t.startswith(("http://", "https://", "image:", "k8s:", "aws:", "gcp:", "*.")):
        t = os.path.abspath(os.path.expanduser(t))
    rows = history.load(t, args.last)
    if not rows and t.startswith(("http://", "https://")):
        rows = history.load(t.rstrip("/") + "/", args.last)
    if not rows:
        return _err(f"no recorded scans for {t} (run a scan first; `vulnfind trend --list` shows tracked targets)")
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(history.to_html(t, rows))
        print(f"wrote {args.output}")
        return 0
    st = Style(use_color(sys.stdout, args.color))
    totals = [r["total"] for r in rows]
    print(f"\n  {st(t, 'bold')}  ·  {len(rows)} scans  ·  open findings {history.sparkline(totals)}\n")
    print("  " + st(f"{'WHEN':<17} {'GRADE':>5} {'CRIT':>5} {'HIGH':>5} {'MED':>5} {'LOW':>5} {'TOTAL':>6}  CHANGE", "bold"))
    prev = None
    for r in rows:
        c = r["counts"]
        delta = "" if prev is None else (st(f"+{r['total'] - prev}", "bred") if r["total"] > prev else
                                         st(f"{r['total'] - prev}", "green") if r["total"] < prev else st("=", "grey"))
        print(f"  {r['ts'][:16].replace('T', ' '):<17} {r['grade']:>5} {c.get('CRITICAL', 0):>5} {c.get('HIGH', 0):>5} "
              f"{c.get('MEDIUM', 0):>5} {c.get('LOW', 0):>5} {r['total']:>6}  {delta}")
        prev = r["total"]
    print()
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    from . import bench
    s = bench.run()
    st = Style(use_color(sys.stdout))
    print(f"\n  recall    {s.recall:6.1%}  ({len(s.tp)} of {len(s.tp) + len(s.fn)} labelled vulnerabilities found)")
    print(f"  precision {s.precision:6.1%}  ({len(s.fp)} false positive(s) on {s.safe_lines} labelled-safe lines)\n")
    for label, rows, color in (("missed", s.fn, "bred"), ("false positive", s.fp, "yellow")):
        for rel, line, rule in rows if (args.verbose or len(rows) <= 10) else rows[:10]:
            print(f"  {st(label, color)}  {rule}  {rel}:{line}")
    ok = s.recall >= args.min_recall and s.precision >= args.min_precision
    if not ok:
        print(st(f"\n  below threshold (recall >= {args.min_recall}, precision >= {args.min_precision})", "bred"))
    return 0 if ok else 1


def cmd_subdomains(args: argparse.Namespace) -> int:
    from .web import subdomains
    from .web.client import Client
    if not args.quiet:
        print(Style(use_color(sys.stderr, args.color))("  Only check domains you own or are authorised to test.", "grey"), file=sys.stderr)

    def go(progress):
        warnings: List[str] = []
        names, found = subdomains.scan(args.domain, Client(rate=8), args.max_hosts, progress, warnings)
        result = ScanResult(root=f"*.{args.domain}", scanners=["subdomains"], findings=found, warnings=warnings)
        result.pages_scanned = len(names)
        if args.list and not args.quiet:
            print("\n".join(names), file=sys.stderr)
        result.warnings.insert(0, f"{len(names)} hostnames found in certificate transparency logs")
        return result
    return _run_infra(args, f"Discovering and checking subdomains of {args.domain}", go)


def _state_path(state_dir: Optional[str], target: str) -> str:
    import hashlib
    base = state_dir or os.path.join(os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state"), "vulnfind", "monitor")
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, hashlib.sha256(target.encode()).hexdigest()[:16] + ".json")


def _scan_target(target: str, args: argparse.Namespace, progress: Progress) -> ScanResult:
    from . import remote
    if target.startswith("image:"):
        from .image import scan_image
        return scan_image(target[6:], offline=args.offline, use_cache=not args.no_cache, progress=progress)
    if target.startswith(("http://", "https://")) and not remote.is_repo_url(target):
        from .web import WebOptions, scan_site
        return scan_site(target, WebOptions(offline=args.offline, use_cache=not args.no_cache, progress=progress))
    o = dict(BUILTIN_DEFAULTS)
    o["offline"], o["no_cache"] = args.offline, args.no_cache
    ns = argparse.Namespace(staged=False, diff=None)
    if remote.is_repo_url(target):
        with remote.Clone(target) as path:
            res = scan(path, _options(o, ns, path, progress))
        res.root = remote.normalise(target)[0]
        return res
    root = os.path.abspath(os.path.expanduser(target))
    if not os.path.isdir(root):
        raise ValueError(f"not a folder, repo URL, https:// URL or image:<ref>: {target}")
    return scan(root, _options(o, ns, root, progress))


def cmd_monitor(args: argparse.Namespace) -> int:
    from .automation import compare, notify
    if args.print_cron is not None:
        exe = shutil.which("vulnfind") or f"{sys.executable} -m vulnfind"
        extra = " ".join(f"--notify '{u}'" for u in args.notify)
        from .remote import is_repo_url
        targets = [t if t.startswith(("http://", "https://", "image:")) or is_repo_url(t) else os.path.abspath(os.path.expanduser(t))
                   for t in args.targets]
        print(f"{args.print_cron} {exe} monitor {' '.join(targets)} {extra} --no-progress --quiet-ok >> ~/.vulnfind-monitor.log 2>&1")
        print("# add with `crontab -e` (macOS: or a launchd agent). vulnfind does not install it for you.", file=sys.stderr)
        return 0
    try:
        alert_on = _parse_sev(args.alert_on, "--alert-on")
        fail_on = None if args.fail_on.lower() == "none" else _parse_sev(args.fail_on, "--fail-on")
    except ValueError as e:
        return _err(str(e))
    st = Style(use_color(sys.stdout, args.color))
    progress = Progress(enabled=not (args.no_progress or args.quiet), color=args.color is not False)
    exit_code = 0
    for target in args.targets:
        progress.log(st(f"▸ {target}", "bold"))
        try:
            result = _scan_target(target, args, progress)
        except (ValueError, OSError) as e:
            progress.close()
            print(f"vulnfind: error: {target}: {e}", file=sys.stderr)
            exit_code = 2
            continue
        from .enrich import prioritise
        prioritise(result.findings)
        progress.close()
        current = json.loads(FORMATTERS["json"](result))
        path = _state_path(args.state_dir, target)
        previous = None
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                previous = json.load(fh)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(current, fh)
        if previous is None:
            if not args.quiet_ok:
                print(f"  {target}: first run - baseline of {len(result.findings)} finding(s) saved, grade {result.grade}")
            continue
        diff = compare(previous, current)
        new = [f for f in diff["new"] if Severity.parse(f["severity"]) >= alert_on]
        if fail_on is not None and any(Severity.parse(f["severity"]) >= fail_on for f in diff["new"]):
            exit_code = max(exit_code, 1)
        if not new and not diff["fixed"]:
            if not args.quiet_ok:
                print(f"  {target}: no changes (grade {result.grade}, {len(result.findings)} open)")
            continue
        print(f"\n  {st(target, 'bold')}: " + st(f"{len(new)} new", "bred", "bold") + " · " + st(f"{len(diff['fixed'])} fixed", "green"))
        for f in new:
            print(f"    {st('+', 'bred')} {f['severity']:<8} {f['title']}  {st(f['file'] + (':' + str(f['line']) if f.get('line') else ''), 'cyan')}")
        for f in diff["fixed"][:10]:
            print(f"    {st('✔', 'green')} fixed    {f['title']}")
        if new or args.notify_always:
            alert = ScanResult(root=result.root, scanners=result.scanners)
            alert.findings = [f for f in result.findings if f.fingerprint in {n["fingerprint"] for n in new}]
            for url in args.notify:
                ok, info = notify(url, alert)
                print(f"    notify: {'sent' if ok else 'FAILED'} ({info})", file=sys.stderr)
    progress.close()
    return exit_code


def cmd_routes(args: argparse.Namespace) -> int:
    root = os.path.abspath(os.path.expanduser(args.path))
    if not os.path.isdir(root):
        return _err(f"not a directory: {args.path}")
    result = scan(root, ScanOptions(scanners=["code"], deep=False, offline=True))
    rows = sorted(result.routes, key=lambda r: (r.path, r.method))
    if args.unauthenticated:
        rows = [r for r in rows if not r.auth]
    if args.json:
        print(json.dumps([{"method": r.method, "path": r.path, "auth": r.auth, "auth_hint": r.auth_hint, "framework": r.framework,
                           "handler": r.handler, "file": r.file, "line": r.line} for r in rows], indent=2))
        return 0
    st = Style(use_color(sys.stdout, args.color))
    if not rows:
        print("no routes found (supports Flask, FastAPI, Django REST decorators, Express-style routers, Next.js route handlers)")
        return 0
    pw = min(max(len(r.path) for r in rows), 50)
    print("\n  " + st(f"{'METHOD':<7} {'PATH':<{pw}}  {'AUTH':<34} LOCATION", "bold"))
    for r in rows:
        auth = st(f"{'✔ ' + r.auth_hint:<34}"[:34], "green") if r.auth else st(f"{'✗ none':<34}", "bred")
        print(f"  {r.method:<7} {r.path[:pw]:<{pw}}  {auth} {st(f'{r.file}:{r.line}', 'grey')}")
    n_open = sum(1 for r in rows if not r.auth)
    print(f"\n  {len(rows)} routes · {n_open} without an auth guard\n")
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    import subprocess
    from . import selfupdate
    kind, source, commit = selfupdate.install_info()
    if kind == "editable":
        print(f"vulnfind {__version__} is an editable install from {source}.\nUpdate it with:  git -C {source} pull")
        return 0
    latest = selfupdate.latest_commit(source if kind == "git" and source else selfupdate.REPO)
    if kind == "git" and commit and latest:
        if commit == latest:
            print(f"vulnfind {__version__} is up to date ({commit[:10]}).")
            return 0
        print(f"update available: {commit[:10]} → {latest[:10]}")
    elif args.check:
        print(f"vulnfind {__version__} ({kind} install); latest commit on GitHub: {(latest or 'unknown')[:10]}")
    if args.check:
        return 0
    cmd = selfupdate.upgrade_command(kind, source)
    print("running: " + " ".join(cmd), flush=True)
    return subprocess.call(cmd)


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
    from .remote import is_repo_url
    if argv and argv[0] not in COMMANDS and is_repo_url(argv[0]):
        argv.insert(0, "scan")  # `vulnfind github.com/owner/repo` clones and scans the code
    elif argv and argv[0] not in COMMANDS and argv[0].lower().startswith(("http://", "https://")):
        argv.insert(0, "web")  # `vulnfind https://example.com` scans a website
    elif not argv or (argv[0] not in COMMANDS and argv[0] not in ("-h", "--help", "--version")):
        argv.insert(0, "scan")
    args = build_parser().parse_args(argv)
    handlers = {"scan": cmd_scan, "web": cmd_web, "ai": cmd_ai, "triage": cmd_triage, "bench": cmd_bench, "trend": cmd_trend, "subdomains": cmd_subdomains, "monitor": cmd_monitor, "image": cmd_image, "k8s": cmd_k8s, "cloud": cmd_cloud, "tfplan": cmd_tfplan,
                "routes": cmd_routes, "update": cmd_update, "sbom": cmd_sbom, "rules": cmd_rules, "explain": cmd_explain, "init": cmd_init,
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
