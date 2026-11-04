"""Website scan orchestration."""

from __future__ import annotations

import os
import secrets
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .. import enrich
from ..models import Finding, ScanResult, Severity
from ..progress import NULL, Progress
from . import active, checks, crawl, dns, libs, paths, software, tls
from .client import BudgetExceeded, Client, normalize, same_origin


@dataclass
class WebOptions:
    max_pages: int = 30
    active: bool = False
    active_budget: int = 150
    rate: float = 8.0
    timeout: float = 15.0
    max_requests: int = 600
    headers: Dict[str, str] = field(default_factory=dict)
    verify_tls: bool = True
    tls: bool = True
    paths: bool = True
    js: bool = True
    dns: bool = True
    offline: bool = False
    use_cache: bool = True
    enrich: bool = True
    min_severity: Severity = Severity.INFO
    progress: Progress = NULL
    login_url: Optional[str] = None
    login_user_env: str = "VULNFIND_USER"
    login_pass_env: str = "VULNFIND_PASSWORD"
    login_success: Optional[str] = None
    openapi: Optional[str] = None
    browser: bool = False


def _dedupe_sitewide(findings: List[Finding]) -> List[Finding]:
    """Header problems repeat on every page: report each once, noting how many pages share it."""
    by_key: Dict[Tuple[str, str], Finding] = {}
    for f in findings:
        key = (f.rule_id, f.title)
        if key in by_key:
            by_key[key].extra["pages_affected"] = by_key[key].extra.get("pages_affected", 1) + 1
        else:
            by_key[key] = f
    for f in by_key.values():
        n = f.extra.get("pages_affected")
        if n:
            f.description += f" (seen on {n} pages)"
    return list(by_key.values())


def _resolve_start(client: Client, url: str, p: Progress):
    """Follow redirects (max 6) to the real landing page; stay on the same site."""
    host = urllib.parse.urlsplit(url).hostname
    current = url
    for _ in range(6):
        r = client.request(current, headers={"Accept": "text/html,*/*;q=0.8"})
        if r.error:
            raise ValueError(f"could not reach {current}: {r.error}")
        loc = r.header("Location")
        if 300 <= r.status < 400 and loc:
            nxt = urllib.parse.urljoin(current, loc)
            nhost = urllib.parse.urlsplit(nxt).hostname
            if nhost != host and nhost not in (f"www.{host}", (host or "")[4:] if (host or "").startswith("www.") else None):
                p.log(f"  ↪ {current} redirects off-site to {nxt}; scanning {current}")
                return current, r
            current = nxt
            continue
        return current, r
    return current, r


def scan_site(url: str, opts: WebOptions) -> ScanResult:
    started = time.time()
    if "://" not in url:
        url = "https://" + url
    url = normalize(url)
    p = opts.progress
    client = Client(rate=opts.rate, timeout=opts.timeout, max_requests=opts.max_requests, headers=dict(opts.headers),
                    verify_tls=opts.verify_tls)
    result = ScanResult(root=url, scanners=["web"])
    raw: List[Finding] = []

    if opts.login_url:  # log in first so the start URL and crawl see the authenticated site
        from .login import login
        p.stage("Logging in")
        res = login(client, opts.login_url, opts.login_user_env, opts.login_pass_env, opts.login_success)
        raw += res.findings
        if not res.ok:
            p.done("Login failed", ok=False)
            raise ValueError(f"login failed: {res.message}")
        p.done(res.message.replace(os.environ.get(opts.login_user_env, "\0"), "test user"))

    p.stage(f"Connecting to {urllib.parse.urlsplit(url).netloc}")
    start, first = _resolve_start(client, url, p)
    result.root = start
    parts = urllib.parse.urlsplit(start)
    base = f"{parts.scheme}://{parts.netloc}"
    p.done(f"Reached {start} (HTTP {first.status}, {first.elapsed * 1000:.0f} ms)")

    try:
        if parts.scheme == "https" and opts.tls:
            p.stage("Checking TLS certificate & protocol versions")
            tls_found = tls.check(parts.hostname or "", parts.port or 443, base, opts.timeout)
            raw += tls_found
            p.done(f"TLS checked · {len(tls_found)} issue(s)")
        if client.tls_error and not any(f.rule_id == "WEB-TLS-INVALID-CERT" for f in raw):
            raw.append(checks.F("WEB-TLS-INVALID-CERT", "TLS certificate is not trusted", Severity.HIGH, base,
                                f"Certificate verification failed: {client.tls_error}.", "Install a valid certificate for this hostname.", "CWE-295"))

        seeds = paths.sitemap_urls(client, base) if opts.max_pages > 1 else []
        api_calls: set = set()
        if opts.browser:
            from . import browser
            p.stage("Rendering JavaScript in headless Chromium")
            links, _, api_calls = browser.render([start], start, headers=opts.headers, cookies=client.cookies)
            seeds += sorted(links)
            p.done(f"Browser found {len(links)} rendered link(s) and {len(api_calls)} API call(s)")
        p.stage("Crawling site", total=opts.max_pages)
        pages, fetched = crawl.crawl(client, start, opts.max_pages, on_page=lambda pg: p.advance(1, urllib.parse.urlsplit(pg.url).path or "/"),
                                     extra_seeds=seeds)
        result.pages_scanned = len(pages)
        p.done(f"Crawled {len(pages)} page(s)")

        p.stage("Checking headers, cookies, CORS & page content")
        header_found: List[Finding] = []
        for pg in pages:
            header_found += checks.header_checks(pg.response, parts.scheme == "https")
            raw += checks.content_checks(pg, start)
        raw += _dedupe_sitewide(header_found)
        raw += checks.cookie_checks([first] + list(fetched.values()), parts.scheme == "https")
        raw += checks.https_checks(client, start, first)
        raw += checks.cors_checks(client, start)
        raw += checks.methods_check(client, start)
        not_found = client.request(f"{base}/vulnfind-404-{secrets.token_hex(5)}")
        errors: List[Finding] = []
        for resp in [first, not_found] + list(fetched.values()):
            errors += checks.error_checks(resp)
        raw += _dedupe_sitewide(errors)
        p.done("Checked security headers, cookies, CORS, mixed content and error pages")

        if opts.browser and api_calls:
            raw.append(checks.F("WEB-API-INVENTORY", f"Front-end calls {len(api_calls)} API endpoint(s)", Severity.INFO, start,
                                "Endpoints observed while rendering the site; make sure each enforces auth and validates input: "
                                + ", ".join(sorted(api_calls)[:20]), "Review these endpoints (or scan them with --openapi).",
                                endpoints=sorted(api_calls)))

        if opts.openapi:
            from . import api
            spec, src = api.load_spec(client, opts.openapi)
            n_ops = sum(1 for v in (spec.get("paths") or {}).values() if isinstance(v, dict) and "get" in v)
            p.stage("Testing API operations from the OpenAPI spec (GET only, unauthenticated)", total=n_ops or None)
            api_findings, tested = api.scan_api(client, spec, start, src)
            raw += api_findings
            p.done(f"Tested {tested} API operation(s) · {len(api_findings)} issue(s)")

        if opts.paths:
            p.stage("Probing for exposed files & admin endpoints", total=len(paths.PROBES))
            exposed = paths.probe_paths(client, base, on_done=lambda path: p.advance(1, path))
            raw += exposed
            raw += paths.robots_and_security_txt(client, base)
            p.done(f"Probed {len(paths.PROBES)} sensitive paths · {len(exposed)} exposed")

        if opts.js:
            scripts = list(dict.fromkeys(src for pg in pages for src, _ in pg.scripts if src))
            own = [s for s in scripts if same_origin(s, start)]
            p.stage("Analysing JavaScript (libraries, secrets, source maps)", total=min(len(own), 25) or None)
            pages_html = [(pg.url, pg.response.text) for pg in pages]
            detected, js_findings = libs.analyse_scripts(client, start, scripts, pages_html, on_done=lambda n: p.advance(1, n))
            raw += _dedupe_sitewide(js_findings)
            n_libs = len({(d.name, d.version) for d in detected})
            p.done(f"Analysed {len(own)} script(s) · {n_libs} librar{'y' if n_libs == 1 else 'ies'} identified")
            if detected:
                p.stage("Checking JavaScript libraries against OSV.dev" if not opts.offline else "Listing JavaScript libraries")
                lib_findings = libs.library_findings(detected, opts.offline, opts.use_cache, result.warnings)
                raw += lib_findings
                if opts.enrich and not opts.offline and lib_findings:
                    enrich.enrich(lib_findings, opts.use_cache, result.warnings)
                n_vuln = sum(1 for f in lib_findings if f.rule_id == "WEB-VULNERABLE-JS-LIBRARY")
                p.done(f"{n_vuln} vulnerable librar{'y' if n_vuln == 1 else 'ies'}")

        stack: Dict[Tuple[str, str], software.Software] = {}
        generator = next((pg.meta.get("generator") for pg in pages if pg.meta.get("generator")), None)
        for resp in [first, not_found] + list(fetched.values()):
            for sw in software.fingerprint(resp.headers, generator):
                stack.setdefault((sw.key, sw.version), sw)
        if stack:
            names = ", ".join(f"{software.PRODUCTS[k][0]} {v}" for k, v in stack)
            p.stage(f"Looking up CVEs for {names} (NVD)" if not opts.offline else "Listing server software")
            sw_findings = software.software_findings(stack.values(), base, opts.use_cache, result.warnings, opts.offline)
            if opts.enrich and not opts.offline and sw_findings:
                enrich.enrich(sw_findings, opts.use_cache, result.warnings)
            raw += sw_findings
            n_cves = sum(len(f.extra.get("aliases", [])) for f in sw_findings)
            p.done(f"Server software: {names} · {n_cves} known CVE(s)")

        if opts.dns and not opts.offline:
            p.stage("Checking email spoofing protection (SPF, DMARC, CAA)")
            raw += dns.check(parts.hostname or "", result.warnings)
            p.done("DNS records checked")

        if opts.active:
            p.stage("Active tests: reflected XSS, SQL errors, open redirects")
            act, tested = active.run(client, pages, start, opts.active_budget, on_done=lambda s: p.detail(s))
            raw += act
            p.done(f"Actively tested {tested} parameter(s) · {len(act)} confirmed issue(s)")
    except BudgetExceeded:
        result.warnings.append(f"stopped at the request budget ({opts.max_requests}); raise --max-requests for a fuller scan")

    result.requests_made = client.requests_made
    for f in raw:
        if f.severity < opts.min_severity:
            result.below_threshold += 1
        else:
            result.findings.append(f)
    enrich.prioritise(result.findings)
    result.findings.sort(key=lambda x: (-x.severity, -x.extra.get("priority", 0), x.rule_id, x.file))
    result.duration = time.time() - started
    return result
