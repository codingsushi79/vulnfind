"""Passive checks on responses: security headers, cookies, CORS, page content, error pages."""

from __future__ import annotations

import re
import urllib.parse
from typing import Dict, Iterable, List, Optional

from ..models import Finding, Severity as S
from .client import Client, Response, origin, same_origin
from .crawl import Page


def F(rule_id: str, title: str, sev: S, url: str, desc: str, fix: str, cwe: Optional[str] = None,
      snippet: Optional[str] = None, refs: Iterable[str] = (), **extra) -> Finding:
    return Finding(rule_id=rule_id, title=title, severity=sev, category="web", file=url, snippet=snippet,
                   description=desc, fix=fix, cwe=cwe, references=list(refs), extra=extra)


MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"


# ---------------------------------------------------------------- transport

def https_checks(client: Client, start: str, start_resp: Response) -> List[Finding]:
    out: List[Finding] = []
    p = urllib.parse.urlsplit(start)
    host = p.hostname or ""
    local = host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost") or host.endswith(".test")
    if p.scheme == "http":
        https_url = urllib.parse.urlunsplit(("https", p.netloc.split(":")[0], p.path or "/", p.query, ""))
        r = client.request(https_url) if not local else None
        if r is not None and r.error is None:
            out.append(F("WEB-NO-HTTPS-REDIRECT", "Site is served over plain HTTP", S.MEDIUM, start,
                         "The HTTP version does not redirect to HTTPS, so users who type the address or follow an old link "
                         "use an unencrypted connection.", "Redirect all HTTP traffic to HTTPS (301) and enable HSTS.", "CWE-319"))
        elif not local:
            out.append(F("WEB-NO-HTTPS", "Site is not available over HTTPS", S.HIGH, start,
                         "Everything - logins, cookies, page content - travels unencrypted and can be read or modified in transit.",
                         "Serve the site over HTTPS (Let's Encrypt is free) and redirect HTTP to it.", "CWE-319"))
    else:
        # does plain HTTP redirect to HTTPS?
        http_url = urllib.parse.urlunsplit(("http", p.netloc.split(":")[0], "/", "", ""))
        r = client.request(http_url)
        if r.error is None and r.status and not (300 <= r.status < 400 and r.header("Location").lower().startswith("https://")):
            if r.status < 400:
                out.append(F("WEB-NO-HTTPS-REDIRECT", "HTTP does not redirect to HTTPS", S.MEDIUM, http_url,
                             f"http:// returns {r.status} instead of redirecting, so the first request is unencrypted and can be "
                             "intercepted (SSL stripping).", "Return a 301 redirect to https:// for every HTTP request.", "CWE-319"))
    return out


# ---------------------------------------------------------------- headers

def _csp_directives(csp: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for part in csp.split(";"):
        bits = part.strip().split()
        if bits:
            out[bits[0].lower()] = [b.lower() for b in bits[1:]]
    return out


def header_checks(resp: Response, is_https: bool) -> List[Finding]:
    url = resp.url
    out: List[Finding] = []
    h = resp.header
    if is_https:
        hsts = h("Strict-Transport-Security")
        if not hsts:
            out.append(F("WEB-HSTS-MISSING", "Missing Strict-Transport-Security (HSTS)", S.MEDIUM, url,
                         "Without HSTS, browsers will still try http:// first, allowing SSL-stripping attacks on hostile networks.",
                         "Send: Strict-Transport-Security: max-age=31536000; includeSubDomains", "CWE-319", refs=[MDN + "Strict-Transport-Security"]))
        else:
            m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
            if not m or int(m.group(1)) < 15552000:
                out.append(F("WEB-HSTS-SHORT", "HSTS max-age is too short", S.LOW, url,
                             f"max-age={m.group(1) if m else '?'}; browsers forget the HTTPS-only rule quickly.",
                             "Use max-age of at least 15552000 (180 days), ideally 31536000.", "CWE-319", snippet=hsts))

    if resp.is_html:
        csp = h("Content-Security-Policy")
        if not csp:
            ro = h("Content-Security-Policy-Report-Only")
            out.append(F("WEB-CSP-MISSING", "No Content-Security-Policy" + (" (report-only)" if ro else ""), S.MEDIUM if not ro else S.LOW, url,
                         "A CSP is the main browser-side defence against XSS: it limits where scripts may load from and blocks inline injection.",
                         "Start with: Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self' "
                         "and tighten from there (use nonces for inline scripts).", "CWE-693", refs=[MDN + "Content-Security-Policy"]))
        else:
            d = _csp_directives(csp)
            script = d.get("script-src", d.get("default-src", []))
            weak = []
            if "'unsafe-inline'" in script and not any(x.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-", "'strict-dynamic'")) for x in script):
                weak.append("'unsafe-inline' scripts")
            if "'unsafe-eval'" in script:
                weak.append("'unsafe-eval'")
            if any(x in ("*", "http:", "https:", "data:") for x in script):
                weak.append("wildcard/scheme script sources")
            if "script-src" not in d and "default-src" not in d:
                weak.append("no script-src/default-src")
            if weak:
                out.append(F("WEB-CSP-WEAK", "Weak Content-Security-Policy", S.MEDIUM if "'unsafe-inline' scripts" in weak or "no script-src/default-src" in weak else S.LOW,
                             url, "The CSP allows " + ", ".join(weak) + ", which defeats most of its XSS protection.",
                             "Remove 'unsafe-inline'/'unsafe-eval' (use nonces or hashes) and list explicit script origins.", "CWE-693",
                             snippet=csp[:200]))
        fa = "frame-ancestors" in csp.lower()
        if not h("X-Frame-Options") and not fa:
            out.append(F("WEB-CLICKJACKING", "Page can be framed (clickjacking)", S.MEDIUM, url,
                         "Without X-Frame-Options or CSP frame-ancestors, another site can load this page in an invisible frame "
                         "and trick users into clicking buttons.", "Send: Content-Security-Policy: frame-ancestors 'self' (or X-Frame-Options: DENY).",
                         "CWE-1021", refs=[MDN + "X-Frame-Options"]))
        if h("X-Content-Type-Options").lower() != "nosniff":
            out.append(F("WEB-NOSNIFF-MISSING", "Missing X-Content-Type-Options: nosniff", S.LOW, url,
                         "Browsers may MIME-sniff responses and execute uploaded files as scripts or styles.",
                         "Send: X-Content-Type-Options: nosniff", "CWE-693"))
        if not h("Referrer-Policy"):
            out.append(F("WEB-REFERRER-POLICY", "Missing Referrer-Policy", S.LOW, url,
                         "Full URLs (which can contain tokens or IDs) may leak to third-party sites via the Referer header.",
                         "Send: Referrer-Policy: strict-origin-when-cross-origin", "CWE-200"))
        if not h("Permissions-Policy"):
            out.append(F("WEB-PERMISSIONS-POLICY", "Missing Permissions-Policy", S.INFO, url,
                         "Restricting powerful browser features (camera, microphone, geolocation) limits what injected code can do.",
                         "Send e.g.: Permissions-Policy: camera=(), microphone=(), geolocation=()", "CWE-693"))

    disclosures = []
    server = h("Server")
    if re.search(r"\d", server):
        disclosures.append(f"Server: {server}")
    for name in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "X-Drupal-Cache", "X-Runtime"):
        if h(name) and name != "X-Runtime":
            disclosures.append(f"{name}: {h(name)}")
    if disclosures:
        out.append(F("WEB-VERSION-DISCLOSURE", "Server software/version disclosed in headers", S.LOW, url,
                     "Version banners tell attackers exactly which exploits to try.",
                     "Remove or genericise these headers (e.g. nginx `server_tokens off`, Express `app.disable('x-powered-by')`).",
                     "CWE-200", snippet="; ".join(disclosures)))
    return out


# ---------------------------------------------------------------- cookies

SESSIONISH = re.compile(r"(?i)sess|sid|auth|token|jwt|login|remember|connect\.sid|csrf|xsrf|account|user")


def cookie_checks(responses: Iterable[Response], is_https: bool) -> List[Finding]:
    seen: Dict[str, Finding] = {}
    for resp in responses:
        for raw in resp.header_all("Set-Cookie"):
            name = raw.split("=", 1)[0].strip()
            if not name or name in seen:
                continue
            attrs = [a.strip().lower() for a in raw.split(";")[1:]]
            flags = {a.split("=", 1)[0]: (a.split("=", 1)[1] if "=" in a else "") for a in attrs}
            if any(a.startswith(("max-age=0", "expires=thu, 01 jan 1970")) for a in attrs):
                continue  # deletion cookie
            missing = []
            if is_https and "secure" not in flags:
                missing.append("Secure")
            if "httponly" not in flags:
                missing.append("HttpOnly")
            samesite = flags.get("samesite", "")
            if not samesite:
                missing.append("SameSite")
            elif samesite == "none" and "secure" not in flags:
                missing.append("Secure (required with SameSite=None)")
            if not missing:
                continue
            sensitive = bool(SESSIONISH.search(name))
            if sensitive and ("Secure" in missing or "HttpOnly" in missing):
                sev = S.MEDIUM
            elif sensitive:
                sev = S.LOW
            else:
                sev = S.LOW if "Secure" in missing else S.INFO
            seen[name] = F("WEB-COOKIE-FLAGS", f"Cookie '{name}' missing {', '.join(missing)}", sev, resp.url,
                           ("Secure keeps the cookie off plain HTTP; HttpOnly hides it from JavaScript (XSS can't steal it); "
                            "SameSite stops it riding along on cross-site requests (CSRF)."),
                           f"Set-Cookie: {name}=…; Secure; HttpOnly; SameSite=Lax", "CWE-614",
                           snippet=re.sub(r"=([^;]{6})[^;]*", r"=\1…", raw, count=1)[:200])
    return list(seen.values())


# ---------------------------------------------------------------- CORS

def cors_checks(client: Client, url: str) -> List[Finding]:
    out: List[Finding] = []
    evil = "https://vulnfind-cors-probe.example"
    for probe in (evil, "null"):
        r = client.request(url, headers={"Origin": probe})
        acao = r.header("Access-Control-Allow-Origin")
        creds = r.header("Access-Control-Allow-Credentials").lower() == "true"
        if acao == probe:
            out.append(F("WEB-CORS-REFLECT", f"CORS trusts arbitrary origins{' (with credentials)' if creds else ''}"
                         + (" incl. 'null'" if probe == "null" else ""),
                         S.HIGH if creds else S.MEDIUM, url,
                         f"The server echoed Origin: {probe} back in Access-Control-Allow-Origin"
                         + (" and allows credentials, so any website can read authenticated responses as the logged-in user." if creds
                            else ", so any website can read these responses."),
                         "Validate Origin against an explicit allow-list; never reflect it blindly or allow 'null'.", "CWE-942",
                         snippet=f"Access-Control-Allow-Origin: {acao}" + ("; Access-Control-Allow-Credentials: true" if creds else "")))
            break
        if acao == "*" and creds and probe == evil:
            out.append(F("WEB-CORS-WILDCARD-CREDS", "CORS wildcard combined with credentials", S.LOW, url,
                         "Browsers refuse this combination, but it signals a misunderstood CORS policy.",
                         "Use an explicit origin allow-list when credentials are needed.", "CWE-942"))
    return out


def methods_check(client: Client, url: str) -> List[Finding]:
    r = client.request(url, method="OPTIONS")
    allow = (r.header("Allow") or r.header("Access-Control-Allow-Methods")).upper()
    risky = [m for m in ("TRACE", "PUT", "DELETE", "CONNECT") if re.search(r"\b" + m + r"\b", allow)]
    if not risky or r.status >= 400:
        return []
    return [F("WEB-RISKY-METHODS", f"Server advertises {', '.join(risky)}", S.LOW if risky == ["TRACE"] else S.MEDIUM, url,
              "TRACE enables cross-site tracing; PUT/DELETE on static paths can allow file upload or deletion if not authenticated.",
              "Disable unused HTTP methods at the web server.", "CWE-650", snippet=f"Allow: {allow}")]


# ---------------------------------------------------------------- page content

def content_checks(page: Page, start: str) -> List[Finding]:
    out: List[Finding] = []
    url = page.url
    https = url.startswith("https://")
    if https:
        active = [u for u, _ in page.scripts if u and u.startswith("http://")] + \
                 [u for u in page.iframes + page.stylesheets if u.startswith("http://")]
        if active:
            out.append(F("WEB-MIXED-CONTENT", "HTTPS page loads scripts/frames/styles over HTTP", S.MEDIUM, url,
                         "Active mixed content can be modified in transit, giving a network attacker full control of the page "
                         "(modern browsers block it, which breaks the page instead).",
                         "Load every resource over https:// (or use protocol-relative/relative URLs).", "CWE-319",
                         snippet=", ".join(active[:3])))
        passive = [u for u in page.images if u.startswith("http://")]
        if passive:
            out.append(F("WEB-MIXED-CONTENT-PASSIVE", "HTTPS page loads images/media over HTTP", S.LOW, url,
                         "Passive mixed content can be swapped or tracked in transit.", "Use https:// for all media.", "CWE-319",
                         snippet=", ".join(passive[:3])))
    third_party = sorted({urllib.parse.urlsplit(u).netloc for u, a in page.scripts
                          if u and not same_origin(u, start) and not a.get("integrity")})
    if third_party:
        out.append(F("WEB-NO-SRI", "Third-party scripts without Subresource Integrity", S.LOW, url,
                     "If one of these CDNs or vendors is compromised, the attacker's code runs on your site "
                     "(as in the polyfill.io incident).",
                     "Add integrity=\"sha384-…\" crossorigin=\"anonymous\" to pinned third-party scripts, or self-host them.",
                     "CWE-353", snippet=", ".join(third_party[:6])))
    for form in page.forms:
        has_pw = any(t == "password" for _, t in form.inputs)
        if not has_pw:
            continue
        if not https or form.action.startswith("http://"):
            out.append(F("WEB-PASSWORD-OVER-HTTP", "Password form submits over plain HTTP", S.HIGH, url,
                         "Credentials are sent unencrypted and can be captured on the network.",
                         "Serve the page and the form action over HTTPS.", "CWE-319", snippet=f"<form action=\"{form.action}\">"))
        if form.method == "get":
            out.append(F("WEB-PASSWORD-IN-URL", "Password form uses GET", S.MEDIUM, url,
                         "The password ends up in the URL: browser history, server logs and Referer headers.",
                         "Use method=\"post\" for login forms.", "CWE-598", snippet=f"<form method=\"get\" action=\"{form.action}\">"))
    gen = page.meta.get("generator")
    if gen and re.search(r"\d", gen):
        out.append(F("WEB-GENERATOR-DISCLOSURE", f"CMS/version disclosed: {gen}", S.LOW, url,
                     "The generator meta tag reveals the exact CMS version, making it easy to match known exploits.",
                     "Remove the generator tag and keep the CMS updated.", "CWE-200", snippet=f'<meta name="generator" content="{gen}">'))
    for c in page.comments:
        if re.search(r"(?i)\b(?:password|passwd|api[_-]?key|secret|todo:?\s*(?:remove|fix)\s*(?:auth|security)|BEGIN [A-Z ]*PRIVATE KEY)", c):
            out.append(F("WEB-SENSITIVE-COMMENT", "Sensitive-looking HTML comment", S.LOW, url,
                         "HTML comments are visible to every visitor.", "Strip comments from production HTML.", "CWE-615",
                         snippet=("<!-- " + c[:120] + " -->")))
            break
    return out


# ---------------------------------------------------------------- verbose errors / debug modes

ERROR_SIGNATURES = [
    (r"Werkzeug Debugger|__debugger__\?cmd=|The debugger caught an exception", "WEB-DEBUG-EXPOSED",
     "Werkzeug interactive debugger exposed", S.CRITICAL, "The Werkzeug debugger lets anyone who reaches an error page run Python code on the server."),
    (r"You're seeing this error because you have <code>DEBUG = True</code>|Django tried these URL patterns", "WEB-DEBUG-EXPOSED",
     "Django DEBUG mode enabled", S.HIGH, "Debug pages leak settings, SQL queries, file paths and the full URL map."),
    (r"Whoops! There was an error|Illuminate\\[A-Za-z\\]+Exception", "WEB-DEBUG-EXPOSED",
     "Laravel debug page exposed", S.HIGH, "Laravel debug output leaks environment details and has enabled RCE before (CVE-2021-3129)."),
    (r"Action Controller: Exception caught|<h1>Routing Error</h1>", "WEB-DEBUG-EXPOSED",
     "Rails development error page", S.HIGH, "Rails development mode exposes source code and routes."),
    (r"Symfony Exception|sf-toolbar", "WEB-DEBUG-EXPOSED",
     "Symfony debug toolbar exposed", S.HIGH, "The Symfony profiler exposes requests, environment and credentials."),
    (r"Traceback \(most recent call last\)", "WEB-ERROR-DISCLOSURE", "Python stack trace in response", S.MEDIUM,
     "Stack traces reveal code paths and library versions."),
    (r"(?:Fatal error|Warning|Parse error|Notice)</b>:\s.*? in <b>/", "WEB-ERROR-DISCLOSURE", "PHP error with file path", S.MEDIUM,
     "PHP errors reveal file paths and code."),
    (r"at [\w$.]+\([\w]+\.java:\d+\)|java\.lang\.\w+Exception", "WEB-ERROR-DISCLOSURE", "Java stack trace in response", S.MEDIUM,
     "Stack traces reveal code and framework versions."),
    (r"System\.\w+Exception:|Server Error in '/' Application", "WEB-ERROR-DISCLOSURE", "ASP.NET error details exposed", S.MEDIUM,
     "Detailed errors reveal stack traces and versions."),
    (r"<title>Index of /|<h1>Index of /|Directory listing for /", "WEB-DIRECTORY-LISTING", "Directory listing enabled", S.MEDIUM,
     "Anyone can browse every file in this directory."),
]


def error_checks(resp: Response) -> List[Finding]:
    if not resp.body:
        return []
    text = resp.text[:300_000]
    out = []
    for pattern, rule_id, title, sev, desc in ERROR_SIGNATURES:
        m = re.search(pattern, text)
        if m:
            listing = rule_id == "WEB-DIRECTORY-LISTING"
            out.append(F(rule_id, title, sev, resp.url, desc,
                         "Disable directory browsing (nginx autoindex off / Apache Options -Indexes)." if listing
                         else "Disable debug mode in production and serve generic error pages.",
                         "CWE-548" if listing else "CWE-209",
                         snippet=text[max(0, m.start() - 40):m.end() + 40].replace("\n", " ")[:200]))
    return out
