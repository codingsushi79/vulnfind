"""Opt-in active checks (--active). Only for sites you own or are authorised to test.

Scope is deliberately narrow and non-destructive:
- only GET requests, only to same-origin URLs/parameters the crawler already found
- harmless marker values (no payloads that modify data, no POST/PUT/DELETE)
- a hard cap on the number of requests
"""

from __future__ import annotations

import re
import secrets
import urllib.parse
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

from ..models import Finding, Severity as S
from .checks import F
from .client import BudgetExceeded, Client, same_origin
from .crawl import Page

SQL_ERRORS = re.compile(
    r"You have an error in your SQL syntax|mysql_fetch|MySqlException|SQLSTATE\[|PG::SyntaxError|pg_query\(\)|"
    r"unterminated quoted string at or near|syntax error at or near|ORA-0\d{4}|quoted string not properly terminated|"
    r"SQLite3::SQLException|sqlite3\.OperationalError|near \".*?\": syntax error|Microsoft OLE DB Provider for|"
    r"Unclosed quotation mark after the character string|System\.Data\.SqlClient\.SqlException|"
    r"SQL command not properly ended|Incorrect syntax near|Npgsql\.PostgresException|org\.hibernate\.exception", re.I)
REDIRECT_PARAMS = re.compile(r"(?i)^(?:next|url|redirect(?:_?ur[il])?|return(?:_?to|_?url)?|returnurl|dest(?:ination)?|continue|goto|target|r|u|callback|forward|out)$")
REDIRECT_TARGET = "https://vulnfind-redirect-probe.example/"


def _targets(pages: Sequence[Page], start: str) -> List[Tuple[str, List[str]]]:
    """(url, [param names]) for every same-origin GET endpoint with parameters."""
    seen: Set[Tuple[str, Tuple[str, ...]]] = set()
    out = []
    candidates: List[Tuple[str, List[str]]] = []
    for p in pages:
        for link in [p.url] + p.links:
            parts = urllib.parse.urlsplit(link)
            if parts.query:
                candidates.append((link, [k for k, _ in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)]))
        for form in p.forms:
            if form.method == "get":
                names = [n for n, t in form.inputs if n and t not in ("submit", "button", "file", "password", "hidden", "image", "reset")]
                if names:
                    candidates.append((form.action, names))
    for url, names in candidates:
        if not same_origin(url, start):
            continue
        base = urllib.parse.urlsplit(url)._replace(query="", fragment="").geturl()
        key = (base, tuple(sorted(set(names))))
        if key not in seen:
            seen.add(key)
            out.append((url, sorted(set(names))))
    return out


def _with_param(url: str, name: str, value: str) -> str:
    parts = urllib.parse.urlsplit(url)
    q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if any(k == name for k, _ in q):
        q = [(k, value if k == name else v) for k, v in q]
    else:
        q.append((name, value))
    return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(q), fragment=""))


def run(client: Client, pages: Sequence[Page], start: str, budget: int = 150,
        on_done: Optional[Callable[[str], None]] = None) -> Tuple[List[Finding], int]:
    """Returns (findings, number of parameters tested)."""
    findings: List[Finding] = []
    reported: Set[Tuple[str, str, str]] = set()
    used = 0
    targets = _targets(pages, start)
    tested = 0

    def report(kind: str, url: str, param: str, f: Finding) -> None:
        base = urllib.parse.urlsplit(url).path
        if (kind, base, param) not in reported:
            reported.add((kind, base, param))
            findings.append(f)

    try:
        for url, params in targets:
            for name in params[:8]:
                if used + 3 > budget:
                    raise BudgetExceeded("active budget")
                tested += 1
                if on_done:
                    on_done(f"{urllib.parse.urlsplit(url).path}?{name}=")
                # 1. reflected XSS: does an HTML-significant marker come back unescaped?
                tag = "vf" + secrets.token_hex(4)
                marker = f'{tag}"\'<{tag}x>'
                r = client.request(_with_param(url, name, marker))
                used += 1
                if r.is_html and f"<{tag}x>" in r.text:
                    ctx = r.text[max(0, r.text.find(f"<{tag}x>") - 60):r.text.find(f"<{tag}x>") + 30].replace("\n", " ")
                    report("xss", url, name, F(
                        "WEB-REFLECTED-XSS", f"Reflected XSS: parameter '{name}' is echoed unescaped", S.HIGH, _with_param(url, name, "<script>…"),
                        f"A probe containing <{tag}x> sent in '{name}' came back verbatim in the HTML, so an attacker can craft a link "
                        "that runs JavaScript in a victim's session.",
                        "HTML-encode output (use your template engine's auto-escaping) and add a strict Content-Security-Policy.", "CWE-79",
                        snippet=ctx, param=name, confidence="high"))
                # 2. error-based SQL injection: does a lone quote produce a database error that the baseline doesn't?
                r_quote = client.request(_with_param(url, name, "1'\")"))
                used += 1
                m = SQL_ERRORS.search(r_quote.text[:200_000]) if r_quote.body else None
                if m:
                    base_r = client.request(_with_param(url, name, "1"))
                    used += 1
                    if not SQL_ERRORS.search(base_r.text[:200_000]):
                        report("sqli", url, name, F(
                            "WEB-SQL-ERROR", f"SQL injection: parameter '{name}' triggers a database error", S.CRITICAL,
                            _with_param(url, name, "1'"),
                            "Adding a quote to this parameter breaks the SQL query (database error in the response), which means the "
                            "value is concatenated into SQL - usually fully exploitable.",
                            "Use parameterised queries / an ORM for every database access; never build SQL from request values.",
                            "CWE-89", snippet=m.group(0)[:160], param=name, confidence="high"))
                # 3. open redirect on redirect-looking parameters
                if REDIRECT_PARAMS.match(name):
                    r_red = client.request(_with_param(url, name, REDIRECT_TARGET))
                    used += 1
                    loc = r_red.header("Location")
                    if 300 <= r_red.status < 400 and loc.startswith(REDIRECT_TARGET.rstrip("/")):
                        report("redirect", url, name, F(
                            "WEB-OPEN-REDIRECT", f"Open redirect via '{name}'", S.MEDIUM, _with_param(url, name, REDIRECT_TARGET),
                            "The site redirects to any URL given in this parameter, which lends your domain's credibility to phishing links "
                            "and can leak OAuth tokens.", "Only allow relative paths or an allow-list of hosts.", "CWE-601",
                            snippet=f"{r_red.status} Location: {loc}", param=name, confidence="high"))
    except BudgetExceeded:
        pass
    return findings, tested
