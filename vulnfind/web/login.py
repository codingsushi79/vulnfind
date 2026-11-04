"""Form-based login so the crawler can scan pages behind authentication.

Credentials come from environment variables (never command-line arguments, which end up in
shell history and process lists). The flow: GET the login page, find the form with a password
field, fill username/password plus any hidden fields (CSRF tokens), submit it, follow redirects,
and keep the resulting session cookies. It also checks two login weaknesses on the way:
missing CSRF protection on the login form and session IDs that aren't rotated at login.
"""

from __future__ import annotations

import os
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional

from ..models import Finding, Severity as S
from .checks import F
from .client import Client, _cookie_pairs, same_origin
from .crawl import parse

SESSIONISH = ("sess", "sid", "auth", "token", "jwt", "login", "remember", "connect.sid")


@dataclass
class LoginResult:
    ok: bool
    message: str
    findings: List[Finding] = field(default_factory=list)


def login(client: Client, login_url: str, user_env: str, pass_env: str, success_text: Optional[str] = None,
          user_field: Optional[str] = None, pass_field: Optional[str] = None) -> LoginResult:
    username, password = os.environ.get(user_env), os.environ.get(pass_env)
    if not username or not password:
        return LoginResult(False, f"set the {user_env} and {pass_env} environment variables with the test account's credentials")
    if login_url.startswith("http://") and not login_url.startswith(("http://localhost", "http://127.0.0.1")):
        return LoginResult(False, "refusing to send credentials over plain HTTP; use the https:// login URL")
    client.use_jar = True
    page = client.request(login_url, headers={"Accept": "text/html"})
    if client.tls_error and client.verify_tls:
        return LoginResult(False, f"refusing to send credentials: the TLS certificate isn't trusted ({client.tls_error}); pass --insecure to override")
    if page.error or page.status >= 400:
        return LoginResult(False, f"could not load {login_url} (HTTP {page.status or page.error})")
    pre_login = dict(client.cookies)
    forms = [f for f in parse(page).forms if any(t == "password" for _, t in f.inputs)]
    if not forms:
        return LoginResult(False, f"no form with a password field on {login_url}")
    form = forms[0]
    if not same_origin(form.action, login_url):
        return LoginResult(False, f"login form posts to another origin ({form.action}); not sending credentials there")
    fields = {}
    html = page.text
    for name, typ in form.inputs:
        if not name:
            continue
        if typ == "password" or name == pass_field:
            fields[name] = password
        elif name == user_field or (not user_field and typ in ("email", "text") and not any(v == username for v in fields.values())):
            fields[name] = username
        elif typ in ("hidden", "checkbox"):
            fields[name] = _input_value(html, name)
    findings: List[Finding] = []
    if not any(t == "hidden" and any(k in n.lower() for k in ("csrf", "token", "authenticity", "nonce", "xsrf")) for n, t in form.inputs) \
            and not any(k.lower().startswith(("csrf", "xsrf")) for k in pre_login):
        findings.append(F("WEB-LOGIN-NO-CSRF", "Login form has no CSRF token", S.LOW, login_url,
                          "Without a token, another site can log a victim into the attacker's account (login CSRF).",
                          "Add a CSRF token to the login form (most frameworks do this automatically).", "CWE-352"))
    body = urllib.parse.urlencode(fields).encode()
    method = "POST" if form.method != "get" else "GET"
    target = form.action if method == "POST" else form.action + ("&" if "?" in form.action else "?") + body.decode()
    resp = client.request(target, method=method, data=body if method == "POST" else None,
                          headers={"Content-Type": "application/x-www-form-urlencoded", "Referer": login_url, "Origin": _origin(login_url)})
    for _ in range(5):
        loc = resp.header("Location")
        if not (300 <= resp.status < 400 and loc):
            break
        nxt = urllib.parse.urljoin(resp.url, loc)
        if not same_origin(nxt, login_url):
            break
        resp = client.request(nxt)
    still_login_form = any(t == "password" for f in parse(resp).forms for _, t in f.inputs) if resp.is_html else False
    ok = (success_text in resp.text) if success_text else (not still_login_form and resp.status < 400)
    if not ok:
        client.use_jar = False
        return LoginResult(False, "login did not succeed (still on the login form" + (f", or '{success_text}' not found" if success_text else "") + ")",
                           findings)
    # session fixation: a pre-login session cookie that keeps its value after login
    for name, before in pre_login.items():
        if any(k in name.lower() for k in SESSIONISH) and client.cookies.get(name) == before:
            findings.append(F("WEB-SESSION-FIXATION", f"Session cookie '{name}' is not rotated at login", S.MEDIUM, login_url,
                              "The session ID stays the same before and after authentication, so an attacker who plants a session ID "
                              "in a victim's browser can ride their logged-in session.",
                              "Issue a new session ID on login (e.g. session.regenerate(), request.session.cycle_key()).", "CWE-384"))
    return LoginResult(True, f"logged in as {username} ({len(client.cookies)} session cookie(s))", findings)


def _input_value(html: str, name: str) -> str:
    import re
    m = re.search(r"<input[^>]*name=[\"']" + re.escape(name) + r"[\"'][^>]*>", html, re.I)
    if not m:
        return ""
    v = re.search(r"value=[\"']([^\"']*)[\"']", m.group(0), re.I)
    return v.group(1) if v else ""


def _origin(url: str) -> str:
    p = urllib.parse.urlsplit(url)
    return f"{p.scheme}://{p.netloc}"
