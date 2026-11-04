"""API scanning driven by an OpenAPI / Swagger spec (JSON).

For every GET operation (never POST/PUT/PATCH/DELETE - nothing is modified):
- call it *without* credentials: a 2xx on an operation the spec says needs auth is a broken auth check
- sensitive-looking endpoints that answer anonymously
- verbose errors and secrets in API responses
Also checks the spec itself: plain-HTTP servers, no security schemes at all.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from ..models import Finding, Severity as S
from .checks import F, error_checks
from .client import BudgetExceeded, Client
from .libs import secret_findings

SENSITIVE = re.compile(r"(?i)/(?:admin|internal|users?|accounts?|customers?|orders?|payments?|billing|invoices?|secrets?|keys?|tokens?|"
                       r"config|settings|export|reports?|audit|logs?|employees?|members?|profiles?)\b")


def load_spec(client: Client, source: str) -> Tuple[Dict[str, Any], str]:
    if source.startswith(("http://", "https://")):
        r = client.request(source, headers={"Accept": "application/json"}, max_body=8 * 1024 * 1024)
        if r.status != 200:
            raise ValueError(f"could not fetch OpenAPI spec {source} (HTTP {r.status or r.error})")
        text = r.text
    else:
        with open(source, encoding="utf-8") as fh:
            text = fh.read()
    try:
        spec = json.loads(text)
    except ValueError:
        raise ValueError(f"{source}: only JSON OpenAPI/Swagger specs are supported (convert YAML with e.g. `yq -o json`)")
    if not isinstance(spec, dict) or not ("openapi" in spec or "swagger" in spec) or "paths" not in spec:
        raise ValueError(f"{source}: not an OpenAPI/Swagger document")
    return spec, source


def _base_url(spec: dict, site: str) -> str:
    if spec.get("servers"):
        url = spec["servers"][0].get("url", "")
        return urllib.parse.urljoin(site, url).rstrip("/")
    if spec.get("host") or spec.get("basePath"):
        scheme = (spec.get("schemes") or [urllib.parse.urlsplit(site).scheme])[0]
        return f"{scheme}://{spec.get('host') or urllib.parse.urlsplit(site).netloc}{spec.get('basePath', '')}".rstrip("/")
    return site.rstrip("/")


def _example(param: dict) -> str:
    schema = param.get("schema") or param
    for key in ("example", "default"):
        if key in param:
            return str(param[key])
        if key in schema:
            return str(schema[key])
    if schema.get("enum"):
        return str(schema["enum"][0])
    t = schema.get("type", "string")
    fmt = schema.get("format", "")
    if t in ("integer", "number"):
        return "1"
    if t == "boolean":
        return "true"
    if fmt == "uuid":
        return "00000000-0000-0000-0000-000000000001"
    return "test"


def scan_api(client: Client, spec: dict, site: str, spec_source: str, max_ops: int = 150) -> Tuple[List[Finding], int]:
    findings: List[Finding] = []
    base = _base_url(spec, site)
    anon = Client(rate=client.rate, timeout=client.timeout, max_requests=max_ops + 5, verify_tls=client.verify_tls,
                  headers={k: v for k, v in client.headers.items() if k.lower() not in ("authorization", "cookie", "x-api-key")})
    global_security = spec.get("security")
    schemes = (spec.get("components") or {}).get("securitySchemes") or spec.get("securityDefinitions") or {}
    if not schemes:
        findings.append(F("API-NO-SECURITY-SCHEMES", "OpenAPI spec defines no authentication", S.INFO, spec_source,
                          "No security schemes are declared, so either the API is fully public or its auth is undocumented.",
                          "Declare the API's auth (securitySchemes + security) so clients and scanners can verify it.", "CWE-306"))
    for srv in spec.get("servers") or []:
        if str(srv.get("url", "")).startswith("http://") and "localhost" not in srv.get("url", ""):
            findings.append(F("API-HTTP-SERVER", f"API server over plain HTTP: {srv['url']}", S.MEDIUM, spec_source,
                              "API traffic (including tokens) is unencrypted.", "Serve the API over HTTPS only.", "CWE-319"))
    tested = 0
    for path, item in (spec.get("paths") or {}).items():
        op = (item or {}).get("get")
        if not op or tested >= max_ops:
            continue
        params = list(item.get("parameters") or []) + list(op.get("parameters") or [])
        url_path = path
        query = {}
        for p in params:
            if "$ref" in p:
                continue
            if p.get("in") == "path":
                url_path = url_path.replace("{" + p["name"] + "}", urllib.parse.quote(_example(p)))
            elif p.get("in") == "query" and p.get("required"):
                query[p["name"]] = _example(p)
        url_path = re.sub(r"\{[^}]+\}", "1", url_path)
        url = base + url_path + (("?" + urllib.parse.urlencode(query)) if query else "")
        declared = op.get("security", global_security)
        needs_auth = bool(declared) and any(bool(req) for req in declared)
        try:
            r = anon.request(url, headers={"Accept": "application/json"})
        except BudgetExceeded:
            break
        tested += 1
        if r.error:
            continue
        findings += error_checks(r)
        ok = 200 <= r.status < 300 and len(r.body) > 2 and not (r.is_html and "login" in r.text.lower()[:5000])
        if ok and needs_auth:
            findings.append(F("API-AUTH-NOT-ENFORCED", f"GET {path} answers without credentials", S.HIGH, url,
                              f"The spec says this operation requires {', '.join(k for req in declared for k in req) or 'authentication'}, "
                              f"but an anonymous request got HTTP {r.status} with a {len(r.body)}-byte body.",
                              "Enforce authentication in the handler/middleware for this route, not just in the documentation.", "CWE-306",
                              snippet=r.text[:160].replace("\n", " "), operation=f"GET {path}"))
        elif ok and SENSITIVE.search(path):
            findings.append(F("API-ANONYMOUS-SENSITIVE", f"Sensitive endpoint GET {path} is public", S.MEDIUM, url,
                              "This endpoint returns data anonymously and its path suggests it shouldn't.",
                              "Require authentication, or document it as intentionally public.", "CWE-306",
                              snippet=r.text[:160].replace("\n", " "), operation=f"GET {path}"))
        if ok:
            findings += secret_findings(url, r.text[:500_000])
    return findings, tested
