"""HTTP route inventory and missing-authentication detection.

Understands Flask / FastAPI / Django views (Python AST), Express / Koa-style routers
and Next.js route handlers / pages API (JS/TS). Each route records whether some form
of authentication guards it (decorator, dependency, middleware, or an explicit
session/user check in the handler).

A route is reported only when the project demonstrably uses auth elsewhere (so a
public site doesn't get flooded) and the route changes state or looks sensitive.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..models import Finding, Severity as S

AUTH_NAME = re.compile(r"(?i)auth|login|logged_?in|jwt|token|permission|perm_|role|admin_required|requires?_user|current_user|"
                       r"protect|guard|session|passport|verify(?:user|token|session)|ensure|is_?admin|signed_?in|clerk|getServerSession|"
                       r"user_passes_test|staff_member_required|api_key|apikey|scope")
INLINE_AUTH = re.compile(r"(?i)\b(?:current_user|request\.user\.is_(?:authenticated|staff|superuser)|session\.get\(\s*['\"]user|"
                         r"g\.user|get_current_user|getServerSession|auth\(\)|currentUser\(|getToken\(|req\.user\b|req\.session\.user|"
                         r"ctx\.state\.user|verifyToken|verify_jwt|jwt\.verify|abort\(\s*40[13]|status\(\s*40[13]\)|HTTPException\(\s*status_code\s*=\s*40[13]|"
                         r"raise PermissionDenied|res\.sendStatus\(\s*40[13]\))")
# Project-specific guards: requireOperator(), ensureAdmin(), assertRole(), checkPermission(), authorize(), getCurrentUser() ...
GUARD_CALL = re.compile(r"\b(?:require|ensure|assert|check|verify|enforce|authori[sz]e|must|only)_?(?:[A-Z]\w*|user|admin|auth|role|login|operator|owner|"
                        r"permission|session|staff|signed_in|logged_in)\w*\s*\(|\b(?:get_?current_?user|getCurrentUser|currentUser|getUser|getSession|"
                        r"auth|getAuth|requireUser)\s*\(|\bcurrent_user\b|\brequest\.user\b")
PUBLIC_PATH = re.compile(r"(?i)/(?:login|logout|signin|signup|sign-in|sign-up|register|auth|oauth|callback|webhooks?|health|healthz|"
                         r"ready|status|ping|metrics|public|static|assets|favicon|robots|sitemap|password|forgot|reset|verify|confirm|"
                         r"csrf|\.well-known)|^/$")
SENSITIVE_PATH = re.compile(r"(?i)/(?:admin|internal|manage|users?|accounts?|settings|billing|payments?|orders?|export|import|"
                            r"delete|upload|config|secrets?|keys?|tokens?|debug|reports?|invoices?|members?|roles?|permissions?)\b")
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass
class Route:
    file: str
    line: int
    end_line: int
    method: str
    path: str
    framework: str
    handler: str
    auth: Optional[bool]  # None = can't tell
    auth_hint: str = ""


# ---------------------------------------------------------------- Python

ROUTE_DECOS = {"route": None, "get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE",
               "api_route": None, "websocket": "WS", "api_view": None}


def _dotted(n: ast.AST) -> str:
    parts = []
    while isinstance(n, ast.Attribute):
        parts.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        parts.append(n.id)
    elif isinstance(n, ast.Call):
        return _dotted(n.func)
    return ".".join(reversed(parts))


def python_routes(source: str, rel: str) -> List[Route]:
    try:
        tree = ast.parse(source, filename=rel)
    except (SyntaxError, ValueError, RecursionError):
        return []
    lines = source.splitlines()
    local_funcs = {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    guarded_blueprint = bool(re.search(r"@\w+\.before_(?:app_)?request[\s\S]{0,400}?(?:login|auth|session|current_user|abort\(\s*40[13])", source))
    out: List[Route] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        route_decos = []
        auth_hint = ""
        for d in node.decorator_list:
            name = _dotted(d)
            last = name.rsplit(".", 1)[-1]
            if last in ROUTE_DECOS and (isinstance(d, ast.Call) or last == "api_view"):
                route_decos.append((d, last))
            elif AUTH_NAME.search(name):
                auth_hint = f"@{name}"
            if isinstance(d, ast.Call):
                for kw in d.keywords:  # FastAPI dependencies=[Depends(auth)]
                    if kw.arg == "dependencies" and AUTH_NAME.search(ast.dump(kw.value)):
                        auth_hint = "dependencies=[…auth…]"
        if not route_decos:
            continue
        # FastAPI parameter dependencies: user = Depends(get_current_user)
        for default in list(node.args.defaults) + [d for d in node.args.kw_defaults if d is not None]:
            if isinstance(default, ast.Call) and _dotted(default.func).endswith(("Depends", "Security")) and AUTH_NAME.search(ast.dump(default)):
                auth_hint = auth_hint or "Depends(auth)"
        body = "\n".join(lines[node.lineno - 1:getattr(node, "end_lineno", node.lineno)])
        if not auth_hint and _guarded(body):
            auth_hint = "checks user/session in handler"
        if not auth_hint:  # one level of delegation to a helper defined in this module
            for call in re.findall(r"(?<![\w.])([A-Za-z_]\w*)\s*\(", body):
                helper = local_funcs.get(call)
                if helper is not None and helper is not node:
                    hb = "\n".join(lines[helper.lineno:getattr(helper, "end_lineno", helper.lineno)])
                    if _guarded(hb):
                        auth_hint = f"via {call}()"
                        break
        if not auth_hint and guarded_blueprint:
            auth_hint = "before_request guard"
        for d, kind in route_decos:
            path = "/"
            if isinstance(d, ast.Call) and d.args and isinstance(d.args[0], ast.Constant) and isinstance(d.args[0].value, str):
                path = d.args[0].value
            methods = [ROUTE_DECOS[kind]] if ROUTE_DECOS.get(kind) else ["GET"]
            if isinstance(d, ast.Call):
                for kw in d.keywords:
                    if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                        methods = [e.value.upper() for e in kw.value.elts if isinstance(e, ast.Constant)]
            if kind == "api_view" and isinstance(d, ast.Call) and d.args and isinstance(d.args[0], (ast.List, ast.Tuple)):
                methods = [e.value.upper() for e in d.args[0].elts if isinstance(e, ast.Constant)]
            fw = "fastapi" if kind in ("get", "post", "put", "patch", "delete", "api_route") and "fastapi" in source.lower() else \
                 "django" if kind == "api_view" else "flask"
            for m in methods:
                out.append(Route(rel, node.lineno, getattr(node, "end_lineno", node.lineno), m, path, fw, node.name,
                                 bool(auth_hint), auth_hint))
    # Django function views with @login_required but no decorator route (URLconf elsewhere): inventory only if in views.py
    return out


# ---------------------------------------------------------------- JavaScript / TypeScript

EXPRESS = re.compile(r"\b([A-Za-z_$][\w$]*)\.(get|post|put|patch|delete|all)\s*\(\s*(['\"`])(/[^'\"`]*)\3\s*,(.*)$")
USE_AUTH = re.compile(r"\b([A-Za-z_$][\w$]*)\.use\s*\(([^)]*)\)")
SERVER_FRAMEWORK = re.compile(r"""require\(\s*['"](?:express|koa-router|@koa/router|fastify|hono|restify|polka)['"]\s*\)|"""
                              r"""from\s+['"](?:express|koa-router|@koa/router|fastify|hono|restify|polka)['"]|\bRouter\(\)|new\s+Hono\(""")
HTTP_CLIENTS = {"axios", "http", "https", "fetch", "client", "request", "superagent", "got", "ky", "api", "$", "jQuery", "cache",
                "map", "store", "redis", "localStorage", "sessionStorage", "params", "headers", "searchParams", "Object", "Reflect"}
NEXT_HANDLER = re.compile(r"^\s*export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b|^\s*export\s+const\s+(GET|POST|PUT|PATCH|DELETE)\s*=")


def _guarded(text: str) -> bool:
    return bool(INLINE_AUTH.search(text) or GUARD_CALL.search(text))


def _js_function_body(source: str, name: str) -> Optional[str]:
    m = re.search(r"(?:function\s+" + re.escape(name) + r"\s*\(|(?:const|let)\s+" + re.escape(name) + r"\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>)", source)
    if not m:
        return None
    return "\n".join(source[m.start():].splitlines()[:80])


def _delegated_guard(handler: str, source: str, rel: str, root: Optional[str]) -> Optional[str]:
    """One level of delegation: does a function the handler calls perform an auth check?"""
    import os
    called = set(re.findall(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(", handler)) - {"if", "for", "while", "switch", "return", "await", "catch",
                                                                              "function", "require", "json", "parse"}
    for name in sorted(called):
        body = _js_function_body(source, name)
        if body is None and root:
            imp = re.search(r"import\s*\{[^}]*\b" + re.escape(name) + r"\b[^}]*\}\s*from\s*['\"]([^'\"]+)['\"]", source)
            if imp:
                spec = imp.group(1)
                base = os.path.join(root, "src", spec[2:]) if spec.startswith("@/") else \
                    os.path.normpath(os.path.join(root, os.path.dirname(rel), spec)) if spec.startswith(".") else None
                for cand in ([base + ext for ext in (".ts", ".tsx", ".js", ".mjs", "/index.ts", "/index.js")] if base else []):
                    if os.path.isfile(cand):
                        try:
                            with open(cand, encoding="utf-8", errors="replace") as fh:
                                body = _js_function_body(fh.read(400_000), name)
                        except OSError:
                            body = None
                        break
        if body and _guarded(body.split("\n", 1)[1] if "\n" in body else body):
            return f"via {name}()"
    return None


def js_routes(source: str, rel: str, root: Optional[str] = None) -> List[Route]:
    out: List[Route] = []
    lines = source.splitlines()
    guarded_from: Dict[str, int] = {}  # router var -> line after which router.use(auth) applies
    is_server = bool(SERVER_FRAMEWORK.search(source))
    for i, line in enumerate(lines, 1):
        u = USE_AUTH.search(line)
        if u and AUTH_NAME.search(u.group(2)) and not re.search(r"['\"`]/", u.group(2).split(",")[0]):
            guarded_from.setdefault(u.group(1), i)
    for i, line in enumerate(lines, 1):
        m = EXPRESS.search(line)
        if not m or m.group(1) in HTTP_CLIENTS:
            continue
        if not is_server and m.group(1) not in ("app", "router", "server") and not m.group(1).endswith("Router"):
            continue
        var, method, path, rest = m.group(1), m.group(2).upper(), m.group(4), m.group(5)
        middleware = rest.rsplit(",", 1)[0] if rest.count(",") else ""
        handler_text = "\n".join(lines[i - 1:i + 40])
        hint = ""
        if middleware and AUTH_NAME.search(middleware):
            hint = "middleware: " + AUTH_NAME.search(middleware).group(0)
        elif var in guarded_from and guarded_from[var] < i:
            hint = f"{var}.use(auth)"
        elif _guarded(handler_text.split("\n});")[0]):
            hint = "checks user/session in handler"
        else:
            hint = _delegated_guard(handler_text.split("\n});")[0], source, rel, root) or ""
        out.append(Route(rel, i, min(i + 40, len(lines)), "ALL" if method == "ALL" else method, path, "express",
                         "(inline)", bool(hint), hint))
    # Next.js app router: app/**/route.ts, pages/api/**
    nm = re.search(r"(?:^|/)app/(.*)/route\.(?:ts|js|mjs|tsx)$", rel) or re.search(r"(?:^|/)pages/api/(.*)\.(?:ts|js|tsx)$", rel)
    if nm:
        path = "/" + re.sub(r"\((?:[^)]+)\)/?", "", nm.group(1)).replace("[", ":").replace("]", "")
        if "/pages/api/" in "/" + rel:
            path = "/api" + path
        for i, line in enumerate(lines, 1):
            h = NEXT_HANDLER.match(line)
            if h:
                body = "\n".join(lines[i - 1:i + 60]).split("\n}\n")[0]
                hint = "checks session in handler" if _guarded(body) or AUTH_NAME.search(body) else \
                    (_delegated_guard(body, source, rel, root) or "")
                out.append(Route(rel, i, min(i + 60, len(lines)), h.group(1) or h.group(2), path, "nextjs", h.group(1) or h.group(2),
                                 bool(hint), hint))
    return out


def routes_for(source: str, rel: str, root: Optional[str] = None) -> List[Route]:
    if rel.endswith(".py"):
        return python_routes(source, rel)
    if rel.endswith((".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")):
        return js_routes(source, rel, root)
    return []


# ---------------------------------------------------------------- findings

def missing_auth_findings(routes: Sequence[Route]) -> List[Finding]:
    if not any(r.auth for r in routes):
        return []  # no auth anywhere: probably a public app/API; nothing to compare against
    out: List[Finding] = []
    for r in routes:
        if r.auth or PUBLIC_PATH.search(r.path):
            continue
        sensitive = bool(SENSITIVE_PATH.search(r.path))
        if r.method not in STATE_CHANGING and not sensitive:
            continue
        admin = bool(re.search(r"(?i)/(?:admin|internal|manage|debug|secrets?)", r.path))
        sev = S.HIGH if admin else S.MEDIUM
        out.append(Finding(
            "ROUTE-NO-AUTH", f"{r.method} {r.path} has no authentication check", sev, "code", r.file, r.line,
            snippet=f"{r.framework}: {r.method} {r.path} -> {r.handler}",
            description=("Other routes in this project are protected, but this one has no auth decorator, dependency, middleware or "
                         "user/session check. " + ("It changes state, so anyone could trigger it." if r.method in STATE_CHANGING
                                                    else "Its path suggests it returns sensitive data.")),
            fix="Add the same auth guard used by your other routes (e.g. @login_required / Depends(get_current_user) / auth middleware), "
                "or mark it intentionally public with `# vulnfind:ignore ROUTE-NO-AUTH`.",
            cwe="CWE-306", extra={"route": f"{r.method} {r.path}", "framework": r.framework, "confidence": "medium"}))
    return out


def annotate_flows(findings: Iterable[Finding], routes: Sequence[Route]) -> None:
    """Tag data-flow findings with the route they live in; unauthenticated entry points rank higher."""
    by_file: Dict[str, List[Route]] = {}
    for r in routes:
        by_file.setdefault(r.file, []).append(r)
    for f in findings:
        if not f.extra.get("flow") or not f.line:
            continue
        inside = [r for r in by_file.get(f.file, []) if r.line <= f.line <= r.end_line]
        if inside:
            r = max(inside, key=lambda r: r.line)
            f.extra["route"] = f"{r.method} {r.path}"
            f.extra["route_auth"] = r.auth
            if r.auth is False:
                f.extra["context"] = f"reachable without login via {r.method} {r.path}"
