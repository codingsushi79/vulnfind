"""Function-level reachability for dependency advisories.

For each advisory we try to learn *which functions* are vulnerable:
- Go advisories in OSV list exact symbols (ecosystem_specific.imports[].symbols), as used by govulncheck;
- for other ecosystems we extract identifiers the advisory text names (`_.template`, `yaml.load()`, ...).

Then we look at the files that import the package and check whether any of those
functions is actually referenced through the package's local alias. The result
(True / False / None = unknown) feeds the priority score: a CVE in a function you
never call is far less urgent than one on your hot path.
"""

from __future__ import annotations

import os
import re
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .models import Finding

GENERIC = {"load", "get", "set", "parse", "merge", "read", "write", "request", "send", "open", "run", "call", "init", "create",
           "update", "delete", "find", "render", "compile", "exec", "execute", "format", "join", "split", "filter", "map",
           "default", "config", "options", "handler", "next", "use", "then", "value", "data", "name", "path", "url", "key"}
STOP = {"true", "false", "null", "none", "undefined", "nan", "this", "self", "http", "https", "json", "html", "xml", "utf",
        "proto", "__proto__", "constructor", "prototype", "object", "string", "number", "array", "function", "window", "document"}

_BACKTICK = re.compile(r"`([A-Za-z_$][\w$]*(?:(?:\.|::|#)[A-Za-z_$][\w$]*)*)(\([^`]*\))?`")
_CALLISH = re.compile(r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)\(\)")
_THE_FN = re.compile(r"\bthe ([A-Za-z_$][\w$]*) (?:function|method)\b")


def symbol_source(vuln: dict) -> Optional[str]:
    """'osv' when the advisory lists exact vulnerable symbols, else 'text' (heuristic) or None."""
    for aff in vuln.get("affected") or []:
        for imp in (aff.get("ecosystem_specific") or {}).get("imports") or []:
            if imp.get("symbols"):
                return "osv"
    return None


def symbols_for(vuln: dict, pkg_name: str, ecosystem: str) -> List[str]:
    """Vulnerable function/method names for this package, best effort."""
    out: List[str] = []
    for aff in vuln.get("affected") or []:
        for imp in (aff.get("ecosystem_specific") or {}).get("imports") or []:
            if imp.get("path", "").startswith(pkg_name) or ecosystem == "Go":
                out += imp.get("symbols") or []
    if out:
        return sorted(set(out))
    text = " ".join([vuln.get("summary") or "", (vuln.get("details") or "")[:4000]])
    # Only identifiers written like code that is *called*: `a.b`, `fn()`, a.b(), "the fn function".
    found = [name for name, parens in _BACKTICK.findall(text) if "." in name or "::" in name or "#" in name or parens]
    found += _CALLISH.findall(text) + _THE_FN.findall(text)
    pkg_bits = {pkg_name.lower(), pkg_name.lower().split("/")[-1], pkg_name.lower().replace("-", "_")}
    clean = []
    for s in found:
        s = s.replace("::", ".").replace("#", ".")
        last = s.split(".")[-1]
        if len(last) < 3 or last.lower() in STOP or s.lower() in pkg_bits or re.fullmatch(r"v?\d[\w.]*", s):
            continue
        if "/" in s or s.endswith((".js", ".py", ".json", ".ts", ".go")):
            continue
        clean.append(s)
    return sorted(set(clean))[:12]


# ---------------------------------------------------------------- per-language alias extraction

def _aliases(lang: str, text: str, pkg: str) -> Tuple[Set[str], Set[str]]:
    """(module aliases, directly imported names) bound to `pkg` in this file."""
    mods: Set[str] = set()
    names: Set[str] = set()
    q = re.escape(pkg)
    if lang == "py":
        top = re.escape(pkg.split(".")[0])
        for m in re.finditer(r"(?m)^\s*import\s+(" + top + r"(?:\.[\w.]+)?)(?:\s+as\s+(\w+))?", text):
            mods.add(m.group(2) or m.group(1))
        for m in re.finditer(r"(?m)^\s*from\s+" + top + r"(?:\.[\w.]+)?\s+import\s+\(?([^)\n]+)", text):
            for part in m.group(1).split(","):
                bits = part.strip().split(" as ")
                if bits[0].strip():
                    names.add((bits[1] if len(bits) > 1 else bits[0]).strip())
    elif lang == "js":
        for m in re.finditer(r"(?:const|let|var)\s+([\w$]+)\s*=\s*require\(\s*['\"]" + q + r"(?:/[^'\"]*)?['\"]\s*\)", text):
            mods.add(m.group(1))
        for m in re.finditer(r"(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\(\s*['\"]" + q + r"(?:/[^'\"]*)?['\"]\s*\)", text):
            names |= {p.split(":")[-1].strip() for p in m.group(1).split(",") if p.strip()}
        for m in re.finditer(r"import\s+([^'\";]+?)\s+from\s+['\"]" + q + r"(?:/([^'\"]*))?['\"]", text):
            clause, sub = m.group(1), m.group(2)
            d = re.match(r"\s*([\w$]+)\s*(?:,|$)", clause)
            if d:
                mods.add(d.group(1))
            ns = re.search(r"\*\s+as\s+([\w$]+)", clause)
            if ns:
                mods.add(ns.group(1))
            br = re.search(r"\{([^}]*)\}", clause)
            if br:
                names |= {p.split(" as ")[-1].strip() for p in br.group(1).split(",") if p.strip()}
            if sub and d:  # import tmpl from 'lodash/template'
                names.add(d.group(1))
    elif lang == "go":
        for m in re.finditer(r'(?m)^\s*(?:import\s+)?([\w.]+\s+)?"(' + q + r'[\w./\-]*)"', text):
            alias = (m.group(1) or "").strip()
            mods.add(alias if alias and alias not in (".", "_") else m.group(2).rstrip("/").split("/")[-1])
    return mods, names


def used_symbols(lang: str, text: str, pkg: str, symbols: Sequence[str]) -> List[str]:
    """Which of `symbols` this file references via the package (empty if the file doesn't import it)."""
    mods, names = _aliases(lang, text, pkg)
    if not mods and not names:
        return []
    pkg_bits = {pkg.lower(), pkg.lower().split("/")[-1]}
    hits = []
    for sym in symbols:
        parts = sym.split(".")
        last = parts[-1]
        method_call = re.search(r"\." + re.escape(last) + r"\s*\(", text)
        if lang == "go" and len(parts) == 2:  # Type.Method on a value from the package
            if method_call:
                hits.append(sym)
            continue
        if lang == "js" and len(parts) >= 2 and parts[0] not in mods and parts[0].lower() not in pkg_bits:
            # method on an object the package hands you (res.redirect, app.use, client.query)
            if method_call and last.lower() not in GENERIC:
                hits.append(sym)
            elif method_call and parts[0] in text:
                hits.append(sym)
            continue
        if any(re.search(r"(?<![\w$.])" + re.escape(m) + r"\." + re.escape(last) + r"\b", text) for m in mods):
            hits.append(sym)
        elif last in names and re.search(r"(?<![\w$.])" + re.escape(last) + r"\s*\(", text):
            hits.append(sym)
    return hits


def is_used(lang: str, text: str, pkg: str, symbols: Sequence[str]) -> bool:
    return bool(used_symbols(lang, text, pkg, symbols))


LANG = {"PyPI": "py", "npm": "js", "Go": "go"}
EXTS = {"py": (".py",), "js": (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte"), "go": (".go",)}


def annotate(findings: Iterable[Finding], root: str, import_files: Dict[Tuple[str, str], List[str]], max_files: int = 60) -> None:
    """Set extra['symbol_reachable'] on dependency findings that carry vulnerable_symbols."""
    cache: Dict[str, str] = {}

    def text_of(rel: str) -> str:
        if rel not in cache:
            try:
                with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as fh:
                    cache[rel] = fh.read(2_000_000)
            except OSError:
                cache[rel] = ""
        return cache[rel]

    for f in findings:
        syms = f.extra.get("vulnerable_symbols")
        lang = LANG.get(f.extra.get("ecosystem", ""))
        if not syms or not lang:
            continue
        pkg = f.extra.get("package", "")
        key_name = pkg if lang != "py" else _py_import_name(pkg)
        files = [rel for (l, n), rels in import_files.items() if l == lang and (n == key_name or (lang == "go" and n.startswith(pkg)))
                 for rel in rels][:max_files]
        if not files:
            continue  # package not imported at all: the import-level flag already covers this
        called: List[str] = []
        for rel in files:
            for s in used_symbols(lang, text_of(rel), pkg if lang != "py" else key_name, syms):
                if s not in called:
                    called.append(s)
        f.extra["symbol_reachable"] = bool(called)
        f.extra["called_symbols"] = called


def _py_import_name(pkg: str) -> str:
    from .depgraph import PY_IMPORT_NAMES
    n = pkg.lower()
    return PY_IMPORT_NAMES.get(n, n.replace("-", "_"))
