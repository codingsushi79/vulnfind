"""Lightweight taint tracking for JavaScript / TypeScript.

Without a JS parser in the standard library this works line by line, but it is
scope-aware: variables are tracked per function body (brace depth), assignments
from request data (req.query, req.body, ctx.request.body, event.body, location.search,
URLSearchParams ...) taint a variable, taint flows through further assignments,
template literals, concatenation and destructuring, sanitisers clear it, and a
finding is reported when a tainted value reaches a dangerous sink.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Tuple

from ..models import Finding, Severity as S

SOURCE = re.compile(
    r"(?<![\w$.])(?:req|request|ctx\.request|ctx|context\.req)\.(?:query|body|params|headers|cookies|files|file|search|hostname|path|url|originalUrl)\b"
    r"|(?<![\w$.])event\.(?:body|queryStringParameters|pathParameters|multiValueQueryStringParameters|headers)\b"
    r"|(?<![\w$.])(?:window\.)?location\.(?:search|hash|href|pathname)\b|(?<![\w$.])document\.(?:URL|cookie|referrer|documentURI)\b"
    r"|\bsearchParams\.get\(|\bnew\s+URLSearchParams\(|(?<![\w$.])process\.argv\b|\buseSearchParams\(|\bformData\.get\("
)
SANITIZER = re.compile(
    r"\b(?:parseInt|parseFloat|Number|Boolean|encodeURIComponent|encodeURI|escape|escapeHtml|DOMPurify\.sanitize|sanitize\w*|"
    r"validator\.\w+|xss|path\.basename|basename|mysql\.escape|connection\.escape|pg\.escapeLiteral|escapeLiteral|"
    r"crypto\.createHash|uuidValidate|isUUID|z\.\w+\(|\w+Schema\.parse|Joi\.)\s*\("
)
DECL = re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[^=]+)?=\s*(?!=)(.+)$")
ASSIGN = re.compile(r"^\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*(\+?=)\s*(?!=)(.+)$")
DESTRUCT = re.compile(r"^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(.+)$")
ARRAY_DESTRUCT = re.compile(r"^\s*(?:const|let|var)\s*\[([^\]]*)\]\s*=\s*(.+)$")
FUNC_START = re.compile(r"\bfunction\b|=>\s*\{|^\s*(?:async\s+)?[A-Za-z_$][\w$]*\s*\([^)]*\)\s*\{")


@dataclass(frozen=True)
class Sink:
    key: str
    rule_id: str
    title: str
    severity: S
    cwe: str
    pattern: "re.Pattern[str]"
    fix: str
    whole_line: bool = False  # check the whole remainder of the line, not just the first argument
    needs_html: bool = False


SINKS: List[Sink] = [
    Sink("cmdi", "JS-TAINT-CMDI", "OS command injection", S.CRITICAL, "CWE-78",
         # bare calls (destructured from child_process) or module-qualified - never RegExp#exec
         re.compile(r"(?<![\w$.])(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|execa|execaCommand)\s*\("
                    r"|\b(?:child_process|childProcess|cp|shell|execa)\.(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|command)\s*\("),
         "Use execFile/spawn with an argument array and no shell; validate against an allow-list."),
    Sink("code", "JS-TAINT-CODE", "Code injection", S.CRITICAL, "CWE-95",
         re.compile(r"(?<![\w$.])eval\s*\(|\bnew\s+Function\s*\(|\bvm\.run\w*\s*\(|\bnew\s+vm\.Script\s*\(|\bset(?:Timeout|Interval)\s*\(\s*(?![\w$]*\s*=>|function|\(|async)"),
         "Never evaluate user input; use JSON.parse or a lookup table."),
    Sink("sqli", "JS-TAINT-SQLI", "SQL injection", S.CRITICAL, "CWE-89",
         re.compile(r"\.(?:query|execute|raw|unsafe|\$queryRawUnsafe|\$executeRawUnsafe|whereRaw|orderByRaw|havingRaw|literal)\s*\("),
         "Use placeholders ($1 / ?) and pass values separately."),
    Sink("nosql", "JS-TAINT-NOSQL", "NoSQL injection", S.HIGH, "CWE-943",
         re.compile(r"\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|countDocuments|where|aggregate)\s*\("),
         "Validate types (e.g. ensure strings, not objects) before using values in queries; strip $-operators."),
    Sink("path", "JS-TAINT-PATH", "Path traversal", S.HIGH, "CWE-22",
         re.compile(r"\b(?:readFile|readFileSync|createReadStream|createWriteStream|writeFile|writeFileSync|appendFile|appendFileSync|"
                    r"unlink|unlinkSync|rmSync|readdirSync|sendFile|statSync|existsSync)\s*\("
                    r"|(?<![\w$.])(?:open|stat|rm|readdir|require)\s*\(|\bfs\w*\.(?:open|stat|rm|readdir|promises\.\w+)\s*\("
                    r"|\bres\.(?:download|attachment)\s*\("),
         "Resolve the path and verify it stays inside the intended base directory; reject '..'."),
    Sink("ssrf", "JS-TAINT-SSRF", "Server-side request forgery", S.HIGH, "CWE-918",
         re.compile(r"(?<![\w$.])(?:fetch|axios(?:\.(?:get|post|put|patch|delete|request|head))?|got|superagent\.\w+|needle|request|https?\.(?:get|request)|undici\.request)\s*\("),
         "Validate the destination against an allow-list and block private IP ranges."),
    Sink("redirect", "JS-TAINT-REDIRECT", "Open redirect", S.MEDIUM, "CWE-601",
         re.compile(r"\.redirect\s*\(|(?:window\.)?location(?:\.href)?\s*=(?!=)|location\.(?:assign|replace)\s*\("),
         "Only redirect to relative paths or allow-listed hosts."),
    Sink("xss", "JS-TAINT-XSS", "Cross-site scripting", S.HIGH, "CWE-79",
         re.compile(r"\.(?:innerHTML|outerHTML)\s*\+?=|\bdocument\.write(?:ln)?\s*\(|\.insertAdjacentHTML\s*\(|__html\s*:|\$\([^)]*\)\.html\s*\("),
         "Use textContent or sanitize with DOMPurify before inserting HTML.", whole_line=True),
    Sink("xss", "JS-TAINT-XSS", "Reflected XSS in response", S.HIGH, "CWE-79",
         re.compile(r"\bres\.(?:send|write|end)\s*\("),
         "Render through an escaping template engine or escape the value before sending HTML.", needs_html=True),
    Sink("redos", "JS-TAINT-REDOS", "Regular expression built from input (ReDoS)", S.MEDIUM, "CWE-1333",
         re.compile(r"\bnew\s+RegExp\s*\(|(?<![\w$.])RegExp\s*\("),
         "Escape user input before building a RegExp (or use a fixed pattern) and cap input length."),
    Sink("deser", "JS-TAINT-DESER", "Unsafe deserialization", S.CRITICAL, "CWE-502",
         re.compile(r"\b(?:unserialize|deserialize|yaml\.load|YAML\.load)\s*\("),
         "Parse with JSON.parse / yaml.load with a safe schema."),
    Sink("proto", "JS-TAINT-PROTO", "Prototype pollution", S.HIGH, "CWE-1321",
         re.compile(r"\b(?:_\.merge|_\.mergeWith|_\.defaultsDeep|_\.set|_\.setWith|merge|deepmerge|deepMerge|extend|\$\.extend)\s*\("),
         "Validate input with a schema; never deep-merge raw request objects."),
]

SUPERSEDES = {
    "cmdi": {"JS-CHILD-PROCESS"}, "code": {"JS-EVAL", "JS-STRING-TIMER"}, "sqli": {"JS-SQL-INJECTION"},
    "nosql": {"JS-NOSQL-INJECTION"}, "path": {"JS-PATH-TRAVERSAL"}, "ssrf": {"JS-SSRF"}, "redirect": {"JS-OPEN-REDIRECT"},
    "xss": {"JS-XSS-INNERHTML", "JS-XSS-REACT"}, "redos": set(), "deser": set(), "proto": {"JS-PROTOTYPE-POLLUTION"},
}

_STRINGS = re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"")


@dataclass
class Var:
    source: str
    line: int
    trace: Tuple[Tuple[int, str], ...]
    depth: int


def _call_args(text: str, start: int) -> str:
    """Return the text inside the parentheses that open at/after `start`."""
    i = text.find("(", start)
    if i == -1:
        return text[start:]
    depth, j = 0, i
    while j < len(text):
        c = text[j]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return text[i + 1:j]
        j += 1
    return text[i + 1:]


def _first_arg(args: str) -> str:
    depth, in_str = 0, None
    for i, c in enumerate(args):
        if in_str:
            if c == in_str and args[i - 1] != "\\":
                in_str = None
            continue
        if c in "'\"`":
            in_str = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            return args[:i]
    return args


def _strip_comment(line: str) -> str:
    s = line.strip()
    if s.startswith(("//", "*", "/*")):
        return ""
    return line


_JS_KEYWORDS = {"true", "false", "null", "undefined", "new", "await", "typeof", "this", "return", "const", "let", "var", "of", "in"}


def _js_identifiers(segment: str) -> set:
    """Identifiers that carry values into this expression (template ${...} parts kept, string text dropped)."""
    seg = re.sub(r"`([^`]*)`", lambda m: " ".join(re.findall(r"\$\{([^}]*)\}", m.group(1))), segment)
    seg = _STRINGS.sub('""', seg)
    seg = re.sub(r"(?<![\w$])[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+\s*\(", "(", seg)  # obj.method( is a call, not a value
    names = re.findall(r"(?<![\w$.])[A-Za-z_$][\w$]*(?![\w$])(?!\s*\()", seg)
    return {n for n in names if n not in _JS_KEYWORDS and not re.fullmatch(r"[A-Z_][A-Z0-9_]*", n)}


def _complete(segment: str) -> bool:
    """Only a fully visible expression can prove a value clean: multi-line templates/strings/calls can't."""
    s = segment.strip()
    if not s or s.count("`") % 2 or s.count("(") > s.count(")") or s.count("[") > s.count("]") or s.count("{") > s.count("}"):
        return False
    return not s.endswith(("+", "(", ",", "=", ".", "&&", "||", "?", ":"))  # odd backtick count already caught


def findings(text: str, rel: str, clean_out: Optional[set] = None) -> Iterator[Finding]:
    tainted: Dict[str, Var] = {}
    clean: set = set()
    depth = 0
    seen = set()
    lines = text.splitlines()

    def uses(segment: str) -> Optional[Var]:
        m = SOURCE.search(segment)
        if m:
            return Var(m.group(0).rstrip("("), lineno, ((lineno, f"input: {m.group(0).rstrip('(')}"),), depth)
        for name, var in tainted.items():
            if re.search(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])", segment):
                return var
        return None

    for lineno, raw in enumerate(lines, 1):
        line = _strip_comment(raw)
        if not line:
            continue
        code_only = _STRINGS.sub('""', line)

        # ---- assignments (taint propagation)
        rhs = None
        targets: List[str] = []
        m = DESTRUCT.match(line)
        if m:
            for part in m.group(1).split(","):
                part = part.strip().split("=")[0].strip()
                if not part or part.startswith("..."):
                    part = part[3:].strip()
                name = part.split(":")[-1].strip()
                if re.match(r"^[A-Za-z_$][\w$]*$", name):
                    targets.append(name)
            rhs = m.group(2)
        else:
            m = ARRAY_DESTRUCT.match(line)
            if m:
                targets = [p.strip() for p in m.group(1).split(",") if re.match(r"^\s*[A-Za-z_$][\w$]*\s*$", p)]
                rhs = m.group(2)
            else:
                m = DECL.match(line)
                if m:
                    targets, rhs = [m.group(1)], m.group(2)
                else:
                    m = ASSIGN.match(line)
                    if m and not line.lstrip().startswith(("if", "for", "while", "return")):
                        targets, rhs = [m.group(1)], m.group(3)
                        if m.group(2) == "+=" and m.group(1) in tainted:
                            rhs = None  # stays tainted
        if rhs is not None and targets:
            src = uses(rhs)
            if src and not SANITIZER.search(rhs):
                for t in targets:
                    tainted[t] = Var(src.source, src.line, (src.trace + ((lineno, f"{t} = …"),))[-8:], depth)
                    clean.discard(t)
            else:
                proven = _complete(rhs) and (bool(SANITIZER.search(rhs)) or (not src and not (_js_identifiers(rhs) - clean)))
                for t in targets:
                    tainted.pop(t, None)
                    (clean.add if proven else clean.discard)(t)

        # ---- sinks
        for sink in SINKS:
            for sm in sink.pattern.finditer(line):
                if sink.whole_line or sink.key == "redirect" and "=" in sm.group(0):
                    segment = line[sm.end():]
                else:
                    segment = _first_arg(_call_args(line, sm.end() - 1))
                if sink.key in ("ssrf", "redirect") and re.match(r"\s*(?:new\s+URL\(\s*)?['\"`]/(?!/)", segment):
                    continue  # fixed relative path (request URL only used as the base): stays same-origin
                if sink.needs_html and "<" not in segment:
                    continue
                if sink.key == "nosql" and not re.match(r"\s*[A-Za-z_$][\w$.]*\s*$", segment) and not re.search(r":\s*[A-Za-z_$][\w$.]*", segment):
                    continue
                if sink.key == "path" and sm.group(0).startswith("require") and not re.search(r"[`+]", segment):
                    if not uses(segment):
                        continue
                if SANITIZER.search(segment):
                    continue
                src = uses(segment)
                if not src:
                    if clean_out is not None and _complete(segment) and not (_js_identifiers(segment) - clean):
                        clean_out.add((lineno, sink.key))
                    continue
                if (lineno, sink.key) in seen:
                    continue
                seen.add((lineno, sink.key))
                trace = src.trace + ((lineno, f"sink: {sm.group(0).strip()}…"),)
                flow = [f"line {ln}: {txt}" for ln, txt in trace]
                severity = sink.severity.lowered() if src.source == "process.argv" else sink.severity
                yield Finding(
                    rule_id=sink.rule_id, title=f"{sink.title}: input reaches {sm.group(0).strip().rstrip('(').strip()}",
                    severity=severity, category="code", file=rel, line=lineno, column=sm.start() + 1,
                    snippet=raw.strip()[:300],
                    description=(f"Untrusted data from {src.source} (line {src.line}) reaches a {sink.title.lower()} sink on line {lineno}. "
                                 "Data flow: " + " → ".join(t for _, t in trace)),
                    fix=sink.fix, cwe=sink.cwe,
                    extra={"flow": flow, "source": src.source, "confidence": "medium"},
                )

        # ---- scope tracking: drop variables declared in a block that just closed
        depth += code_only.count("{") - code_only.count("}")
        if depth < 0:
            depth = 0
        for name in [n for n, v in tainted.items() if v.depth > depth]:
            del tainted[name]
