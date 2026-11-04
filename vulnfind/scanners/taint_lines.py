"""Line-based, scope-aware taint tracking for Go and PHP.

Same model as the JS tracker: request data taints a variable, taint flows through
assignments and string building, sanitisers clear it, and a finding is raised when a
tainted value reaches a dangerous sink argument. Variables are scoped to the brace
block they were assigned in.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Pattern, Sequence, Set, Tuple

from ..models import Finding, Severity as S


@dataclass(frozen=True)
class Sink:
    key: str
    title: str
    severity: S
    cwe: str
    pattern: Pattern[str]
    fix: str
    arg: Optional[int] = 0  # which call argument must be tainted (None = rest of the line)
    rule: Optional[str] = None  # rule-id suffix when several sinks share one vulnerability class


@dataclass(frozen=True)
class Lang:
    name: str
    prefix: str  # rule id prefix
    sources: Pattern[str]
    assign: Pattern[str]  # groups: targets, operator, rhs
    sanitizers: Pattern[str]
    var: str  # regex for a variable reference, with {name}
    sinks: Sequence[Sink]
    supersedes: Dict[str, set]
    comment: Tuple[str, ...] = ("//", "#", "*", "/*")
    literal: Pattern[str] = re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`[^`]*`")


def _call_args(text: str, open_paren: int) -> List[str]:
    depth, cur, args, quote = 0, [], [], None
    i = open_paren
    while i < len(text):
        c = text[i]
        if quote:
            cur.append(c)
            if c == "\\" and i + 1 < len(text):
                cur.append(text[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"`":
            quote = c
            cur.append(c)
        elif c in "([{":
            depth += 1
            if depth > 1:
                cur.append(c)
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                args.append("".join(cur))
                return args
            cur.append(c)
        elif c == "," and depth == 1:
            args.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    args.append("".join(cur))
    return args


_STRINGS = re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`[^`]*`")


@dataclass
class _Var:
    source: str
    line: int
    trace: Tuple[Tuple[int, str], ...]
    depth: int


_KEYWORDS = {"true", "false", "null", "nil", "None", "undefined", "new", "return", "await", "const", "let", "var", "int", "string"}


def _identifiers(segment: str, lang: "Lang") -> Set[str]:
    code = lang.literal.sub('""', segment)
    code = re.sub(r"(?<![\w$])[A-Za-z_]\w*(?:(?:\.|->|::)[A-Za-z_]\w*)+\s*\(", "(", code)  # fmt.Sprintf( / $db->query( are calls, not values
    if lang.name == "php":  # only $tokens are variables; bare words inside "…" strings are just text
        return {n for n in re.findall(r"\$[A-Za-z_]\w*", code) if not re.fullmatch(r"\$_[A-Z]+", n) and n != "$this"}
    names = re.findall(r"(?<![\w.$])\$?[A-Za-z_][\w]*(?![\w(])(?!\s*\()", code)
    return {n for n in names if n not in _KEYWORDS and not re.fullmatch(r"[A-Z_][A-Z0-9_]*", n.lstrip("$"))}


def _complete(segment: str) -> bool:
    """Only a fully visible expression can prove a value clean: multi-line templates/strings/calls can't."""
    s = segment.strip()
    if not s or s.count("`") % 2 or s.count("(") > s.count(")") or s.count("[") > s.count("]") or s.count("{") > s.count("}"):
        return False
    return not s.endswith(("+", "(", ",", "=", ".", "&&", "||", "?", ":"))  # odd backtick count already caught


def findings(lang: Lang, text: str, rel: str, clean_out: Optional[Set[Tuple[int, str]]] = None) -> Iterator[Finding]:
    tainted: Dict[str, _Var] = {}
    clean: Set[str] = set()
    depth = 0
    seen = set()

    def uses(segment: str, lineno: int) -> Optional[_Var]:
        m = lang.sources.search(segment)
        if m:
            src = m.group(0).rstrip("(")
            return _Var(src, lineno, ((lineno, f"input: {src}"),), depth)
        # Variable references inside string literals don't count - except PHP "…$var…" interpolation.
        code = lang.literal.sub('""', segment)
        for name, v in tainted.items():
            if re.search(lang.var.format(name=re.escape(name)), code):
                return v
        return None

    for lineno, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith(lang.comment):
            continue
        line = raw.split(" //", 1)[0] if lang.name == "go" else raw

        m = lang.assign.match(line)
        if m:
            targets = [t.strip() for t in m.group(1).split(",") if t.strip() and t.strip() not in ("_", "err", "$err")]
            op, rhs = m.group(2), m.group(3)
            src = uses(rhs, lineno)
            if src and not lang.sanitizers.search(rhs):
                for t in targets:
                    tainted[t] = _Var(src.source, src.line, (src.trace + ((lineno, f"{t} = …"),))[-8:], depth)
                    clean.discard(t)
            elif op in ("=", ":="):
                for t in targets:
                    if t in tainted and tainted[t].depth >= depth:
                        del tainted[t]
                proven = _complete(rhs.rstrip(";")) and (bool(lang.sanitizers.search(rhs)) or (not src and not (_identifiers(rhs, lang) - clean)))
                for t in targets:
                    (clean.add if proven else clean.discard)(t)

        for sink in lang.sinks:
            for sm in sink.pattern.finditer(line):
                if sink.arg is None:
                    segment = line[sm.end():]
                else:
                    paren = line.find("(", sm.end() - 1)
                    args = _call_args(line, paren) if paren != -1 else []
                    segment = args[sink.arg] if sink.arg < len(args) else ""
                if not segment:
                    continue
                has_source = bool(lang.sources.search(segment))
                if lang.sanitizers.search(segment) or (not has_source and _complete(segment) and not (_identifiers(segment, lang) - clean)):
                    if clean_out is not None:
                        clean_out.add((lineno, sink.rule or sink.key))
                    continue
                src = uses(segment, lineno)
                if not src or (lineno, sink.key) in seen:
                    continue
                seen.add((lineno, sink.key))
                trace = src.trace + ((lineno, f"sink: {sm.group(0).strip()}…"),)
                yield Finding(
                    rule_id=f"{lang.prefix}-TAINT-{(sink.rule or sink.key).upper()}", title=f"{sink.title}: input reaches {sm.group(0).strip().rstrip('(').strip()}",
                    severity=sink.severity, category="code", file=rel, line=lineno, column=sm.start() + 1, snippet=stripped[:300],
                    description=(f"Untrusted data from {src.source} (line {src.line}) reaches a {sink.title.lower()} sink on line {lineno}. "
                                 "Data flow: " + " → ".join(t for _, t in trace)),
                    fix=sink.fix, cwe=sink.cwe,
                    extra={"flow": [f"line {ln}: {t}" for ln, t in trace], "source": src.source, "confidence": "medium",
                           "sink_key": sink.rule or sink.key},
                )

        code = _STRINGS.sub('""', line)
        depth = max(0, depth + code.count("{") - code.count("}"))
        for name in [n for n, v in tainted.items() if v.depth > depth]:
            del tainted[name]


# ---------------------------------------------------------------- PHP

PHP = Lang(
    name="php", prefix="PHP",
    sources=re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER\[['\"](?:HTTP_|QUERY_STRING|REQUEST_URI|PATH_INFO))[^\s;,)]*"
                       r"|file_get_contents\(\s*['\"]php://input|\$request->(?:input|get|query|post|all|cookie|header)\(|\bgetallheaders\("),
    assign=re.compile(r"^\s*(\$[A-Za-z_]\w*(?:\s*,\s*\$[A-Za-z_]\w*)*)\s*(\.=|=)(?!=)\s*(.+?);?\s*$"),
    sanitizers=re.compile(r"\b(?:intval|floatval|boolval|\(int\)|\(float\)|htmlspecialchars|htmlentities|escapeshellarg|escapeshellcmd|"
                          r"mysqli_real_escape_string|real_escape_string|pg_escape_string|addslashes|filter_var|filter_input|basename|"
                          r"strip_tags|urlencode|rawurlencode|ctype_digit|is_numeric|->quote)\s*\(|\(int\)"),
    var=r"{name}(?![\w])",
    literal=re.compile(r"'(?:\\.|[^'\\])*'"),  # single-quoted only: "...$var..." interpolates
    sinks=[
        Sink("sqli", "SQL injection", S.CRITICAL, "CWE-89",
             re.compile(r"\b(?:mysqli_query|pg_query|sqlite_query|mssql_query|odbc_exec|mysqli_real_query|mysqli_multi_query)\s*\("),
             "Use prepared statements with bound parameters (PDO / mysqli_stmt).", arg=1),  # (connection, query)
        Sink("sqli0", "SQL injection", S.CRITICAL, "CWE-89",
             re.compile(r"\bmysql_query\s*\(|->(?:query|exec|prepare|rawQuery|whereRaw|selectRaw|multi_query|real_query)\s*\("),
             "Use prepared statements with bound parameters (PDO / mysqli_stmt).", arg=0, rule="sqli"),
        Sink("cmdi", "OS command injection", S.CRITICAL, "CWE-78",
             re.compile(r"(?<![\w>:$])(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\("),
             "Avoid the shell; if unavoidable wrap every argument in escapeshellarg().", arg=0),
        Sink("code", "Code injection", S.CRITICAL, "CWE-95",
             re.compile(r"(?<![\w>:$])(?:eval|assert|create_function)\s*\("), "Never evaluate request data as PHP.", arg=0),
        Sink("lfi", "File inclusion", S.CRITICAL, "CWE-98",
             re.compile(r"\b(?:include|include_once|require|require_once)\b\s*\(?"), "Map input to an allow-list of files.", arg=None),
        Sink("xss", "Cross-site scripting", S.HIGH, "CWE-79",
             re.compile(r"^\s*(?:echo|print)\b|<\?=|\bprintf\s*\("), "Escape output with htmlspecialchars($v, ENT_QUOTES, 'UTF-8').", arg=None),
        Sink("path", "Path traversal / SSRF", S.HIGH, "CWE-22",
             re.compile(r"\b(?:file_get_contents|fopen|readfile|file|unlink|file_put_contents|opendir|scandir|copy|rename|simplexml_load_file)\s*\("),
             "Restrict paths with basename() and an allow-listed directory; never pass request data to URL-capable file functions.", arg=0),
        Sink("ssrf", "Server-side request forgery", S.HIGH, "CWE-918",
             re.compile(r"curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,|curl_init\s*\("), "Validate URLs against an allow-list of hosts.", arg=None),
        Sink("redirect", "Open redirect", S.MEDIUM, "CWE-601",
             re.compile(r"\bheader\s*\(\s*['\"]Location:"), "Only redirect to relative paths or allow-listed hosts.", arg=None),
        Sink("deser", "Unsafe deserialization", S.CRITICAL, "CWE-502",
             re.compile(r"\bunserialize\s*\("), "Use json_decode() for untrusted data.", arg=0),
    ],
    supersedes={"sqli": {"PHP-SQL-INJECTION"}, "cmdi": {"PHP-COMMAND-INJECTION"}, "code": {"PHP-CODE-EXEC"},
                "lfi": {"PHP-FILE-INCLUSION"}, "xss": {"PHP-XSS"}, "deser": {"PHP-UNSERIALIZE"}},
)

# ---------------------------------------------------------------- Go

GO = Lang(
    name="go", prefix="GO",
    sources=re.compile(r"\br\.URL\.Query\(\)(?:\.Get\([^)]*\))?|\br\.(?:FormValue|PostFormValue|URL\.RawQuery|URL\.Path|Header\.Get|Referer)\b\(?"
                       r"|\bmux\.Vars\(\s*r\s*\)|\bchi\.URLParam\(|\bc\.(?:Query|Param|PostForm|DefaultQuery|DefaultPostForm|GetHeader|QueryParam|FormValue|Params|Cookie)\("
                       r"|\bos\.Args\b|\br\.Body\b|\bctx\.(?:Query|Param|FormValue|Params)\("),
    assign=re.compile(r"^\s*((?:[A-Za-z_]\w*\s*,\s*)*[A-Za-z_]\w*)\s*(:=|=|\+=)(?!=)\s*(.+)$"),
    sanitizers=re.compile(r"\bstrconv\.(?:Atoi|ParseInt|ParseUint|ParseFloat|ParseBool)\(|\b(?:url\.QueryEscape|url\.PathEscape|html\.EscapeString|"
                          r"template\.HTMLEscapeString|template\.JSEscapeString|filepath\.Base|path\.Base|uuid\.Parse|netip\.ParseAddr)\("),
    var=r"(?<![\w.]){name}(?![\w])",
    sinks=[
        Sink("sqli", "SQL injection", S.CRITICAL, "CWE-89",
             re.compile(r"\.(?:Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext|Raw|Where|Order|Select|Having|Joins)\s*\("),
             "Use placeholders ($1 / ?) and pass values as separate arguments.", arg=0),
        Sink("cmdi", "OS command injection", S.CRITICAL, "CWE-78",
             re.compile(r"\bexec\.Command(?:Context)?\s*\("), "Call a fixed binary with validated arguments; never `sh -c` with input.", arg=None),
        Sink("path", "Path traversal", S.HIGH, "CWE-22",
             re.compile(r"\b(?:os\.(?:Open|OpenFile|ReadFile|Create|Remove|RemoveAll|WriteFile|ReadDir|Stat)|ioutil\.(?:ReadFile|WriteFile|ReadDir))\s*\("),
             "Join with a fixed base, filepath.Clean it, and verify the result stays under the base directory.", arg=0),
        Sink("servefile", "Path traversal", S.HIGH, "CWE-22",
             re.compile(r"\bhttp\.ServeFile\s*\("), "Serve from an http.Dir/FS rooted at a fixed directory.", arg=2, rule="path"),
        Sink("ssrf", "Server-side request forgery", S.HIGH, "CWE-918",
             re.compile(r"\bhttp\.(?:Get|Post|Head|PostForm)\s*\(|\b\w*[cC]lient\.(?:Get|Post|Head)\s*\("),
             "Validate the destination host against an allow-list and block private ranges.", arg=0),
        Sink("ssrfreq", "Server-side request forgery", S.HIGH, "CWE-918",
             re.compile(r"\bhttp\.NewRequest(?:WithContext)?\s*\("), "Validate the destination host against an allow-list.", arg=None, rule="ssrf"),
        Sink("redirect", "Open redirect", S.MEDIUM, "CWE-601",
             re.compile(r"\bhttp\.Redirect\s*\("), "Only redirect to relative paths or allow-listed hosts.", arg=2),
        Sink("xss", "Cross-site scripting", S.HIGH, "CWE-79",
             re.compile(r"\btemplate\.(?:HTML|JS|URL|HTMLAttr|CSS)\s*\("), "Let html/template escape values; never wrap input in template.HTML.", arg=0),
        Sink("xsswrite", "Reflected XSS in response", S.MEDIUM, "CWE-79",
             re.compile(r"\bfmt\.Fprint(?:f|ln)?\s*\(\s*w\s*,|\bw\.Write\s*\(|\bio\.WriteString\s*\(\s*w\s*,"),
             "Render through html/template, or set Content-Type: text/plain and escape the value.", arg=None, rule="xss"),
    ],
    supersedes={"sqli": {"GO-SQL-INJECTION"}, "cmdi": {"GO-SHELL-EXEC"}, "xss": {"GO-TEMPLATE-UNESCAPED"}},
)

BY_EXT = {".php": PHP, ".phtml": PHP, ".inc": PHP, ".go": GO}
