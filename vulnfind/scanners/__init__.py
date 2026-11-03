"""Shared machinery for regex-driven scanners."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Callable, Iterator, List, Optional, Sequence, Tuple

from ..models import Finding, Severity
from ..walker import SourceFile, line_index, locate

COMMENT_PREFIXES = ("#", "//", "/*", "*", "<!--", "--", ";")


@dataclass
class Rule:
    id: str
    title: str
    severity: Severity
    pattern: str
    description: str
    fix: str = ""
    cwe: Optional[str] = None
    exts: Tuple[str, ...] = ()  # file extensions this rule applies to (empty = any)
    names: Tuple[str, ...] = ()  # filename globs this rule applies to (OR-ed with exts)
    paths: Tuple[str, ...] = ()  # relative-path globs this rule applies to
    flags: int = 0
    references: Tuple[str, ...] = ()
    keywords: Tuple[str, ...] = ()  # lowercase literals; the regex only runs if one is present
    skip_comments: bool = True
    skip_strings: bool = True  # ignore matches that start inside a string literal
    # Optional extra check on the match; return False to drop it.
    validate: Optional[Callable[["re.Match[str]", str], bool]] = None
    _regex: Optional["re.Pattern[str]"] = field(default=None, repr=False)

    @property
    def regex(self) -> "re.Pattern[str]":
        if self._regex is None:
            self._regex = re.compile(self.pattern, self.flags | re.MULTILINE)
        return self._regex

    def applies_to(self, f: SourceFile) -> bool:
        if not (self.exts or self.names or self.paths):
            return True
        if self.exts and f.ext in self.exts:
            return True
        if self.names and any(fnmatch.fnmatch(f.name, n) for n in self.names):
            return True
        if self.paths and any(fnmatch.fnmatch(f.rel, p) for p in self.paths):
            return True
        return False


def run_rules(rules: Sequence[Rule], f: SourceFile, category: str, text: Optional[str] = None,
              snippet: Callable[[str, "re.Match[str]"], str] = lambda line, m: line.strip()) -> Iterator[Finding]:
    text = f.text() if text is None else text
    index: Optional[List[int]] = None
    lower: Optional[str] = None
    for rule in rules:
        if not rule.applies_to(f):
            continue
        if rule.keywords:
            if lower is None:
                lower = text.lower()
            if not any(k in lower for k in rule.keywords):
                continue
        seen_lines = set()
        for m in rule.regex.finditer(text):
            if index is None:
                index = line_index(text)
            line_no, col = locate(index, m.start())
            if line_no in seen_lines:
                continue
            start = index[line_no - 1]
            end = text.find("\n", start)
            line = text[start:end if end != -1 else len(text)]
            if rule.skip_comments and line.lstrip().startswith(COMMENT_PREFIXES):
                continue
            if rule.skip_strings and _in_string(line, col - 1):
                continue
            if rule.validate and not rule.validate(m, line):
                continue
            seen_lines.add(line_no)
            yield Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity, category=category,
                file=f.rel, line=line_no, column=col, snippet=snippet(line, m)[:300],
                description=rule.description, fix=rule.fix or None, cwe=rule.cwe,
                references=list(rule.references),
            )


def _in_string(line: str, pos: int) -> bool:
    """True if `pos` falls inside a '...', "..." or `...` literal on this line."""
    quote = None
    i = 0
    while i < pos and i < len(line):
        c = line[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"`":
            quote = c
        i += 1
    return quote is not None


_SUPPRESS = re.compile(r"(?:vulnfind:\s*ignore|nosec|gitleaks:allow|noqa:\s*vulnfind)([^\n]*)", re.I)


def is_suppressed(lines: List[str], line_no: int, rule_id: str) -> bool:
    """Inline suppression: `vulnfind:ignore [RULE-ID ...]` on the line or the line above."""
    for ln in (line_no, line_no - 1):
        if 1 <= ln <= len(lines):
            if ln != line_no and not lines[ln - 1].lstrip().startswith(COMMENT_PREFIXES):
                continue  # the line above only counts when it is a standalone comment
            m = _SUPPRESS.search(lines[ln - 1])
            if m:
                ids = re.findall(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+", m.group(1).upper())
                if not ids or rule_id.upper() in ids:
                    return True
    return False
