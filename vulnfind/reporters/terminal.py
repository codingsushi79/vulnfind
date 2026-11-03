"""Human-friendly coloured terminal report."""

from __future__ import annotations

import os
import shutil
import sys
import textwrap
from collections import OrderedDict
from typing import Dict, List, TextIO

from .. import __version__
from ..models import CATEGORIES, Finding, ScanResult, Severity
from ..osv import _vkey
from ..scanners.deps import UPGRADE_CMD


class Style:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: str, *codes: str) -> str:
        if not self.enabled or not codes:
            return text
        table = {"bold": "1", "dim": "2", "italic": "3", "under": "4", "red": "31", "green": "32", "yellow": "33",
                 "blue": "34", "magenta": "35", "cyan": "36", "white": "37", "grey": "90", "bred": "91",
                 "bg_red": "41", "bg_yellow": "43", "bg_magenta": "45", "bg_blue": "44", "bg_grey": "100"}
        return f"\033[{';'.join(table[c] for c in codes)}m{text}\033[0m"


SEV_STYLE = {
    Severity.CRITICAL: ("bold", "white", "bg_magenta"),
    Severity.HIGH: ("bold", "white", "bg_red"),
    Severity.MEDIUM: ("bold", "yellow"),
    Severity.LOW: ("blue",),
    Severity.INFO: ("grey",),
}
SEV_TEXT = {Severity.CRITICAL: ("bold", "magenta"), Severity.HIGH: ("bold", "bred"), Severity.MEDIUM: ("yellow",),
            Severity.LOW: ("blue",), Severity.INFO: ("grey",)}
GRADE_STYLE = {"A": "green", "B": "green", "C": "yellow", "D": "bred", "F": "magenta"}


def use_color(stream: TextIO, forced: bool = None) -> bool:
    if forced is not None:
        return forced
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty() and os.environ.get("TERM") != "dumb"


def _badge(st: Style, sev: Severity) -> str:
    label = f" {sev.label:<8} " if st.enabled else f"[{sev.label}]".ljust(10)
    return st(label, *SEV_STYLE[sev])


def _rel_root(root: str) -> str:
    home = os.path.expanduser("~")
    return "~" + root[len(home):] if root.startswith(home) else root


def _group_dependencies(findings: List[Finding]) -> List[Dict]:
    groups: "OrderedDict[tuple, Dict]" = OrderedDict()
    for f in findings:
        key = (f.extra.get("package"), f.extra.get("version"), f.file)
        g = groups.setdefault(key, {"findings": [], "severity": f.severity, "first": f})
        g["findings"].append(f)
        g["severity"] = max(g["severity"], f.severity)
    out = list(groups.values())
    for g in out:
        fixes = [x.extra.get("fixed") for x in g["findings"]]
        g["fix"] = max((x for x in fixes if x), key=_vkey) if any(fixes) else None
        g["unfixed"] = sum(1 for x in fixes if not x)
        g["findings"].sort(key=lambda x: -x.severity)
    out.sort(key=lambda g: (-g["severity"], -len(g["findings"])))
    return out


def _fix_line(st: Style, text: str, width: int) -> str:
    body = textwrap.fill(text, width=width - 4, initial_indent=" " * 10, subsequent_indent=" " * 10)
    return "      " + st("fix ", "green") + body[10:] + "\n"


def render(result: ScanResult, out: TextIO = sys.stdout, color: bool = None, verbose: bool = False,
           limit: int = 0) -> None:
    st = Style(use_color(out, color))
    width = min(shutil.get_terminal_size((100, 24)).columns, 120)
    rule = st("─" * (width - 4), "grey")
    w = out.write

    w("\n  " + st("vulnfind", "bold", "cyan") + st(f" {__version__}", "grey") + st("  ·  ", "grey") + st(_rel_root(result.root), "bold") + "\n")
    w("  " + rule + "\n")

    if not result.findings:
        w("\n  " + st("✔ No vulnerabilities found.", "bold", "green") + "\n")

    by_cat: Dict[str, List[Finding]] = {}
    for f in result.findings:
        by_cat.setdefault(f.category, []).append(f)

    wrap = textwrap.TextWrapper(width=width - 8, initial_indent="      ", subsequent_indent="      ")
    for cat, heading in CATEGORIES.items():
        items = by_cat.get(cat)
        if not items:
            continue
        count = f"  {len(items)}"
        if cat == "dependency":
            n_pkgs = len({(x.extra.get("package"), x.extra.get("version"), x.file) for x in items})
            count = f"  {len(items)} advisories in {n_pkgs} package{'s' if n_pkgs != 1 else ''}"
        w("\n  " + st(heading.upper(), "bold", "under") + st(count, "grey") + "\n")
        shown = 0
        if cat == "dependency":
            for g in _group_dependencies(items):
                if limit and shown >= limit:
                    break
                shown += 1
                first = g["first"]
                arrow = st(f"  →  {g['fix']}", "green", "bold") if g["fix"] else st("  (no fix yet)", "grey")
                loc = st(first.location, "grey")
                w(f"\n  {_badge(st, g['severity'])} {st(first.extra['package'], 'bold')} {first.extra['version']}{arrow}   {loc}\n")
                for v in g["findings"][: (None if verbose else 4)]:
                    ids = v.extra.get("aliases") or [v.rule_id]
                    other = f" ({ids[1]})" if len(ids) > 1 else ""
                    cvss = st(f"  CVSS {v.extra['cvss']}", "grey") if v.extra.get("cvss") else ""
                    w(f"      {st('•', *SEV_TEXT[v.severity])} {st(ids[0], 'bold')}{st(other, 'grey')} {v.title}{cvss}\n")
                    if verbose:
                        w(st(wrap.fill(v.description), "grey") + "\n")
                        for r in v.references[:3]:
                            w("        " + st(r, "under", "blue") + "\n")
                hidden = len(g["findings"]) - (len(g["findings"]) if verbose else 4)
                if hidden > 0:
                    w(st(f"      … {hidden} more (use -v)\n", "grey"))
                if g["fix"]:
                    cmd = UPGRADE_CMD.get(first.extra["ecosystem"], "upgrade to {fix}").format(name=first.extra["package"], fix=g["fix"])
                    w(_fix_line(st, cmd, width))
                    if g["unfixed"]:
                        w(st(f"      ({g['unfixed']} of these have no fixed version yet)\n", "grey"))
                elif first.fix:
                    w(_fix_line(st, first.fix, width))
        else:
            for f in items:
                if limit and shown >= limit:
                    break
                shown += 1
                ctx = st(f"  ({f.extra['context']})", "grey") if f.extra.get("context") else ""
                w(f"\n  {_badge(st, f.severity)} {st(f.title, 'bold')}   {st(f.location, 'cyan')}{ctx}\n")
                if f.snippet:
                    w("      " + st("│ ", "grey") + f.snippet[: width - 12] + "\n")
                meta = " · ".join(x for x in (f.rule_id, f.cwe) if x)
                if verbose:
                    w(st(wrap.fill(f.description), "grey") + "\n")
                    for r in f.references[:3]:
                        w("      " + st(r, "under", "blue") + "\n")
                elif f.category in ("file", "config") and f.description:
                    w(st(wrap.fill(f.description), "grey") + "\n")
                if f.fix:
                    w(_fix_line(st, f.fix, width))
                w("      " + st(meta, "grey") + "\n")
        if limit and len(items) > shown and cat != "dependency":
            w(st(f"\n  … {len(items) - shown} more {heading.lower()} (raise --limit)\n", "grey"))

    for msg in result.warnings:
        w("\n  " + st("! " + msg, "yellow") + "\n")

    counts = result.counts()
    w("\n  " + rule + "\n  ")
    parts = []
    for sev in sorted(Severity, reverse=True):
        n = counts[sev.label]
        parts.append(st(f"{n} {sev.label.lower()}", *SEV_TEXT[sev]) if n else st(f"0 {sev.label.lower()}", "grey"))
    grade = result.grade
    w(st("Findings ", "bold") + "  ".join(parts) + "     " + st("Grade ", "bold") + st(f"{grade}", "bold", GRADE_STYLE[grade]) + st(f" ({result.score}/100)", "grey") + "\n")
    stats = [f"{result.files_scanned} files", f"{len(result.manifests)} manifests", f"{len(result.packages)} packages"]
    if result.suppressed:
        stats.append(f"{result.suppressed} suppressed")
    if result.below_threshold:
        stats.append(f"{result.below_threshold} below --min-severity")
    stats.append(f"{result.duration:.1f}s")
    w("  " + st(" · ".join(stats), "grey") + "\n\n")
