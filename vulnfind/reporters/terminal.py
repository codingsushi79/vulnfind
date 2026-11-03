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
from ..osv import pick_target
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
        g["fix"] = pick_target(fixes)
        g["unfixed"] = sum(1 for x in fixes if not x)
        g["findings"].sort(key=lambda x: (-x.extra.get("priority", 0), -x.severity))
    for g in out:
        g["priority"] = max(x.extra.get("priority", 0) for x in g["findings"])
        g["kev"] = next((x.extra["kev"] for x in g["findings"] if x.extra.get("kev")), None)
        g["epss"] = max((x.extra.get("epss") or 0 for x in g["findings"]), default=0)
    out.sort(key=lambda g: (-g["severity"], -g["priority"], -len(g["findings"])))
    return out


def _dep_context(st: Style, first: Finding) -> str:
    x = first.extra
    bits = []
    if x.get("direct") is True:
        bits.append("direct dependency")
    elif x.get("via"):
        chain = x["via"]
        shown = " > ".join(chain[:4]) + (" > …" if len(chain) > 4 else "")
        bits.append(f"via {shown}")
    elif x.get("direct") is False:
        bits.append("transitive")
    if x.get("imported") is True:
        bits.append("imported by your code")
    elif x.get("imported") is False:
        bits.append("not imported directly")
    if x.get("dev"):
        bits.append("dev-only")
    return st(" · ".join(bits), "grey") if bits else ""


def _intel(st: Style, kev, epss: float) -> str:
    parts = []
    if kev:
        tag = "EXPLOITED IN THE WILD" + (" · ransomware" if kev.get("ransomware") else "")
        parts.append(st(f" ⚠ {tag} ", "bold", "white", "bg_red"))
    if epss and epss >= 0.01:
        color = "bred" if epss >= 0.5 else "yellow" if epss >= 0.1 else "grey"
        parts.append(st(f"EPSS {epss * 100:.0f}%", color))
    return "  ".join(parts)


def _top_priorities(st: Style, result: ScanResult, w, width: int, n: int = 5) -> None:
    ranked = sorted(result.findings, key=lambda f: -f.extra.get("priority", 0))
    seen, rows = set(), []
    for f in ranked:
        key = (f.extra.get("package"), f.file) if f.category == "dependency" else (f.rule_id, f.file, f.line)
        if key in seen:
            continue
        seen.add(key)
        rows.append(f)
        if len(rows) >= n:
            break
    w("\n  " + st("FIX THESE FIRST", "bold", "under") + st("  ranked by severity, exploitation evidence and reachability", "grey") + "\n\n")
    for i, f in enumerate(rows, 1):
        if f.category == "dependency":
            what = f"{f.extra.get('package')} {f.extra.get('version')}"
            if f.extra.get("fixed"):
                what += st(f" → {f.extra['fixed']}", "green")
            what += st(f"  {f.rule_id}", "grey")
        else:
            what = f.title
        intel = _intel(st, f.extra.get("kev"), f.extra.get("epss") or 0)
        prio = st(f"{f.extra.get('priority', 0):>3}", *SEV_TEXT[f.severity])
        w(f"  {st(str(i) + '.', 'grey')} {prio}  {what}  {st(f.location, 'cyan')}" + (f"  {intel}" if intel else "") + "\n")


def render_multi(results: List[ScanResult], out: TextIO = sys.stdout, color: bool = None) -> None:
    """Compact table for scanning many projects at once."""
    st = Style(use_color(out, color))
    w = out.write
    names = [_rel_root(r.root) for r in results]
    nw = min(max([len(n) for n in names] + [7]), 60)
    w("\n  " + st("vulnfind", "bold", "cyan") + st(f" {__version__}", "grey") + st(f"  ·  {len(results)} projects", "grey") + "\n\n")
    w("  " + st(f"{'PROJECT':<{nw}}  GRADE  CRIT  HIGH   MED   LOW  PKGS   TIME", "bold") + "\n")
    for name, r in sorted(zip(names, results), key=lambda x: (x[1].score, x[0])):
        c = r.counts()
        cells = [st(f"{c['CRITICAL']:>4}", "magenta") if c["CRITICAL"] else f"{0:>4}",
                 st(f"{c['HIGH']:>5}", "bred") if c["HIGH"] else f"{0:>5}",
                 st(f"{c['MEDIUM']:>5}", "yellow") if c["MEDIUM"] else f"{0:>5}", f"{c['LOW']:>5}"]
        shown = name if len(name) <= nw else "…" + name[-(nw - 1):]
        w(f"  {shown:<{nw}}  " + st(f"{r.grade:^5}", "bold", GRADE_STYLE[r.grade]) + "  " + " ".join(cells)
          + f"  {len(r.packages):>4}  " + st(f"{r.duration:>4.1f}s", "grey") + "\n")
        for msg in r.warnings[:2]:
            w("  " + st(f"{'':<{nw}}  ! {msg[:80]}", "yellow") + "\n")
    total = sum(len(r.findings) for r in results)
    w("\n  " + st(f"{total} findings across {len(results)} projects", "bold") + st("  (scan one project for details)", "grey") + "\n\n")


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

    if len(result.findings) >= 8:
        _top_priorities(st, result, w, width)

    wrap = textwrap.TextWrapper(width=width - 8, initial_indent="      ", subsequent_indent="      ")
    for cat, heading in CATEGORIES.items():
        items = by_cat.get(cat)
        if not items:
            continue
        count = f"  {len(items)}"
        if cat == "dependency":
            adv = [x for x in items if "package" in x.extra and not x.rule_id.startswith("DEP-")]
            n_pkgs = len({(x.extra.get("package"), x.extra.get("version"), x.file) for x in adv})
            count = f"  {len(adv)} advisories in {n_pkgs} package{'s' if n_pkgs != 1 else ''}"
            if len(items) > len(adv):
                count += f" · {len(items) - len(adv)} other"
        w("\n  " + st(heading.upper(), "bold", "under") + st(count, "grey") + "\n")
        shown = 0
        if cat == "dependency":
            others = [x for x in items if "package" not in x.extra or x.rule_id.startswith("DEP-")]
            items_adv = [x for x in items if x not in others]
            for g in _group_dependencies(items_adv) + [{"findings": [o], "severity": o.severity, "first": o, "fix": None,
                                                         "unfixed": 0, "priority": 0, "kev": None, "epss": 0} for o in others]:
                if limit and shown >= limit:
                    break
                shown += 1
                first = g["first"]
                if first.rule_id.startswith("DEP-"):
                    w(f"\n  {_badge(st, first.severity)} {st(first.title, 'bold')}   {st(first.location, 'cyan')}\n")
                    if first.snippet:
                        w("      " + st("│ ", "grey") + first.snippet[: width - 12] + "\n")
                    w(st(wrap.fill(first.description), "grey") + "\n")
                    if first.fix:
                        w(_fix_line(st, first.fix, width))
                    w("      " + st(first.rule_id, "grey") + "\n")
                    continue
                arrow = st(f"  →  {g['fix']}", "green", "bold") if g["fix"] else st("  (no fix yet)", "grey")
                loc = st(first.location, "grey")
                w(f"\n  {_badge(st, g['severity'])} {st(first.extra['package'], 'bold')} {first.extra['version']}{arrow}   {loc}\n")
                ctx = _dep_context(st, first)
                intel = _intel(st, g["kev"], g["epss"])
                if ctx or intel:
                    w("      " + "   ".join(x for x in (intel, ctx) if x) + "\n")
                for v in g["findings"][: (None if verbose else 4)]:
                    ids = v.extra.get("aliases") or [v.rule_id]
                    other = f" ({ids[1]})" if len(ids) > 1 else ""
                    cvss = st(f"  CVSS {v.extra['cvss']}", "grey") if v.extra.get("cvss") else ""
                    kev = st("  ⚠ KEV", "bold", "bred") if v.extra.get("kev") else ""
                    epss = st(f"  EPSS {v.extra['epss'] * 100:.1f}%", "grey") if v.extra.get("epss") and v.extra["epss"] >= 0.01 else ""
                    w(f"      {st('•', *SEV_TEXT[v.severity])} {st(ids[0], 'bold')}{st(other, 'grey')} {v.title}{cvss}{epss}{kev}\n")
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
                flow = f.extra.get("flow")
                if flow:
                    steps = flow if verbose or len(flow) <= 6 else flow[:2] + [f"… {len(flow) - 4} more steps"] + flow[-2:]
                    w("      " + st("data flow", "magenta") + "\n")
                    for i, step in enumerate(steps):
                        conn = "└─" if i == len(steps) - 1 else "├─"
                        w("      " + st(conn, "grey") + " " + st(step[: width - 14], "grey" if 0 < i < len(steps) - 1 else "white") + "\n")
                if f.extra.get("history"):
                    x = f.extra
                    w("      " + st(f"commit {x['commit'][:10]} · {x.get('author', '')} · {str(x.get('date', ''))[:10]} · \"{x.get('subject', '')}\"", "magenta") + "\n")
                meta = " · ".join(x for x in (f.rule_id, f.cwe, f"priority {f.extra['priority']}" if "priority" in f.extra else None) if x)
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
    if result.commits_scanned:
        stats.append(f"{result.commits_scanned} commits")
    if result.suppressed:
        stats.append(f"{result.suppressed} suppressed")
    if result.below_threshold:
        stats.append(f"{result.below_threshold} below --min-severity")
    stats.append(f"{result.duration:.1f}s")
    w("  " + st(" · ".join(stats), "grey") + "\n\n")
