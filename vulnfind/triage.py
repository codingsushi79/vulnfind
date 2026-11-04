"""`vulnfind triage`: walk through findings and record decisions.

Decisions are stored in .vulnfind-baseline.json at the project root (commit it), which every
later scan loads automatically, so a team triages once instead of re-reading the same issues:
  a  accept the risk (with a reason)       -> hidden from future scans
  p  false positive (with a reason)        -> hidden from future scans
  r  ignore this rule for the whole project -> `rule:ID` in .vulnfindignore
  s  skip / fix later                      -> stays in reports
  o  show the file location for your editor
  q  quit (decisions so far are already saved)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from typing import Callable, List, Optional, TextIO

from . import __version__
from .models import Finding

BASELINE = ".vulnfind-baseline.json"


def baseline_path(root: str) -> str:
    return os.path.join(root, BASELINE)


def load(root: str) -> dict:
    try:
        with open(baseline_path(root), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {"findings": data}
    except (OSError, ValueError):
        return {"tool": "vulnfind", "findings": []}


def save(root: str, data: dict) -> None:
    data["tool"], data["version"] = "vulnfind", __version__
    data["findings"].sort(key=lambda d: (d.get("file", ""), d.get("rule_id", "")))
    tmp = baseline_path(root) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, baseline_path(root))


def _who(root: str) -> str:
    try:
        out = subprocess.run(["git", "-C", root, "config", "user.name"], capture_output=True, text=True, timeout=10)
        return out.stdout.strip() or os.environ.get("USER", "")
    except (OSError, subprocess.SubprocessError):
        return os.environ.get("USER", "")


def run(root: str, findings: List[Finding], ask: Callable[[str], str] = input, out: TextIO = sys.stdout,
        color: Callable[[str, str], str] = lambda s, c: s) -> dict:
    data = load(root)
    known = {d["fingerprint"] for d in data["findings"]}
    todo = [f for f in sorted(findings, key=lambda f: -f.extra.get("priority", 0)) if f.fingerprint not in known]
    stats = {"accepted": 0, "false-positive": 0, "rule-ignored": 0, "skipped": 0}
    ignored_rules = set()
    who = _who(root)
    w = out.write
    if not todo:
        w("Nothing to triage - every finding already has a decision.\n")
        return stats
    w(f"\n{len(todo)} finding(s) to triage, highest priority first. Decisions are saved to {BASELINE} as you go.\n")
    for i, f in enumerate(todo, 1):
        if f.rule_id in ignored_rules:
            continue
        w("\n" + color(f"[{i}/{len(todo)}] {f.severity.label} · priority {f.extra.get('priority', '?')}", "bold") + f"  {f.title}\n")
        w(f"  {f.location}\n")
        if f.snippet:
            w(f"  │ {f.snippet[:160]}\n")
        for step in (f.extra.get("flow") or [])[:6]:
            w(f"  ├ {step[:140]}\n")
        if f.fix:
            w(f"  fix: {f.fix[:220]}\n")
        while True:
            choice = ask("  [a]ccept risk  [p] false positive  [r] ignore rule  [s]kip  [o]pen  [q]uit > ").strip().lower()[:1]
            if choice == "o":
                w(f"  {os.path.join(root, f.file)}:{f.line or 1}\n")
                continue
            break
        if choice == "q":
            break
        if choice in ("a", "p"):
            reason = ask("  reason (required, e.g. 'only admins can reach this'): ").strip()
            while not reason:
                reason = ask("  a short reason is required: ").strip()
            status = "accepted" if choice == "a" else "false-positive"
            data["findings"].append({"fingerprint": f.fingerprint, "rule_id": f.rule_id, "file": f.file, "title": f.title,
                                     "status": status, "reason": reason, "by": who, "date": time.strftime("%Y-%m-%d")})
            save(root, data)
            stats[status] += 1
        elif choice == "r":
            path = os.path.join(root, ".vulnfindignore")
            reason = ask(f"  why ignore {f.rule_id} everywhere? ").strip() or "triaged"
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(f"rule:{f.rule_id}  # {reason} ({who}, {time.strftime('%Y-%m-%d')})\n")
            ignored_rules.add(f.rule_id)
            stats["rule-ignored"] += 1
        else:
            stats["skipped"] += 1
    w("\n" + ", ".join(f"{v} {k}" for k, v in stats.items()) + "\n")
    if stats["accepted"] or stats["false-positive"]:
        w(f"Commit {BASELINE} so teammates and CI share these decisions.\n")
    return stats
