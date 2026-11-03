"""Automatic dependency upgrades for vulnerable packages.

Edits manifests in place (requirements*.txt, package.json, go.mod), adds npm/yarn/pnpm
overrides for vulnerable *transitive* packages, and prints the follow-up commands
(lockfile regeneration) plus manual steps for ecosystems it can't edit safely.
"""

from __future__ import annotations

import difflib
import json
import os
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .models import Finding, ScanResult
from .osv import pick_target
from .scanners.deps import UPGRADE_CMD


@dataclass
class Plan:
    edits: Dict[str, Tuple[str, str]] = field(default_factory=OrderedDict)  # abs path -> (old, new)
    notes: List[str] = field(default_factory=list)
    commands: List[str] = field(default_factory=list)
    manual: List[str] = field(default_factory=list)
    upgrades: List[Tuple[str, str, str, str, bool]] = field(default_factory=list)  # (eco, name, old, new, major)


def _major(v: str) -> str:
    return re.split(r"[.\-+]", v.lstrip("v"))[0]


def targets(result: ScanResult) -> Dict[Tuple[str, str, str, str], Tuple[str, List[Finding]]]:
    """(manifest, ecosystem, name, version) -> (safe target version, findings it fixes)."""
    groups: Dict[Tuple[str, str, str, str], List[Finding]] = OrderedDict()
    for f in result.findings:
        if f.category == "dependency" and f.extra.get("fixed"):
            key = (f.file, f.extra["ecosystem"], f.extra["package"], f.extra["version"])
            groups.setdefault(key, []).append(f)
    out = {}
    for key, fs in groups.items():
        out[key] = (pick_target(f.extra["fixed"] for f in fs), fs)
    return out


def _read(path: str) -> Optional[str]:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def plan(result: ScanResult) -> Plan:
    pl = Plan()
    root = result.root
    current: Dict[str, str] = {}

    def text_of(rel: str) -> Optional[str]:
        path = os.path.join(root, rel)
        if path not in current:
            t = pl.edits[path][1] if path in pl.edits else _read(path)
            if t is None:
                return None
            current[path] = t
        return current[path]

    def set_text(rel: str, new: str) -> None:
        path = os.path.join(root, rel)
        old = pl.edits[path][0] if path in pl.edits else _read(path) or ""
        current[path] = new
        pl.edits[path] = (old, new)

    overrides: Dict[str, Dict[str, str]] = OrderedDict()  # package.json rel -> {name: version}
    after: set = set()

    for (manifest, eco, name, version), (fix, fs) in targets(result).items():
        major = _major(fix) != _major(version)
        pl.upgrades.append((eco, name, version, fix, major))
        base = os.path.basename(manifest)
        mdir = os.path.dirname(manifest)
        if eco == "PyPI" and base.lower().endswith(".txt"):
            text = text_of(manifest)
            pat = re.compile(r"(?im)^(\s*" + r"[-_.]+".join(map(re.escape, re.split(r"[-_.]+", name))) + r"\s*(?:\[[^\]]*\])?\s*===?\s*)" + re.escape(version) + r"\b")
            if text and pat.search(text):
                set_text(manifest, pat.sub(lambda m: m.group(1) + fix, text))
                after.add(f"pip install -r {manifest}")
                continue
        if eco == "npm" and base in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "package.json", "bun.lock"):
            pj_rel = os.path.join(mdir, "package.json") if mdir else "package.json"
            pj = text_of(pj_rel)
            if pj is None:
                pl.manual.append(f"{name} {version} -> {fix}: no package.json next to {manifest}")
                continue
            data = json.loads(pj)
            direct_section = next((s for s in ("dependencies", "devDependencies", "optionalDependencies")
                                   if name in (data.get(s) or {})), None)
            tool = "pnpm" if base == "pnpm-lock.yaml" else "yarn" if base == "yarn.lock" else "npm"
            if direct_section:
                spec = data[direct_section][name]
                prefix = re.match(r"^\s*([\^~]|>=)?", spec).group(1) or ""
                pat = re.compile(r'("' + re.escape(name) + r'"\s*:\s*")' + re.escape(spec) + '"')
                set_text(pj_rel, pat.sub(lambda m: m.group(1) + prefix + fix + '"', pj, count=1))
            else:
                overrides.setdefault(pj_rel, OrderedDict())[name] = fix
                pl.notes.append(f"{name} is a transitive dependency ({' > '.join(fs[0].extra.get('via') or []) or 'indirect'}); "
                                f"pinned via {tool} overrides")
            after.add({"npm": "npm install", "yarn": "yarn install", "pnpm": "pnpm install"}[tool] + (f"  (in {mdir})" if mdir else ""))
            continue
        if eco == "Go" and base == "go.mod" and name != "stdlib":
            text = text_of(manifest)
            pat = re.compile(r"(?m)^(\s*(?:require\s+)?" + re.escape(name) + r"\s+)v" + re.escape(version) + r"\b")
            if text and pat.search(text):
                set_text(manifest, pat.sub(lambda m: m.group(1) + "v" + fix, text))
                after.add("go mod tidy" + (f"  (in {mdir})" if mdir else ""))
                continue
        if eco == "Go" and name == "stdlib":
            pl.manual.append(f"Go toolchain {version} -> {fix}: update the `go`/`toolchain` line in {manifest} and your CI image")
            continue
        cmd = UPGRADE_CMD.get(eco, "upgrade {name} to {fix}").format(name=name, fix=fix)
        pl.commands.append(cmd + (f"   # in {mdir}" if mdir else ""))

    for pj_rel, pins in overrides.items():
        pj = text_of(pj_rel)
        data = json.loads(pj, object_pairs_hook=OrderedDict)
        lock_dir = os.path.join(root, os.path.dirname(pj_rel))
        indent = 2 if '\n  "' in pj else 4
        if os.path.exists(os.path.join(lock_dir, "pnpm-lock.yaml")):
            key, nested = "pnpm", True
        elif os.path.exists(os.path.join(lock_dir, "yarn.lock")):
            key, nested = "resolutions", False
        else:
            key, nested = "overrides", False
        if key not in data:
            # Insert textually so the rest of the file keeps its formatting.
            body = json.dumps({"overrides": pins} if nested else pins, indent=indent).replace("\n", "\n" + " " * indent)
            end = pj.rstrip().rfind("}")
            head = pj[:end].rstrip()
            set_text(pj_rel, f'{head},\n{" " * indent}"{key}": {body}\n' + pj[end:].lstrip(" \t"))
        else:
            target = data[key].setdefault("overrides", OrderedDict()) if nested else data[key]
            target.update(pins)
            set_text(pj_rel, json.dumps(data, indent=indent, ensure_ascii=False) + "\n")

    pl.commands = sorted(after) + pl.commands
    return pl


def diff(pl: Plan, root: str) -> str:
    chunks = []
    for path, (old, new) in pl.edits.items():
        rel = os.path.relpath(path, root)
        chunks.extend(difflib.unified_diff(old.splitlines(True), new.splitlines(True), f"a/{rel}", f"b/{rel}"))
    return "".join(chunks)


def apply(pl: Plan) -> List[str]:
    written = []
    for path, (_, new) in pl.edits.items():
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(new)
        written.append(path)
    return written
