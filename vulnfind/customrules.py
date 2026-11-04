"""User-defined regex rules.

Loaded from (all optional, merged in this order):
  ~/.config/vulnfind/rules/*.json        personal rules for every project
  <project>/.vulnfind/rules/*.json       rules committed with a project
  "rules": [...] in .vulnfind.json       inline rules

Each rule:
  {
    "id": "ACME-NO-INTERNAL-API",          required, unique
    "title": "Internal admin API called from a handler",
    "severity": "high",                    info | low | medium | high | critical
    "pattern": "internal_admin_api\\(",    Python regex, matched per line
    "category": "code",                    code | secret | config (default code)
    "extensions": [".py"],                 optional file filter
    "files": ["src/**/*.py"],              optional path globs
    "description": "...", "fix": "...", "cwe": "CWE-284", "ignore_case": false,
    "skip_comments": true
  }
"""

from __future__ import annotations

import glob
import json
import os
import re
from typing import Any, Dict, List

from .models import Severity
from .scanners import Rule

CATEGORIES = {"code", "secret", "config"}


def _config_home() -> str:
    return os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")


def parse(raw: Dict[str, Any], source: str) -> Rule:
    for key in ("id", "title", "pattern"):
        if not raw.get(key):
            raise ValueError(f"{source}: custom rule is missing '{key}'")
    rid = str(raw["id"]).upper()
    try:
        sev = Severity.parse(str(raw.get("severity", "medium")))
    except ValueError as e:
        raise ValueError(f"{source}: rule {rid}: {e}")
    flags = re.I if raw.get("ignore_case") else 0
    try:
        re.compile(raw["pattern"], flags)
    except re.error as e:
        raise ValueError(f"{source}: rule {rid}: invalid regex: {e}")
    category = raw.get("category", "code")
    if category not in CATEGORIES:
        raise ValueError(f"{source}: rule {rid}: category must be one of {', '.join(sorted(CATEGORIES))}")
    exts = tuple(e if e.startswith(".") else "." + e for e in raw.get("extensions", []))
    rule = Rule(rid, str(raw["title"]), sev, raw["pattern"], str(raw.get("description", "Matched a custom rule.")),
                str(raw.get("fix", "")), raw.get("cwe"), exts, (), tuple(raw.get("files", [])), flags,
                tuple(raw.get("references", [])))
    rule.skip_comments = bool(raw.get("skip_comments", category != "secret"))
    rule.skip_strings = bool(raw.get("skip_strings", False))
    rule.category = category  # type: ignore[attr-defined]
    return rule


def load(root: str, inline: List[Dict[str, Any]] = ()) -> List[Rule]:
    rules: List[Rule] = []
    paths = sorted(glob.glob(os.path.join(_config_home(), "vulnfind", "rules", "*.json")))
    paths += sorted(glob.glob(os.path.join(root, ".vulnfind", "rules", "*.json")))
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            try:
                data = json.load(fh)
            except ValueError as e:
                raise ValueError(f"{path}: invalid JSON: {e}")
        items = data.get("rules", data) if isinstance(data, dict) else data
        if not isinstance(items, list):
            raise ValueError(f"{path}: expected a list of rules or {{\"rules\": [...]}}")
        rules += [parse(r, path) for r in items]
    rules += [parse(r, ".vulnfind.json") for r in inline or []]
    seen = set()
    for r in rules:
        if r.id in seen:
            raise ValueError(f"duplicate custom rule id {r.id}")
        seen.add(r.id)
    return rules
