"""`vulnfind bench`: precision / recall of the scanner on a labelled corpus.

Labels live in comments of the case files:
  `expect: RULE-ID`        this line must produce a finding with that rule
  `expect-above: RULE-ID`  the previous non-comment line must (for formats without trailing comments)
  `safe`                   this line must produce no finding at all (false-positive check)
Unlabelled lines are not scored.
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

CASES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cases")
PLACEMENT = {"ci.yml": ".github/workflows/ci.yml"}
LABEL = re.compile(r"(?:#|//)\s*(expect|expect-above):\s*([A-Z0-9][A-Z0-9-]+)|(?:#|//)\s*safe\b")


@dataclass
class Score:
    tp: List[Tuple[str, int, str]] = field(default_factory=list)
    fn: List[Tuple[str, int, str]] = field(default_factory=list)
    fp: List[Tuple[str, int, str]] = field(default_factory=list)
    safe_lines: int = 0

    @property
    def recall(self) -> float:
        return len(self.tp) / max(1, len(self.tp) + len(self.fn))

    @property
    def precision(self) -> float:
        return len(self.tp) / max(1, len(self.tp) + len(self.fp))


def labels(path: str, rel: str) -> Tuple[Dict[int, Set[str]], Set[int]]:
    expected: Dict[int, Set[str]] = {}
    safe: Set[int] = set()
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    last_code = 0
    for i, line in enumerate(lines, 1):
        for m in LABEL.finditer(line):
            if m.group(1) == "expect":
                expected.setdefault(i, set()).add(m.group(2))
            elif m.group(1) == "expect-above":
                expected.setdefault(last_code, set()).add(m.group(2))
            else:
                safe.add(i)
        if line.strip() and not line.lstrip().startswith(("#", "//")):
            last_code = i
    return expected, safe


def run() -> Score:
    from ..engine import ScanOptions, scan
    score = Score()
    with tempfile.TemporaryDirectory(prefix="vulnfind-bench-") as root:
        layout: Dict[str, str] = {}
        for name in sorted(os.listdir(CASES)):
            rel = PLACEMENT.get(name, name)
            dest = os.path.join(root, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copy(os.path.join(CASES, name), dest)
            layout[rel] = dest
        result = scan(root, ScanOptions(offline=True, scanners=["secrets", "code", "config"], use_gitignore=False,
                                        downgrade_tests=False))
        by_line: Dict[Tuple[str, int], Set[str]] = {}
        for f in result.findings:
            if f.line:
                by_line.setdefault((f.file, f.line), set()).add(f.rule_id)
        for rel, path in layout.items():
            expected, safe = labels(path, rel)
            score.safe_lines += len(safe)
            for line, rules in expected.items():
                got = by_line.get((rel, line), set())
                for r in rules:
                    (score.tp if r in got else score.fn).append((rel, line, r))
            for line in safe:
                for r in by_line.get((rel, line), set()):
                    score.fp.append((rel, line, r))
    return score
