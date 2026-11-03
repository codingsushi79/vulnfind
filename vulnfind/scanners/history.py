"""Scan git history for secrets that were committed at some point.

Deleting a secret from the latest commit does not un-leak it: anyone with a clone can
still read it. This walks `git log -p` (added lines only), runs the secret rules on
each commit's additions, and reports secrets that are no longer in the working tree
(those still present are already reported by the normal scan).
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from typing import Callable, Dict, Iterator, List, Optional, Tuple

from ..models import Finding
from ..walker import SourceFile
from . import run_rules
from .secrets import SECRET_RULES, SKIP_NAMES, SKIP_SUFFIXES, _secret_snippet

COMMIT_MARK = "\x00\x00commit "


def count_commits(root: str, depth: Optional[int]) -> int:
    try:
        out = subprocess.run(["git", "-C", root, "rev-list", "--all", "--count", "--", "."], capture_output=True, text=True, timeout=60)
        n = int(out.stdout.strip() or 0)
    except (OSError, ValueError, subprocess.SubprocessError):
        return 0
    return min(n, depth) if depth else n


def _iter_commits(root: str, depth: Optional[int]) -> Iterator[Tuple[Dict[str, str], Dict[str, List[Tuple[int, str]]]]]:
    """Yield (commit meta, {path: [(line_no, added_text)]}) for each commit, newest first."""
    # %x00 makes git emit NUL bytes (they can't be passed in argv directly); --relative keeps paths
    # relative to `root` and limits the log to it when scanning a subfolder of a repository.
    cmd = ["git", "-C", root, "log", "--all", "-p", "--relative", "--no-color", "--unified=0", "--no-ext-diff",
           "--no-renames", "--diff-filter=AM", "--format=%x00%x00commit %H%x1f%an%x1f%aI%x1f%s"]
    if depth:
        cmd.append(f"--max-count={depth}")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    meta: Optional[Dict[str, str]] = None
    files: Dict[str, List[Tuple[int, str]]] = {}
    path: Optional[str] = None
    line_no = 0
    assert proc.stdout is not None
    try:
        for raw in proc.stdout:
            line = raw.decode("utf-8", "replace").rstrip("\n")
            if line.startswith(COMMIT_MARK):
                if meta:
                    yield meta, files
                h, author, date, subject = (line[len(COMMIT_MARK):].split("\x1f") + ["", "", "", ""])[:4]
                meta, files, path = {"hash": h, "author": author, "date": date, "subject": subject}, {}, None
            elif line.startswith("+++ "):
                target = line[4:]
                path = target[2:] if target.startswith("b/") else None
            elif line.startswith("@@"):
                # @@ -a,b +c,d @@
                try:
                    plus = line.split("+", 1)[1].split(" ", 1)[0]
                    line_no = int(plus.split(",")[0])
                except (IndexError, ValueError):
                    line_no = 0
            elif path and line.startswith("+") and not line.startswith("+++"):
                files.setdefault(path, []).append((line_no, line[1:]))
                line_no += 1
        if meta:
            yield meta, files
    finally:
        proc.stdout.close()
        proc.wait()


def scan(root: str, depth: Optional[int] = None, on_commit: Optional[Callable[[str], None]] = None) -> List[Finding]:
    found: Dict[str, Finding] = {}
    current_cache: Dict[str, str] = {}

    def still_present(rel: str, value: str) -> bool:
        if rel not in current_cache:
            try:
                with open(os.path.join(root, rel), "rb") as fh:
                    current_cache[rel] = fh.read().decode("utf-8", "replace")
            except OSError:
                current_cache[rel] = ""
        return value in current_cache[rel]

    for meta, files in _iter_commits(root, depth):
        if on_commit:
            on_commit(meta["hash"][:8])
        for rel, added in files.items():
            name = rel.rsplit("/", 1)[-1]
            if name in SKIP_NAMES or name.lower().endswith(SKIP_SUFFIXES):
                continue
            text = "\n".join(t for _, t in added)
            if len(text) > 2_000_000:
                continue
            f = SourceFile(path=os.path.join(root, rel), rel=rel, size=len(text))
            f._text, f._binary = text, False
            for fnd in run_rules(SECRET_RULES, f, "secret", text, _secret_snippet):
                real_line, raw = added[fnd.line - 1] if fnd.line and fnd.line <= len(added) else (None, "")
                m = next((r.regex.search(raw) for r in SECRET_RULES if r.id == fnd.rule_id), None)
                value = (m.group(m.lastindex) if m and m.lastindex else m.group(0)) if m else raw
                if still_present(rel, value):
                    continue  # the working-tree scan reports it
                key = hashlib.sha256(f"{fnd.rule_id}|{value}".encode()).hexdigest()
                # git log is newest-first, so overwriting keeps the commit that introduced it.
                fnd.line = real_line
                fnd.title = f"{fnd.title} (in git history)"
                fnd.description = (f"{fnd.description} It was removed from the current files but is still in git history - "
                                   "anyone with a clone of the repository can recover it.")
                fnd.fix = ("Rotate it now (removing it is not enough), then rewrite history with git filter-repo or BFG "
                           "and force-push; ask collaborators to re-clone.")
                prev = found.get(key)
                fnd.extra = {"commit": meta["hash"], "author": meta["author"], "date": meta["date"],
                             "subject": meta["subject"][:80], "occurrences": (prev.extra["occurrences"] + 1) if prev else 1,
                             "history": True}
                fnd.file = rel
                found[key] = fnd
    return list(found.values())
