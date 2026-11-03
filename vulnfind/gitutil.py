"""Git helpers for diff-aware scanning and hook installation."""

from __future__ import annotations

import os
import stat
import subprocess
from typing import List, Optional, Set


def _git(root: str, *args: str) -> Optional[str]:
    try:
        out = subprocess.run(["git", "-C", root, *args], capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.decode("utf-8", "replace") if out.returncode == 0 else None


def repo_root(path: str) -> Optional[str]:
    out = _git(path, "rev-parse", "--show-toplevel")
    return out.strip() if out else None


def _relative(root: str, paths: List[str]) -> Set[str]:
    """git prints paths relative to the repo root; convert them to be relative to `root`."""
    top = repo_root(root)
    if not top:
        return set(paths)
    prefix = os.path.relpath(os.path.realpath(root), os.path.realpath(top)).replace(os.sep, "/")
    if prefix in (".", ""):
        return set(paths)
    prefix += "/"
    return {p[len(prefix):] for p in paths if p.startswith(prefix)}


def staged_files(root: str) -> Optional[Set[str]]:
    out = _git(root, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    return None if out is None else _relative(root, [p for p in out.split("\0") if p])


def changed_files(root: str, base: str) -> Optional[Set[str]]:
    """Files changed since the merge-base with `base`, plus uncommitted and untracked files."""
    mb = _git(root, "merge-base", base, "HEAD")
    ref = mb.strip() if mb else base
    committed = _git(root, "diff", "--name-only", "--diff-filter=ACMR", "-z", ref)
    if committed is None:
        return None
    untracked = _git(root, "ls-files", "--others", "--exclude-standard", "-z") or ""
    # `git diff` prints paths relative to the repo top; `ls-files` relative to root.
    return _relative(root, [p for p in committed.split("\0") if p]) | {p for p in untracked.split("\0") if p}


HOOK_MARK = "# >>> vulnfind pre-commit >>>"
HOOK_END = "# <<< vulnfind pre-commit <<<"
HOOK_BODY = f"""{HOOK_MARK}
# Installed by `vulnfind hook install`. Blocks commits that add secrets or high-risk issues.
# Bypass once with: git commit --no-verify
if command -v vulnfind >/dev/null 2>&1; then
  vulnfind --staged --scanners secrets,code,config --fail-on {{fail_on}} --no-progress --quiet-ok --limit 20 || {{
    echo "vulnfind: commit blocked (fix the issues above, add '# vulnfind:ignore RULE-ID', or use --no-verify)"; exit 1; }}
else
  echo "vulnfind: not on PATH, skipping pre-commit scan" >&2
fi
{HOOK_END}
"""


def hooks_dir(root: str) -> Optional[str]:
    custom = _git(root, "config", "--get", "core.hooksPath")
    top = repo_root(root)
    if not top:
        return None
    if custom and custom.strip():
        p = custom.strip()
        return p if os.path.isabs(p) else os.path.join(top, p)
    gd = _git(root, "rev-parse", "--git-common-dir")
    gd = gd.strip() if gd else ".git"
    return os.path.join(gd if os.path.isabs(gd) else os.path.join(root, gd), "hooks")


def install_hook(root: str, fail_on: str = "high") -> str:
    d = hooks_dir(root)
    if not d:
        raise RuntimeError("not inside a git repository")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "pre-commit")
    body = HOOK_BODY.replace("{fail_on}", fail_on)
    existing = ""
    if os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            existing = fh.read()
        if HOOK_MARK in existing:
            start, end = existing.index(HOOK_MARK), existing.index(HOOK_END) + len(HOOK_END)
            new = existing[:start] + body.strip("\n") + existing[end:]
        else:
            new = existing.rstrip("\n") + "\n\n" + body  # keep the user's existing hook
    else:
        new = "#!/bin/sh\n" + body
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(new)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def uninstall_hook(root: str) -> Optional[str]:
    d = hooks_dir(root)
    path = os.path.join(d, "pre-commit") if d else None
    if not path or not os.path.exists(path):
        return None
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    if HOOK_MARK not in text:
        return None
    start, end = text.index(HOOK_MARK), text.index(HOOK_END) + len(HOOK_END)
    rest = (text[:start] + text[end:]).strip()
    if rest in ("", "#!/bin/sh"):
        os.remove(path)
    else:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(rest + "\n")
    return path
