"""Scan a remote git repository by URL (shallow clone into a temp dir, static scan only - nothing is executed)."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from typing import Optional, Tuple

_HOSTS = r"(?:github\.com|gitlab\.com|bitbucket\.org|codeberg\.org|git\.sr\.ht|dev\.azure\.com|gitea\.com)"
REPO_URL = re.compile(
    r"^(?:(?:https?://)?(?:www\.)?" + _HOSTS + r"/[\w.\-]+/[\w.\-]+(?:/tree/[\w.\-/]+)?/?(?:\.git)?"
    r"|git@[\w.\-]+:[\w.\-]+/[\w.\-]+(?:\.git)?"
    r"|(?:https?|ssh|git)://\S+\.git)$", re.I)


def is_repo_url(arg: str) -> bool:
    return bool(REPO_URL.match(arg.strip()))


def normalise(arg: str) -> Tuple[str, Optional[str]]:
    """(clone URL, branch) - accepts github.com/o/r, https://github.com/o/r/tree/dev, git@…, *.git."""
    arg = arg.strip().rstrip("/")
    branch = None
    m = re.match(r"^(?:https?://)?(?:www\.)?(" + _HOSTS + r"/[\w.\-]+/[\w.\-]+?)(?:\.git)?(?:/tree/([\w.\-/]+))?$", arg, re.I)
    if m:
        return f"https://{m.group(1)}.git", m.group(2)
    return arg, None


class Clone:
    """Context manager: shallow-clones a repo and removes it afterwards."""

    def __init__(self, url: str, full_history: bool = False, timeout: int = 600):
        self.url, self.branch = normalise(url)
        self.full_history = full_history
        self.timeout = timeout
        self.path: Optional[str] = None

    def __enter__(self) -> str:
        self.path = tempfile.mkdtemp(prefix="vulnfind-clone-")
        cmd = ["git", "-c", "core.hooksPath=/dev/null", "clone", "--quiet", "--no-tags"]
        if not self.full_history:
            cmd += ["--depth", "1"]
        if self.branch:
            cmd += ["--branch", self.branch]
        cmd += [self.url, self.path]
        # GIT_TERMINAL_PROMPT=0: fail instead of hanging on a credential prompt for private repos.
        env = {"GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
        import os
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout, env={**os.environ, **env})
        if proc.returncode != 0:
            shutil.rmtree(self.path, ignore_errors=True)
            msg = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "git clone failed"
            raise ValueError(f"could not clone {self.url}: {msg}")
        return self.path

    def __exit__(self, *exc) -> None:
        if self.path:
            shutil.rmtree(self.path, ignore_errors=True)
