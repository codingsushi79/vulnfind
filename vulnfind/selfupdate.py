"""`vulnfind update`: upgrade vulnfind itself, using whatever installed it."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from typing import Optional, Tuple

REPO = "https://github.com/codingsushi79/vulnfind"


def install_info() -> Tuple[str, Optional[str], Optional[str]]:
    """(kind, source url/path, installed commit). kind: editable | git | pypi | source."""
    try:
        from importlib import metadata
        dist = metadata.distribution("vulnfind")
        raw = dist.read_text("direct_url.json")
    except Exception:
        return "source", None, None
    if not raw:
        return "pypi", None, None
    info = json.loads(raw)
    if (info.get("dir_info") or {}).get("editable"):
        return "editable", info.get("url", "").replace("file://", ""), None
    if info.get("vcs_info"):
        return "git", info.get("url"), info["vcs_info"].get("commit_id")
    return "source", info.get("url"), None


def latest_commit(url: str = REPO) -> Optional[str]:
    try:
        out = subprocess.run(["git", "ls-remote", url, "HEAD"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.split()[0] if out.returncode == 0 and out.stdout.strip() else None


def installer() -> str:
    prefix = os.path.realpath(sys.prefix)
    if os.sep + os.path.join("uv", "tools") + os.sep in prefix + os.sep and shutil.which("uv"):
        return "uv"
    if os.sep + "pipx" + os.sep in prefix and shutil.which("pipx"):
        return "pipx"
    return "pip"


def upgrade_command(kind: str, source: Optional[str]) -> Optional[list]:
    target = f"git+{source or REPO}" if kind == "git" else "vulnfind"
    how = installer()
    if kind == "editable":
        return None
    if how == "uv":
        return ["uv", "tool", "install", "--force", target]
    if how == "pipx":
        return ["pipx", "install", "--force", target]
    return [sys.executable, "-m", "pip", "install", "--upgrade", target]
