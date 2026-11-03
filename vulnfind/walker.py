"""File discovery: walks the target folder honouring .gitignore, .vulnfindignore and CLI excludes."""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Iterable, Iterator, List, Optional, Set, Tuple

DEFAULT_EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "jspm_packages",
    ".venv", "venv", "env", ".env.d", "__pycache__", ".tox", ".nox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".gradle", ".idea", ".vscode", ".next", ".nuxt",
    ".svelte-kit", ".turbo", ".parcel-cache", ".cache", "dist", "build", "out",
    "target", "coverage", ".terraform", "Pods", "DerivedData", ".dart_tool",
    "site-packages", ".eggs",
}
# vendor/ often contains third-party code the user didn't write; still useful but noisy.
DEFAULT_EXCLUDED_DIRS.add("vendor")

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".avif", ".tiff", ".psd",
    ".mp3", ".mp4", ".mov", ".avi", ".mkv", ".wav", ".flac", ".ogg", ".webm",
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".jar", ".war", ".ear",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".exe", ".dll", ".so", ".dylib", ".a", ".o", ".obj", ".class", ".pyc", ".pyo",
    ".wasm", ".node", ".bin", ".dat", ".iso", ".dmg",
}


def _glob_to_regex(pattern: str) -> str:
    """Translate a gitignore-style glob to a regex (supports **, *, ?, [..])."""
    out = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if pattern[i:i + 3] == "**/":
                out.append("(?:.*/)?")
                i += 3
                continue
            if pattern[i:i + 2] == "**":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = pattern.find("]", i + 1)
            if j == -1:
                out.append(re.escape(c))
            else:
                body = pattern[i + 1:j].replace("\\", "\\\\")
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append(f"[{body}]")
                i = j
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


@dataclass
class _Rule:
    regex: "re.Pattern[str]"
    negate: bool
    dir_only: bool
    anchored: bool


class PathMatcher:
    """A small gitignore-compatible matcher (last matching rule wins)."""

    def __init__(self, patterns: Iterable[str] = ()):
        self.rules: List[_Rule] = []
        for p in patterns:
            self.add(p)

    def add(self, pattern: str) -> None:
        pattern = pattern.rstrip("\n").rstrip()
        if not pattern or pattern.startswith("#"):
            return
        negate = pattern.startswith("!")
        if negate:
            pattern = pattern[1:]
        dir_only = pattern.endswith("/")
        pattern = pattern.rstrip("/")
        anchored = "/" in pattern
        pattern = pattern.lstrip("/")
        if pattern.startswith("**/"):
            anchored = False
            pattern = pattern[3:]
        if not pattern:
            return
        regex = re.compile(_glob_to_regex(pattern) + r"\Z")
        self.rules.append(_Rule(regex, negate, dir_only, anchored))

    def matches(self, rel_path: str, is_dir: bool = False) -> bool:
        if not self.rules:
            return False
        parts = rel_path.split("/")
        ignored = False
        # Check every ancestor directory and finally the path itself.
        for depth in range(1, len(parts) + 1):
            candidate = "/".join(parts[:depth])
            cand_is_dir = is_dir or depth < len(parts)
            base = parts[depth - 1]
            for rule in self.rules:
                if rule.dir_only and not cand_is_dir:
                    continue
                target = candidate if rule.anchored else base
                if rule.regex.match(target):
                    ignored = not rule.negate
            if ignored and depth < len(parts):
                return True  # a parent directory is excluded
        return ignored


@dataclass
class IgnoreConfig:
    paths: PathMatcher = field(default_factory=PathMatcher)
    rules: Set[str] = field(default_factory=set)
    vulns: Set[str] = field(default_factory=set)

    @classmethod
    def load(cls, root: str, extra_files: Iterable[str] = ()) -> "IgnoreConfig":
        cfg = cls()
        for path in [os.path.join(root, ".vulnfindignore"), *extra_files]:
            if not os.path.isfile(path):
                continue
            with open(path, encoding="utf-8", errors="replace") as fh:
                for raw in fh:
                    line = raw.split(" #", 1)[0].strip()
                    if not line or line.startswith("#"):
                        continue
                    low = line.lower()
                    if low.startswith("rule:"):
                        cfg.rules.add(line[5:].strip().upper())
                    elif low.startswith("vuln:"):
                        cfg.vulns.add(line[5:].strip().upper())
                    else:
                        cfg.paths.add(line)
        return cfg


@dataclass
class SourceFile:
    path: str  # absolute
    rel: str  # posix path relative to scan root
    size: int
    _text: Optional[str] = None
    _binary: Optional[bool] = None

    @property
    def name(self) -> str:
        return self.rel.rsplit("/", 1)[-1]

    @property
    def ext(self) -> str:
        name = self.name.lower()
        return name[name.rfind("."):] if "." in name else ""

    def is_binary(self) -> bool:
        if self._binary is None:
            if self.ext in BINARY_EXTENSIONS:
                self._binary = True
            else:
                try:
                    with open(self.path, "rb") as fh:
                        self._binary = b"\0" in fh.read(8192)
                except OSError:
                    self._binary = True
        return self._binary

    def text(self) -> str:
        if self._text is None:
            try:
                with open(self.path, "rb") as fh:
                    self._text = fh.read().decode("utf-8", errors="replace")
            except OSError:
                self._text = ""
        return self._text


def _git_files(root: str) -> Optional[Set[str]]:
    """Files git would track (tracked + untracked-but-not-ignored), or None if not a repo."""
    try:
        proc = subprocess.run(
            ["git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            capture_output=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return {p for p in proc.stdout.decode("utf-8", "replace").split("\0") if p}


def git_tracked(root: str) -> Optional[Set[str]]:
    try:
        proc = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return {p for p in proc.stdout.decode("utf-8", "replace").split("\0") if p}


def walk(
    root: str,
    ignore: IgnoreConfig,
    excludes: Iterable[str] = (),
    use_gitignore: bool = True,
    include_vendor: bool = False,
    only: Optional[Set[str]] = None,
) -> Iterator[SourceFile]:
    """Yield scannable files. Inside a git repo, git's own file list is used (fast, exact
    .gitignore semantics); otherwise the tree is walked with a gitignore-compatible matcher.
    `only` restricts the walk to a set of relative paths (diff / pre-commit modes)."""
    root = os.path.abspath(root)
    cli = PathMatcher(excludes)
    excluded_dirs = set(DEFAULT_EXCLUDED_DIRS)
    if include_vendor:
        excluded_dirs -= {"vendor", "node_modules"}

    def skip(rel: str, is_dir: bool = False) -> bool:
        return ignore.paths.matches(rel, is_dir) or cli.matches(rel, is_dir)

    allowed = _git_files(root) if use_gitignore else None
    if allowed is not None or only is not None:
        candidates = sorted(only if only is not None else allowed)
        for rel in candidates:
            parts = rel.split("/")
            if any(p in excluded_dirs for p in parts[:-1]) or skip(rel):
                continue
            if only is not None and allowed is not None and rel not in allowed:
                continue
            full = os.path.join(root, rel)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            yield SourceFile(full, rel, size)
        return

    fallback = PathMatcher()
    if use_gitignore:
        gi = os.path.join(root, ".gitignore")
        if os.path.isfile(gi):
            with open(gi, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    fallback.add(line)

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir + "/"
        keep = []
        for d in sorted(dirnames):
            rel = rel_dir + d
            if d in excluded_dirs or os.path.islink(os.path.join(dirpath, d)):
                continue
            if skip(rel, True) or fallback.matches(rel, True):
                continue
            keep.append(d)
        dirnames[:] = keep
        for fname in sorted(filenames):
            rel = rel_dir + fname
            full = os.path.join(dirpath, fname)
            if os.path.islink(full) or skip(rel) or fallback.matches(rel):
                continue
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            yield SourceFile(full, rel, size)


def line_index(text: str) -> List[int]:
    """Offsets of each line start, for O(log n) offset -> line lookups."""
    idx = [0]
    pos = text.find("\n")
    while pos != -1:
        idx.append(pos + 1)
        pos = text.find("\n", pos + 1)
    return idx


def locate(index: List[int], offset: int) -> Tuple[int, int]:
    """Return 1-based (line, column) for a character offset."""
    import bisect

    i = bisect.bisect_right(index, offset) - 1
    return i + 1, offset - index[i] + 1
