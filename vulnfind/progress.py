"""Live progress display on stderr: animated spinner, progress bars and per-stage timings.

Renders only when stderr is an interactive terminal, so CI logs, pipes and
`-f json` output stay clean. Every method is a no-op when disabled.
"""

from __future__ import annotations

import os
import shutil
import sys
import threading
import time
from typing import Optional, TextIO

FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


class Progress:
    def __init__(self, enabled: bool = True, stream: Optional[TextIO] = None, color: bool = True):
        self.stream = stream or sys.stderr
        self.enabled = enabled and hasattr(self.stream, "isatty") and self.stream.isatty() \
            and os.environ.get("TERM") != "dumb" and not os.environ.get("CI")
        self.color = color and not os.environ.get("NO_COLOR")
        self._lock = threading.Lock()
        self._label = ""
        self._detail = ""
        self._total: Optional[int] = None
        self._done = 0
        self._stage_start = 0.0
        self._active = False
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._frame = 0

    # -- styling -------------------------------------------------------------
    def _c(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color else text

    # -- public API ----------------------------------------------------------
    def stage(self, label: str, total: Optional[int] = None, detail: str = "") -> "Progress":
        """Start a new stage (finishing the current one silently if still open)."""
        if not self.enabled:
            return self
        with self._lock:
            self._label, self._total, self._done, self._detail = label, total, 0, detail
            self._stage_start = time.time()
            self._active = True
        self._ensure_thread()
        return self

    def advance(self, n: int = 1, detail: Optional[str] = None) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._done += n
            if detail is not None:
                self._detail = detail

    def set_total(self, total: Optional[int]) -> None:
        if self.enabled:
            with self._lock:
                self._total = total

    def detail(self, text: str) -> None:
        if self.enabled:
            with self._lock:
                self._detail = text

    def done(self, summary: str = "", ok: bool = True) -> None:
        """Finish the current stage and leave a ✔ line with its timing."""
        if not self.enabled:
            return
        with self._lock:
            if not self._active:
                return
            elapsed = time.time() - self._stage_start
            self._active = False
            mark = self._c("✔", "32") if ok else self._c("!", "33")
            text = summary or self._label
            self._write_line(f"  {mark} {text} {self._c(f'{elapsed:.1f}s', '90')}")

    def log(self, message: str) -> None:
        """Print a permanent line above the spinner."""
        if not self.enabled:
            return
        with self._lock:
            self._write_line(f"  {message}")

    def close(self) -> None:
        if not self.enabled:
            return
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
        with self._lock:
            self.stream.write("\r\033[2K")
            self.stream.flush()

    def __enter__(self) -> "Progress":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- rendering -----------------------------------------------------------
    def _ensure_thread(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, name="vulnfind-progress", daemon=True)
            self._thread.start()

    def _run(self) -> None:
        while not self._stop.wait(0.08):
            with self._lock:
                if self._active:
                    self._render()

    def _write_line(self, text: str) -> None:
        self.stream.write("\r\033[2K" + text + "\n")
        if self._active:
            self._render()
        else:
            self.stream.flush()

    def _render(self) -> None:
        width = shutil.get_terminal_size((100, 20)).columns
        self._frame = (self._frame + 1) % len(FRAMES)
        spin = self._c(FRAMES[self._frame], "36")
        elapsed = time.time() - self._stage_start
        parts = [f"  {spin} {self._label}"]
        if self._total:
            frac = min(self._done / self._total, 1.0)
            bar_w = 24
            filled = int(frac * bar_w)
            bar = self._c("█" * filled, "36") + self._c("░" * (bar_w - filled), "90")
            parts.append(f" {bar} {self._done}/{self._total}")
            if self._done and frac < 1 and elapsed > 2:
                eta = elapsed / frac - elapsed
                parts.append(self._c(f" ~{eta:.0f}s left", "90"))
        else:
            parts.append(self._c(f" {elapsed:.1f}s", "90"))
        line = "".join(parts)
        visible = len(_strip(line))
        if self._detail and visible + 4 < width:
            room = width - visible - 3
            d = self._detail if len(self._detail) <= room else "…" + self._detail[-(room - 1):]
            line += self._c("  " + d, "90")
        self.stream.write("\r\033[2K" + line)
        self.stream.flush()


def _strip(s: str) -> str:
    import re
    return re.sub(r"\033\[[0-9;]*m", "", s)


NULL = Progress(enabled=False)
