"""`vulnfind ai`: project-specific explanations and fix patches from Claude (optional).

Requires the official SDK (`pip install "vulnfind[ai]"`, i.e. `anthropic`) and credentials
(ANTHROPIC_API_KEY or an `ant auth login` profile). Sends each selected finding plus the
surrounding source lines to the Claude API - nothing is sent unless you run this command.
"""

from __future__ import annotations

import json
import os
from typing import Dict, Iterator, List, Optional, Tuple

from .models import Finding

MODEL = "claude-opus-5-5"
CONTEXT_LINES = 30

SYSTEM = """You are a senior application security engineer reviewing findings from an automated scanner (vulnfind) \
in the user's own codebase. For each finding you get the scanner's output and the relevant source code.

Answer in Markdown with exactly these sections:
## Verdict
One line: "Real issue", "Likely real", "Probably a false positive" or "Can't tell from this context", then one sentence why.
## What could happen
2-4 sentences, concrete to this code: who could do what, and what the impact is.
## Fix
The smallest correct change, as a unified diff against the file shown (use the real file path and line numbers). \
Keep the project's style; don't refactor unrelated code. If dependencies need upgrading, give the exact command instead.
## Check
One or two ways to confirm the fix (a test case, a request to try, a command to run).

If the code shown isn't enough to decide, say what else you would need to see instead of guessing."""


class AIUnavailable(RuntimeError):
    pass


def check_available() -> None:
    try:
        import anthropic  # noqa: F401
    except ImportError:
        raise AIUnavailable("`vulnfind ai` needs the Anthropic SDK: pip install \"vulnfind[ai]\" (or pip install anthropic)")


def _client():
    try:
        import anthropic
    except ImportError:
        raise AIUnavailable("`vulnfind ai` needs the Anthropic SDK: pip install \"vulnfind[ai]\" (or pip install anthropic)")
    return anthropic, anthropic.Anthropic()


def _context(root: str, rel: str, line: Optional[int]) -> Optional[str]:
    path = os.path.join(root, rel)
    if not line or not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return None
    lo, hi = max(1, line - CONTEXT_LINES), min(len(lines), line + CONTEXT_LINES)
    return "\n".join(f"{n:>5}{'>' if n == line else ' '} {lines[n - 1]}" for n in range(lo, hi + 1))


def build_prompt(f: Finding, root: str) -> str:
    finding = {k: v for k, v in f.to_dict().items() if k not in ("fingerprint",) and v not in (None, "", [], {})}
    parts = [f"Scanner finding:\n```json\n{json.dumps(finding, indent=2, default=str)}\n```"]
    seen = set()
    files: List[Tuple[str, Optional[int]]] = [(f.file, f.line)]
    for step in f.extra.get("flow") or []:  # cross-file flows: "app/db.py:4: …"
        head = step.split(": ", 1)[0]
        if ".py:" in head or ".js:" in head or ".go:" in head or ".php:" in head:
            path, _, ln = head.rpartition(":")
            if ln.isdigit():
                files.append((path, int(ln)))
    for rel, line in files:
        if (rel, line) in seen:
            continue
        seen.add((rel, line))
        ctx = _context(root, rel, line)
        if ctx:
            parts.append(f"Source of {rel} around line {line} ('>' marks the line):\n```\n{ctx}\n```")
    return "\n\n".join(parts)


def explain(findings: List[Finding], root: str, model: str = MODEL, effort: str = "high") -> Iterator[Tuple[Finding, str]]:
    anthropic, client = _client()
    for f in findings:
        try:
            # Security-analysis prompts can trip safety classifiers on benign code; the server-side
            # "default" fallback re-runs a declined request on Anthropic's recommended fallback model.
            with client.beta.messages.stream(
                model=model,
                max_tokens=16000,
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
                thinking={"type": "adaptive"},
                output_config={"effort": effort},
                system=SYSTEM,
                messages=[{"role": "user", "content": build_prompt(f, root)}],
            ) as stream:
                message = stream.get_final_message()
        except anthropic.AuthenticationError:
            raise AIUnavailable("no valid Anthropic credentials: set ANTHROPIC_API_KEY or run `ant auth login`")
        except anthropic.PermissionDeniedError as e:
            raise AIUnavailable(f"API key lacks permission: {e.message}")
        except anthropic.RateLimitError:
            yield f, "_Rate limited by the Claude API - try again shortly or with fewer findings (--top)._"
            continue
        except anthropic.APIStatusError as e:
            yield f, f"_Claude API error {e.status_code}: {e.message}_"
            continue
        except anthropic.APIConnectionError:
            raise AIUnavailable("could not reach the Claude API (network error)")
        if message.stop_reason == "refusal":
            yield f, "_The model declined to analyse this finding._"
            continue
        text = "".join(b.text for b in message.content if b.type == "text").strip()
        if message.stop_reason == "max_tokens":
            text += "\n\n_(answer truncated at the output limit)_"
        yield f, text or "_(empty response)_"
