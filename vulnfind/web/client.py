"""Small, polite HTTP client for website scanning (stdlib only).

- never follows redirects implicitly (checks need to see them)
- rate limited and capped in total requests
- bodies are read up to a size limit
- TLS failures are recorded once, then the scan continues unverified so
  the rest of the site can still be checked
"""

from __future__ import annotations

import http.client
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from email.message import Message
from typing import Dict, List, Optional

from .. import __version__

MAX_BODY = 1024 * 1024


@dataclass
class Response:
    url: str
    status: int
    headers: Message
    body: bytes = b""
    elapsed: float = 0.0
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status < 300

    def header(self, name: str, default: str = "") -> str:
        v = self.headers.get(name) if self.headers is not None else None
        return v if v is not None else default

    def header_all(self, name: str) -> List[str]:
        return self.headers.get_all(name) or [] if self.headers is not None else []

    @property
    def content_type(self) -> str:
        return self.header("Content-Type").split(";")[0].strip().lower()

    @property
    def is_html(self) -> bool:
        ct = self.content_type
        return ct in ("text/html", "application/xhtml+xml") or (not ct and self.text[:200].lstrip().lower().startswith(("<!doctype html", "<html")))

    @property
    def text(self) -> str:
        if not hasattr(self, "_text"):
            self._text = self.body.decode("utf-8", "replace")
        return self._text


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class BudgetExceeded(RuntimeError):
    pass


@dataclass
class Client:
    rate: float = 8.0  # requests per second
    timeout: float = 15.0
    max_requests: int = 600
    headers: Dict[str, str] = field(default_factory=dict)
    verify_tls: bool = True
    requests_made: int = 0
    tls_error: Optional[str] = None
    use_jar: bool = False  # keep cookies the site sets (enabled after a login)
    cookies: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        self._next_slot = 0.0
        self._ctx_verified = ssl.create_default_context()
        # vulnfind:ignore PY-TLS-VERIFY-OFF - deliberately inspecting untrusted/legacy TLS; never used to send secrets
        self._ctx_unverified = ssl._create_unverified_context()

    def _remember(self, headers) -> None:
        if not self.use_jar:
            return
        for k, v in _cookie_pairs(headers).items():
            if v is None:
                self.cookies.pop(k, None)
            else:
                self.cookies[k] = v

    def _wait_turn(self) -> None:
        with self._lock:
            if self.requests_made >= self.max_requests:
                raise BudgetExceeded(f"request budget of {self.max_requests} reached")
            self.requests_made += 1
            now = time.monotonic()
            slot = max(now, self._next_slot)
            self._next_slot = slot + 1.0 / max(self.rate, 0.1)
        delay = slot - time.monotonic()
        if delay > 0:
            time.sleep(delay)

    def request(self, url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None,
                data: Optional[bytes] = None, max_body: int = MAX_BODY) -> Response:
        self._wait_turn()
        hdrs = {"User-Agent": f"vulnfind/{__version__} (security scanner)", "Accept": "*/*"}
        hdrs.update(self.headers)
        if self.use_jar and self.cookies:
            jar = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            hdrs["Cookie"] = (hdrs["Cookie"] + "; " + jar) if hdrs.get("Cookie") else jar
        hdrs.update(headers or {})
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        insecure = not self.verify_tls or self.tls_error is not None
        ctx = self._ctx_unverified if insecure else self._ctx_verified
        opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))
        start = time.monotonic()
        try:
            with opener.open(req, timeout=self.timeout) as resp:
                body = resp.read(max_body) if method != "HEAD" else b""
                self._remember(resp.headers)
                return Response(resp.geturl(), resp.status, resp.headers, body, time.monotonic() - start)
        except urllib.error.HTTPError as e:  # 3xx/4xx/5xx still carry useful headers & bodies
            try:
                body = e.read(max_body) if method != "HEAD" else b""
            except (OSError, http.client.HTTPException):
                body = b""
            finally:
                e.close()
            self._remember(e.headers)
            return Response(url, e.code, e.headers, body, time.monotonic() - start)
        except urllib.error.URLError as e:
            reason = e.reason
            if isinstance(reason, ssl.SSLCertVerificationError) and not insecure:
                self.tls_error = getattr(reason, "verify_message", None) or str(reason)
                with self._lock:
                    self.requests_made -= 1  # retry doesn't count twice
                return self.request(url, method, headers, data, max_body)
            return Response(url, 0, Message(), b"", time.monotonic() - start, error=str(reason))
        except (socket.timeout, TimeoutError):
            return Response(url, 0, Message(), b"", time.monotonic() - start, error="timeout")
        except (OSError, http.client.HTTPException, ValueError) as e:
            return Response(url, 0, Message(), b"", time.monotonic() - start, error=f"{e.__class__.__name__}: {e}")


def _cookie_pairs(headers) -> Dict[str, Optional[str]]:
    out: Dict[str, Optional[str]] = {}
    for raw in (headers.get_all("Set-Cookie") or []) if headers is not None else []:
        name, _, rest = raw.partition("=")
        value = rest.split(";", 1)[0]
        expired = re.search(r"(?i);\s*(?:max-age=0|expires=thu, 01 jan 1970)", raw)
        out[name.strip()] = None if expired or value == "" else value
    return out


def origin(url: str) -> str:
    p = urllib.parse.urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def same_origin(a: str, b: str) -> bool:
    return origin(a).lower() == origin(b).lower()


def normalize(url: str) -> str:
    """Drop fragments; keep query (it matters for active checks)."""
    p = urllib.parse.urlsplit(url)
    path = p.path or "/"
    return urllib.parse.urlunsplit((p.scheme.lower(), p.netloc.lower(), path, p.query, ""))
