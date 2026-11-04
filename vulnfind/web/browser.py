"""Optional headless-browser rendering for single-page apps (uses Playwright if installed).

Static crawling can't see links that JavaScript renders. With --browser, pages are loaded in
headless Chromium; links in the rendered DOM and the API endpoints the front-end calls (XHR /
fetch) are fed back into the scan. Playwright is an optional dependency:
    pip install playwright && python -m playwright install chromium
"""

from __future__ import annotations

import urllib.parse
from typing import Dict, List, Sequence, Set, Tuple


class BrowserUnavailable(ValueError):
    pass


def available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
        return True
    except ImportError:
        return False


def render(urls: Sequence[str], origin: str, timeout_ms: int = 15000, headers: Dict[str, str] = None,
           cookies: Dict[str, str] = None) -> Tuple[Set[str], Set[str], Set[str]]:
    """(rendered same-origin links, script URLs, API endpoints called by the page)."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise BrowserUnavailable("--browser needs Playwright: `pip install playwright && python -m playwright install chromium`")
    links: Set[str] = set()
    scripts: Set[str] = set()
    api: Set[str] = set()
    host = urllib.parse.urlsplit(origin).hostname
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            ctx = browser.new_context(extra_http_headers={k: v for k, v in (headers or {}).items() if k.lower() != "cookie"},
                                      ignore_https_errors=True)
            if cookies:
                ctx.add_cookies([{"name": k, "value": v, "domain": host, "path": "/"} for k, v in cookies.items()])
            page = ctx.new_page()

            def on_request(req):
                if req.resource_type in ("xhr", "fetch") and urllib.parse.urlsplit(req.url).hostname == host:
                    api.add(req.method + " " + req.url.split("#")[0])
            page.on("request", on_request)
            for url in urls:
                try:
                    page.goto(url, wait_until="networkidle", timeout=timeout_ms)
                except Exception:
                    continue
                for href in page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)"):
                    if urllib.parse.urlsplit(href).hostname == host:
                        links.add(href.split("#")[0])
                for src in page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)"):
                    scripts.add(src)
        finally:
            browser.close()
    return links, scripts, api
