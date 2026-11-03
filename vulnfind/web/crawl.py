"""HTML parsing and a bounded same-origin crawler."""

from __future__ import annotations

import re
import urllib.parse
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Callable, Dict, List, Optional, Tuple

from .client import Client, Response, normalize, same_origin

# Never follow links that could change state, even with GET.
DANGEROUS_LINK = re.compile(r"(?i)log_?out|sign_?out|delete|remove|destroy|unsubscribe|deactivate|reset|/revoke|cancel")
SKIP_EXT = re.compile(r"(?i)\.(?:png|jpe?g|gif|webp|avif|svg|ico|bmp|pdf|zip|gz|tgz|rar|7z|mp[34]|mov|avi|webm|woff2?|ttf|eot|css|xml|txt|json|map|exe|dmg|apk)$")


@dataclass
class Form:
    action: str
    method: str
    inputs: List[Tuple[str, str]]  # (name, type)


@dataclass
class Page:
    url: str
    response: Response
    links: List[str] = field(default_factory=list)
    scripts: List[Tuple[Optional[str], Dict[str, str]]] = field(default_factory=list)  # (src or None for inline, attrs)
    inline_scripts: List[str] = field(default_factory=list)
    stylesheets: List[str] = field(default_factory=list)
    iframes: List[str] = field(default_factory=list)
    images: List[str] = field(default_factory=list)
    forms: List[Form] = field(default_factory=list)
    meta: Dict[str, str] = field(default_factory=dict)
    comments: List[str] = field(default_factory=list)


class _Parser(HTMLParser):
    def __init__(self, base: str):
        super().__init__(convert_charrefs=True)
        self.base = base
        self.page_links: List[str] = []
        self.scripts: List[Tuple[Optional[str], Dict[str, str]]] = []
        self.inline: List[str] = []
        self.styles: List[str] = []
        self.iframes: List[str] = []
        self.images: List[str] = []
        self.forms: List[Form] = []
        self.meta: Dict[str, str] = {}
        self.comments: List[str] = []
        self._in_script = False
        self._script_buf: List[str] = []
        self._form: Optional[Form] = None

    def _abs(self, u: str) -> str:
        return urllib.parse.urljoin(self.base, u.strip())

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "base" and a.get("href"):
            self.base = self._abs(a["href"])
        elif tag == "a" and a.get("href") and not a["href"].startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
            self.page_links.append(self._abs(a["href"]))
        elif tag == "script":
            if a.get("src"):
                self.scripts.append((self._abs(a["src"]), a))
            else:
                self._in_script = True
                self._script_buf = []
        elif tag == "link" and "stylesheet" in a.get("rel", "").lower() and a.get("href"):
            self.styles.append(self._abs(a["href"]))
        elif tag in ("iframe", "frame") and a.get("src"):
            self.iframes.append(self._abs(a["src"]))
        elif tag in ("img", "audio", "video", "source") and a.get("src"):
            self.images.append(self._abs(a["src"]))
        elif tag == "form":
            self._form = Form(self._abs(a.get("action") or self.base), (a.get("method") or "get").lower(), [])
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None:
            self._form.inputs.append((a.get("name", ""), (a.get("type") or ("text" if tag != "input" else "text")).lower()))
        elif tag == "meta" and a.get("name"):
            self.meta[a["name"].lower()] = a.get("content", "")

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script:
            self._in_script = False
            self.inline.append("".join(self._script_buf))
        elif tag == "form":
            self._form = None

    def handle_data(self, data):
        if self._in_script:
            self._script_buf.append(data)

    def handle_comment(self, data):
        if data.strip():
            self.comments.append(data.strip())


def parse(resp: Response) -> Page:
    p = _Parser(resp.url)
    try:
        p.feed(resp.text)
        p.close()
    except Exception:  # broken markup: keep whatever was parsed
        pass
    return Page(resp.url, resp, p.page_links, p.scripts, p.inline, p.styles, p.iframes, p.images, p.forms, p.meta, p.comments)


def crawl(client: Client, start: str, max_pages: int, on_page: Optional[Callable[[Page], None]] = None,
          extra_seeds: List[str] = ()) -> Tuple[List[Page], Dict[str, Response]]:
    """BFS over same-origin HTML pages. Returns pages and every fetched response by URL."""
    seen = {normalize(start)}
    queue = deque([start] + [s for s in extra_seeds if same_origin(s, start)])
    for s in extra_seeds:
        seen.add(normalize(s))
    pages: List[Page] = []
    fetched: Dict[str, Response] = {}
    while queue and len(pages) < max_pages:
        url = queue.popleft()
        resp = client.request(url, headers={"Accept": "text/html,application/xhtml+xml,*/*;q=0.8"})
        fetched[normalize(url)] = resp
        # follow same-origin redirects as new pages
        if 300 <= resp.status < 400 and resp.header("Location"):
            nxt = urllib.parse.urljoin(url, resp.header("Location"))
            if same_origin(nxt, start) and normalize(nxt) not in seen:
                seen.add(normalize(nxt))
                queue.appendleft(nxt)
            continue
        if resp.error or not resp.is_html:
            continue
        page = parse(resp)
        pages.append(page)
        if on_page:
            on_page(page)
        for link in page.links + [f.action for f in page.forms if f.method == "get"]:
            n = normalize(link)
            if n in seen or not same_origin(link, start) or SKIP_EXT.search(urllib.parse.urlsplit(link).path) \
                    or DANGEROUS_LINK.search(link):
                continue
            # don't explode on endless query permutations: at most 3 variants per path
            path = urllib.parse.urlsplit(n).path
            if sum(1 for s in seen if urllib.parse.urlsplit(s).path == path) >= 3:
                continue
            seen.add(n)
            queue.append(link)
    return pages, fetched
