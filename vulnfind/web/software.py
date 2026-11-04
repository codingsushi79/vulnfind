"""Server-side software fingerprinting -> known CVEs (NVD).

Reads version banners the site already publishes (Server, X-Powered-By, X-AspNet-Version,
<meta name="generator">) and looks each product/version up in NIST's National Vulnerability
Database by CPE. Purely passive: nothing is sent to the target beyond the normal crawl.

Caveat surfaced in every finding: Linux distributions often backport security fixes
without changing the version string (e.g. "Apache/2.4.41 (Ubuntu)"), so a version
match on a distro build is a strong lead, not proof.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from .. import __version__
from ..models import Finding, Severity as S
from ..osv import _cache_dir
from .checks import F

NVD_API = os.environ.get("VULNFIND_NVD_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
CACHE_TTL = 24 * 3600

# banner token (lowercase) -> (display name, [(cpe vendor, cpe product), ...] tried in order)
PRODUCTS: Dict[str, Tuple[str, List[Tuple[str, str]]]] = {
    "apache": ("Apache httpd", [("apache", "http_server")]),
    "nginx": ("nginx", [("f5", "nginx"), ("nginx", "nginx")]),
    "openresty": ("OpenResty", [("openresty", "openresty")]),
    "microsoft-iis": ("Microsoft IIS", [("microsoft", "internet_information_services")]),
    "lighttpd": ("lighttpd", [("lighttpd", "lighttpd")]),
    "litespeed": ("LiteSpeed", [("litespeedtech", "litespeed_web_server")]),
    "openssl": ("OpenSSL", [("openssl", "openssl")]),
    "php": ("PHP", [("php", "php")]),
    "mod_ssl": ("mod_ssl", [("modssl", "mod_ssl")]),
    "jetty": ("Eclipse Jetty", [("eclipse", "jetty")]),
    "apache-coyote": ("Apache Tomcat", [("apache", "tomcat")]),
    "tomcat": ("Apache Tomcat", [("apache", "tomcat")]),
    "caddy": ("Caddy", [("caddyserver", "caddy")]),
    "gunicorn": ("Gunicorn", [("gunicorn", "gunicorn")]),
    "werkzeug": ("Werkzeug", [("palletsprojects", "werkzeug")]),
    "envoy": ("Envoy", [("envoyproxy", "envoy")]),
    "varnish": ("Varnish", [("varnish-software", "varnish_cache"), ("varnish-cache", "varnish")]),
    "squid": ("Squid", [("squid-cache", "squid")]),
    "asp.net": ("ASP.NET", [("microsoft", "asp.net")]),
    "wordpress": ("WordPress", [("wordpress", "wordpress")]),
    "drupal": ("Drupal", [("drupal", "drupal")]),
    "joomla!": ("Joomla!", [("joomla", "joomla\\!")]),
    "joomla": ("Joomla!", [("joomla", "joomla\\!")]),
    "ghost": ("Ghost", [("ghost", "ghost")]),
    "mediawiki": ("MediaWiki", [("mediawiki", "mediawiki")]),
    "typo3": ("TYPO3", [("typo3", "typo3")]),
}

DISTRO = re.compile(r"\((?:Ubuntu|Debian|CentOS|Red Hat|RHEL|Fedora|Amazon|Rocky|AlmaLinux|SUSE|Oracle|Alpine)[^)]*\)|\bel\d\b|\bdeb\d+u\d+", re.I)
TOKEN = re.compile(r"([A-Za-z][A-Za-z0-9_.!\-]*)/(\d+(?:\.\d+){1,3}[a-z]?)")


@dataclass(frozen=True)
class Software:
    key: str  # PRODUCTS key
    version: str
    source: str  # where it was seen, e.g. "Server header"
    banner: str
    distro: bool


def fingerprint(headers, generator: Optional[str] = None) -> List[Software]:
    """Product/version pairs from response headers and the generator meta tag."""
    found: Dict[Tuple[str, str], Software] = {}
    for header in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"):
        value = headers.get(header) if headers is not None else None
        if not value:
            continue
        distro = bool(DISTRO.search(value))
        if header == "X-AspNet-Version":
            m = re.match(r"\s*(\d+(?:\.\d+){1,3})", value)
            if m:
                found.setdefault(("asp.net", m.group(1)), Software("asp.net", m.group(1), header, value, distro))
            continue
        for name, version in TOKEN.findall(value):
            key = name.lower()
            if key in PRODUCTS:
                found.setdefault((key, version), Software(key, version, f"{header} header", value, distro))
    if generator:
        m = re.match(r"\s*([A-Za-z!]+)\s+(\d+(?:\.\d+){1,3})", generator)
        if m and m.group(1).lower() in PRODUCTS:
            key = m.group(1).lower()
            found.setdefault((key, m.group(2)), Software(key, m.group(2), "generator meta tag", generator, False))
    return list(found.values())


# ---------------------------------------------------------------- NVD client

class NVDClient:
    def __init__(self, use_cache: bool = True, timeout: float = 30.0):
        self.use_cache = use_cache
        self.timeout = timeout
        self.api_key = os.environ.get("NVD_API_KEY")
        self._last = 0.0

    def _cache_path(self, cpe: str) -> str:
        return os.path.join(os.path.dirname(_cache_dir()), "nvd", re.sub(r"[^A-Za-z0-9._-]", "_", cpe) + ".json")

    def cves_for(self, cpe: str) -> Optional[List[dict]]:
        """All CVE records whose applicability includes this exact CPE (version ranges are evaluated by NVD)."""
        path = self._cache_path(cpe)
        if self.use_cache and os.path.isfile(path) and time.time() - os.path.getmtime(path) < CACHE_TTL:
            try:
                with open(path, encoding="utf-8") as fh:
                    return json.load(fh)
            except (OSError, ValueError):
                pass
        out: List[dict] = []
        start = 0
        while True:
            data = self._get({"cpeName": cpe, "resultsPerPage": 2000, "startIndex": start})
            if data is None:
                return None
            out += [v["cve"] for v in data.get("vulnerabilities", [])]
            start += data.get("resultsPerPage", 0) or 2000
            if start >= data.get("totalResults", 0):
                break
        if self.use_cache:
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(out, fh)
            except OSError:
                pass
        return out

    def _get(self, params: dict) -> Optional[dict]:
        url = NVD_API + "?" + urllib.parse.urlencode(params)
        headers = {"User-Agent": f"vulnfind/{__version__}"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        # Public limit: 5 requests / 30 s without a key, 50 with one.
        gap = 0.7 if self.api_key else 6.5
        for attempt in range(4):
            wait = self._last + gap - time.monotonic()
            if wait > 0 and self._last:
                time.sleep(wait)
            self._last = time.monotonic()
            try:
                with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    return {"vulnerabilities": [], "totalResults": 0}
                if e.code in (403, 429, 503):
                    time.sleep(6 * (attempt + 1))
                    continue
                return None
            except (urllib.error.URLError, OSError, ValueError):
                time.sleep(2)
        return None


def _cvss(cve: dict) -> Tuple[Optional[float], Optional[str]]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key) or []:
            data = m.get("cvssData") or {}
            if data.get("baseScore") is not None:
                return float(data["baseScore"]), data.get("vectorString")
    return None, None


def _summary(cve: dict) -> str:
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    return re.sub(r"\s+", " ", desc).strip()


def software_findings(found: Iterable[Software], url: str, use_cache: bool, warnings: List[str], offline: bool = False) -> List[Finding]:
    out: List[Finding] = []
    client = NVDClient(use_cache=use_cache)
    for sw in found:
        name, cpes = PRODUCTS[sw.key]
        if offline:
            out.append(F("WEB-SERVER-SOFTWARE", f"Server software: {name} {sw.version}", S.INFO, url,
                         f"Detected from the {sw.source} (offline mode: not checked for CVEs).", "Re-run without --offline.",
                         snippet=sw.banner, product=name, version=sw.version))
            continue
        cves = None
        cpe_used = None
        for vendor, product in cpes:
            cpe = f"cpe:2.3:a:{vendor}:{product}:{sw.version}:*:*:*:*:*:*:*"
            result = client.cves_for(cpe)
            if result is None:
                warnings.append(f"NVD lookup failed for {name} {sw.version} (rate-limited or offline); set NVD_API_KEY for higher limits.")
                break
            if result:
                cves, cpe_used = result, cpe
                break
        if not cves:
            continue
        rated = []
        for c in cves:
            if c.get("vulnStatus") in ("Rejected",):
                continue
            score, vector = _cvss(c)
            rated.append((score or 0.0, c, vector))
        if not rated:
            continue
        rated.sort(key=lambda x: (-(1 if x[1].get("cisaExploitAdd") else 0), -x[0]))
        exploited = [c for _, c, _ in rated if c.get("cisaExploitAdd")]
        top_score = max(s for s, _, _ in rated)
        sev = S.from_score(top_score) if top_score else S.MEDIUM
        if exploited:
            sev = S.CRITICAL
        ids = [c["id"] for _, c, _ in rated]
        lines = []
        for score, c, _ in rated[:6]:
            kev = " [actively exploited]" if c.get("cisaExploitAdd") else ""
            lines.append(f"{c['id']} (CVSS {score:g}){kev}: {_summary(c)[:140]}")
        backport = (" The banner shows a distribution build, which may include backported fixes - confirm with your package manager "
                    "(e.g. `apt changelog`, `rpm -q --changelog`).") if sw.distro else ""
        kev_note = (f" {len(exploited)} of them {'is' if len(exploited) == 1 else 'are'} on CISA's Known Exploited "
                    "Vulnerabilities list.") if exploited else ""
        out.append(F(
            "WEB-OUTDATED-SOFTWARE",
            f"{name} {sw.version}: {len(rated)} known CVE{'s' if len(rated) != 1 else ''}"
            + (f", incl. {exploited[0]['id']} (exploited in the wild)" if exploited else ""),
            sev, url,
            f"The {sw.source} advertises {name} {sw.version}. NVD lists {len(rated)} vulnerabilities affecting this version.{kev_note}"
            f"{backport} Most severe: " + " | ".join(lines),
            f"Upgrade {name} to the latest release in a supported branch, then hide the version banner.",
            "CWE-1104", snippet=sw.banner,
            refs=[f"https://nvd.nist.gov/vuln/detail/{i}" for i in ids[:3]],
            product=name, version=sw.version, cpe=cpe_used, aliases=ids, cvss=top_score or None,
            confidence="medium" if sw.distro else "high",
            **({"kev": {"cve": exploited[0]["id"], "date_added": exploited[0].get("cisaExploitAdd"),
                        "name": exploited[0].get("cisaVulnerabilityName"), "ransomware": False}} if exploited else {}),
        ))
    return out
