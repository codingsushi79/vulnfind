"""Client-side JavaScript analysis: library fingerprinting (-> OSV CVEs), secrets in
served JS/HTML, and publicly accessible source maps."""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from .. import osv
from ..models import Finding, Package, Severity as S
from ..scanners import run_rules
from ..scanners.secrets import SECRET_RULES, _secret_snippet
from ..walker import SourceFile
from .checks import F
from .client import Client, Response, same_origin

V = r"(\d+\.\d+\.\d+(?:-(?!min\b|slim\b)[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?)"  # 3.5.0, 3.0.0-rc.1 (not ".min")

# (npm package, content regex) - banners that survive minification
CONTENT_SIGNATURES: List[Tuple[str, "re.Pattern[str]"]] = [(n, re.compile(p)) for n, p in [
    ("jquery", r"/\*!? *jQuery v" + V + r"|jQuery JavaScript Library v" + V),
    ("jquery-ui", r"jQuery UI - v" + V),
    ("jquery-validation", r"jQuery Validation Plugin (?:- )?v" + V),
    ("angular", r"AngularJS v" + V),
    ("bootstrap", r"Bootstrap v" + V + r" \("),
    ("lodash", r"(?s)\blodash\b.{0,600}?\bVERSION\s*=\s*['\"]" + V),
    ("underscore", r"Underscore\.js " + V),
    ("moment", r"(?s)//! moment\.js.{0,40}?//! version : " + V + r"|moment\.version\s*=\s*['\"]" + V),
    ("vue", r"Vue\.js v" + V),
    ("react", r"@license React v" + V + r"|react\.production\.min\.js[^\n]{0,40}v" + V),
    ("handlebars", r"handlebars v" + V),
    ("dompurify", r"DOMPurify " + V),
    ("axios", r"axios v" + V + r"|axios@" + V),
    ("knockout", r"Knockout JavaScript library v" + V),
    ("tinymce", r"TinyMCE version " + V),
    ("highlight.js", r"Highlight\.js v" + V),
    ("chart.js", r"Chart\.js v" + V),
    ("select2", r"Select2 " + V),
    ("video.js", r"Video\.js " + V),
    ("ckeditor4", r"CKEDITOR\.version\s*=\s*['\"]" + V),
    ("next", r"\"next\"\s*:\s*\{\s*\"version\"\s*:\s*\"" + V),
]]

CDNJS_NAMES = {"jquery": "jquery", "lodash.js": "lodash", "angular.js": "angular", "moment.js": "moment",
               "twitter-bootstrap": "bootstrap", "bootstrap": "bootstrap", "vue": "vue", "react": "react", "jqueryui": "jquery-ui",
               "underscore.js": "underscore", "handlebars.js": "handlebars", "dompurify": "dompurify", "axios": "axios",
               "Chart.js": "chart.js", "highlight.js": "highlight.js", "select2": "select2", "knockout": "knockout",
               "tinymce": "tinymce", "video.js": "video.js", "jquery-validate": "jquery-validation"}

URL_SIGNATURES = [
    re.compile(r"(?:cdn\.jsdelivr\.net/npm|unpkg\.com)/((?:@[\w.\-]+/)?[\w.\-]+)@" + V + r"/"),
    re.compile(r"cdnjs\.cloudflare\.com/ajax/libs/([\w.\-]+)/" + V + r"/"),
    re.compile(r"code\.jquery\.com/(jquery)-" + V + r"(?:\.min|\.slim|\.slim\.min)?\.js"),
    re.compile(r"code\.jquery\.com/ui/" + V + r"/"),
    re.compile(r"ajax\.googleapis\.com/ajax/libs/([\w.\-]+)/" + V + r"/"),
    re.compile(r"/(jquery|bootstrap|angular|lodash|moment|vue|react|handlebars|underscore|knockout)[.\-]" + V + r"(?:\.min)?\.js"),
]


@dataclass
class Detected:
    name: str
    version: str
    where: str  # URL of the script or page
    how: str


def detect_from_url(src: str) -> Optional[Tuple[str, str]]:
    for i, rxp in enumerate(URL_SIGNATURES):
        m = rxp.search(src)
        if not m:
            continue
        if i == 3:
            return "jquery-ui", m.group(1)
        name, version = m.group(1), m.group(2)
        if "cdnjs" in rxp.pattern or "googleapis" in rxp.pattern:
            name = CDNJS_NAMES.get(name, CDNJS_NAMES.get(name.lower(), name.lower()))
            if name == "angularjs":
                name = "angular"
        return name, version
    return None


def detect_from_content(text: str) -> List[Tuple[str, str]]:
    found = []
    head = text[:3_000_000]
    for name, rxp in CONTENT_SIGNATURES:
        m = rxp.search(head)
        if m:
            version = next((g for g in m.groups() if g), None)
            if version:
                found.append((name, version))
    return found


def library_findings(detected: Sequence[Detected], offline: bool, use_cache: bool, warnings: List[str]) -> List[Finding]:
    unique: Dict[Tuple[str, str], Detected] = {}
    for d in detected:
        unique.setdefault((d.name, d.version), d)
    if not unique:
        return []
    out: List[Finding] = []
    if offline:
        for d in unique.values():
            out.append(F("WEB-JS-LIBRARY", f"JavaScript library: {d.name} {d.version}", S.INFO, d.where,
                         "Detected (offline mode: not checked for known vulnerabilities).", "Re-run without --offline to check for CVEs.",
                         snippet=f"{d.name}@{d.version} ({d.how})", package=d.name, version=d.version))
        return out
    pkgs = [Package(d.name, d.version, "npm", d.where) for d in unique.values()]
    try:
        results = osv.OSVClient(use_cache=use_cache).query(pkgs)
    except osv.OSVError as e:
        warnings.append(f"JS library CVE lookup failed: {e}")
        return []
    for pkg in pkgs:
        d = unique[(pkg.name, pkg.version)]
        vulns = osv.dedupe(results.get(("npm", pkg.name, pkg.version), []))
        if not vulns:
            continue
        rated = sorted(((osv.severity_of(v), v) for v in vulns), key=lambda x: -x[0][0])
        sev = rated[0][0][0]
        fixes = [osv.best_fix(v, pkg) for v in vulns]
        target = osv.pick_target(fixes)
        ids = [i for v in vulns for i in osv.aliases(v)]
        top = "; ".join(f"{osv.aliases(v)[0]}: {(v.get('summary') or '').strip()[:80]}" for (_, v) in rated[:4])
        out.append(F("WEB-VULNERABLE-JS-LIBRARY", f"Vulnerable JavaScript library: {pkg.name} {pkg.version} ({len(vulns)} known issue{'s' if len(vulns) != 1 else ''})",
                     sev, d.where, f"The site serves {pkg.name} {pkg.version} to every visitor. Known issues: {top}.",
                     f"Upgrade {pkg.name} to {target} or later." if target else "No fixed release published; consider replacing the library.",
                     "CWE-1395", snippet=f"{pkg.name}@{pkg.version} ({d.how})",
                     refs=[f"https://osv.dev/vulnerability/{osv.aliases(rated[0][1])[0]}"],
                     package=pkg.name, version=pkg.version, ecosystem="npm", fixed=target, aliases=list(dict.fromkeys(ids)),
                     cvss=rated[0][0][1]))
    return out


# Rules that are noise on public front-end code (public-by-design keys, generic matches).
_WEB_SECRET_SKIP = {"SECRET-GENERIC", "SECRET-DOTENV", "SECRET-JWT", "SECRET-STRIPE-TEST", "SECRET-NPMRC-AUTH"}
WEB_SECRET_RULES = [r for r in SECRET_RULES if r.id not in _WEB_SECRET_SKIP]


def secret_findings(url: str, text: str) -> List[Finding]:
    f = SourceFile(path=url, rel=url, size=len(text))
    f._text, f._binary = text, False
    out = []
    seen = set()
    for fnd in run_rules(WEB_SECRET_RULES, f, "web", text, lambda line, m: _secret_snippet(line[max(0, m.start() - 60 - _line_start(text, m.start())):][:200], m)):
        if fnd.rule_id in seen:
            continue
        seen.add(fnd.rule_id)
        fnd.category = "web"
        fnd.title = f"{fnd.title} exposed in client-side code"
        fnd.description = "This value is shipped to every visitor's browser. " + fnd.description
        if fnd.rule_id == "SECRET-GOOGLE-API-KEY":
            fnd.severity = S.LOW
            fnd.description = ("Google API keys in front-end code are normal for Maps/Firebase, but must be restricted by HTTP referrer "
                               "and API, or anyone can use them on your bill.")
            fnd.fix = "In Google Cloud Console, restrict the key to your domains and to only the APIs it needs."
        out.append(fnd)
    return out


def _line_start(text: str, pos: int) -> int:
    return pos - (text.rfind("\n", 0, pos) + 1)


SOURCEMAP = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"]+\.map)\s*$", re.M)


def analyse_scripts(client: Client, start: str, script_urls: Sequence[str], pages_html: Sequence[Tuple[str, str]],
                    max_scripts: int = 25, on_done=None) -> Tuple[List[Detected], List[Finding]]:
    detected: List[Detected] = []
    findings: List[Finding] = []
    maps: List[str] = []
    for url in script_urls:
        hit = detect_from_url(url)
        if hit:
            detected.append(Detected(hit[0], hit[1], url, "script URL"))
    for page_url, html in pages_html:
        for name, version in detect_from_content(html):
            detected.append(Detected(name, version, page_url, "inline script"))
        findings += secret_findings(page_url, html)
    own = [u for u in script_urls if same_origin(u, start)][:max_scripts]
    for url in own:
        r: Response = client.request(url, max_body=4 * 1024 * 1024)
        if on_done:
            on_done(url.rsplit("/", 1)[-1][:40])
        if r.status != 200 or not r.body:
            continue
        text = r.text
        for name, version in detect_from_content(text):
            detected.append(Detected(name, version, url, "banner in bundle"))
        findings += secret_findings(url, text)
        m = SOURCEMAP.search(text[-2000:])
        if m and not m.group(1).startswith("data:"):
            maps.append(urllib.parse.urljoin(url, m.group(1)))
    exposed = []
    for mp in maps[:5]:
        r = client.request(mp, headers={"Range": "bytes=0-2047"}, max_body=2048)
        if r.status in (200, 206) and ('"mappings"' in r.text or '"sources"' in r.text):
            exposed.append(mp)
    if exposed:
        findings.append(F("WEB-SOURCEMAP-EXPOSED", "JavaScript source maps are public", S.MEDIUM, exposed[0],
                          "Source maps let anyone reconstruct your original front-end source code, comments and internal API paths.",
                          "Don't deploy .map files publicly (or restrict them to your error-tracking service).", "CWE-540",
                          snippet=", ".join(u.rsplit("/", 1)[-1] for u in exposed)))
    return detected, findings
