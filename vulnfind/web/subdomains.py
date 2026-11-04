"""Subdomain discovery (certificate transparency) and subdomain-takeover detection.

`vulnfind subdomains example.com` - for domains you own. Finds every hostname that ever had a
public TLS certificate (crt.sh, CertSpotter fallback), resolves it via DNS-over-HTTPS and flags:
- dangling CNAMEs that point at a deprovisioned cloud resource someone else could claim
  (GitHub Pages, Heroku, S3, Azure, Shopify, Fastly, Vercel, Netlify, …)
- forgotten staging/dev/test hosts that are still publicly reachable
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Set, Tuple

from .. import __version__
from ..models import Finding, Severity as S
from . import dns
from .checks import F
from .client import Client

# (CNAME suffix regex, service, body fingerprint of an unclaimed resource or None = NXDOMAIN target is enough)
TAKEOVER = [
    (r"\.github\.io$", "GitHub Pages", r"There isn't a GitHub Pages site here"),
    (r"\.herokuapp\.com$|\.herokudns\.com$", "Heroku", r"No such app|herokucdn\.com/error-pages/no-such-app"),
    (r"\.s3[.-](?:[\w-]+\.)?amazonaws\.com$|\.s3-website[.-]", "AWS S3", r"NoSuchBucket|The specified bucket does not exist"),
    (r"\.cloudfront\.net$", "AWS CloudFront", r"The request could not be satisfied.*?Bad request|ERROR: The request could not be satisfied"),
    (r"\.elasticbeanstalk\.com$", "AWS Elastic Beanstalk", None),
    (r"\.azurewebsites\.net$|\.cloudapp\.net$|\.cloudapp\.azure\.com$|\.trafficmanager\.net$|\.blob\.core\.windows\.net$|\.azureedge\.net$",
     "Microsoft Azure", None),
    (r"\.myshopify\.com$|shops\.myshopify\.com$", "Shopify", r"Sorry, this shop is currently unavailable|Only one step left"),
    (r"\.fastly\.net$", "Fastly", r"Fastly error: unknown domain"),
    (r"\.vercel-dns\.com$|\.vercel\.app$|\.now\.sh$", "Vercel", r"DEPLOYMENT_NOT_FOUND|The deployment could not be found"),
    (r"\.netlify\.app$|\.netlify\.com$", "Netlify", r"Not Found - Request ID"),
    (r"\.ghost\.io$", "Ghost", r"The thing you were looking for is no longer here|Domain error"),
    (r"\.zendesk\.com$", "Zendesk", r"Help Center Closed"),
    (r"\.bitbucket\.io$", "Bitbucket", r"Repository not found"),
    (r"\.readme\.io$", "ReadMe", r"Project doesnt exist"),
    (r"\.surge\.sh$", "Surge", r"project not found"),
    (r"\.pantheonsite\.io$", "Pantheon", r"The gods are wise|404 error unknown site"),
    (r"\.domains\.tumblr\.com$", "Tumblr", r"Whatever you were looking for doesn't currently exist"),
    (r"\.wordpress\.com$", "WordPress.com", r"Do you want to register"),
    (r"\.helpscoutdocs\.com$", "Help Scout", r"No settings were found for this company"),
    (r"\.webflow\.io$|proxy-ssl\.webflow\.com$", "Webflow", r"The page you are looking for doesn't exist or has been moved"),
    (r"\.fly\.dev$", "Fly.io", None),
    (r"\.onrender\.com$", "Render", None),
]
FORGOTTEN = re.compile(r"(?i)^(?:dev|devel|develop|staging|stage|stg|test|testing|qa|uat|preprod|pre-prod|beta|old|legacy|backup|bak|"
                       r"tmp|temp|demo|sandbox|internal|admin|jenkins|grafana|kibana|phpmyadmin|git|gitlab)\d*[.-]")


def _fetch_json(url: str, timeout: float = 45):
    req = urllib.request.Request(url, headers={"User-Agent": f"vulnfind/{__version__}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace") or "[]")


def discover(domain: str, warnings: List[str]) -> Set[str]:
    names: Set[str] = set()
    try:
        for row in _fetch_json(f"https://crt.sh/?q={urllib.parse.quote('%.' + domain)}&output=json"):
            for n in str(row.get("name_value", "")).split("\n"):
                names.add(n.strip().lower())
    except Exception as e:
        warnings.append(f"crt.sh unavailable ({e.__class__.__name__}); trying CertSpotter")
        try:
            for row in _fetch_json(f"https://api.certspotter.com/v1/issuances?domain={urllib.parse.quote(domain)}"
                                   "&include_subdomains=true&expand=dns_names"):
                names.update(n.lower() for n in row.get("dns_names", []))
        except Exception as e2:
            warnings.append(f"CertSpotter unavailable too ({e2.__class__.__name__}); no subdomains discovered")
    clean = {n.lstrip("*.") for n in names if n}
    return {n for n in clean if n == domain or n.endswith("." + domain)}


def _resolve(name: str) -> Tuple[List[str], List[str], bool]:
    """(cname chain, A records, nxdomain)."""
    try:
        url = f"{dns.DOH}?name={urllib.parse.quote(name)}&type=A"
        req = urllib.request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": f"vulnfind/{__version__}"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        return [], [], False
    cnames = [a["data"].rstrip(".").lower() for a in data.get("Answer") or [] if a.get("type") == 5]
    addrs = [a["data"] for a in data.get("Answer") or [] if a.get("type") == 1]
    return cnames, addrs, data.get("Status") == 3


def check_host(name: str, client: Client) -> List[Finding]:
    out: List[Finding] = []
    cnames, addrs, nx = _resolve(name)
    target = cnames[-1] if cnames else None
    if target:
        for pattern, service, fingerprint in TAKEOVER:
            if not re.search(pattern, target):
                continue
            tgt_cn, tgt_addrs, tgt_nx = _resolve(target)
            evidence = None
            if tgt_nx or (not addrs and not tgt_addrs):
                evidence = f"CNAME target {target} does not resolve (NXDOMAIN)"
            elif fingerprint:
                for scheme in ("https", "http"):
                    r = client.request(f"{scheme}://{name}/", headers={"Accept": "text/html"})
                    if r.body and re.search(fingerprint, r.text[:50_000], re.S):
                        evidence = f"{service} serves its 'unclaimed' page for this host"
                        break
            if evidence:
                out.append(F("WEB-SUBDOMAIN-TAKEOVER", f"Subdomain takeover possible: {name} → {service}", S.HIGH if fingerprint else S.MEDIUM,
                             f"dns://{name}",
                             f"{name} points (CNAME) at {target} on {service}, but that resource no longer exists: {evidence}. Anyone can "
                             f"create it on {service} and serve content (phishing, cookie theft) on your domain.",
                             f"Delete the DNS record for {name}, or re-claim the {service} resource.", "CWE-350",
                             snippet=f"{name} CNAME {target}", service=service))
            break
        else:
            if nx:
                out.append(F("WEB-DANGLING-CNAME", f"Dangling CNAME: {name} → {target}", S.LOW, f"dns://{name}",
                             "The CNAME target doesn't resolve; if the target domain/resource can be registered by someone else, this becomes a takeover.",
                             f"Remove the stale DNS record for {name}.", "CWE-350", snippet=f"{name} CNAME {target}"))
    if (addrs or (cnames and not nx)) and FORGOTTEN.search(name):
        r = client.request(f"https://{name}/", headers={"Accept": "text/html"})
        if r.error:
            r = client.request(f"http://{name}/", headers={"Accept": "text/html"})
        if not r.error and r.status and r.status < 400:
            out.append(F("WEB-FORGOTTEN-HOST", f"Non-production host is publicly reachable: {name}", S.LOW, f"https://{name}/",
                         f"{name} answers HTTP {r.status} from the internet. Staging/dev/admin hosts are often less patched and less protected.",
                         "Put non-production hosts behind VPN/SSO, or remove them.", "CWE-1059", snippet=r.header("Server") or None))
    return out


def scan(domain: str, client: Client, max_hosts: int = 300, progress=None, warnings: Optional[List[str]] = None) -> Tuple[List[str], List[Finding]]:
    warnings = warnings if warnings is not None else []
    domain = domain.lower().strip().lstrip("*.").rstrip(".")
    if "://" in domain:
        domain = urllib.parse.urlsplit(domain).hostname or domain
    names = sorted(discover(domain, warnings))[:max_hosts]
    findings: List[Finding] = []
    if progress is not None:
        progress.set_total(len(names))
    with ThreadPoolExecutor(max_workers=8) as pool:
        for host, found in zip(names, pool.map(lambda n: check_host(n, client), names)):
            findings += found
            if progress is not None:
                progress.advance(1, host)
    return names, findings
