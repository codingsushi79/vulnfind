"""Email-spoofing protection (SPF, DMARC) and CAA via DNS-over-HTTPS (stdlib has no TXT resolver)."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import urllib.parse
import urllib.request
from typing import List, Optional

from .. import __version__
from ..models import Finding, Severity as S
from .checks import F

DOH = os.environ.get("VULNFIND_DOH_URL", "https://cloudflare-dns.com/dns-query")


def txt(name: str, rtype: str = "TXT", timeout: float = 10) -> Optional[List[str]]:
    url = f"{DOH}?name={urllib.parse.quote(name)}&type={rtype}"
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": f"vulnfind/{__version__}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode())
    if data.get("Status") not in (0, 3):  # NOERROR / NXDOMAIN
        return None
    return [a.get("data", "").replace('" "', "").strip('"') for a in data.get("Answer") or []
            if a.get("type") in (16, 257)]


def mail_domain(host: str) -> Optional[str]:
    host = host.lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    if "." not in host or host.endswith((".localhost", ".local", ".test", ".internal", ".example")) or host == "localhost":
        return None
    return host[4:] if host.startswith("www.") else host


def check(host: str, warnings: List[str]) -> List[Finding]:
    domain = mail_domain(host)
    if not domain:
        return []
    out: List[Finding] = []
    try:
        spf_records = [r for r in (txt(domain) or []) if r.lower().startswith("v=spf1")]
        dmarc_records = [r for r in (txt(f"_dmarc.{domain}") or []) if r.lower().startswith("v=dmarc1")]
        caa = txt(domain, "CAA")
    except Exception as e:
        warnings.append(f"DNS checks skipped ({e.__class__.__name__}): could not reach {DOH}")
        return []
    where = f"dns://{domain}"
    if not spf_records:
        out.append(F("WEB-DNS-NO-SPF", "No SPF record", S.MEDIUM, where,
                     f"Nothing tells mail servers which hosts may send email as @{domain}, making spoofed phishing easier.",
                     f'Publish a TXT record, e.g. "v=spf1 include:<your mail provider> -all" (or "v=spf1 -all" if the domain sends no mail).',
                     "CWE-290"))
    else:
        spf = spf_records[0]
        if re.search(r"\+all\b", spf):
            out.append(F("WEB-DNS-SPF-PERMISSIVE", "SPF allows every server (+all)", S.HIGH, where,
                         "+all authorises the whole internet to send mail as your domain.", "End the record with -all or ~all.", "CWE-290", snippet=spf))
        elif re.search(r"\?all\b", spf) or not re.search(r"[-~]all\b|redirect=", spf):
            out.append(F("WEB-DNS-SPF-WEAK", "SPF policy is neutral", S.LOW, where,
                         "?all (or no 'all' mechanism) gives receivers no instruction to reject forgeries.", "End the record with -all or ~all.",
                         "CWE-290", snippet=spf))
    if not dmarc_records:
        out.append(F("WEB-DNS-NO-DMARC", "No DMARC policy", S.MEDIUM, where,
                     f"Without DMARC, receivers have no policy for mail that fails SPF/DKIM, so @{domain} can be spoofed in phishing.",
                     f'Publish TXT _dmarc.{domain} "v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}" and move to p=reject.', "CWE-290"))
    else:
        m = re.search(r"\bp\s*=\s*(\w+)", dmarc_records[0], re.I)
        if m and m.group(1).lower() == "none":
            out.append(F("WEB-DNS-DMARC-NONE", "DMARC policy is p=none (monitor only)", S.LOW, where,
                         "Spoofed mail is reported but still delivered.", "Move to p=quarantine, then p=reject.", "CWE-290",
                         snippet=dmarc_records[0][:150]))
    if caa is not None and not caa:
        out.append(F("WEB-DNS-NO-CAA", "No CAA record", S.INFO, where,
                     "Any certificate authority may issue certificates for this domain.",
                     f'Add e.g. {domain}. CAA 0 issue "letsencrypt.org" for the CA(s) you use.', "CWE-295"))
    return out
