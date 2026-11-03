"""TLS / certificate checks."""

from __future__ import annotations

import socket
import ssl
import time
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from ..models import Finding, Severity as S


def _finding(rule_id: str, title: str, sev: S, url: str, desc: str, fix: str, cwe: str, snippet: Optional[str] = None,
             extra: Optional[dict] = None) -> Finding:
    return Finding(rule_id=rule_id, title=title, severity=sev, category="web", file=url, snippet=snippet,
                   description=desc, fix=fix, cwe=cwe, extra=extra or {})


def _handshake(host: str, port: int, ctx: ssl.SSLContext, timeout: float) -> Tuple[Optional[ssl.SSLSocket], Optional[str]]:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return None, f"connect failed: {e}"
    try:
        return ctx.wrap_socket(sock, server_hostname=host), None
    except (ssl.SSLError, OSError) as e:
        sock.close()
        return None, str(e)


def _decode_unverified(der: Optional[bytes]) -> Optional[dict]:
    """Python only parses *verified* peer certs; decode an untrusted one so expiry is still checked."""
    if not der:
        return None
    import os
    import tempfile
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
            fh.write(ssl.DER_cert_to_PEM_cert(der))
            path = fh.name
        try:
            return ssl._ssl._test_decode_cert(path)  # CPython helper; stable since 3.x
        finally:
            os.unlink(path)
    except Exception:
        return None


def cert_days_left(not_after: str, now: Optional[float] = None) -> int:
    expires = ssl.cert_time_to_seconds(not_after)
    return int((expires - (now if now is not None else time.time())) // 86400)


def check(host: str, port: int, url: str, timeout: float = 10.0) -> List[Finding]:
    out: List[Finding] = []
    verified = ssl.create_default_context()
    s, err = _handshake(host, port, verified, timeout)
    if s is None:
        if err and "connect failed" in err:
            return out
        out.append(_finding(
            "WEB-TLS-INVALID-CERT", "TLS certificate is not trusted", S.HIGH, url,
            f"Certificate verification failed: {err}. Browsers show a full-page warning; users who click through "
            "can be intercepted.", "Install a certificate from a trusted CA (e.g. Let's Encrypt) that covers this hostname, with the full chain.",
            "CWE-295"))
        # vulnfind:ignore PY-TLS-VERIFY-OFF - deliberately inspecting untrusted/legacy TLS; never used to send secrets
        loose = ssl._create_unverified_context()
        s, _ = _handshake(host, port, loose, timeout)
        if s is None:
            return out
        cert = _decode_unverified(s.getpeercert(binary_form=True))
    else:
        cert = s.getpeercert()
    version = s.version() or ""
    cipher = s.cipher()
    s.close()

    if cert:
        days = cert_days_left(cert["notAfter"])
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        info = {"expires": cert["notAfter"], "days_left": days, "issuer": issuer.get("organizationName") or issuer.get("commonName"),
                "protocol": version, "cipher": cipher[0] if cipher else None}
        if days < 0:
            out.append(_finding("WEB-TLS-EXPIRED", "TLS certificate has expired", S.CRITICAL, url,
                                f"The certificate expired on {cert['notAfter']}.", "Renew the certificate and automate renewal.", "CWE-298", extra=info))
        elif days < 14:
            out.append(_finding("WEB-TLS-EXPIRING", f"TLS certificate expires in {days} days", S.HIGH, url,
                                f"The certificate expires on {cert['notAfter']}.", "Renew now and automate renewal (certbot / ACME).", "CWE-298", extra=info))
        elif days < 30:
            out.append(_finding("WEB-TLS-EXPIRING", f"TLS certificate expires in {days} days", S.MEDIUM, url,
                                f"The certificate expires on {cert['notAfter']}.", "Make sure automatic renewal is working.", "CWE-298", extra=info))

    # Obsolete protocol versions still accepted?
    for name, ver in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        # vulnfind:ignore PY-TLS-VERIFY-OFF - deliberately inspecting untrusted/legacy TLS; never used to send secrets
        ctx = ssl._create_unverified_context()
        try:
            ctx.minimum_version = ver
            ctx.maximum_version = ver
        except (ValueError, ssl.SSLError):
            continue
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")  # OpenSSL 1.1+: allow the legacy suites these versions need
        except ssl.SSLError:
            pass  # LibreSSL has no SECLEVEL and allows them already
        sock, e = _handshake(host, port, ctx, timeout)
        negotiated = sock.version() if sock is not None else None
        if sock is not None:
            sock.close()
        if negotiated in ("TLSv1", "TLSv1.1"):  # some TLS libraries ignore the cap and negotiate 1.2+
            out.append(_finding("WEB-TLS-OLD-PROTOCOL", f"Server accepts {name}", S.MEDIUM, url,
                                f"{name} is deprecated (RFC 8996) and has known weaknesses (BEAST, weak MACs).",
                                "Allow only TLS 1.2 and 1.3 in the server / load balancer config.", "CWE-326", snippet=name))
    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
        out.append(_finding("WEB-TLS-OLD-PROTOCOL", f"Server negotiates {version} by default", S.HIGH, url,
                            "Modern clients are being served an obsolete protocol.", "Enable TLS 1.2+.", "CWE-326"))
    return out
