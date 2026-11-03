"""Website vulnerability scanning (DAST): `vulnfind web https://example.com`."""

from .scanner import WebOptions, scan_site

__all__ = ["WebOptions", "scan_site"]


def rule_catalog():
    """(id, severity, title, description) for `vulnfind rules`."""
    from .paths import PROBES
    rows = [
        ("WEB-TLS-INVALID-CERT", "HIGH", "TLS certificate not trusted", "Expired chain, self-signed or hostname mismatch."),
        ("WEB-TLS-EXPIRED", "CRITICAL", "TLS certificate expired", "Certificate validity has ended."),
        ("WEB-TLS-EXPIRING", "MEDIUM", "TLS certificate expiring soon", "Under 30 days (HIGH under 14)."),
        ("WEB-TLS-OLD-PROTOCOL", "MEDIUM", "TLS 1.0/1.1 accepted", "Deprecated protocol versions negotiated."),
        ("WEB-NO-HTTPS", "HIGH", "No HTTPS", "Site only reachable over plain HTTP."),
        ("WEB-NO-HTTPS-REDIRECT", "MEDIUM", "HTTP not redirected to HTTPS", "First request can be SSL-stripped."),
        ("WEB-HSTS-MISSING", "MEDIUM", "Missing HSTS", "Strict-Transport-Security not sent."),
        ("WEB-HSTS-SHORT", "LOW", "HSTS max-age too short", "Under 180 days."),
        ("WEB-CSP-MISSING", "MEDIUM", "No Content-Security-Policy", "Main browser-side XSS defence absent."),
        ("WEB-CSP-WEAK", "MEDIUM", "Weak CSP", "unsafe-inline / unsafe-eval / wildcard script sources."),
        ("WEB-CLICKJACKING", "MEDIUM", "Page can be framed", "No X-Frame-Options or frame-ancestors."),
        ("WEB-NOSNIFF-MISSING", "LOW", "Missing X-Content-Type-Options", "MIME sniffing allowed."),
        ("WEB-REFERRER-POLICY", "LOW", "Missing Referrer-Policy", "URLs may leak via Referer."),
        ("WEB-PERMISSIONS-POLICY", "INFO", "Missing Permissions-Policy", "Powerful features not restricted."),
        ("WEB-VERSION-DISCLOSURE", "LOW", "Version banners", "Server / X-Powered-By reveal versions."),
        ("WEB-COOKIE-FLAGS", "MEDIUM", "Cookie missing Secure/HttpOnly/SameSite", "Session cookies exposed to XSS, CSRF or plain HTTP."),
        ("WEB-CORS-REFLECT", "HIGH", "CORS reflects any origin", "Arbitrary sites can read (authenticated) responses."),
        ("WEB-CORS-WILDCARD-CREDS", "LOW", "CORS * with credentials", "Misconfigured CORS policy."),
        ("WEB-RISKY-METHODS", "MEDIUM", "TRACE/PUT/DELETE enabled", "Unneeded HTTP methods advertised."),
        ("WEB-MIXED-CONTENT", "MEDIUM", "Mixed content", "HTTPS page loads scripts/frames over HTTP."),
        ("WEB-NO-SRI", "LOW", "Third-party scripts without SRI", "Supply-chain risk from CDNs/vendors."),
        ("WEB-PASSWORD-OVER-HTTP", "HIGH", "Password form over HTTP", "Credentials sent unencrypted."),
        ("WEB-PASSWORD-IN-URL", "MEDIUM", "Password form uses GET", "Passwords end up in URLs and logs."),
        ("WEB-GENERATOR-DISCLOSURE", "LOW", "CMS version disclosed", "meta generator reveals the version."),
        ("WEB-SENSITIVE-COMMENT", "LOW", "Sensitive HTML comment", "Comments mention passwords/keys."),
        ("WEB-DEBUG-EXPOSED", "HIGH", "Framework debug mode exposed", "Werkzeug, Django, Laravel, Rails, Symfony debug pages."),
        ("WEB-ERROR-DISCLOSURE", "MEDIUM", "Stack traces in responses", "Python/PHP/Java/.NET error details."),
        ("WEB-DIRECTORY-LISTING", "MEDIUM", "Directory listing", "Index of / pages."),
        ("WEB-VULNERABLE-JS-LIBRARY", "HIGH", "Vulnerable JavaScript library", "Served library version has known CVEs (OSV + KEV/EPSS)."),
        ("WEB-SOURCEMAP-EXPOSED", "MEDIUM", "Public source maps", "Original front-end source is downloadable."),
        ("WEB-NO-SECURITY-TXT", "INFO", "No security.txt", "No vulnerability disclosure contact (RFC 9116)."),
        ("WEB-ROBOTS-DISCLOSURE", "INFO", "robots.txt lists sensitive paths", "Hidden areas advertised."),
        ("WEB-DNS-NO-SPF", "MEDIUM", "No SPF record", "Domain can be spoofed in email."),
        ("WEB-DNS-SPF-PERMISSIVE", "HIGH", "SPF +all", "Any server may send as the domain."),
        ("WEB-DNS-NO-DMARC", "MEDIUM", "No DMARC policy", "Spoofed mail has no rejection policy."),
        ("WEB-DNS-DMARC-NONE", "LOW", "DMARC p=none", "Monitor-only policy."),
        ("WEB-DNS-NO-CAA", "INFO", "No CAA record", "Any CA may issue certificates."),
        ("WEB-REFLECTED-XSS", "HIGH", "Reflected XSS (--active)", "Parameter echoed unescaped into HTML."),
        ("WEB-SQL-ERROR", "CRITICAL", "SQL injection (--active)", "A quote in a parameter triggers a database error."),
        ("WEB-OPEN-REDIRECT", "MEDIUM", "Open redirect (--active)", "Redirect parameter accepts any URL."),
    ]
    seen = {r[0] for r in rows}
    for p in PROBES:
        if p.rule_id not in seen:
            seen.add(p.rule_id)
            rows.append((p.rule_id, p.severity.label, p.title, p.desc))
    return rows
