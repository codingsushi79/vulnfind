"""Probe well-known sensitive paths. Every hit is confirmed by a content signature and
compared against a random-path baseline, so sites that answer 200 for everything
("soft 404") do not produce false positives. GET only; binary files use a Range
request so nothing large is downloaded."""

from __future__ import annotations

import hashlib
import re
import secrets
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, List, Optional

from ..models import Finding, Severity as S
from .checks import F
from .client import BudgetExceeded, Client, Response


@dataclass(frozen=True)
class Probe:
    path: str
    rule_id: str
    title: str
    severity: S
    check: Callable[[Response], bool]
    desc: str
    fix: str
    cwe: str = "CWE-538"
    binary: bool = False


def has(*needles: str) -> Callable[[Response], bool]:
    return lambda r: any(n in r.text for n in needles)


def rx(pattern: str, flags: int = 0) -> Callable[[Response], bool]:
    c = re.compile(pattern, flags)
    return lambda r: bool(c.search(r.text[:200_000]))


def starts(prefix: bytes) -> Callable[[Response], bool]:
    return lambda r: r.body.startswith(prefix)


def not_html(check: Callable[[Response], bool]) -> Callable[[Response], bool]:
    return lambda r: not r.is_html and check(r)


ENV_RX = r"(?m)^\s*(?:export\s+)?[A-Z][A-Z0-9_]{2,}\s*=\s*\S"
REMOVE = "Remove it from the web root (or block it in the server config) and rotate any credentials it contained."

PROBES: List[Probe] = [
    Probe("/.git/HEAD", "WEB-EXPOSED-GIT", "Git repository exposed (.git/)", S.CRITICAL,
          not_html(rx(r"^(?:ref: refs/|[0-9a-f]{40}\s*$)")),
          "The .git directory is downloadable: tools like git-dumper can rebuild your full source code and history, "
          "including any secrets ever committed.", "Block /.git in the web server and deploy without the .git folder."),
    Probe("/.git/config", "WEB-EXPOSED-GIT", "Git config exposed", S.HIGH, not_html(has("[core]")),
          "The repository config (remote URLs, sometimes embedded credentials) is public.", "Block /.git in the web server."),
    Probe("/.env", "WEB-EXPOSED-ENV", "Environment file exposed (.env)", S.CRITICAL, not_html(rx(ENV_RX)),
          "Environment files usually hold database passwords, API keys and app secrets.", REMOVE),
    Probe("/.env.production", "WEB-EXPOSED-ENV", "Environment file exposed (.env.production)", S.CRITICAL, not_html(rx(ENV_RX)),
          "Production environment variables are publicly readable.", REMOVE),
    Probe("/.env.local", "WEB-EXPOSED-ENV", "Environment file exposed (.env.local)", S.CRITICAL, not_html(rx(ENV_RX)),
          "Environment variables are publicly readable.", REMOVE),
    Probe("/.aws/credentials", "WEB-EXPOSED-CREDENTIALS", "AWS credentials file exposed", S.CRITICAL, has("aws_access_key_id"),
          "Cloud credentials are publicly downloadable.", REMOVE),
    Probe("/.git-credentials", "WEB-EXPOSED-CREDENTIALS", "Git credentials exposed", S.CRITICAL, not_html(rx(r"https?://[^:\s]+:[^@\s]+@")),
          "Plain-text git credentials are publicly downloadable.", REMOVE),
    Probe("/id_rsa", "WEB-EXPOSED-CREDENTIALS", "SSH private key exposed", S.CRITICAL, has("PRIVATE KEY-----"),
          "A private key is publicly downloadable.", REMOVE),
    Probe("/.ssh/id_rsa", "WEB-EXPOSED-CREDENTIALS", "SSH private key exposed", S.CRITICAL, has("PRIVATE KEY-----"),
          "A private key is publicly downloadable.", REMOVE),
    Probe("/.npmrc", "WEB-EXPOSED-CREDENTIALS", "npm config exposed", S.HIGH, not_html(rx(r"_auth|registry=")),
          "npm config may include registry auth tokens.", REMOVE),
    Probe("/.vscode/sftp.json", "WEB-EXPOSED-CREDENTIALS", "Editor SFTP config exposed", S.HIGH, has('"host"', '"password"'),
          "Deployment host and credentials are publicly readable.", REMOVE),
    Probe("/terraform.tfstate", "WEB-EXPOSED-CREDENTIALS", "Terraform state exposed", S.CRITICAL, has('"terraform_version"'),
          "Terraform state contains infrastructure secrets in plain text.", REMOVE),
    Probe("/wp-config.php.bak", "WEB-EXPOSED-BACKUP", "WordPress config backup exposed", S.CRITICAL, has("DB_PASSWORD"),
          "The WordPress database password and auth salts are publicly readable.", REMOVE),
    Probe("/wp-config.php~", "WEB-EXPOSED-BACKUP", "WordPress config backup exposed", S.CRITICAL, has("DB_PASSWORD"),
          "The WordPress database password and auth salts are publicly readable.", REMOVE),
    Probe("/wp-config.php.save", "WEB-EXPOSED-BACKUP", "WordPress config backup exposed", S.CRITICAL, has("DB_PASSWORD"),
          "The WordPress database password and auth salts are publicly readable.", REMOVE),
    Probe("/config.php.bak", "WEB-EXPOSED-BACKUP", "PHP config backup exposed", S.HIGH, has("<?php"),
          "PHP source served as plain text (backups are not executed).", REMOVE),
    Probe("/index.php.bak", "WEB-EXPOSED-BACKUP", "PHP source backup exposed", S.MEDIUM, has("<?php"), "PHP source is readable.", REMOVE),
    Probe("/backup.sql", "WEB-EXPOSED-DUMP", "Database dump exposed", S.CRITICAL, rx(r"CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump"),
          "A database dump (user data, password hashes) is publicly downloadable.", REMOVE),
    Probe("/dump.sql", "WEB-EXPOSED-DUMP", "Database dump exposed", S.CRITICAL, rx(r"CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump"),
          "A database dump is publicly downloadable.", REMOVE),
    Probe("/database.sql", "WEB-EXPOSED-DUMP", "Database dump exposed", S.CRITICAL, rx(r"CREATE TABLE|INSERT INTO"),
          "A database dump is publicly downloadable.", REMOVE),
    Probe("/backup.zip", "WEB-EXPOSED-BACKUP", "Backup archive exposed", S.HIGH, starts(b"PK\x03\x04"),
          "A site backup archive is downloadable.", REMOVE, binary=True),
    Probe("/site.zip", "WEB-EXPOSED-BACKUP", "Site archive exposed", S.HIGH, starts(b"PK\x03\x04"),
          "A site archive is downloadable.", REMOVE, binary=True),
    Probe("/backup.tar.gz", "WEB-EXPOSED-BACKUP", "Backup archive exposed", S.HIGH, starts(b"\x1f\x8b"),
          "A site backup archive is downloadable.", REMOVE, binary=True),
    Probe("/.DS_Store", "WEB-EXPOSED-DSSTORE", ".DS_Store file exposed", S.LOW, starts(b"\x00\x00\x00\x01Bud1"),
          "macOS metadata files list the names of every file in the directory, including hidden ones.", REMOVE, binary=True),
    Probe("/.svn/entries", "WEB-EXPOSED-VCS", "Subversion metadata exposed", S.HIGH, not_html(rx(r"^\d+\s*$|svn:|<wc-entries", re.M)),
          "SVN metadata can reveal or reconstruct source code.", "Block /.svn and deploy without it."),
    Probe("/.hg/requires", "WEB-EXPOSED-VCS", "Mercurial repository exposed", S.HIGH, not_html(has("revlogv1", "store")),
          "Mercurial metadata can reconstruct source code.", "Block /.hg and deploy without it."),
    Probe("/.htpasswd", "WEB-EXPOSED-CREDENTIALS", ".htpasswd exposed", S.HIGH, not_html(rx(r"(?m)^[^:\s]+:(?:\$apr1\$|\$2[aby]\$|\{SHA\}|\$1\$)")),
          "Password hashes for HTTP auth are downloadable and can be cracked offline.", REMOVE),
    Probe("/.htaccess", "WEB-EXPOSED-CONFIG", ".htaccess exposed", S.LOW, not_html(rx(r"(?i)RewriteEngine|Deny from|Require |AuthType")),
          "Server rules (and sometimes protected paths) are readable.", "Deny access to dotfiles."),
    Probe("/web.config", "WEB-EXPOSED-CONFIG", "web.config exposed", S.HIGH, has("<configuration"),
          "IIS/ASP.NET configuration, often with connection strings, is readable.", REMOVE),
    Probe("/docker-compose.yml", "WEB-EXPOSED-CONFIG", "docker-compose.yml exposed", S.MEDIUM, not_html(rx(r"(?m)^services:|^version:")),
          "Service layout, image names and often environment secrets are readable.", REMOVE),
    Probe("/Dockerfile", "WEB-EXPOSED-CONFIG", "Dockerfile exposed", S.LOW, not_html(rx(r"(?m)^FROM\s+\S")),
          "Build details are readable.", REMOVE),
    Probe("/phpinfo.php", "WEB-PHPINFO", "phpinfo() page exposed", S.HIGH, has("<title>PHP ", "phpinfo()"),
          "phpinfo reveals the PHP version, modules, paths and environment variables (sometimes secrets).", REMOVE),
    Probe("/info.php", "WEB-PHPINFO", "phpinfo() page exposed", S.HIGH, has("<title>PHP ", "phpinfo()"),
          "phpinfo reveals versions, paths and environment variables.", REMOVE),
    Probe("/server-status", "WEB-SERVER-STATUS", "Apache server-status exposed", S.MEDIUM, has("Apache Server Status"),
          "Live requests (URLs, client IPs, sometimes session tokens in query strings) are visible.", "Restrict mod_status to localhost/admins."),
    Probe("/server-info", "WEB-SERVER-STATUS", "Apache server-info exposed", S.MEDIUM, has("Apache Server Information"),
          "Full server configuration is visible.", "Restrict mod_info to admins."),
    Probe("/actuator/env", "WEB-SPRING-ACTUATOR", "Spring Boot actuator /env exposed", S.HIGH, has('"propertySources"', '"activeProfiles"'),
          "Configuration properties (sometimes credentials) are readable; some actuators allow changing settings.",
          "Expose only health/info, behind authentication (management.endpoints.web.exposure.include)."),
    Probe("/actuator/heapdump", "WEB-SPRING-ACTUATOR", "Spring Boot heap dump downloadable", S.CRITICAL, starts(b"JAVA PROFILE"),
          "A full memory dump with sessions, passwords and keys can be downloaded.", "Disable the heapdump endpoint.", binary=True),
    Probe("/actuator", "WEB-SPRING-ACTUATOR", "Spring Boot actuator index exposed", S.LOW, has('"_links"'),
          "Lists management endpoints.", "Expose only health/info, behind authentication."),
    Probe("/debug/pprof/", "WEB-DEBUG-ENDPOINT", "Go pprof debug endpoint exposed", S.MEDIUM, has("Types of profiles available"),
          "Profiling endpoints leak internals and can be abused for DoS.", "Serve pprof on an internal-only port."),
    Probe("/elmah.axd", "WEB-DEBUG-ENDPOINT", "ELMAH error log exposed", S.HIGH, has("Error Log for"),
          "Error logs with request details (cookies, session IDs) are public.", "Restrict ELMAH to administrators."),
    Probe("/trace.axd", "WEB-DEBUG-ENDPOINT", "ASP.NET trace exposed", S.HIGH, has("Application Trace"),
          "Request traces (headers, cookies, form data) are public.", "Disable tracing in production."),
    Probe("/_profiler/", "WEB-DEBUG-ENDPOINT", "Symfony profiler exposed", S.HIGH, has("Symfony Profiler"),
          "Every request, including credentials and environment, can be inspected.", "Disable the profiler in production."),
    Probe("/storage/logs/laravel.log", "WEB-EXPOSED-LOG", "Laravel log file exposed", S.HIGH, rx(r"\.(?:ERROR|WARNING|INFO): "),
          "Application logs (stack traces, sometimes tokens) are public.", REMOVE),
    Probe("/debug.log", "WEB-EXPOSED-LOG", "Debug log exposed", S.MEDIUM, not_html(rx(r"PHP (?:Fatal|Warning|Notice)|Traceback|Exception|\[error\]")),
          "Logs reveal internals and sometimes credentials.", REMOVE),
    Probe("/error.log", "WEB-EXPOSED-LOG", "Error log exposed", S.MEDIUM, not_html(rx(r"PHP (?:Fatal|Warning|Notice)|Traceback|Exception|\[error\]")),
          "Logs reveal internals and sometimes credentials.", REMOVE),
    Probe("/crossdomain.xml", "WEB-CROSSDOMAIN", "Permissive crossdomain.xml", S.MEDIUM, rx(r'allow-access-from\s+domain="\*"'),
          "Any Flash/legacy client from any domain can read authenticated responses.", "Restrict allowed domains or remove the file."),
    Probe("/phpmyadmin/", "WEB-ADMIN-PANEL", "phpMyAdmin publicly reachable", S.MEDIUM, has("phpMyAdmin"),
          "A database admin panel on the internet is a common brute-force and exploit target.", "Restrict by IP / VPN, or remove it."),
    Probe("/xmlrpc.php", "WEB-WP-XMLRPC", "WordPress XML-RPC enabled", S.LOW, has("XML-RPC server accepts POST requests only"),
          "XML-RPC allows amplified password brute-forcing (system.multicall) and pingback abuse.", "Disable xmlrpc.php if unused."),
    Probe("/wp-json/wp/v2/users", "WEB-WP-USER-ENUM", "WordPress usernames exposed via REST API", S.LOW, rx(r'"slug"\s*:\s*"[^"]+"'),
          "Login names are listed publicly, halving the work for password attacks.", "Restrict the users endpoint to authenticated requests."),
    Probe("/swagger.json", "WEB-API-DOCS", "API specification public", S.INFO, rx(r'"(?:swagger|openapi)"\s*:'),
          "Full API surface is documented publicly; make sure every endpoint is authenticated as intended.", "Restrict if the API is not public."),
    Probe("/openapi.json", "WEB-API-DOCS", "API specification public", S.INFO, rx(r'"openapi"\s*:'),
          "Full API surface is documented publicly.", "Restrict if the API is not public."),
    Probe("/v2/api-docs", "WEB-API-DOCS", "API specification public", S.INFO, rx(r'"swagger"\s*:'),
          "Full API surface is documented publicly.", "Restrict if the API is not public."),
    Probe("/graphql?query=%7B__typename%7D", "WEB-GRAPHQL", "GraphQL endpoint found", S.INFO, rx(r'"__typename"|"data"\s*:'),
          "GraphQL endpoint answers anonymous queries; check that introspection is disabled and every resolver enforces auth.",
          "Disable introspection in production and add query depth/cost limits.", "CWE-200"),
]


def _fingerprint(r: Response) -> str:
    # strip things that vary per request (the random path itself, timestamps, nonces)
    t = re.sub(r"vulnfind-[0-9a-f]+|\d{2,}|nonce-[\w+/=]+", "", r.text[:20000])
    return hashlib.sha256(t.encode("utf-8", "replace")).hexdigest()


def probe_paths(client: Client, base: str, on_done: Optional[Callable[[str], None]] = None, workers: int = 4) -> List[Finding]:
    root = base.rstrip("/")
    # soft-404 baseline
    junk = client.request(f"{root}/vulnfind-{secrets.token_hex(6)}.txt")
    baseline = _fingerprint(junk) if junk.status == 200 else None

    def run(p: Probe) -> Optional[Finding]:
        url = root + p.path
        try:
            r = client.request(url, headers={"Range": "bytes=0-4095"} if p.binary else None,
                               max_body=4096 if p.binary else 256 * 1024)
        except BudgetExceeded:
            return None
        finally:
            if on_done:
                on_done(p.path)
        if r.error or r.status not in (200, 206):
            return None
        if baseline and _fingerprint(r) == baseline:
            return None
        try:
            if not p.check(r):
                return None
        except Exception:
            return None
        snippet = None if p.binary else re.sub(r"(?i)((?:pass(?:word)?|secret|key|token)\w*\s*[=:]\s*)\S+", r"\1••••", r.text[:160]).strip().replace("\n", " ⏎ ")
        return F(p.rule_id, p.title, p.severity, url, p.desc, p.fix, p.cwe, snippet=snippet)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(run, PROBES))
    out = [r for r in results if r]
    # .git/HEAD and .git/config are one problem: keep the most severe
    if sum(1 for f in out if f.rule_id == "WEB-EXPOSED-GIT") > 1:
        keep = max((f for f in out if f.rule_id == "WEB-EXPOSED-GIT"), key=lambda f: f.severity)
        out = [f for f in out if f.rule_id != "WEB-EXPOSED-GIT" or f is keep]
    return out


def robots_and_security_txt(client: Client, base: str) -> List[Finding]:
    root = base.rstrip("/")
    out: List[Finding] = []
    st = client.request(root + "/.well-known/security.txt")
    if not (st.status == 200 and "contact:" in st.text.lower() and not st.is_html):
        out.append(F("WEB-NO-SECURITY-TXT", "No security.txt", S.INFO, root + "/.well-known/security.txt",
                     "Researchers who find a vulnerability have no published way to report it (RFC 9116).",
                     "Publish /.well-known/security.txt with Contact: and Expires: fields.", "CWE-1059"))
    robots = client.request(root + "/robots.txt")
    if robots.status == 200 and not robots.is_html:
        hidden = re.findall(r"(?im)^\s*disallow:\s*(/\S*(?:admin|backup|private|secret|internal|staging|dev|config|old|test|debug)\S*)", robots.text)
        if hidden:
            out.append(F("WEB-ROBOTS-DISCLOSURE", "robots.txt points at sensitive-looking paths", S.INFO, root + "/robots.txt",
                         "robots.txt is public; listing private areas there advertises them. It is not access control.",
                         "Protect these paths with authentication instead of hiding them.", "CWE-200", snippet=", ".join(hidden[:8])))
    return out


def sitemap_urls(client: Client, base: str, limit: int = 50) -> List[str]:
    r = client.request(base.rstrip("/") + "/sitemap.xml", max_body=512 * 1024)
    if r.status != 200 or "<urlset" not in r.text:
        return []
    return re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", r.text)[:limit]
