"""Sensitive-file checks: key stores, env files, credentials, state/dump files, permissions."""

from __future__ import annotations

import fnmatch
import os
import re
import stat
import subprocess
from typing import Iterator, Optional, Set

from ..models import Finding, Severity as S
from ..walker import SourceFile

# (glob, rule id, title, severity, description)
SENSITIVE = [
    ("id_rsa", "FILE-SSH-KEY", "SSH private key file", S.CRITICAL, "An SSH private key is stored in the project."),
    ("id_dsa", "FILE-SSH-KEY", "SSH private key file", S.CRITICAL, "An SSH private key is stored in the project."),
    ("id_ecdsa", "FILE-SSH-KEY", "SSH private key file", S.CRITICAL, "An SSH private key is stored in the project."),
    ("id_ed25519", "FILE-SSH-KEY", "SSH private key file", S.CRITICAL, "An SSH private key is stored in the project."),
    ("*.ppk", "FILE-SSH-KEY", "PuTTY private key file", S.CRITICAL, "A PuTTY private key is stored in the project."),
    ("*.p12", "FILE-KEYSTORE", "Certificate key store", S.HIGH, "PKCS#12 bundles usually contain a private key."),
    ("*.pfx", "FILE-KEYSTORE", "Certificate key store", S.HIGH, "PFX bundles usually contain a private key."),
    ("*.jks", "FILE-KEYSTORE", "Java key store", S.HIGH, "Java key stores usually contain private keys."),
    ("*.keystore", "FILE-KEYSTORE", "Key store", S.HIGH, "Key stores (e.g. Android signing keys) contain private keys."),
    ("*.kdbx", "FILE-PASSWORD-DB", "KeePass password database", S.HIGH, "A password manager database is in the project."),
    (".htpasswd", "FILE-HTPASSWD", "htpasswd file", S.HIGH, "Contains password hashes for HTTP basic auth."),
    (".git-credentials", "FILE-GIT-CREDENTIALS", "Git credential store", S.CRITICAL, "Contains plain-text git credentials/tokens."),
    (".pgpass", "FILE-DB-CREDENTIALS", "PostgreSQL password file", S.HIGH, "Contains plain-text database passwords."),
    (".my.cnf", "FILE-DB-CREDENTIALS", "MySQL client config", S.MEDIUM, "Often contains a plain-text database password."),
    ("credentials", "FILE-CLOUD-CREDENTIALS", "Cloud credentials file", S.HIGH, "Looks like an AWS/cloud CLI credentials file."),
    ("credentials.json", "FILE-CLOUD-CREDENTIALS", "Credentials file", S.MEDIUM, "Often an OAuth client secret or service-account key."),
    ("*.tfstate", "FILE-TFSTATE", "Terraform state file", S.HIGH, "Terraform state stores resource attributes - including secrets - in plain text."),
    ("*.tfstate.backup", "FILE-TFSTATE", "Terraform state backup", S.HIGH, "Terraform state stores resource attributes - including secrets - in plain text."),
    ("*.tfvars", "FILE-TFVARS", "Terraform variables file", S.LOW, "tfvars files frequently hold credentials; make sure this one does not."),
    ("*.sql", "FILE-DB-DUMP", "SQL dump", S.MEDIUM, "This looks like a database dump; dumps often contain personal data or password hashes."),
    ("*.sqlite", "FILE-DB-DUMP", "SQLite database", S.LOW, "A database file is committed; it may contain user data."),
    ("*.sqlite3", "FILE-DB-DUMP", "SQLite database", S.LOW, "A database file is committed; it may contain user data."),
    ("*.db", "FILE-DB-DUMP", "Database file", S.LOW, "A database file is committed; it may contain user data."),
    ("*.bak", "FILE-BACKUP", "Backup file", S.LOW, "Backup files can expose old code or config, and are often served as plain text."),
    ("*.swp", "FILE-BACKUP", "Editor swap file", S.LOW, "Editor swap files can leak source code if served."),
    ("*.hprof", "FILE-HEAP-DUMP", "Heap dump", S.HIGH, "Heap dumps contain in-memory secrets, sessions and user data."),
    ("*.core", "FILE-HEAP-DUMP", "Core dump", S.MEDIUM, "Core dumps contain process memory, which may include secrets."),
    ("*.ovpn", "FILE-VPN-CONFIG", "VPN profile", S.MEDIUM, "VPN profiles frequently embed keys and certificates."),
    ("wp-config.php", "FILE-APP-CONFIG", "WordPress config", S.MEDIUM, "Contains database credentials and auth salts."),
    ("secrets.yml", "FILE-APP-CONFIG", "Secrets file", S.MEDIUM, "Explicitly named secrets file."),
    ("master.key", "FILE-APP-CONFIG", "Rails master key", S.CRITICAL, "Decrypts Rails encrypted credentials."),
    ("*.env", "FILE-ENV", "Environment file", S.MEDIUM, "Environment files typically contain credentials."),
]
ENV_SAFE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults", ".tpl")


def _match(name: str) -> Optional[tuple]:
    lower = name.lower()
    if lower == ".env" or (lower.startswith(".env.") and not lower.endswith(ENV_SAFE_SUFFIXES)):
        return (".env", "FILE-ENV", "Environment file", S.MEDIUM, "Environment files typically contain credentials.")
    if lower.endswith(ENV_SAFE_SUFFIXES) or lower.endswith(".pub"):
        return None
    for entry in SENSITIVE:
        if fnmatch.fnmatch(lower, entry[0]):
            return entry
    return None


def _looks_like_dump(f: SourceFile) -> bool:
    if re.search(r"(?i)migrat|schema|seed|fixture|init", f.rel):
        return False
    if re.search(r"(?i)dump|backup|export|prod|snapshot", f.name):
        return True
    if f.size > 1024 * 1024 * 20:
        return True
    try:
        with open(f.path, "rb") as fh:
            head = fh.read(256 * 1024).decode("utf-8", "replace")
    except OSError:
        return False
    return "-- Dump" in head or "pg_dump" in head or "mysqldump" in head or head.count("INSERT INTO") >= 50


def _git_ignored(f: SourceFile) -> bool:
    try:
        return subprocess.run(["git", "-C", os.path.dirname(f.path), "check-ignore", "-q", f.name],
                              capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def scan(f: SourceFile, tracked: Optional[Set[str]]) -> Iterator[Finding]:
    hit = _match(f.name)
    if hit:
        _, rule_id, title, sev, desc = hit
        if rule_id == "FILE-CLOUD-CREDENTIALS" and f.name == "credentials" and "/.aws/" not in "/" + f.rel and not f.rel.startswith(".aws/"):
            hit = None
        elif rule_id == "FILE-ENV" and f.size == 0:
            hit = None
        elif rule_id == "FILE-DB-DUMP" and f.ext == ".sql" and not _looks_like_dump(f):
            hit = None  # schema files / migrations are normal
    if hit:
        fix = "Remove it from the repository, add it to .gitignore, and rotate anything it contains."
        extra = {}
        if tracked is not None:
            if f.rel in tracked:
                desc += " It is tracked by git, so it is in your history."
                sev = max(sev, S.HIGH) if rule_id == "FILE-ENV" else sev
                extra["git"] = "tracked"
            elif _git_ignored(f):
                desc += " It is git-ignored (lower risk), but keep it out of build artifacts and Docker images."
                sev = sev.lowered()
                extra["git"] = "ignored"
                fix = "Keep it ignored, add it to .dockerignore, and never bake it into images."
            else:
                desc += " It is NOT in .gitignore - the next `git add .` will commit it."
                extra["git"] = "untracked"
                fix = f"Add '{f.name}' to .gitignore now, and rotate anything it contains if it was ever shared."
        yield Finding(rule_id=rule_id, title=title, severity=sev, category="file", file=f.rel,
                      description=desc, fix=fix, cwe="CWE-538", extra=extra)

    if os.name == "posix":
        try:
            mode = os.stat(f.path).st_mode
        except OSError:
            return
        if mode & stat.S_IWOTH:
            yield Finding(rule_id="FILE-WORLD-WRITABLE", title="World-writable file", severity=S.MEDIUM, category="file",
                          file=f.rel, description=f"File mode {stat.filemode(mode)} lets any local user modify it.",
                          fix=f"chmod o-w '{f.rel}'", cwe="CWE-732")
