"""Infrastructure-as-code and CI checks: Dockerfile, docker-compose, Kubernetes,
GitHub Actions, Terraform, nginx, plus end-of-life runtime detection."""

from __future__ import annotations

import os
import re
from typing import Iterator, List, Optional

from ..models import Finding, Severity as S
from ..walker import SourceFile
from . import Rule, run_rules

DOCKERFILE = ("Dockerfile", "Dockerfile.*", "*.dockerfile", "Containerfile")
COMPOSE = ("docker-compose*.yml", "docker-compose*.yaml", "compose.yml", "compose.yaml", "compose.*.yml", "compose.*.yaml")
YAML = (".yml", ".yaml")
TF = (".tf", ".tf.json", ".hcl")
WORKFLOWS = (".github/workflows/*.yml", ".github/workflows/*.yaml", "*/.github/workflows/*.yml", "*/.github/workflows/*.yaml")

R = Rule
CONFIG_RULES: List[Rule] = [
    # ---------------------------------------------------------------- Dockerfile
    R("DOCKER-ADD-URL", "ADD with remote URL", S.MEDIUM, r"^ADD[ \t]+(?:--\S+[ \t]+)*https?://",
      "ADD fetches remote files without integrity verification.", "Use curl with checksum verification, or ADD --checksum=sha256:...",
      "CWE-494", names=DOCKERFILE, flags=re.I),
    R("DOCKER-SECRET-ENV", "Secret baked into image via ENV/ARG", S.HIGH,
      r"^(?:ENV|ARG)[ \t]+\w*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY)\w*(?:[ \t]*=[ \t]*|[ \t]+)\S+",
      "ENV/ARG values are stored in image layers and visible via `docker history`.", "Use BuildKit secrets (RUN --mount=type=secret) or runtime env vars.",
      "CWE-538", names=DOCKERFILE, flags=re.I),
    R("DOCKER-SUDO", "sudo used in Dockerfile", S.LOW, r"^RUN[ \t][^\n]*\bsudo\b",
      "sudo in images usually means the runtime user can escalate privileges.", "Run privileged steps before switching USER.", "CWE-250",
      names=DOCKERFILE, flags=re.I),
    R("DOCKER-SSH-PORT", "SSH port exposed", S.MEDIUM, r"^EXPOSE[ \t][^\n]*\b22\b", "Containers should not run an SSH server.",
      "Use docker exec / kubectl exec instead of SSH.", "CWE-284", names=DOCKERFILE, flags=re.I),

    # ---------------------------------------------------------------- docker-compose / Kubernetes / Helm
    R("CONTAINER-PRIVILEGED", "Privileged container", S.HIGH, r"^[ \t-]*privileged[ \t]*:[ \t]*true\b",
      "Privileged containers have full access to the host kernel and devices - escaping is trivial.",
      "Remove privileged; grant only the specific capabilities needed (cap_add).", "CWE-250", YAML),
    R("CONTAINER-DOCKER-SOCKET", "Docker socket mounted into container", S.HIGH, r"/var/run/docker\.sock",
      "Mounting the Docker socket gives the container root on the host.", "Avoid it; use a rootless builder or a socket proxy with an allow-list.",
      "CWE-250", YAML),
    R("CONTAINER-HOST-NAMESPACE", "Host network/PID/IPC namespace shared", S.MEDIUM,
      r"^[ \t-]*(?:hostNetwork|hostPID|hostIPC)[ \t]*:[ \t]*true\b|^[ \t-]*(?:network_mode|pid|ipc)[ \t]*:[ \t]*['\"]?host\b",
      "Sharing host namespaces breaks container isolation.", "Remove host namespace sharing.", "CWE-668", YAML),
    R("K8S-PRIV-ESCALATION", "allowPrivilegeEscalation enabled", S.MEDIUM, r"^[ \t-]*allowPrivilegeEscalation[ \t]*:[ \t]*true\b",
      "Processes can gain more privileges than their parent (setuid binaries).", "Set allowPrivilegeEscalation: false.", "CWE-250", YAML),
    R("K8S-RUN-AS-ROOT", "Container runs as root", S.MEDIUM, r"^[ \t-]*runAsUser[ \t]*:[ \t]*0\b|^[ \t-]*runAsNonRoot[ \t]*:[ \t]*false\b",
      "Running as UID 0 makes any container escape a host-root compromise.", "Set runAsNonRoot: true and a non-zero runAsUser.", "CWE-250", YAML),
    R("K8S-HOSTPATH", "hostPath volume", S.MEDIUM, r"^[ \t-]*hostPath[ \t]*:",
      "hostPath volumes expose the node filesystem to the pod.", "Use PersistentVolumes / emptyDir.", "CWE-668", YAML),
    R("K8S-SECRET-PLAINTEXT", "Plain-text secret in Kubernetes manifest", S.HIGH, r"^[ \t]*stringData[ \t]*:",
      "Secrets committed as stringData are readable by anyone with repo access.", "Use sealed-secrets, SOPS or an external secret store.",
      "CWE-312", YAML),

    # ---------------------------------------------------------------- GitHub Actions
    R("GHA-SCRIPT-INJECTION", "GitHub Actions script injection", S.HIGH,
      r"\$\{\{[ \t]*github\.(?:event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label)|comment\.body|review\.body|review_comment\.body|"
      r"pages\.[^}\n]*\.page_name|commits\.[^}\n]*\.(?:message|author\.(?:email|name))|head_commit\.(?:message|author\.(?:email|name))|discussion\.(?:title|body)|workflow_run\.head_branch)|head_ref)[ \t]*\}\}",
      "Attacker-controlled event data is expanded directly into the workflow. In a `run:` step this allows arbitrary command execution with the workflow's token and secrets.",
      "Pass the value through an env var (env: TITLE: ${{ github.event.issue.title }}) and reference \"$TITLE\" in the script.",
      "CWE-94", paths=WORKFLOWS, skip_comments=False,
      references=("https://securitylab.github.com/research/github-actions-untrusted-input/",)),
    R("GHA-WRITE-ALL", "Workflow token has write-all permissions", S.MEDIUM, r"^[ \t]*permissions[ \t]*:[ \t]*write-all\b",
      "A compromised step can push code, create releases and modify the repo.", "Grant least privilege, e.g. permissions: contents: read.",
      "CWE-250", paths=WORKFLOWS),
    R("GHA-UNPINNED-ACTION", "Third-party action not pinned to a commit SHA", S.LOW,
      r"^[ \t-]*uses[ \t]*:[ \t]*['\"]?(?!actions/|github/|docker://|\./)([\w.-]+/[\w./-]+)@(?![0-9a-f]{40}\b)([\w.\-/]+)",
      "Tags can be moved by the action's owner (or an attacker who compromises them), as in the tj-actions/changed-files incident.",
      "Pin to a full-length commit SHA: uses: owner/action@<sha> # v1.2.3", "CWE-829", paths=WORKFLOWS),
    R("GHA-INSECURE-COMMANDS", "ACTIONS_ALLOW_UNSECURE_COMMANDS enabled", S.HIGH, r"ACTIONS_ALLOW_UNSECURE_COMMANDS[ \t]*:[ \t]*['\"]?true",
      "Re-enables the deprecated set-env/add-path commands, which allow environment injection.", "Use $GITHUB_ENV / $GITHUB_PATH files.",
      "CWE-94", paths=WORKFLOWS),

    # ---------------------------------------------------------------- Terraform
    R("TF-OPEN-INGRESS", "Security group open to the internet", S.MEDIUM, r"cidr_blocks[ \t]*=[ \t]*\[[^\]\n]*\"0\.0\.0\.0/0\"|ipv6_cidr_blocks[ \t]*=[ \t]*\[[^\]\n]*\"::/0\"",
      "Ingress from 0.0.0.0/0 exposes the resource to the whole internet.", "Restrict CIDR ranges to known networks.", "CWE-284", TF),
    R("TF-PUBLIC-BUCKET", "Public S3 bucket ACL", S.HIGH, r"\bacl[ \t]*=[ \t]*\"public-read(?:-write)?\"|block_public_(?:acls|policy)[ \t]*=[ \t]*false",
      "The bucket is publicly readable (or writable).", "Use private ACLs and enable S3 Block Public Access.", "CWE-284", TF),
    R("TF-UNENCRYPTED", "Storage encryption disabled", S.MEDIUM, r"\b(?:encrypted|storage_encrypted|enable_encryption)[ \t]*=[ \t]*false",
      "Data at rest is not encrypted.", "Set encrypted = true (and use a KMS key).", "CWE-311", TF),
    R("TF-PUBLIC-DB", "Database publicly accessible", S.HIGH, r"\bpublicly_accessible[ \t]*=[ \t]*true",
      "The database has a public endpoint.", "Set publicly_accessible = false and use private subnets.", "CWE-284", TF),
    R("TF-IAM-WILDCARD", "IAM policy grants * on *", S.HIGH, r"\"?Action\"?[ \t]*[:=][ \t]*\[?[ \t]*\"\*\"",
      "Wildcard IAM actions grant full administrative access.", "List only the specific actions required.", "CWE-269", TF + (".json",)),
    R("TF-HARDCODED-CREDS", "Credentials in Terraform provider", S.HIGH, r"^[ \t]*(?:access_key|secret_key|password|client_secret)[ \t]*=[ \t]*\"[^\"$\n]{4,}\"",
      "Credentials hard-coded in Terraform end up in VCS and state files.", "Use variables marked sensitive, env vars, or a secrets backend.",
      "CWE-798", TF),

    R("TF-IMDSV1", "EC2 metadata service v1 allowed", S.MEDIUM, r"\bhttp_tokens[ \t]*=[ \t]*\"optional\"",
      "IMDSv1 lets SSRF bugs steal instance credentials (the Capital One breach).", "Set http_tokens = \"required\".", "CWE-918", TF),
    R("TF-KMS-NO-ROTATION", "KMS key rotation disabled", S.LOW, r"\benable_key_rotation[ \t]*=[ \t]*false",
      "Long-lived keys increase the blast radius of a key compromise.", "Set enable_key_rotation = true.", "CWE-320", TF),
    R("TF-NO-DELETION-PROTECTION", "Database deletion protection disabled", S.LOW, r"\bdeletion_protection[ \t]*=[ \t]*false",
      "A single mistaken apply (or attacker) can delete the database.", "Set deletion_protection = true for production.", "CWE-693", TF),
    R("K8S-IMAGE-UNPINNED", "Container image not pinned", S.LOW, r"^[ \t-]*image[ \t]*:[ \t]*['\"]?(?![^\s'\"]*@sha256:)[^\s'\"$:{]+(?::latest)?['\"]?[ \t]*$",
      "Untagged / :latest images change underneath you and can't be audited.", "Pin a version tag, ideally with @sha256 digest.", "CWE-1357", YAML),
    R("GHA-SECRETS-INHERIT", "Reusable workflow inherits all secrets", S.LOW, r"^[ \t]*secrets[ \t]*:[ \t]*inherit\b",
      "Every repository secret is passed to the called workflow.", "Pass only the secrets it needs.", "CWE-250", paths=WORKFLOWS),
    R("CONFIG-EXTRA-INDEX-URL", "pip --extra-index-url (dependency confusion)", S.MEDIUM, r"(?:^|\s)--?extra-index-url\b|^[ \t]*extra-index-url[ \t]*=",
      "pip picks the highest version across ALL indexes, so an attacker can publish your private package name on PyPI and win.",
      "Use a single --index-url that proxies PyPI, or pin hashes (--require-hashes).", "CWE-427",
      exts=(".txt", ".cfg", ".conf", ".ini", ".toml", ".yml", ".yaml", ".sh"), names=("Dockerfile*", "pip.conf", "requirements*.txt")),
    R("CONFIG-HTTP-REGISTRY", "Package registry over plain HTTP", S.HIGH,
      r"(?:registry|index-url|index_url|--index-url|source)[\"']?[ \t]*[=: ][ \t]*[\"']?http://(?!localhost|127\.0\.0\.1)",
      "Packages downloaded over HTTP can be swapped in transit (man-in-the-middle code execution).", "Use https:// registries.", "CWE-494",
      exts=(".txt", ".cfg", ".conf", ".ini", ".toml", ".yml", ".yaml", ".json"), names=(".npmrc", ".yarnrc", ".yarnrc.yml", "pip.conf", "Gemfile")),

    # ---------------------------------------------------------------- web servers / misc config
    R("NGINX-AUTOINDEX", "Directory listing enabled", S.LOW, r"^[ \t]*autoindex[ \t]+on[ \t]*;", "Directory listing leaks file names.",
      "Set autoindex off.", "CWE-548", names=("nginx.conf", "*.nginx", "*.conf")),
    R("NGINX-SERVER-TOKENS", "Server version disclosed", S.INFO, r"^[ \t]*server_tokens[ \t]+on[ \t]*;", "Version banners help attackers pick exploits.",
      "Set server_tokens off.", "CWE-200", names=("nginx.conf", "*.nginx", "*.conf")),
    # vulnfind:ignore CONFIG-WEAK-TLS
    R("CONFIG-WEAK-TLS", "Obsolete TLS/SSL protocol enabled", S.MEDIUM, r"\b(?:ssl_protocols|SSLProtocol|MinProtocol|min_version|minVersion)\b[^\n]*\b(?:SSLv2|SSLv3|TLSv1(?:\.0|\.1)?|TLSv1_1|TLS1_0|TLS1_1)\b(?![.\d])",
      "SSLv3/TLS 1.0/1.1 have known attacks (POODLE, BEAST) and are deprecated.", "Allow only TLS 1.2 and 1.3.", "CWE-326",
      exts=(".conf", ".cfg", ".ini", ".yml", ".yaml", ".js", ".ts", ".py", ".go", ".toml")),
]


# Config values are routinely quoted ("true", "/var/run/docker.sock"), so strings are in scope.
for _r in CONFIG_RULES:
    _r.skip_strings = False


# ---------------------------------------------------------------- structural checks

def _finding(rule_id, title, sev, f, line, snippet, desc, fix, cwe=None, refs=()) -> Finding:
    return Finding(rule_id=rule_id, title=title, severity=sev, category="config", file=f.rel, line=line,
                   snippet=(snippet or "").strip()[:300] or None, description=desc, fix=fix, cwe=cwe, references=list(refs))


def _is_dockerfile(f: SourceFile) -> bool:
    n = f.name
    return n in ("Dockerfile", "Containerfile") or n.startswith("Dockerfile.") or n.lower().endswith(".dockerfile")


def _dockerfile_checks(f: SourceFile, text: str) -> Iterator[Finding]:
    lines = text.splitlines()
    stages = [i for i, l in enumerate(lines) if re.match(r"^\s*FROM\s", l, re.I)]
    if not stages:
        return
    aliases = set()
    for i in stages:
        m = re.match(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", lines[i], re.I)
        if not m:
            continue
        image = m.group(1)
        if m.group(2):
            aliases.add(m.group(2).lower())
        if image.lower() in aliases or image.lower() == "scratch" or image.startswith("$") or "@sha256:" in image:
            continue
        tag = image.rsplit("/", 1)[-1].partition(":")[2]
        if not tag or tag == "latest":
            yield _finding("DOCKER-LATEST-TAG", "Base image not pinned", S.LOW, f, i + 1, lines[i],
                           "Using an untagged or :latest base image makes builds non-reproducible and can silently pull a vulnerable image.",
                           "Pin a specific tag, ideally with a digest: FROM node:22.11-alpine@sha256:...", "CWE-1357")
    last_stage = stages[-1]
    users = [(i, l) for i, l in enumerate(lines) if re.match(r"^\s*USER\s", l, re.I) and i > last_stage]
    if not users:
        yield _finding("DOCKER-ROOT-USER", "Container runs as root (no USER)", S.MEDIUM, f, last_stage + 1, lines[last_stage],
                       "The final image stage has no USER instruction, so the process runs as root.",
                       "Add a non-root user: RUN adduser -D app && USER app", "CWE-250")
    else:
        i, l = users[-1]
        if re.match(r"^\s*USER\s+(?:root|0)(?::\S+)?\s*$", l, re.I):
            yield _finding("DOCKER-ROOT-USER", "Container runs as root", S.MEDIUM, f, i + 1, l,
                           "The final USER is root.", "Switch to a non-root user before CMD/ENTRYPOINT.", "CWE-250")
    copy_all = next((i for i, l in enumerate(lines) if re.match(r"^\s*(?:COPY|ADD)\s+(?:--\S+\s+)*\.\s+\S", l, re.I)), None)
    if copy_all is not None and f.path and not os.path.exists(os.path.join(os.path.dirname(f.path), ".dockerignore")):
        yield _finding("DOCKER-NO-DOCKERIGNORE", "COPY . without a .dockerignore", S.MEDIUM, f, copy_all + 1, lines[copy_all],
                       "The entire build context - .env files, .git history, keys, node_modules - is copied into the image, "
                       "where anyone who pulls it can read them.",
                       "Add a .dockerignore (at least: .git, .env*, *.pem, node_modules) or COPY only what the app needs.", "CWE-538")
    if not any(re.match(r"^\s*HEALTHCHECK\s", l, re.I) for l in lines):
        yield _finding("DOCKER-NO-HEALTHCHECK", "No HEALTHCHECK defined", S.INFO, f, None, None,
                       "Without a HEALTHCHECK, orchestrators cannot detect a hung container.", "Add a HEALTHCHECK instruction.")


_PR_HEAD = re.compile(r"\$\{\{\s*github\.(?:event\.pull_request\.head\.(?:sha|ref)|head_ref)\s*\}\}|refs/pull/")


def _workflow_checks(f: SourceFile, text: str) -> Iterator[Finding]:
    if not re.search(r"\.github/workflows/[^/]+\.ya?ml$", f.rel):
        return
    if re.search(r"(?m)^\s*(?:on:.*\bpull_request\b|-?\s*pull_request\s*:?\s*$)", text):
        m = re.search(r"(?m)^\s*runs-on\s*:\s*\[?[^\n]*self-hosted", text)
        if m:
            yield _finding("GHA-SELF-HOSTED-PR", "Self-hosted runner used for pull requests", S.MEDIUM, f,
                           text.count("\n", 0, m.start()) + 1, m.group(0),
                           "Pull requests (including from forks, depending on settings) can run arbitrary code on your self-hosted machine, "
                           "which usually persists between jobs and sits inside your network.",
                           "Use GitHub-hosted runners for PRs, or ephemeral, isolated self-hosted runners with fork PR approval required.", "CWE-829")
    if not re.search(r"(?m)^\s*(?:on:.*\bpull_request_target\b|-?\s*pull_request_target\s*:?)", text) \
            and not re.search(r"(?m)^on\s*:\s*\[?[^\n]*pull_request_target", text):
        return
    for m in re.finditer(r"(?m)^.*\bref\s*:\s*.*$", text):
        if _PR_HEAD.search(m.group(0)):
            line = text.count("\n", 0, m.start()) + 1
            yield _finding("GHA-PWN-REQUEST", "pull_request_target checks out untrusted PR code", S.CRITICAL, f, line, m.group(0),
                           "The workflow runs on pull_request_target (with secrets and a write token) and checks out the PR's head. "
                           "Any build/test step then executes attacker code with those privileges ('pwn request').",
                           "Use the pull_request trigger for untrusted code, or split into a privileged workflow_run that never executes PR code.",
                           "CWE-829", ("https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",))


# End-of-life runtimes as of late 2026 (python.org, nodejs.org, php.net, ruby-lang.org release schedules).
EOL = {
    "python": lambda v: v[0] < 3 or (v[0] == 3 and len(v) > 1 and v[1] < 10),
    "node": lambda v: v[0] < 22 or (v[0] % 2 == 1 and v[0] < 27),
    "php": lambda v: v[0] < 8 or (v[0] == 8 and len(v) > 1 and v[1] < 2),
    "ruby": lambda v: v[0] < 3 or (v[0] == 3 and len(v) > 1 and v[1] < 3),
    "golang": lambda v: v[0] == 1 and len(v) > 1 and v[1] < 24,
}


def _parse_version(s: str) -> Optional[List[int]]:
    m = re.match(r"v?(\d+)(?:\.(\d+))?", s.strip())
    return [int(x) for x in m.groups() if x is not None] if m else None


def _eol_finding(f: SourceFile, runtime: str, version: str, line: Optional[int], snippet: str) -> Optional[Finding]:
    v = _parse_version(version)
    if not v or not EOL[runtime](v):
        return None
    return _finding("RUNTIME-EOL", f"End-of-life runtime: {runtime} {version}", S.MEDIUM, f, line, snippet,
                    f"{runtime} {version} no longer receives security patches; new CVEs in the runtime will never be fixed.",
                    f"Upgrade to a supported {runtime} release.", "CWE-1104")


def _eol_checks(f: SourceFile, text: str) -> Iterator[Finding]:
    name = f.name
    if _is_dockerfile(f):
        for m in re.finditer(r"(?mi)^\s*FROM\s+(?:--platform=\S+\s+)?(?:[\w.\-]+/)?(?:library/)?(python|node|php|ruby|golang):(\d+(?:\.\d+)?)", text):
            fnd = _eol_finding(f, m.group(1).lower(), m.group(2), text.count("\n", 0, m.start()) + 1, m.group(0))
            if fnd:
                yield fnd
    files = {".nvmrc": "node", ".node-version": "node", ".python-version": "python", ".ruby-version": "ruby", "runtime.txt": "python"}
    if name in files:
        value = text.strip().splitlines()[0] if text.strip() else ""
        value = value.replace("python-", "").replace("ruby-", "")
        fnd = _eol_finding(f, files[name], value, 1, value)
        if fnd:
            yield fnd
    if name == "package.json":
        m = re.search(r'"engines"\s*:\s*\{[^}]*"node"\s*:\s*"[^"\d]*(\d+(?:\.\d+)?)', text)
        if m:
            fnd = _eol_finding(f, "node", m.group(1), text.count("\n", 0, m.start(1)) + 1, m.group(0).split("\n")[-1])
            if fnd:
                yield fnd


DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "SYS_RAWIO", "BPF", "ALL"}


def _capability_checks(f: SourceFile, text: str) -> Iterator[Finding]:
    """Flag dangerous capabilities under `cap_add:` (compose) or `capabilities: add:` (k8s)."""
    if f.ext not in YAML or "cap" not in text:
        return
    block_indent = None
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" -"))
        m = re.match(r"^\s*-?\s*(cap_add|add)\s*:\s*(.*)$", line)
        if m:
            block_indent = indent if not m.group(2) else None
            caps = re.findall(r"[A-Z_]+", m.group(2))
        elif block_indent is not None and stripped.startswith("-") and indent > block_indent - 1:
            caps = re.findall(r"[A-Z_]+", stripped)
        else:
            if stripped and block_indent is not None and indent <= block_indent:
                block_indent = None
            continue
        for cap in caps:
            if cap.replace("CAP_", "") in DANGEROUS_CAPS:
                yield _finding("CONTAINER-DANGEROUS-CAP", f"Dangerous capability added: {cap}", S.HIGH, f, lineno, line,
                               f"{cap} enables container escape or host tampering.",
                               "Drop ALL capabilities and add back only what is strictly required.", "CWE-250")


def _remote_admin_ports(found: List[Finding], text: str) -> None:
    """0.0.0.0/0 ingress on SSH/RDP/database ports is much worse than on 443."""
    lines = text.splitlines()
    for fnd in found:
        if fnd.rule_id != "TF-OPEN-INGRESS" or not fnd.line:
            continue
        window = "\n".join(lines[max(0, fnd.line - 8):fnd.line + 3])
        port = re.search(r"\b(?:from_port|to_port|port)\s*=\s*(22|3389|3306|5432|6379|27017|9200|5984|11211)\b", window)
        if port:
            fnd.severity = S.HIGH
            names = {"22": "SSH", "3389": "RDP", "3306": "MySQL", "5432": "PostgreSQL", "6379": "Redis", "27017": "MongoDB",
                     "9200": "Elasticsearch", "5984": "CouchDB", "11211": "Memcached"}
            fnd.title = f"{names[port.group(1)]} (port {port.group(1)}) open to the internet"
            fnd.description = "An administrative or database port accepts connections from anywhere - a prime target for brute force and exploits."


def scan(f: SourceFile) -> Iterator[Finding]:
    text = f.text()
    yield from _capability_checks(f, text)
    rule_hits = list(run_rules(CONFIG_RULES, f, "config", text))
    if f.ext in TF:
        _remote_admin_ports(rule_hits, text)
    yield from rule_hits
    if _is_dockerfile(f):
        yield from _dockerfile_checks(f, text)
    yield from _workflow_checks(f, text)
    yield from _eol_checks(f, text)
