"""Hard-coded secret detection: 35+ provider-specific token formats plus generic
password/key assignments filtered by entropy and placeholder heuristics."""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Iterator, List

from ..models import Finding, Severity as S
from ..walker import SourceFile
from . import Rule, run_rules

SKIP_NAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "Cargo.lock",
    "poetry.lock", "Pipfile.lock", "composer.lock", "Gemfile.lock", "go.sum", "uv.lock", "pdm.lock",
    "packages.lock.json", "gradle.lockfile", "pubspec.lock", "mix.lock",
}
SKIP_SUFFIXES = (".min.js", ".min.css", ".map", ".svg", ".lock")

FIX = "Revoke/rotate this credential now, purge it from git history (git filter-repo / BFG), and load it from an environment variable or secret manager."

PLACEHOLDER = re.compile(
    r"^(?:x+|\*+|\.+|-+|_+|0+|changeit|example\w*|sample\w*|dummy\w*|fake\w*|placeholder\w*|your[_-]?\w*|my[_-]?\w*|"
    r"test\w*|todo|tbd|none|null|nil|undefined|true|false|secret|password|passwd|redacted|insert\w*|replace\w*|"
    r"enter\w*|<[^>]*>|\{\{.*\}\}|\$\{.*\}|\$\(.*\)|%\(.*\)s|%s|\$[A-Z_]+|\{[a-z_]+\})$",
    re.I,
)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _real_value(value: str) -> bool:
    v = value.strip()
    if PLACEHOLDER.match(v):
        return False
    low = v.lower()
    if any(t in low for t in ("example", "xxxx", "****", "changeme_", "your_", "your-", "<", "${", "{{", "process.env",
                               "os.environ", "getenv", "env(", "dummy", "placeholder")):
        return False
    return True


def _group_is_real(group: int = 1, min_entropy: float = 0.0):
    def check(m: "re.Match[str]", line: str) -> bool:
        value = m.group(group)
        return _real_value(value) and entropy(value) >= min_entropy
    return check


def _generic_check(m: "re.Match[str]", line: str) -> bool:
    key, value = m.group(1).lower(), m.group(2)
    if not _real_value(value) or len(set(value)) < 4:
        return False
    if re.search(r"\b(?:function|def|return|lambda|=>)\b", line):
        return False
    if "pass" in key or "pwd" in key:
        return True
    # API keys / tokens: require a random-looking value.
    return entropy(value) >= 3.5 and len(value) >= 12


_URL_HOST = re.compile(r"@\[?([A-Za-z0-9.\-_:]+?)\]?(?::\d+)?(?:[/?#'\"\s]|$)")
_PLACEHOLDER_HOSTS = re.compile(r"^(?:host|hostname|your[-_.]?\w*|example\.\w+|.*\.example\.\w+|server|domain|<.*>)$", re.I)
_LOCAL_HOSTS = re.compile(r"^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1|host\.docker\.internal|db|database|postgres|postgresql|mysql|mariadb|mongo|mongodb|redis|rabbitmq)$", re.I)


def _url_check(m: "re.Match[str]", line: str) -> bool:
    if not _real_value(m.group(1)):
        return False
    host = _URL_HOST.search(m.group(0))
    return not (host and _PLACEHOLDER_HOSTS.match(host.group(1)))


def mask(value: str) -> str:
    if len(value) <= 8:
        return value[:2] + "*" * (len(value) - 2)
    return value[:4] + "*" * min(len(value) - 6, 24) + value[-2:]


R = Rule
SECRET_RULES: List[Rule] = [
    R("SECRET-PRIVATE-KEY", "Private key", S.CRITICAL,
      r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED |SSH2 )?PRIVATE KEY(?: BLOCK)?-----",
      "A private key is committed to the repository. Anyone with read access can impersonate the key owner.", FIX, "CWE-321"),
    R("SECRET-AWS-ACCESS-KEY", "AWS access key ID", S.HIGH,
      r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b",
      "AWS access key ID found. Paired with its secret key it grants API access to the AWS account.", FIX, "CWE-798",
      validate=lambda m, l: "EXAMPLE" not in m.group(1)),
    R("SECRET-AWS-SECRET-KEY", "AWS secret access key", S.CRITICAL,
      r"(?i)aws.{0,25}?(?:secret|private).{0,25}?['\"=:\s]([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])",
      "AWS secret access key found - full programmatic access to the AWS account.", FIX, "CWE-798",
      validate=_group_is_real(1, 4.0)),
    R("SECRET-GITHUB-TOKEN", "GitHub token", S.CRITICAL,
      r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b",
      "GitHub personal access / OAuth / app token found.", FIX, "CWE-798"),
    R("SECRET-GITLAB-TOKEN", "GitLab token", S.CRITICAL, r"\b(glpat-[A-Za-z0-9_\-]{20,})\b",
      "GitLab personal access token found.", FIX, "CWE-798"),
    R("SECRET-SLACK-TOKEN", "Slack token", S.HIGH, r"\b(xox[baprse]-[A-Za-z0-9-]{10,})\b",
      "Slack API token found.", FIX, "CWE-798"),
    R("SECRET-SLACK-WEBHOOK", "Slack incoming webhook", S.MEDIUM,
      r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)",
      "Slack webhook URL found - anyone can post messages to the channel.", FIX, "CWE-798"),
    R("SECRET-DISCORD-WEBHOOK", "Discord webhook", S.MEDIUM,
      r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+)",
      "Discord webhook URL found.", FIX, "CWE-798"),
    R("SECRET-STRIPE-LIVE", "Stripe live secret key", S.CRITICAL, r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b",
      "Stripe live secret key - can create charges and read customer data.", FIX, "CWE-798"),
    R("SECRET-STRIPE-TEST", "Stripe test secret key", S.LOW, r"\b(sk_test_[0-9a-zA-Z]{24,})\b",
      "Stripe test-mode key. Not directly exploitable but should still not be committed.", FIX, "CWE-798"),
    R("SECRET-GOOGLE-API-KEY", "Google API key", S.HIGH, r"\b(AIza[0-9A-Za-z\-_]{35})\b",
      "Google API key found. Restrict it by referrer/IP and API scope, or rotate it.", FIX, "CWE-798"),
    R("SECRET-GOOGLE-OAUTH-SECRET", "Google OAuth client secret", S.HIGH, r"\b(GOCSPX-[A-Za-z0-9_\-]{28})\b",
      "Google OAuth client secret found.", FIX, "CWE-798"),
    R("SECRET-GCP-SERVICE-ACCOUNT", "GCP service account key", S.CRITICAL, r'"type"\s*:\s*"service_account"',
      "Google Cloud service-account JSON key file found.", FIX, "CWE-798", exts=(".json",)),
    R("SECRET-OPENAI-KEY", "OpenAI API key", S.HIGH,
      r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}|sk-proj-[A-Za-z0-9_\-]{80,})\b",
      "OpenAI API key found - usage is billed to the key owner.", FIX, "CWE-798"),
    R("SECRET-ANTHROPIC-KEY", "Anthropic API key", S.HIGH, r"\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,})",
      "Anthropic API key found - usage is billed to the key owner.", FIX, "CWE-798"),
    R("SECRET-HUGGINGFACE", "Hugging Face token", S.HIGH, r"\b(hf_[A-Za-z]{34,})\b",
      "Hugging Face access token found.", FIX, "CWE-798"),
    R("SECRET-NPM-TOKEN", "npm access token", S.CRITICAL, r"\b(npm_[A-Za-z0-9]{36})\b",
      "npm token found - can publish packages as you (supply-chain risk).", FIX, "CWE-798"),
    R("SECRET-NPMRC-AUTH", "npm registry auth token", S.HIGH, r"_auth(?:Token)?\s*=\s*([^\s$]{16,})",
      "Registry credential in .npmrc.", FIX, "CWE-798", names=(".npmrc",), validate=_group_is_real(1)),
    R("SECRET-PYPI-TOKEN", "PyPI upload token", S.CRITICAL, r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})",
      "PyPI API token found - can publish packages as you (supply-chain risk).", FIX, "CWE-798"),
    R("SECRET-SENDGRID", "SendGrid API key", S.HIGH, r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b",
      "SendGrid API key found - can send email as your domain.", FIX, "CWE-798"),
    R("SECRET-MAILGUN", "Mailgun API key", S.HIGH, r"\b(key-[0-9a-f]{32})\b",
      "Mailgun API key found.", FIX, "CWE-798"),
    R("SECRET-TWILIO", "Twilio API key", S.HIGH, r"\b(SK[0-9a-f]{32})\b",
      "Twilio API key SID found.", FIX, "CWE-798"),
    R("SECRET-TELEGRAM-BOT", "Telegram bot token", S.MEDIUM, r"\b(\d{8,10}:AA[0-9A-Za-z_\-]{33})\b",
      "Telegram bot token found.", FIX, "CWE-798"),
    R("SECRET-SHOPIFY", "Shopify access token", S.HIGH, r"\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b",
      "Shopify access token found.", FIX, "CWE-798"),
    R("SECRET-SQUARE", "Square access token", S.HIGH, r"\b(sq0(?:atp|csp)-[0-9A-Za-z\-_]{22,43})\b",
      "Square access token / OAuth secret found.", FIX, "CWE-798"),
    R("SECRET-DIGITALOCEAN", "DigitalOcean token", S.HIGH, r"\b(do[opr]_v1_[a-f0-9]{64})\b",
      "DigitalOcean API token found.", FIX, "CWE-798"),
    R("SECRET-DATABRICKS", "Databricks token", S.HIGH, r"\b(dapi[a-f0-9]{32}(?:-\d)?)\b",
      "Databricks personal access token found.", FIX, "CWE-798"),
    R("SECRET-AZURE-STORAGE", "Azure storage account key", S.CRITICAL,
      r"AccountKey=([A-Za-z0-9+/=]{86,88})", "Azure Storage connection string with account key.", FIX, "CWE-798"),
    R("SECRET-HEROKU", "Heroku API key", S.HIGH,
      r"(?i)heroku.{0,20}?['\"=:\s]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
      "Heroku API key found.", FIX, "CWE-798"),
    R("SECRET-DOCKERHUB", "Docker Hub access token", S.HIGH, r"\b(dckr_pat_[A-Za-z0-9_\-]{27,})",
      "Docker Hub personal access token - can push images as you (supply-chain risk).", FIX, "CWE-798"),
    R("SECRET-VAULT", "HashiCorp Vault token", S.CRITICAL, r"\b(hvs\.[A-Za-z0-9_\-]{90,}|hvb\.[A-Za-z0-9_\-]{90,})",
      "HashiCorp Vault service/batch token.", FIX, "CWE-798"),
    R("SECRET-TERRAFORM-CLOUD", "Terraform Cloud token", S.HIGH, r"\b([a-zA-Z0-9]{14}\.atlasv1\.[A-Za-z0-9\-_=]{60,70})",
      "Terraform Cloud/Enterprise API token.", FIX, "CWE-798"),
    R("SECRET-PULUMI", "Pulumi access token", S.HIGH, r"\b(pul-[a-f0-9]{40})\b", "Pulumi access token.", FIX, "CWE-798"),
    R("SECRET-GRAFANA", "Grafana token", S.HIGH, r"\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}|glc_[A-Za-z0-9+/]{32,}={0,2})",
      "Grafana service account / Cloud token.", FIX, "CWE-798"),
    R("SECRET-SENTRY", "Sentry auth token", S.HIGH, r"\b(sntry[us]_[A-Za-z0-9+/=_\-]{50,})", "Sentry auth token.", FIX, "CWE-798"),
    R("SECRET-NEWRELIC", "New Relic key", S.HIGH, r"\b(NRAK-[A-Z0-9]{27}|NRII-[A-Za-z0-9\-]{32})\b", "New Relic API key.", FIX, "CWE-798"),
    R("SECRET-NOTION", "Notion integration token", S.HIGH, r"\b(ntn_[A-Za-z0-9]{46}|secret_[A-Za-z0-9]{43})\b",
      "Notion integration secret.", FIX, "CWE-798"),
    R("SECRET-ATLASSIAN", "Atlassian API token", S.HIGH, r"\b(ATATT3[A-Za-z0-9_\-=]{150,})", "Atlassian (Jira/Confluence) API token.", FIX, "CWE-798"),
    R("SECRET-LINEAR", "Linear API key", S.HIGH, r"\b(lin_api_[A-Za-z0-9]{40})\b", "Linear API key.", FIX, "CWE-798"),
    R("SECRET-POSTMAN", "Postman API key", S.HIGH, r"\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})\b", "Postman API key.", FIX, "CWE-798"),
    R("SECRET-DOPPLER", "Doppler token", S.HIGH, r"\b(dp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,44})\b", "Doppler token.", FIX, "CWE-798"),
    R("SECRET-AGE-KEY", "age encryption secret key", S.CRITICAL, r"\b(AGE-SECRET-KEY-1[0-9A-Z]{58})\b",
      "age private key - decrypts everything encrypted to it (e.g. SOPS files).", FIX, "CWE-321"),
    R("SECRET-MAPBOX", "Mapbox secret token", S.HIGH, r"\b(sk\.eyJ[A-Za-z0-9_\-]{60,}\.[A-Za-z0-9_\-]{20,})", "Mapbox secret access token.", FIX, "CWE-798"),
    R("SECRET-JWT", "JSON Web Token", S.MEDIUM,
      r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})",
      "A signed JWT is hard-coded. If it is long-lived it acts as a bearer credential.", FIX, "CWE-798"),
    R("SECRET-DB-URL", "Database URL with password", S.HIGH,
      r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver)://[^\s:/@'\"]+:([^\s@'\"/]{3,})@[^\s'\"]+",
      "Connection string embeds a database password.", FIX, "CWE-798", validate=_url_check),
    R("SECRET-URL-CREDENTIALS", "Credentials in URL", S.MEDIUM,
      r"\bhttps?://[A-Za-z0-9._%\-]+:([^\s@'\"/]{3,})@[A-Za-z0-9.\-]+",
      "HTTP(S) URL with embedded username:password.", FIX, "CWE-798", validate=_url_check),
    R("SECRET-DOTENV", "Credential in env file", S.MEDIUM,
      r"^[ \t]*(?:export[ \t]+)?([A-Za-z0-9_]*(?:PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY|AUTH)[A-Za-z0-9_]*)[ \t]*=[ \t]*[\"']?([^\s\"'#]{6,})",
      "A credential is stored in an environment file.", FIX, "CWE-798", names=(".env", ".env.*", "*.env", ".envrc"),
      validate=_group_is_real(2)),
    R("SECRET-GENERIC", "Hard-coded credential", S.MEDIUM,
      r"""(?i)\b((?:db_|admin_|root_|app_|client_|api_|secret_)?(?:password|passwd|pwd|secret|secret_key|api[_-]?key|apikey|access[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|signing[_-]?key|encryption[_-]?key))["']?\s*(?:[:=]|:=|=>)\s*[bfru]?["']([^"'\s]{6,})["']""",
      "A credential-looking value is assigned in source code.", FIX, "CWE-798", validate=_generic_check),
]

KEYWORDS = {
    "SECRET-PRIVATE-KEY": ("private key",), "SECRET-AWS-ACCESS-KEY": ("akia", "asia", "abia", "acca"),
    "SECRET-AWS-SECRET-KEY": ("aws",), "SECRET-GITHUB-TOKEN": ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
    "SECRET-GITLAB-TOKEN": ("glpat-",), "SECRET-SLACK-TOKEN": ("xox",), "SECRET-SLACK-WEBHOOK": ("hooks.slack.com",),
    "SECRET-DISCORD-WEBHOOK": ("discord",), "SECRET-STRIPE-LIVE": ("_live_",), "SECRET-STRIPE-TEST": ("sk_test_",),
    "SECRET-GOOGLE-API-KEY": ("aiza",), "SECRET-GOOGLE-OAUTH-SECRET": ("gocspx-",),
    "SECRET-GCP-SERVICE-ACCOUNT": ("service_account",), "SECRET-OPENAI-KEY": ("sk-",), "SECRET-ANTHROPIC-KEY": ("sk-ant-",),
    "SECRET-HUGGINGFACE": ("hf_",), "SECRET-NPM-TOKEN": ("npm_",), "SECRET-NPMRC-AUTH": ("_auth",),
    "SECRET-PYPI-TOKEN": ("pypi-",), "SECRET-SENDGRID": ("sg.",), "SECRET-MAILGUN": ("key-",), "SECRET-TWILIO": ("sk",),
    "SECRET-TELEGRAM-BOT": (":aa",), "SECRET-SHOPIFY": ("shpat_", "shpca_", "shppa_", "shpss_"), "SECRET-SQUARE": ("sq0",),
    "SECRET-DIGITALOCEAN": ("_v1_",), "SECRET-DATABRICKS": ("dapi",), "SECRET-AZURE-STORAGE": ("accountkey=",),
    "SECRET-HEROKU": ("heroku",), "SECRET-JWT": ("eyj",), "SECRET-DB-URL": ("://",), "SECRET-URL-CREDENTIALS": ("://",),
    "SECRET-DOCKERHUB": ("dckr_pat_",), "SECRET-VAULT": ("hvs.", "hvb."), "SECRET-TERRAFORM-CLOUD": (".atlasv1.",),
    "SECRET-PULUMI": ("pul-",), "SECRET-GRAFANA": ("glsa_", "glc_"), "SECRET-SENTRY": ("sntry",), "SECRET-NEWRELIC": ("nrak-", "nrii-"),
    "SECRET-NOTION": ("ntn_", "secret_"), "SECRET-ATLASSIAN": ("atatt3",), "SECRET-LINEAR": ("lin_api_",), "SECRET-POSTMAN": ("pmak-",),
    "SECRET-DOPPLER": ("dp.",), "SECRET-AGE-KEY": ("age-secret-key",), "SECRET-MAPBOX": ("sk.eyj",),
    "SECRET-GENERIC": ("pass", "pwd", "secret", "key", "token"),
}

# Secrets inside comments are still leaked secrets.
for _r in SECRET_RULES:
    _r.keywords = KEYWORDS.get(_r.id, ())
    _r.skip_comments = False
    _r.skip_strings = False


def _secret_snippet(line: str, m: "re.Match[str]") -> str:
    """Never print a full secret: mask the captured value in the snippet."""
    value = m.group(m.lastindex) if m.lastindex else m.group(0)
    if len(value) >= 6 and "PRIVATE KEY" not in value and "service_account" not in value:
        line = line.replace(value, mask(value))
    return line.strip()


def scan(f: SourceFile) -> Iterator[Finding]:
    if f.name in SKIP_NAMES or f.name.lower().endswith(SKIP_SUFFIXES):
        return
    text = f.text()
    if len(text) > 5000 and text.count("\n") < len(text) / 1000:
        return  # minified / generated bundle: one enormous line
    seen = set()
    for finding in run_rules(SECRET_RULES, f, "secret", text, _secret_snippet):
        key = finding.line
        if key in seen:
            continue  # several rules matched the same secret; first (most specific) wins
        seen.add(key)
        if finding.rule_id in ("SECRET-DB-URL", "SECRET-URL-CREDENTIALS"):
            host = _URL_HOST.search(finding.snippet or "")
            if host and _LOCAL_HOSTS.match(host.group(1)):
                finding.severity = S.LOW
                finding.extra["context"] = "local/dev host - likely a development default, but don't reuse it elsewhere"
        yield finding
