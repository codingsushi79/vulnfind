"""Dependency context: direct vs transitive, import reachability, typosquats, hygiene checks."""

from __future__ import annotations

import json
import os
import re
from typing import Dict, Iterable, List, Optional, Set

from .models import Finding, Package, Severity as S

# ---------------------------------------------------------------- direct dependencies from sibling manifests

def _toml_section_keys(text: str, header_re: str) -> Set[str]:
    names: Set[str] = set()
    for m in re.finditer(r"(?ms)^\[" + header_re + r"\]\s*$(.*?)(?=^\[|\Z)", text):
        for k in re.finditer(r'(?m)^\s*"?([A-Za-z0-9_.\-]+)"?\s*=', m.group(1)):
            names.add(k.group(1))
    return names


def declared_names(lock_path: str, ecosystem: str) -> Optional[Set[str]]:
    """Names the project declares itself, read from the manifest next to a lockfile."""
    d = os.path.dirname(lock_path)

    def read(name: str) -> Optional[str]:
        try:
            with open(os.path.join(d, name), encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None

    if ecosystem == "npm":
        text = read("package.json")
        if text is None:
            return None
        try:
            data = json.loads(text)
        except ValueError:
            return None
        out: Set[str] = set()
        for sec in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            out |= set((data.get(sec) or {}).keys())
        return out
    if ecosystem == "PyPI":
        out = set()
        py = read("pyproject.toml")
        if py:
            for arr in re.finditer(r"(?ms)^\s*(?:dependencies|dev-dependencies|[\w-]+)\s*=\s*\[(.*?)\]", py):
                for spec in re.findall(r"[\"']([A-Za-z0-9][A-Za-z0-9._\-]*)", arr.group(1)):
                    out.add(spec)
            out |= _toml_section_keys(py, r"tool\.poetry(?:\.group\.[\w-]+)?\.(?:dev-)?dependencies")
        pf = read("Pipfile")
        if pf:
            out |= _toml_section_keys(pf, r"(?:dev-)?packages")
        out.discard("python")
        return {re.sub(r"[-_.]+", "-", n).lower() for n in out} or None
    if ecosystem == "crates.io":
        text = read("Cargo.toml")
        return _toml_section_keys(text, r"(?:[\w.\-]+\.)?(?:dev-|build-)?dependencies") if text else None
    if ecosystem == "Packagist":
        text = read("composer.json")
        try:
            data = json.loads(text) if text else None
        except ValueError:
            return None
        return set((data.get("require") or {})) | set((data.get("require-dev") or {})) if data else None
    if ecosystem == "RubyGems":
        text = read(os.path.basename(lock_path))
        if text and "DEPENDENCIES" in text:
            section = text.split("DEPENDENCIES", 1)[1]
            return set(re.findall(r"(?m)^  ([A-Za-z0-9_.\-]+)", section.split("\n\n", 1)[0]))
        return None
    return None


# ---------------------------------------------------------------- reachability (imports)

PY_IMPORT_NAMES = {
    "pyyaml": "yaml", "pillow": "pil", "beautifulsoup4": "bs4", "scikit-learn": "sklearn", "opencv-python": "cv2",
    "opencv-python-headless": "cv2", "python-dateutil": "dateutil", "pyjwt": "jwt", "python-jose": "jose",
    "pycryptodome": "crypto", "pycryptodomex": "cryptodome", "pymysql": "pymysql", "psycopg2-binary": "psycopg2",
    "python-dotenv": "dotenv", "protobuf": "google", "google-cloud-storage": "google", "grpcio": "grpc",
    "pyopenssl": "openssl", "attrs": "attr", "msgpack-python": "msgpack", "python-multipart": "multipart",
    "websocket-client": "websocket", "markupsafe": "markupsafe", "typing-extensions": "typing_extensions",
    "discord.py": "discord", "python-telegram-bot": "telegram", "slack-sdk": "slack_sdk", "ruamel.yaml": "ruamel",
    "djangorestframework": "rest_framework", "django-cors-headers": "corsheaders", "pygithub": "github",
    "setuptools": "pkg_resources", "jinja2": "jinja2", "pyzmq": "zmq", "pyserial": "serial",
}

IMPORT_PATTERNS = {
    "py": [re.compile(r"(?m)^\s*import\s+([\w.]+(?:\s*,\s*[\w.]+)*)"), re.compile(r"(?m)^\s*from\s+([\w.]+)\s+import\b")],
    "js": [re.compile(r"""require\(\s*['"]([^'"]+)['"]\s*\)"""), re.compile(r"""\bfrom\s+['"]([^'"]+)['"]"""),
           re.compile(r"""\bimport\s+['"]([^'"]+)['"]"""), re.compile(r"""\bimport\(\s*['"]([^'"]+)['"]\s*\)""")],
    "go": [re.compile(r'(?m)^\s*(?:import\s+)?(?:[\w.]+\s+)?"([\w.\-/]+\.[\w.\-/]+)"')],
    "rb": [re.compile(r"""(?m)^\s*require\s+['"]([^'"]+)['"]""")],
    "rs": [re.compile(r"(?m)^\s*(?:pub\s+)?use\s+([a-z_][a-z0-9_]*)::"), re.compile(r"(?m)^\s*extern\s+crate\s+([a-z_][a-z0-9_]*)")],
}
LANG_OF_EXT = {".py": "py", ".pyw": "py", ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js", ".ts": "js", ".tsx": "js",
               ".mts": "js", ".cts": "js", ".vue": "js", ".svelte": "js", ".astro": "js", ".go": "go", ".rb": "rb", ".rs": "rs"}
ECO_LANG = {"PyPI": "py", "npm": "js", "Go": "go", "RubyGems": "rb", "crates.io": "rs"}


def extract_imports(ext: str, text: str) -> Optional[tuple]:
    lang = LANG_OF_EXT.get(ext)
    if not lang:
        return None
    names: Set[str] = set()
    for pat in IMPORT_PATTERNS[lang]:
        for m in pat.finditer(text):
            for raw in m.group(1).split(","):
                raw = raw.strip().split(" as ")[0].strip()
                if not raw:
                    continue
                if lang == "py":
                    names.add(raw.split(".")[0].lower())
                elif lang == "js":
                    if raw.startswith((".", "/", "node:", "~", "@/", "#")):
                        continue
                    parts = raw.split("/")
                    names.add("/".join(parts[:2]) if raw.startswith("@") else parts[0])
                else:
                    names.add(raw.lower() if lang != "go" else raw)
    return lang, names


def is_imported(pkg: Package, imports: Dict[str, Set[str]]) -> Optional[bool]:
    lang = ECO_LANG.get(pkg.ecosystem)
    if not lang or not imports.get(lang):
        return None
    seen = imports[lang]
    name = pkg.name
    if lang == "py":
        n = name.lower()
        candidates = {n, n.replace("-", "_"), n.replace("-", ""), PY_IMPORT_NAMES.get(n, n)}
        candidates |= {c[7:] for c in candidates if c.startswith("python-")}
        candidates |= {c[3:] for c in candidates if c.startswith("py") and len(c) > 4}
        return bool(candidates & seen)
    if lang == "go":
        if name == "stdlib":
            return True
        return any(i == name or i.startswith(name + "/") for i in seen)
    if lang == "rs":
        return name.replace("-", "_").lower() in seen
    if lang == "rb":
        return name.lower() in seen or name.replace("-", "/").lower() in seen
    return name in seen or (name.startswith("@types/") and name[7:] in seen)


# ---------------------------------------------------------------- typosquats

POPULAR = {
    "npm": set("""react react-dom lodash express axios chalk commander debug moment request typescript webpack eslint prettier
jest mocha vue next uuid dotenv yargs async bluebird underscore jquery body-parser cors mongoose mongodb mysql pg redis
socket.io ws jsonwebtoken bcrypt bcryptjs passport nodemailer cheerio puppeteer glob minimist semver rimraf mkdirp fs-extra
colors inquirer ora nodemon rxjs tslib classnames prop-types styled-components tailwindcss postcss autoprefixer sass vite
rollup esbuild svelte zod joi yup dayjs date-fns luxon ramda immutable redux react-redux react-router react-router-dom
graphql sequelize typeorm prisma knex sharp multer helmet morgan winston pino cross-env concurrently husky lint-staged
node-fetch got superagent qs cookie-parser express-session ejs pug handlebars marked three chart.js electron discord.js
stripe aws-sdk firebase crypto-js form-data chokidar js-yaml xml2js validator nanoid cookie http-proxy serve-static
event-stream eslint-scope babel-cli coffee-script nodemailer-smtp-transport mongoose-paginate webpack-cli ts-node
nuxt gatsby angular openai""".split()),
    "PyPI": set("""requests numpy pandas django flask boto3 botocore urllib3 setuptools six python-dateutil pyyaml certifi idna
chardet charset-normalizer cryptography jinja2 markupsafe click pytest scipy matplotlib pillow sqlalchemy psycopg2
psycopg2-binary pymysql redis celery fastapi uvicorn pydantic starlette gunicorn werkzeug aiohttp httpx beautifulsoup4
lxml scrapy selenium tensorflow torch keras scikit-learn opencv-python transformers openai anthropic colorama tqdm rich
typer attrs packaging pip wheel virtualenv docutils sphinx black flake8 mypy pylint isort coverage tox paramiko pyjwt
bcrypt passlib python-dotenv pymongo elasticsearch protobuf grpcio websocket-client websockets pyopenssl rsa pyasn1
simplejson ujson orjson msgpack pytz tzdata arrow pendulum marshmallow alembic jsonschema oauthlib docker kubernetes
ansible fabric pexpect psutil pygments ipython jupyter notebook nltk spacy xgboost lightgbm plotly seaborn bokeh dash
streamlit gradio langchain tweepy twilio stripe sentry-sdk loguru structlog toml tomli pyparsing cffi pycparser wrapt
decorator filelock platformdirs pyserial pygame colorlog termcolor""".split()),
}
# Legitimate, popular names that sit one edit away from another popular name.
NOT_SQUATS = {"preact", "color", "colour", "mysql2", "pg-promise", "nock", "joi", "jsdom", "ws", "chai", "react-native",
              "pytz", "attr", "ipykernel", "pyaml", "dotenv", "flask-cors", "sqlite3", "click", "request", "redux",
              "vitest", "vue-router", "celery", "jest-cli", "pip", "tqdm", "rich", "arrow", "gulp", "grunt", "yarn",
              "redis-py", "pydantic", "jinja", "pymongo", "mongo", "uuid4", "requests-mock", "torchvision", "sharp",
              "socket.io-client", "debug", "dash", "bokeh", "next", "nuxt", "vite", "sass", "less", "pug", "ejs"}


def _distance(a: str, b: str, limit: int = 2) -> int:
    """Damerau-Levenshtein distance (optimal string alignment), early exit above `limit`."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: List[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def typosquat_target(name: str, ecosystem: str) -> Optional[str]:
    popular = POPULAR.get(ecosystem)
    if not popular:
        return None
    n = name.lower()
    if n in popular or n in NOT_SQUATS or len(n) < 5:
        return None
    norm = re.sub(r"[-_.]", "", n)
    for p in popular:
        if len(p) < 5:
            continue
        if norm == re.sub(r"[-_.]", "", p) and ecosystem == "npm":
            return p  # e.g. "cross-env" vs "crossenv" (a real past attack)
        if _distance(n, p, 1) == 1:
            return p
    return None


def typosquat_findings(packages: Iterable[Package]) -> List[Finding]:
    out, seen = [], set()
    for pkg in packages:
        if pkg.direct is False or (pkg.ecosystem, pkg.name) in seen:
            continue
        seen.add((pkg.ecosystem, pkg.name))
        target = typosquat_target(pkg.name, pkg.ecosystem)
        if target:
            out.append(Finding(
                rule_id="DEP-TYPOSQUAT", title=f"Possible typosquat: '{pkg.name}' looks like '{target}'", severity=S.HIGH,
                category="dependency", file=pkg.source, line=pkg.line, snippet=f"{pkg.name}@{pkg.version}",
                description=(f"'{pkg.name}' is one keystroke away from the popular package '{target}'. Attackers publish "
                             "look-alike names that steal credentials or install backdoors at install time."),
                fix=f"Check this is really the package you meant. If you wanted '{target}', replace it and rotate any secrets on machines that installed '{pkg.name}'.",
                cwe="CWE-1357", extra={"package": pkg.name, "version": pkg.version, "ecosystem": pkg.ecosystem, "lookalike": target,
                                       "aliases": ["DEP-TYPOSQUAT"]},
            ))
    return out


# ---------------------------------------------------------------- hygiene

def hygiene_findings(manifest_files: Iterable, used: List[str]) -> List[Finding]:
    out: List[Finding] = []
    by_dir: Dict[str, Set[str]] = {}
    files = list(manifest_files)
    for f in files:
        by_dir.setdefault(os.path.dirname(f.rel), set()).add(f.name)
    from .manifests import NPM_LOCKS
    for f in files:
        siblings = by_dir.get(os.path.dirname(f.rel), set())
        if f.name == "package.json" and not siblings & NPM_LOCKS:
            try:
                data = json.loads(f.text())
            except ValueError:
                continue
            if data.get("dependencies") or data.get("devDependencies"):
                if os.path.isfile(os.path.join(os.path.dirname(f.path), "package-lock.json")):
                    continue
                out.append(Finding(
                    rule_id="DEP-NO-LOCKFILE", title="No lockfile for package.json", severity=S.LOW, category="dependency",
                    file=f.rel, description="Without a committed lockfile every install can resolve different (possibly "
                    "compromised) versions, and vulnerability results are approximate.",
                    fix="Commit package-lock.json / yarn.lock / pnpm-lock.yaml and install with `npm ci`.", cwe="CWE-1357",
                    extra={"aliases": ["DEP-NO-LOCKFILE"]}))
        if f.name.lower().endswith(".txt") and "requirements" in f.name.lower():
            loose = []
            for line in f.text().splitlines():
                s = line.split("#", 1)[0].strip()
                if not s or s.startswith(("-", "git+", "http")):
                    continue
                if "==" not in s and "@" not in s:
                    loose.append(re.split(r"[<>=!~;\[ ]", s)[0])
            if loose:
                out.append(Finding(
                    rule_id="DEP-UNPINNED", title=f"{len(loose)} unpinned Python requirement{'s' if len(loose) > 1 else ''}",
                    severity=S.LOW, category="dependency", file=f.rel, snippet=", ".join(loose[:6]) + (" …" if len(loose) > 6 else ""),
                    description="Unpinned requirements can't be checked for known CVEs and may silently pull a compromised release.",
                    fix="Pin exact versions (pip-compile / uv pip compile / pip freeze) and use --require-hashes for deploys.",
                    cwe="CWE-1357", extra={"aliases": ["DEP-UNPINNED"], "packages": loose}))
    return out
