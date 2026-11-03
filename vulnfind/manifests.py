"""Dependency manifest / lockfile parsers for 10 ecosystems.

Every parser takes (text, rel_path) and returns a list of Package objects.
Lockfiles are preferred: a package.json is only used when no lockfile sits next to it.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Callable, Dict, List, Optional

from .models import Package

_EXACT_VERSION = re.compile(r"^v?\d+(\.\d+)*([-+.][0-9A-Za-z.\-+]+)?$")


def _line_of(text: str, needle: str, start: int = 0) -> Optional[int]:
    pos = text.find(needle, start)
    return text.count("\n", 0, pos) + 1 if pos != -1 else None


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# ---------------------------------------------------------------- npm

def parse_package_lock(text: str, rel: str) -> List[Package]:
    data = json.loads(text)
    pkgs: List[Package] = []
    packages = data.get("packages")
    if isinstance(packages, dict) and packages:
        for key, meta in packages.items():
            if not key or not isinstance(meta, dict) or meta.get("link"):
                continue
            name = meta.get("name") or key.rsplit("node_modules/", 1)[-1]
            version = meta.get("version")
            if not version or not _EXACT_VERSION.match(version):
                continue
            pkgs.append(Package(name, version, "npm", rel, _line_of(text, f'"{key}"'), bool(meta.get("dev"))))
        return pkgs

    def walk_v1(deps: Dict, ) -> None:
        for name, meta in deps.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version", "")
            if _EXACT_VERSION.match(version):
                pkgs.append(Package(name, version, "npm", rel, _line_of(text, f'"{name}"'), bool(meta.get("dev"))))
            if isinstance(meta.get("dependencies"), dict):
                walk_v1(meta["dependencies"])

    walk_v1(data.get("dependencies") or {})
    return pkgs


def _npm_name_from_spec(spec: str) -> str:
    spec = spec.strip().strip('"').strip("'")
    at = spec.find("@", 1)  # skip the leading @ of scoped packages
    return spec[:at] if at > 0 else spec


def parse_yarn_lock(text: str, rel: str) -> List[Package]:
    pkgs: List[Package] = []
    current: Optional[str] = None
    header_line = 0
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace() and line.rstrip().endswith(":"):
            first = line.rstrip()[:-1].split(",")[0]
            current = _npm_name_from_spec(first)
            header_line = lineno
            if "@workspace:" in line or "@link:" in line or "@file:" in line:
                current = None
            continue
        if current:
            m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
            if m:
                version = m.group(1)
                if _EXACT_VERSION.match(version) and "use.local" not in version:
                    pkgs.append(Package(current, version, "npm", rel, header_line))
                current = None
    return pkgs


_PNPM_KEY = re.compile(r"""^ {2}['"]?/?((?:@[^/\s'"]+/)?[^@/\s'"(]+)[@/](\d[^:('"\s]*)""", re.M)


def parse_pnpm_lock(text: str, rel: str) -> List[Package]:
    pkgs: List[Package] = []
    seen = set()
    section = text.find("\npackages:")
    if section == -1:
        return pkgs
    end = text.find("\nsnapshots:", section)
    body_end = end if end != -1 else len(text)
    for m in _PNPM_KEY.finditer(text, section, body_end):
        key = (m.group(1), m.group(2))
        if key in seen:
            continue
        seen.add(key)
        pkgs.append(Package(m.group(1), m.group(2), "npm", rel, text.count("\n", 0, m.start()) + 1))
    return pkgs


_BUN_ENTRY = re.compile(r'^\s*"[^"]+":\s*\[\s*"((?:@[^/"]+/)?[^@"]+)@(\d[^"]*)"', re.M)


def parse_bun_lock(text: str, rel: str) -> List[Package]:
    return [
        Package(m.group(1), m.group(2), "npm", rel, text.count("\n", 0, m.start()) + 1)
        for m in _BUN_ENTRY.finditer(text)
    ]


def parse_package_json(text: str, rel: str) -> List[Package]:
    data = json.loads(text)
    pkgs: List[Package] = []
    for section, dev in (("dependencies", False), ("devDependencies", True), ("optionalDependencies", False)):
        for name, spec in (data.get(section) or {}).items():
            if not isinstance(spec, str):
                continue
            m = re.match(r"^\s*(?:[\^~=]|>=)?\s*v?(\d+\.\d+\.\d+[0-9A-Za-z.\-+]*)\s*$", spec)
            if m:
                pkgs.append(Package(name, m.group(1), "npm", rel, _line_of(text, f'"{name}"'), dev,
                                    approximate=spec.strip()[0] in "^~>"))
    return pkgs


# ---------------------------------------------------------------- Python

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([0-9][^\s;#,\\]*)")


def parse_requirements(text: str, rel: str) -> List[Package]:
    pkgs = []
    for lineno, line in enumerate(text.splitlines(), 1):
        m = _REQ_LINE.match(line)
        if m:
            pkgs.append(Package(_pep503(m.group(1)), m.group(2), "PyPI", rel, lineno))
    return pkgs


def parse_pipfile_lock(text: str, rel: str) -> List[Package]:
    data = json.loads(text)
    pkgs = []
    for section, dev in (("default", False), ("develop", True)):
        for name, meta in (data.get(section) or {}).items():
            version = (meta or {}).get("version", "")
            if version.startswith("=="):
                pkgs.append(Package(_pep503(name), version[2:], "PyPI", rel, _line_of(text, f'"{name}"'), dev))
    return pkgs


_TOML_PACKAGE = re.compile(
    r'^\[\[package\]\]\s*\n(?:(?!\[).*\n)*?name\s*=\s*"([^"]+)"\s*\n(?:(?!\[).*\n)*?version\s*=\s*"([^"]+)"', re.M
)


def _toml_packages(text: str, rel: str, ecosystem: str, normalize: Callable[[str], str] = str) -> List[Package]:
    pkgs = []
    for m in _TOML_PACKAGE.finditer(text):
        pkgs.append(Package(normalize(m.group(1)), m.group(2), ecosystem, rel, text.count("\n", 0, m.start()) + 1))
    return pkgs


def parse_poetry_lock(text: str, rel: str) -> List[Package]:
    return _toml_packages(text, rel, "PyPI", _pep503)


def parse_cargo_lock(text: str, rel: str) -> List[Package]:
    # Skip local workspace crates (no "source" field) - they are not published.
    pkgs = []
    for block in re.split(r"(?m)^\[\[package\]\]\s*$", text)[1:]:
        name = re.search(r'(?m)^name\s*=\s*"([^"]+)"', block)
        version = re.search(r'(?m)^version\s*=\s*"([^"]+)"', block)
        if name and version and re.search(r"(?m)^source\s*=", block):
            pkgs.append(Package(name.group(1), version.group(1), "crates.io", rel,
                                _line_of(text, f'name = "{name.group(1)}"')))
    return pkgs


# ---------------------------------------------------------------- Go

def parse_go_mod(text: str, rel: str) -> List[Package]:
    pkgs = []
    in_block = False
    replaced = set()
    for line in text.splitlines():
        m = re.match(r"^\s*(?:replace\s+)?(\S+)(?:\s+v\S+)?\s+=>", line)
        if m:
            replaced.add(m.group(1))
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("//", 1)[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        m = None
        if in_block:
            m = re.match(r"^(\S+)\s+(v\S+)", line)
        elif line.startswith("require "):
            m = re.match(r"^require\s+(\S+)\s+(v\S+)", line)
        if m and m.group(1) not in replaced:
            pkgs.append(Package(m.group(1), m.group(2).lstrip("v").replace("+incompatible", ""), "Go", rel, lineno,
                                dev="// indirect" in raw))
    # Go standard library, only when a precise toolchain version is pinned.
    tc = re.search(r"(?m)^toolchain\s+go(\d+\.\d+\.\d+)", text) or re.search(r"(?m)^go\s+(\d+\.\d+\.\d+)\s*$", text)
    if tc:
        pkgs.append(Package("stdlib", tc.group(1), "Go", rel, text.count("\n", 0, tc.start()) + 1))
    return pkgs


# ---------------------------------------------------------------- Ruby / PHP

def parse_gemfile_lock(text: str, rel: str) -> List[Package]:
    pkgs = []
    in_specs = False
    for lineno, line in enumerate(text.splitlines(), 1):
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and line and not line.startswith(" "):
            in_specs = False
        if in_specs:
            m = re.match(r"^ {4}([A-Za-z0-9_.\-]+) \(([^)\s]+)\)", line)
            if m:
                version = m.group(2).split("-")[0] if re.search(r"-(x86|arm|java|universal|aarch)", m.group(2)) else m.group(2)
                pkgs.append(Package(m.group(1), version, "RubyGems", rel, lineno))
    return pkgs


def parse_composer_lock(text: str, rel: str) -> List[Package]:
    data = json.loads(text)
    pkgs = []
    for section, dev in (("packages", False), ("packages-dev", True)):
        for meta in data.get(section) or []:
            name, version = meta.get("name"), str(meta.get("version", "")).lstrip("v")
            if name and _EXACT_VERSION.match(version):
                pkgs.append(Package(name, version, "Packagist", rel, _line_of(text, f'"name": "{name}"'), dev))
    return pkgs


# ---------------------------------------------------------------- JVM / .NET

def parse_pom(text: str, rel: str) -> List[Package]:
    # Strip the default namespace so ElementTree paths stay simple.
    cleaned = re.sub(r'\sxmlns(:\w+)?="[^"]+"', "", text, count=5)
    try:
        root = ET.fromstring(cleaned)
    except ET.ParseError:
        return []
    props = {}
    for p in root.findall("./properties/*"):
        props[p.tag] = (p.text or "").strip()
    for tag in ("version", "groupId"):
        el = root.find(tag) if root.find(tag) is not None else root.find(f"parent/{tag}")
        if el is not None and el.text:
            props[f"project.{tag}"] = el.text.strip()

    def resolve(v: str) -> str:
        for _ in range(5):
            m = re.search(r"\$\{([^}]+)\}", v)
            if not m or m.group(1) not in props:
                break
            v = v.replace(m.group(0), props[m.group(1)])
        return v

    pkgs = []
    for dep in root.iter("dependency"):
        g, a, v = (dep.findtext(x) for x in ("groupId", "artifactId", "version"))
        if not (g and a and v):
            continue
        v = resolve(v.strip())
        if "${" in v or not _EXACT_VERSION.match(v):
            continue
        scope = (dep.findtext("scope") or "").strip()
        pkgs.append(Package(f"{resolve(g.strip())}:{a.strip()}", v, "Maven", rel,
                            _line_of(text, f"<artifactId>{a.strip()}</artifactId>"), scope == "test"))
    return pkgs


def parse_gradle_lockfile(text: str, rel: str) -> List[Package]:
    pkgs = []
    for lineno, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^([^:#\s]+):([^:\s]+):([^=\s]+)=", line)
        if m:
            pkgs.append(Package(f"{m.group(1)}:{m.group(2)}", m.group(3), "Maven", rel, lineno))
    return pkgs


def parse_csproj(text: str, rel: str) -> List[Package]:
    pkgs = []
    for m in re.finditer(r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"', text):
        if _EXACT_VERSION.match(m.group(2)):
            pkgs.append(Package(m.group(1), m.group(2), "NuGet", rel, text.count("\n", 0, m.start()) + 1))
    for m in re.finditer(r'<package\s+id="([^"]+)"\s+version="([^"]+)"', text):
        pkgs.append(Package(m.group(1), m.group(2), "NuGet", rel, text.count("\n", 0, m.start()) + 1))
    return pkgs


def parse_nuget_lock(text: str, rel: str) -> List[Package]:
    data = json.loads(text)
    pkgs, seen = [], set()
    for framework in (data.get("dependencies") or {}).values():
        for name, meta in framework.items():
            version = (meta or {}).get("resolved")
            if version and (name, version) not in seen and meta.get("type") != "Project":
                seen.add((name, version))
                pkgs.append(Package(name, version, "NuGet", rel, _line_of(text, f'"{name}"')))
    return pkgs


# ---------------------------------------------------------------- Dart / Elixir

def parse_pubspec_lock(text: str, rel: str) -> List[Package]:
    pkgs = []
    name = None
    name_line = 0
    hosted = False
    for lineno, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^  ([A-Za-z0-9_]+):\s*$", line)
        if m:
            name, name_line, hosted = m.group(1), lineno, False
            continue
        if name and re.match(r'^    source:\s*"?hosted', line):
            hosted = True
        vm = re.match(r'^    version:\s*"?([^"\s]+)"?', line)
        if name and vm:
            if hosted:
                pkgs.append(Package(name, vm.group(1), "Pub", rel, name_line))
            name = None
    return pkgs


def parse_mix_lock(text: str, rel: str) -> List[Package]:
    return [
        Package(m.group(1), m.group(2), "Hex", rel, text.count("\n", 0, m.start()) + 1)
        for m in re.finditer(r'"([a-z0-9_]+)":\s*\{:hex,\s*:[a-z0-9_]+,\s*"([^"]+)"', text)
    ]


# ---------------------------------------------------------------- registry

LOCKFILES: Dict[str, Callable[[str, str], List[Package]]] = {
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "bun.lock": parse_bun_lock,
    "Pipfile.lock": parse_pipfile_lock,
    "poetry.lock": parse_poetry_lock,
    "uv.lock": parse_poetry_lock,
    "pdm.lock": parse_poetry_lock,
    "go.mod": parse_go_mod,
    "Cargo.lock": parse_cargo_lock,
    "Gemfile.lock": parse_gemfile_lock,
    "composer.lock": parse_composer_lock,
    "pom.xml": parse_pom,
    "gradle.lockfile": parse_gradle_lockfile,
    "packages.lock.json": parse_nuget_lock,
    "packages.config": parse_csproj,
    "pubspec.lock": parse_pubspec_lock,
    "mix.lock": parse_mix_lock,
}

NPM_LOCKS = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"}


def parser_for(filename: str) -> Optional[Callable[[str, str], List[Package]]]:
    if filename in LOCKFILES:
        return LOCKFILES[filename]
    if filename == "package.json":
        return parse_package_json
    low = filename.lower()
    if low.endswith((".csproj", ".fsproj", ".vbproj")):
        return parse_csproj
    if low.endswith(".txt") and ("requirements" in low or low.startswith("constraints")):
        return parse_requirements
    return None
