"""Container image scanning: `vulnfind image nginx:1.21` or `vulnfind image saved.tar`.

Reads a `docker save` / OCI tarball layer by layer (honouring whiteouts) without running
anything, and extracts:
- OS packages: dpkg (Debian/Ubuntu, incl. distroless status.d), apk (Alpine), rpm sqlite db
  (AlmaLinux/Rocky/RHEL family) -> OSV distro advisories
- language packages: node_modules, Python site-packages, Java JARs (incl. nested fat JARs),
  plus any lockfiles shipped in the image
- secrets and credential files left in the filesystem
- image config: root user, secrets in ENV, exposed SSH, end-of-life base OS, stale image
"""

from __future__ import annotations

import io
import json
import os
import re
import sqlite3
import struct
import subprocess
import tarfile
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

from . import osv
from .manifests import parser_for
from .models import Finding, Package, ScanResult, Severity as S
from .progress import NULL, Progress

OS_RELEASE = ("etc/os-release", "usr/lib/os-release")
DPKG = "var/lib/dpkg/status"
DPKG_D = "var/lib/dpkg/status.d/"
APK = "lib/apk/db/installed"
RPM_SQLITE = ("var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite")
NODE_PKG = re.compile(r"(?:^|/)node_modules/((?:@[^/]+/)?[^/@]+)/package\.json$")
PY_DIST = re.compile(r"(?:^|/)(?:site|dist)-packages/([A-Za-z0-9_.]+?)-([0-9][^/]*?)\.(?:dist-info|egg-info)(?:/|$)")
SYSTEM_PREFIX = ("usr/", "lib/", "lib64/", "bin/", "sbin/", "etc/ssl/", "etc/pki/", "var/lib/", "var/cache/", "proc/", "sys/", "opt/java/")
SECRET_NAMES = re.compile(r"(?:^|/)(?:\.env(?:\.[\w.-]+)?|id_rsa|id_ed25519|id_ecdsa|\.git-credentials|\.npmrc|\.pypirc|credentials|"
                          r"config\.json|\.netrc|\.pgpass|[^/]+\.(?:pem|key|p12|pfx))$")
LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "poetry.lock", "Pipfile.lock", "uv.lock",
             "Gemfile.lock", "composer.lock", "go.mod", "Cargo.lock"}
MAX_FILE = 4 * 1024 * 1024
MAX_JAR = 1024 * 1024 * 1024  # streamed via zipfile, not loaded into memory
MAX_BINARY = 400 * 1024 * 1024
EXEC_DIRS = ("usr/bin/", "usr/sbin/", "usr/local/bin/", "usr/local/sbin/", "bin/", "sbin/", "app/", "opt/", "usr/local/apache2/bin/",
             "usr/share/grafana/bin/", "go/bin/", "root/go/bin/", "usr/local/lib/", "usr/lib/", "lib/")
# version strings compiled into server binaries / libraries that weren't installed by a package manager
BINARY_FINGERPRINTS = [
    (re.compile(r"(?:^|/)(?:httpd|apache2)$"), "apache", re.compile(rb"Apache/(2\.\d+\.\d+)")),
    (re.compile(r"(?:^|/)nginx$"), "nginx", re.compile(rb"nginx/(\d+\.\d+\.\d+)")),
    (re.compile(r"(?:^|/)php(?:-fpm)?\d*(?:\.\d+)?$"), "php", re.compile(rb"X-Powered-By: PHP/(\d+\.\d+\.\d+)|PHP/(\d+\.\d+\.\d+)")),
    (re.compile(r"(?:^|/)node$"), "node", re.compile(rb"node/v(\d+\.\d+\.\d+)|https://nodejs\.org/download/release/v(\d+\.\d+\.\d+)")),
    (re.compile(r"(?:^|/)redis-server$"), "redis", re.compile(rb"redis_version:%s|Redis version=(\d+\.\d+\.\d+)|\x00(\d+\.\d+\.\d+)\x00[^\x00]*redis")),
    (re.compile(r"(?:^|/)(?:postgres|postmaster)$"), "postgresql", re.compile(rb"PostgreSQL (\d+\.\d+(?:\.\d+)?)")),
    (re.compile(r"(?:^|/)libssl\.so[.\d]*$"), "openssl", re.compile(rb"OpenSSL (\d+\.\d+\.\d+[a-z]?) ")),
]
GO_BUILDINFO = b"\xff Go buildinf:"
GO_MODLINE = re.compile(rb"(?m)^(mod|dep)\t([^\t\s]+)\t(v[^\t\s]+)")


@dataclass
class ImageFS:
    """The small subset of the final filesystem that we care about."""
    files: Dict[str, bytes] = field(default_factory=dict)
    node: Dict[str, Tuple[str, str]] = field(default_factory=dict)  # path -> (name, version)
    python: Dict[str, Tuple[str, str]] = field(default_factory=dict)
    jars: Dict[str, List[Tuple[str, str]]] = field(default_factory=dict)  # path -> [(group:artifact, version)]
    gobins: Dict[str, Tuple[Optional[str], List[Tuple[str, str]]]] = field(default_factory=dict)  # path -> (go version, modules)
    binaries: Dict[str, Tuple[str, str]] = field(default_factory=dict)  # path -> (product key, version)
    paths: int = 0

    def remove(self, path: str, opaque_dir: bool = False) -> None:
        for store in (self.files, self.node, self.python, self.jars, self.gobins, self.binaries):
            for k in [k for k in store if k == path or k.startswith(path.rstrip("/") + "/")]:
                if opaque_dir and k == path:
                    continue
                del store[k]


def _interesting(path: str) -> Optional[str]:
    if path in OS_RELEASE or path == DPKG or path.startswith(DPKG_D) or path == APK or path in RPM_SQLITE:
        return "os"
    if NODE_PKG.search(path):
        return "node"
    if path.endswith(".jar") or path.endswith(".war"):
        return "jar"
    name = path.rsplit("/", 1)[-1]
    if "node_modules/" in path:
        return None
    if name in LOCKFILES and not path.startswith(SYSTEM_PREFIX):
        return "lock"
    if SECRET_NAMES.search(path) and not path.startswith(SYSTEM_PREFIX):
        return "secret"
    return None


def _jar_coords(data, depth: int = 0) -> List[Tuple[str, str]]:
    """Maven coordinates inside a JAR (bytes or a seekable file object); one level of nested JARs."""
    out: List[Tuple[str, str]] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data) if isinstance(data, bytes) else data)
    except (zipfile.BadZipFile, OSError, ValueError):
        return out
    with zf:
        for info in zf.infolist():
            n = info.filename
            if n.startswith("META-INF/maven/") and n.endswith("/pom.properties"):
                try:
                    props = dict(re.findall(r"(?m)^\s*(groupId|artifactId|version)\s*=\s*(\S+)", zf.read(info).decode("utf-8", "replace")))
                except (zipfile.BadZipFile, OSError, KeyError):
                    continue
                if {"groupId", "artifactId", "version"} <= props.keys():
                    out.append((f"{props['groupId']}:{props['artifactId']}", props["version"]))
            elif depth == 0 and n.endswith(".jar") and info.file_size < 200 * 1024 * 1024:  # Spring Boot / fat jars
                try:
                    out += _jar_coords(zf.read(info), depth + 1)
                except (zipfile.BadZipFile, OSError):
                    continue
    return out


def _layer_members(outer: tarfile.TarFile, layer_name: str) -> Optional[tarfile.TarFile]:
    f = outer.extractfile(layer_name)
    if f is None:
        return None
    try:
        return tarfile.open(fileobj=f, mode="r:*")
    except tarfile.TarError:
        return None


def _scan_binary(fs: ImageFS, path: str, fh) -> None:
    """Go module info (any Go binary) and version strings of well-known servers built from source."""
    head = fh.read(4)
    if head != b"\x7fELF":
        return
    data = head + fh.read()
    for name_rx, key, ver_rx in BINARY_FINGERPRINTS:
        if name_rx.search(path):
            m = ver_rx.search(data)
            version = next((g.decode() for g in (m.groups() if m else ()) if g), None)
            if version:
                fs.binaries[path] = (key, version)
    idx = data.find(GO_BUILDINFO)
    if idx == -1:
        return
    region = data[idx:idx + 64]
    gm = re.search(rb"go1\.\d+(?:\.\d+)?", data[idx:idx + 4096]) or re.search(rb"go1\.\d+(?:\.\d+)?", region)
    mods = [(p.decode("utf-8", "replace"), v.decode("utf-8", "replace")) for kind, p, v in GO_MODLINE.findall(data)]
    fs.gobins[path] = (gm.group(0).decode() if gm else None, list(dict.fromkeys(mods)))


def read_image(tar_path: str, progress: Progress = NULL) -> Tuple[ImageFS, dict, List[str]]:
    """Return (filesystem subset, image config, repo tags)."""
    fs = ImageFS()
    with tarfile.open(tar_path, "r:*") as outer:
        manifest = json.load(outer.extractfile("manifest.json"))[0]
        config = json.load(outer.extractfile(manifest["Config"]))
        layers = manifest["Layers"]
        progress.stage("Reading image layers", total=len(layers))
        for layer_name in layers:
            layer = _layer_members(outer, layer_name)
            progress.advance(1, layer_name.rsplit("/", 1)[-1][:16])
            if layer is None:
                continue
            with layer:
                for m in layer:
                    path = m.name.lstrip("./")
                    fs.paths += 1
                    base = path.rsplit("/", 1)[-1]
                    if base.startswith(".wh."):
                        parent = path[: -len(base)]
                        if base == ".wh..wh..opq":
                            fs.remove(parent, opaque_dir=True)
                        else:
                            fs.remove(parent + base[4:])
                        continue
                    py = PY_DIST.search(path)
                    if py:
                        fs.python[py.group(0)] = (py.group(1), py.group(2))
                    kind = _interesting(path) if m.isfile() else None
                    if not kind and m.isfile() and (m.mode & 0o111 or ".so" in path) and 200_000 < m.size < MAX_BINARY \
                            and path.startswith(EXEC_DIRS):
                        _scan_binary(fs, path, layer.extractfile(m))
                        continue
                    if not kind or m.size > (MAX_JAR if kind == "jar" else MAX_FILE):
                        continue
                    if kind == "jar":
                        coords = _jar_coords(layer.extractfile(m))
                        if coords:
                            fs.jars[path] = coords
                        continue
                    data = layer.extractfile(m).read()
                    if kind == "node":
                        try:
                            meta = json.loads(data.decode("utf-8", "replace"))
                            if isinstance(meta, dict) and meta.get("name") and meta.get("version"):
                                fs.node[path] = (meta["name"], str(meta["version"]))
                        except ValueError:
                            pass
                    elif kind == "jar":
                        coords = _jar_coords(data)
                        if coords:
                            fs.jars[path] = coords
                    else:
                        fs.files[path] = data
        progress.done(f"Read {len(layers)} layers ({fs.paths} paths)")
    return fs, config, manifest.get("RepoTags") or []


# ---------------------------------------------------------------- OS package databases

def os_release(fs: ImageFS) -> Dict[str, str]:
    raw = fs.files.get("etc/os-release") or fs.files.get("usr/lib/os-release") or b""
    return {k: v.strip('"') for k, v in re.findall(r'(?m)^([A-Z_]+)=(.*)$', raw.decode("utf-8", "replace"))}


def osv_ecosystem(rel: Dict[str, str]) -> Optional[str]:
    os_id, ver = rel.get("ID", "").lower(), rel.get("VERSION_ID", "")
    if os_id == "debian" and ver:
        return f"Debian:{ver.split('.')[0]}"
    if os_id == "ubuntu" and ver:
        lts = ver.endswith(".04") and int(ver.split(".")[0]) % 2 == 0
        return f"Ubuntu:{ver}" + (":LTS" if lts else "")
    if os_id == "alpine" and ver:
        return "Alpine:v" + ".".join(ver.split(".")[:2])
    if os_id == "almalinux" and ver:
        return f"AlmaLinux:{ver.split('.')[0]}"
    if os_id == "rocky" and ver:
        return f"Rocky Linux:{ver.split('.')[0]}"
    return None


def dpkg_packages(text: str, source: str, eco: str) -> List[Package]:
    out, seen = [], set()
    for block in text.split("\n\n"):
        f = dict(re.findall(r"(?m)^([A-Za-z-]+):\s*(.*)$", block))
        if not f.get("Package") or "installed" not in f.get("Status", "install ok installed"):
            continue
        name, version = f["Package"], f.get("Version", "")
        src = f.get("Source")
        if src:  # "openssl (3.0.11-1~deb12u2)" - OSV Debian/Ubuntu advisories are keyed by source package
            m = re.match(r"(\S+)(?:\s+\(([^)]+)\))?", src)
            name, version = m.group(1), m.group(2) or version
        if version and (name, version) not in seen:
            seen.add((name, version))
            out.append(Package(name, version, eco, source))
    return out


def apk_packages(text: str, source: str, eco: str) -> List[Package]:
    out, seen = [], set()
    for block in text.split("\n\n"):
        f = dict(re.findall(r"(?m)^([A-Za-z]):(.*)$", block))
        name = f.get("o") or f.get("P")
        if name and f.get("V") and (name, f["V"]) not in seen:
            seen.add((name, f["V"]))
            out.append(Package(name, f["V"], eco, source))
    return out


def _rpm_header(blob: bytes) -> Dict[int, object]:
    """Minimal RPM header parser (tags: 1000 name, 1001 version, 1002 release, 1003 epoch, 1044 sourcerpm)."""
    il, dl = struct.unpack(">II", blob[:8])
    entries = blob[8:8 + il * 16]
    data = blob[8 + il * 16:8 + il * 16 + dl]
    out: Dict[int, object] = {}
    for i in range(il):
        tag, typ, off, cnt = struct.unpack(">IIII", entries[i * 16:(i + 1) * 16])
        if tag not in (1000, 1001, 1002, 1003, 1044):
            continue
        if typ == 6:
            out[tag] = data[off:data.index(b"\0", off)].decode("utf-8", "replace")
        elif typ == 4:
            out[tag] = struct.unpack(">I", data[off:off + 4])[0]
    return out


def rpm_packages(db: bytes, source: str, eco: str) -> List[Package]:
    out: List[Package] = []
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as fh:
        fh.write(db)
        path = fh.name
    try:
        con = sqlite3.connect(path)
        try:
            for (blob,) in con.execute("SELECT blob FROM Packages"):
                try:
                    h = _rpm_header(bytes(blob))
                except (struct.error, ValueError):
                    continue
                if 1000 in h and 1001 in h:
                    ver = f"{h[1001]}-{h.get(1002, '')}".rstrip("-")
                    if h.get(1003):
                        ver = f"{h[1003]}:{ver}"
                    out.append(Package(str(h[1000]), ver, eco, source))
        finally:
            con.close()
    except sqlite3.Error:
        pass
    finally:
        os.unlink(path)
    return out


# ---------------------------------------------------------------- end-of-life base images (as of late 2026)

def os_eol(rel: Dict[str, str]) -> Optional[str]:
    os_id, ver = rel.get("ID", "").lower(), rel.get("VERSION_ID", "")
    try:
        nums = [int(x) for x in re.findall(r"\d+", ver)[:2]]
    except ValueError:
        return None
    if not nums:
        return None
    if os_id == "debian" and nums[0] < 12:
        return f"Debian {ver} (security support ended)"
    if os_id == "ubuntu":
        lts = len(nums) > 1 and nums[1] == 4 and nums[0] % 2 == 0
        if (lts and nums[0] < 22) or (not lts and (nums[0], nums[1] if len(nums) > 1 else 0) < (26, 10)):
            return f"Ubuntu {ver} (standard support ended)"
    if os_id == "alpine" and len(nums) > 1 and nums[0] == 3 and nums[1] < 22:
        return f"Alpine {ver} (branch no longer maintained)"
    if os_id in ("centos",):
        return f"CentOS {ver} (end of life)"
    return None


# ---------------------------------------------------------------- main

def _save(ref: str, pull: bool, progress: Progress) -> str:
    if os.path.isfile(ref):
        return ref
    exe = "docker" if subprocess.run(["which", "docker"], capture_output=True).returncode == 0 else "podman"
    have = subprocess.run([exe, "image", "inspect", ref], capture_output=True)
    if have.returncode != 0:
        if not pull:
            raise ValueError(f"image {ref!r} is not available locally; `docker pull {ref}` first, or pass --pull")
        progress.stage(f"Pulling {ref}")
        r = subprocess.run([exe, "pull", ref], capture_output=True, text=True)
        if r.returncode != 0:
            raise ValueError(f"could not pull {ref}: {r.stderr.strip().splitlines()[-1] if r.stderr.strip() else 'failed'}")
        progress.done(f"Pulled {ref}")
    fd, path = tempfile.mkstemp(prefix="vulnfind-image-", suffix=".tar")
    os.close(fd)
    progress.stage(f"Exporting {ref} from {exe}")
    r = subprocess.run([exe, "save", "-o", path, ref], capture_output=True, text=True)
    if r.returncode != 0:
        os.unlink(path)
        raise ValueError(f"{exe} save failed: {r.stderr.strip()}")
    progress.done(f"Exported {ref} ({os.path.getsize(path) // (1024 * 1024)} MB)")
    return path


def _F(rule, title, sev, where, desc, fix, cwe=None, snippet=None, **extra) -> Finding:
    return Finding(rule, title, sev, "config", where, snippet=snippet, description=desc, fix=fix, cwe=cwe, extra=extra)


def scan_image(ref: str, offline: bool = False, use_cache: bool = True, pull: bool = False, enrich_intel: bool = True,
               progress: Progress = NULL) -> ScanResult:
    from . import enrich
    from .scanners import deps, run_rules
    from .scanners.secrets import SECRET_RULES, _secret_snippet
    from .walker import SourceFile

    started = time.time()
    result = ScanResult(root=f"image:{ref}", scanners=["image"])
    tar_path = _save(ref, pull, progress)
    try:
        fs, config, tags = read_image(tar_path, progress)
    finally:
        if tar_path != ref:
            os.unlink(tar_path)
    result.files_scanned = fs.paths
    rel = os_release(fs)
    eco = osv_ecosystem(rel)
    findings: List[Finding] = []
    packages: List[Package] = []
    os_name = rel.get("PRETTY_NAME") or rel.get("ID", "unknown OS")

    # OS packages
    if DPKG in fs.files or any(k.startswith(DPKG_D) for k in fs.files):
        text = (fs.files.get(DPKG) or b"").decode("utf-8", "replace") + "\n\n" + \
            "\n\n".join(v.decode("utf-8", "replace") for k, v in fs.files.items() if k.startswith(DPKG_D))
        packages += dpkg_packages(text, "/" + DPKG, eco or "Debian")
    if APK in fs.files:
        packages += apk_packages(fs.files[APK].decode("utf-8", "replace"), "/" + APK, eco or "Alpine")
    for p in RPM_SQLITE:
        if p in fs.files:
            packages += rpm_packages(fs.files[p], "/" + p, eco or "Red Hat")
    os_pkgs = len(packages)
    if os_pkgs and not eco:
        result.warnings.append(f"{os_name}: OSV has no advisory feed for this distribution; OS packages inventoried only.")

    # language packages
    for path, (name, version) in fs.node.items():
        packages.append(Package(name, version, "npm", "/" + path))
    for path, (name, version) in fs.python.items():
        packages.append(Package(re.sub(r"[-_.]+", "-", name).lower(), version, "PyPI", "/" + path.rstrip("/")))
    for path, coords in fs.jars.items():
        for ga, version in coords:
            packages.append(Package(ga, version, "Maven", "/" + path))
    for path, (gover, mods) in fs.gobins.items():
        for mod, version in mods:
            if version != "(devel)":
                packages.append(Package(mod, version.lstrip("v").replace("+incompatible", ""), "Go", "/" + path))
        if gover and gover.count(".") == 2:
            packages.append(Package("stdlib", gover[2:], "Go", "/" + path))
    for path, data in fs.files.items():
        base = path.rsplit("/", 1)[-1]
        parser = parser_for(base) if base in LOCKFILES else None
        if parser:
            try:
                packages += parser(data.decode("utf-8", "replace"), "/" + path)
            except Exception:
                pass
    # one package version once per source file
    uniq: Dict[Tuple[str, str, str, str], Package] = {}
    for p in packages:
        uniq.setdefault((p.ecosystem, p.name, p.version, p.source), p)
    packages = list(uniq.values())
    result.packages = packages
    result.manifests = sorted({p.source for p in packages})
    progress.log(f"  ✔ {os_name}: {os_pkgs} OS packages, {len(packages) - os_pkgs} language packages, "
                 f"{len(fs.gobins)} Go binaries, {len(fs.binaries)} server binaries")

    queryable = [p for p in packages if p.ecosystem in ("npm", "PyPI", "Maven", "Go", "crates.io", "RubyGems", "Packagist", "NuGet")
                 or (eco and p.ecosystem == eco)]
    if offline:
        result.warnings.append(f"--offline: {len(packages)} packages inventoried but not checked for CVEs.")
    elif queryable:
        progress.stage(f"Checking {len(queryable)} packages against OSV.dev")
        _, _, dep_findings, _ = deps.scan([], set(), result.warnings, False, use_cache, progress=progress,
                                          packages=queryable, used=result.manifests)
        progress.done(f"Found {len(dep_findings)} known vulnerabilities")
        if enrich_intel and dep_findings:
            progress.stage("Enriching with CISA KEV & EPSS exploit data")
            enrich.enrich(dep_findings, use_cache, result.warnings)
            progress.done("Threat intel applied")
        findings += dep_findings

    where = f"image:{ref}"
    # servers compiled from source (no package-manager record): look their versions up in NVD
    os_names = {p.name.lower() for p in packages[:os_pkgs]}
    sw = []
    from .web import software
    for path, (key, version) in fs.binaries.items():
        if key in software.PRODUCTS and not ({key, "apache2", "httpd"} & os_names if key == "apache" else key in os_names):
            sw.append(software.Software(key, version, f"/{path}", f"{software.PRODUCTS[key][0]} {version} (/{path})", False))
    sw = list({(s.key, s.version): s for s in sw}.values())
    if sw and not offline:
        names = ", ".join(f"{software.PRODUCTS[s.key][0]} {s.version}" for s in sw)
        progress.stage(f"Looking up CVEs for {names} (NVD)")
        bin_findings = software.software_findings(sw, where, use_cache, result.warnings)
        for f in bin_findings:
            f.category = "dependency"
            f.extra.update({"package": f.extra.get("product"), "ecosystem": "binary"})
            f.file = f"{where}:{f.snippet.split('(')[-1].rstrip(')')}" if f.snippet else where
        if enrich_intel and bin_findings:
            enrich.enrich(bin_findings, use_cache, result.warnings)
        findings += [f for f in bin_findings]
        progress.done(f"Compiled-in software: {names}")
    eol = os_eol(rel)
    if eol:
        findings.append(_F("IMAGE-EOL-OS", f"End-of-life base image: {eol}", S.HIGH, where,
                           "The base OS no longer gets security updates, so new CVEs in its packages will never be fixed.",
                           "Rebuild on a supported base (e.g. debian:12-slim, ubuntu:24.04, alpine:3.22+, distroless).", "CWE-1104",
                           snippet=os_name))
    cfg = config.get("config") or {}
    user = (cfg.get("User") or "").split(":")[0]
    if user in ("", "root", "0"):
        findings.append(_F("IMAGE-ROOT-USER", "Image runs as root", S.MEDIUM, where,
                           "Containers from this image run as UID 0 unless the runtime overrides it; a container escape becomes host root.",
                           "Add `USER <non-root>` to the Dockerfile.", "CWE-250", snippet=f"User: {cfg.get('User') or '(unset)'}"))
    for env in cfg.get("Env") or []:
        k, _, v = env.partition("=")
        if re.search(r"(?i)pass|secret|token|api_?key|private_?key|access_?key", k) and v and not re.match(r"^\$|^/|^(?:true|false|\d+)$", v):
            findings.append(_F("IMAGE-SECRET-ENV", f"Secret baked into image ENV: {k}", S.HIGH, where,
                               "ENV values are visible to anyone who can pull the image (`docker inspect`).",
                               "Pass secrets at runtime (orchestrator secrets / env), never in the image.", "CWE-538",
                               snippet=f"{k}={v[:3]}…"))
    if "22/tcp" in (cfg.get("ExposedPorts") or {}):
        findings.append(_F("IMAGE-SSH-EXPOSED", "Image exposes SSH (22/tcp)", S.MEDIUM, where,
                           "Running sshd inside containers widens the attack surface.", "Use `docker exec` / `kubectl exec`.", "CWE-284"))
    created = config.get("created", "")
    if created:
        try:
            from datetime import datetime, timezone
            age = (datetime.now(timezone.utc) - datetime.strptime(created[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)).days
            if age > 365:
                findings.append(_F("IMAGE-STALE", f"Image was built {age // 365} year(s) ago", S.LOW, where,
                                   "Old images miss every security update released since they were built.",
                                   "Rebuild regularly (e.g. weekly) to pick up base image patches.", "CWE-1104", snippet=f"created {created[:10]}"))
        except ValueError:
            pass

    # secrets left in the filesystem
    for path, data in fs.files.items():
        if _interesting(path) != "secret":
            continue
        text = data.decode("utf-8", "replace")
        sf = SourceFile("/" + path, "/" + path, len(data))
        sf._text, sf._binary = text, "\0" in text[:4096]
        if sf._binary:
            continue
        hits = list(run_rules(SECRET_RULES, sf, "secret", text, _secret_snippet))
        for h in hits[:3]:
            h.title += " (inside image)"
            h.file = f"{where}:/{path}"
            findings.append(h)
        if not hits and re.search(r"(?:^|/)(?:id_rsa|id_ed25519|\.git-credentials)$", path):
            findings.append(Finding("IMAGE-SENSITIVE-FILE", f"Sensitive file in image: /{path}", S.HIGH, "secret", f"{where}:/{path}",
                                    description="Credential files shipped in an image can be extracted by anyone who pulls it.",
                                    fix="Remove it and use a .dockerignore / multi-stage build; rotate the credential.", cwe="CWE-538"))

    result.findings = findings
    enrich.prioritise(result.findings)
    result.findings.sort(key=lambda x: (-x.severity, -x.extra.get("priority", 0), x.file))
    result.duration = time.time() - started
    return result
