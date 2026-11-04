"""Core data types shared by every scanner and reporter."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        value = value.strip().upper()
        if value == "MODERATE":
            value = "MEDIUM"
        try:
            return cls[value]
        except KeyError:
            raise ValueError(f"unknown severity: {value!r}") from None

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0:
            return cls.LOW
        return cls.INFO

    def lowered(self) -> "Severity":
        return Severity(max(self - 1, Severity.INFO))

    @property
    def label(self) -> str:
        return self.name


# Finding categories, in the order reports present them.
CATEGORIES = {
    "dependency": "Vulnerable dependencies",
    "secret": "Leaked secrets",
    "code": "Insecure code",
    "config": "Infrastructure & CI configuration",
    "file": "Sensitive files",
    "license": "License compliance",
    "web": "Website",
}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: str
    file: str
    line: Optional[int] = None
    column: Optional[int] = None
    snippet: Optional[str] = None
    description: str = ""
    fix: Optional[str] = None
    cwe: Optional[str] = None
    references: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}" if self.line else self.file

    @property
    def fingerprint(self) -> str:
        """Stable ID that survives line shifts, used by baselines."""
        if self.category == "dependency":
            key = f"{self.rule_id}|{self.file}|{self.extra.get('package')}@{self.extra.get('version')}"
        else:
            key = f"{self.rule_id}|{self.file}|{(self.snippet or '').strip()}"
        return hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:20]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label,
            "category": self.category,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "description": self.description,
            "fix": self.fix,
            "cwe": self.cwe,
            "references": self.references,
            "fingerprint": self.fingerprint,
            **({"extra": self.extra} if self.extra else {}),
        }


@dataclass
class Package:
    name: str
    version: str
    ecosystem: str  # OSV ecosystem name: npm, PyPI, Go, crates.io, ...
    source: str  # manifest file it was found in (relative path)
    line: Optional[int] = None
    dev: bool = False
    approximate: bool = False  # version taken from a range, not a lockfile
    direct: Optional[bool] = None  # declared by the project itself (None = unknown)
    via: List[str] = field(default_factory=list)  # dependency chain from the project, e.g. ["express", "body-parser"]
    imported: Optional[bool] = None  # referenced by an import in the scanned source (None = unknown)

    @property
    def purl(self) -> str:
        kind = {
            "npm": "npm", "PyPI": "pypi", "Go": "golang", "crates.io": "cargo",
            "RubyGems": "gem", "Packagist": "composer", "Maven": "maven", "NuGet": "nuget",
        }.get(self.ecosystem, self.ecosystem.lower())
        name = self.name
        if kind == "maven" and ":" in name:
            name = name.replace(":", "/", 1)
        elif kind == "npm" and name.startswith("@"):
            name = "%40" + name[1:]
        return f"pkg:{kind}/{name}@{self.version}"


@dataclass
class ScanResult:
    root: str
    findings: List[Finding] = field(default_factory=list)
    packages: List[Package] = field(default_factory=list)
    files_scanned: int = 0
    manifests: List[str] = field(default_factory=list)
    duration: float = 0.0
    suppressed: int = 0
    below_threshold: int = 0
    commits_scanned: int = 0
    pages_scanned: int = 0
    routes: List[Any] = field(default_factory=list)  # scanners.routes.Route
    requests_made: int = 0
    warnings: List[str] = field(default_factory=list)
    scanners: List[str] = field(default_factory=list)

    def counts(self) -> Dict[str, int]:
        out = {s.label: 0 for s in sorted(Severity, reverse=True)}
        for f in self.findings:
            out[f.severity.label] += 1
        return out

    @property
    def score(self) -> int:
        c = self.counts()
        penalty = c["CRITICAL"] * 25 + c["HIGH"] * 10 + c["MEDIUM"] * 3 + c["LOW"] * 1
        return max(0, 100 - penalty)

    @property
    def grade(self) -> str:
        if self.counts()["CRITICAL"]:
            return "F"
        s = self.score
        for threshold, letter in ((90, "A"), (80, "B"), (65, "C"), (50, "D")):
            if s >= threshold:
                return letter
        return "F"
