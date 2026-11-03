"""Machine-readable reports: JSON, SARIF 2.1.0, Markdown, CycloneDX SBOM."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List

from .. import __version__
from ..models import CATEGORIES, Finding, ScanResult, Severity

TOOL_URI = "https://github.com/vulnfind/vulnfind"


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def to_json(result: ScanResult) -> str:
    return json.dumps({
        "tool": {"name": "vulnfind", "version": __version__},
        "generated_at": _now(),
        "root": result.root,
        "summary": {
            "counts": result.counts(), "total": len(result.findings), "grade": result.grade, "score": result.score,
            "files_scanned": result.files_scanned, "manifests": result.manifests, "packages": len(result.packages),
            "suppressed": result.suppressed, "below_threshold": result.below_threshold, "duration_seconds": round(result.duration, 2), "scanners": result.scanners,
        },
        "warnings": result.warnings,
        "findings": [f.to_dict() for f in result.findings],
    }, indent=2)


SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
               Severity.LOW: "note", Severity.INFO: "note"}
SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5",
                     Severity.LOW: "3.0", Severity.INFO: "0.0"}


def to_sarif(result: ScanResult) -> str:
    rules: Dict[str, dict] = {}
    results: List[dict] = []
    for f in result.findings:
        if f.rule_id not in rules:
            tags = ["security", f.category] + ([f.cwe] if f.cwe else [])
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": "".join(w.capitalize() for w in f.title.replace("/", " ").split()[:8]) or f.rule_id,
                "shortDescription": {"text": f.title[:200]},
                "fullDescription": {"text": (f.description or f.title)[:1000]},
                "help": {"text": f.fix or f.description, "markdown": f"**Fix:** {f.fix or 'n/a'}"},
                "helpUri": f.references[0] if f.references else TOOL_URI,
                "properties": {"tags": tags, "security-severity": str(f.extra.get("cvss") or SECURITY_SEVERITY[f.severity]),
                               "precision": "high" if f.category in ("dependency", "secret") else "medium"},
            }
        region = {"startLine": f.line or 1}
        if f.column:
            region["startColumn"] = f.column
        if f.snippet:
            region["snippet"] = {"text": f.snippet}
        msg = f.title if f.category != "dependency" else f"{f.snippet}: {f.title}. {f.fix or ''}".strip()
        results.append({
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": msg},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file, "uriBaseId": "%SRCROOT%"}, "region": region}}],
            "partialFingerprints": {"vulnfind/v1": f.fingerprint},
            "properties": {"severity": f.severity.label, "category": f.category},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "vulnfind", "version": __version__, "informationUri": TOOL_URI,
                                "rules": list(rules.values())}},
            "results": results,
            "originalUriBaseIds": {"%SRCROOT%": {"uri": "file://" + result.root.rstrip("/") + "/"}},
        }],
    }
    return json.dumps(doc, indent=2)


def _md_escape(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ")


def to_markdown(result: ScanResult) -> str:
    c = result.counts()
    out = [f"## vulnfind security report — grade **{result.grade}** ({result.score}/100)", ""]
    out.append(" · ".join(f"**{c[s.label]}** {s.label.lower()}" for s in sorted(Severity, reverse=True)))
    out.append("")
    out.append(f"_{result.files_scanned} files, {len(result.packages)} packages from {len(result.manifests)} manifests, "
               f"{result.suppressed} suppressed, {result.duration:.1f}s_")
    if not result.findings:
        out += ["", "✅ No vulnerabilities found."]
    by_cat: Dict[str, List[Finding]] = {}
    for f in result.findings:
        by_cat.setdefault(f.category, []).append(f)
    for cat, heading in CATEGORIES.items():
        items = by_cat.get(cat)
        if not items:
            continue
        out += ["", f"### {heading} ({len(items)})", ""]
        if cat == "dependency":
            out += ["| Severity | Package | Advisory | Fixed in | Manifest |", "|---|---|---|---|---|"]
            for f in items:
                url = f.references[0] if f.references else ""
                out.append(f"| {f.severity.label} | `{f.snippet}` | [{f.rule_id}]({url}) {_md_escape(f.title)} | "
                           f"{f.extra.get('fixed') or '—'} | `{f.location}` |")
        else:
            out += ["| Severity | Issue | Location | Fix |", "|---|---|---|---|"]
            for f in items:
                out.append(f"| {f.severity.label} | **{_md_escape(f.title)}** `{f.rule_id}` | `{f.location}` | {_md_escape(f.fix or '')} |")
    if result.warnings:
        out += ["", "> " + "\n> ".join(result.warnings)]
    return "\n".join(out) + "\n"


def to_cyclonedx(result: ScanResult) -> str:
    seen = set()
    components = []
    for p in result.packages:
        if p.purl in seen:
            continue
        seen.add(p.purl)
        comp = {"type": "library", "name": p.name, "version": p.version, "purl": p.purl, "bom-ref": p.purl,
                "properties": [{"name": "vulnfind:source", "value": p.source}]}
        if p.ecosystem == "Maven" and ":" in p.name:
            comp["group"], comp["name"] = p.name.split(":", 1)
        if p.dev:
            comp["scope"] = "excluded"
        components.append(comp)
    vulns = []
    for f in result.findings:
        if f.category != "dependency":
            continue
        v = {"id": f.rule_id, "source": {"name": "OSV", "url": f.references[0] if f.references else ""},
             "ratings": [{"severity": f.severity.label.lower(), **({"score": f.extra["cvss"], "method": "CVSSv3"} if f.extra.get("cvss") else {})}],
             "description": f.title, "affects": [{"ref": f.extra.get("purl")}]}
        if f.extra.get("fixed"):
            v["recommendation"] = f"Upgrade to {f.extra['fixed']}"
        vulns.append(v)
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": _now(), "tools": [{"vendor": "vulnfind", "name": "vulnfind", "version": __version__}],
                     "component": {"type": "application", "name": result.root.rstrip("/").rsplit("/", 1)[-1], "bom-ref": "root"}},
        "components": components,
    }
    if vulns:
        doc["vulnerabilities"] = vulns
    return json.dumps(doc, indent=2)
