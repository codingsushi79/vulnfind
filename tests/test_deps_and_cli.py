import contextlib
import io
import json
import os
import unittest

from vulnfind import cli, osv
from vulnfind.engine import ScanOptions, scan
from vulnfind.models import Package, Severity
from vulnfind.scanners import deps

from helpers import TempProject

LODASH = Package("lodash", "4.17.20", "npm", "package-lock.json", 3)
VULN = {
    "id": "GHSA-35jh-r3h4-6jhm",
    "aliases": ["CVE-2021-23337"],
    "summary": "Command Injection in lodash",
    "details": "`template` is vulnerable",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
    "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-94"]},
    "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                  "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
    "references": [{"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"}],
}
PYSEC_DUP = {"id": "PYSEC-0000-1", "aliases": ["CVE-2021-23337"], "affected": []}


class FakeClient:
    def __init__(self, results):
        self.results = results

    def query(self, packages):
        return self.results


class OsvHelpersTest(unittest.TestCase):
    def test_severity_and_fix(self):
        sev, score, _ = osv.severity_of(VULN)
        self.assertEqual(sev, Severity.HIGH)
        self.assertEqual(score, 7.2)
        self.assertEqual(osv.best_fix(VULN, LODASH), "4.17.21")
        self.assertEqual(osv.aliases(VULN)[0], "CVE-2021-23337")

    def test_severity_from_cvss_only(self):
        v = {"id": "X", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
        self.assertEqual(osv.severity_of(v)[0], Severity.CRITICAL)
        self.assertEqual(osv.severity_of({"id": "MAL-2024-1"})[0], Severity.CRITICAL)

    def test_dedupe_aliases(self):
        self.assertEqual([v["id"] for v in osv.dedupe([PYSEC_DUP, VULN])], ["GHSA-35jh-r3h4-6jhm"])

    def test_version_compare(self):
        self.assertTrue(osv.version_lt("1.2.9", "1.2.10"))
        self.assertTrue(osv.version_lt("2.0.0-rc1", "2.0.0"))
        self.assertFalse(osv.version_lt("4.17.21", "4.17.21"))
        self.assertTrue(osv.version_lt("2.0.0", "2.0.0.post1"))
        self.assertTrue(osv.version_lt("0.0.0-20200622213623-75b288015ac9", "0.1.0"))
        self.assertTrue(osv.version_lt("1.0", "1.0.1"))

    def test_build_findings_and_ignore(self):
        results = {("npm", "lodash", "4.17.20"): [VULN]}
        findings, suppressed = deps.build_findings([LODASH], results, set())
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual((f.rule_id, f.extra["fixed"], f.line), ("CVE-2021-23337", "4.17.21", 3))
        self.assertIn("npm install lodash@4.17.21", f.fix)
        _, suppressed = deps.build_findings([LODASH], results, {"GHSA-35JH-R3H4-6JHM"})
        self.assertEqual(suppressed, 1)


PROJECT = {
    "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": "4.17.20"}}}),
    "package.json": json.dumps({"dependencies": {"lodash": "^4.17.0"}}),
    "app.py": "import pickle\nx = pickle.loads(data)\ny = eval(z)  # vulnfind:ignore\n",
    "settings.py": 'GITHUB_TOKEN = "ghp_aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6"\n',
    "tests/test_app.py": "x = eval(y)\n",
    "ignored/secret.py": 'k = "AKIAQ3EGRQFAKE7DEMO1"\n',
    ".vulnfindignore": "ignored/\nrule:PY-WEAK-HASH\n",
}


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(args))
    return code, out.getvalue(), err.getvalue()


class EngineTest(unittest.TestCase):
    def test_offline_scan(self):
        with TempProject(PROJECT) as root:
            r = scan(root, ScanOptions(offline=True))
            found = {(f.rule_id, f.file) for f in r.findings}
            self.assertIn(("PY-PICKLE", "app.py"), found)
            self.assertIn(("SECRET-GITHUB-TOKEN", "settings.py"), found)
            self.assertNotIn("ignored/secret.py", {f.file for f in r.findings})
            self.assertEqual(r.suppressed, 1)  # inline ignore on eval
            test_eval = next(f for f in r.findings if f.file == "tests/test_app.py")
            self.assertEqual(test_eval.severity, Severity.MEDIUM)  # downgraded from HIGH
            # package.json is skipped because a lockfile sits next to it
            self.assertEqual(r.manifests, ["package-lock.json"])
            self.assertEqual([(p.name, p.version) for p in r.packages], [("lodash", "4.17.20")])

    def test_dependency_scan_with_fake_osv(self):
        with TempProject(PROJECT) as root:
            from vulnfind.walker import IgnoreConfig, walk
            files = [f for f in walk(root, IgnoreConfig()) if deps.is_manifest(f)]
            pkgs, used, findings, _ = deps.scan(files, set(), [], client=FakeClient({("npm", "lodash", "4.17.20"): [VULN]}))
            self.assertEqual([f.rule_id for f in findings], ["CVE-2021-23337"])


class CliTest(unittest.TestCase):
    def test_exit_codes_and_formats(self):
        with TempProject(PROJECT) as root:
            code, out, _ = run_cli(root, "--offline", "--no-color")
            self.assertEqual(code, 1)
            self.assertIn("Unsafe deserialization", out)
            code, _, _ = run_cli(root, "--offline", "--fail-on", "critical", "-q")
            self.assertEqual(code, 1)  # GitHub token is critical
            code, _, _ = run_cli(root, "--offline", "--fail-on", "none", "-q")
            self.assertEqual(code, 0)

            code, out, _ = run_cli(root, "--offline", "-f", "json")
            data = json.loads(out)
            self.assertGreater(data["summary"]["total"], 0)

            code, out, _ = run_cli(root, "--offline", "-f", "sarif")
            sarif = json.loads(out)
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertTrue(sarif["runs"][0]["results"])

            html_path = os.path.join(root, "r.html")
            md_path = os.path.join(root, "r.md")
            run_cli(root, "--offline", "-q", "-o", html_path, "-o", md_path)
            with open(html_path) as fh:
                self.assertIn("vulnfind security report", fh.read())
            with open(md_path) as fh:
                self.assertIn("| Severity |", fh.read())

    def test_baseline_roundtrip(self):
        with TempProject(PROJECT) as root:
            base = os.path.join(root, "baseline.json")
            code, _, _ = run_cli(root, "--offline", "-q", "--write-baseline", base)
            self.assertEqual(code, 0)
            code, out, _ = run_cli(root, "--offline", "--no-color", "--baseline", base)
            self.assertEqual(code, 0)
            self.assertIn("No vulnerabilities found", out)

    def test_scanner_selection_and_errors(self):
        with TempProject(PROJECT) as root:
            code, out, _ = run_cli(root, "--offline", "--scanners", "secrets", "-f", "json")
            cats = {f["category"] for f in json.loads(out)["findings"]}
            self.assertEqual(cats, {"secret"})
            self.assertEqual(run_cli(root, "--scanners", "nope")[0], 2)
        self.assertEqual(run_cli("/definitely/not/here")[0], 2)

    def test_rules_and_explain(self):
        code, out, _ = run_cli("rules", "--json")
        rules = json.loads(out)
        self.assertGreater(len(rules), 100)
        self.assertEqual(len({r["id"] for r in rules}), len(rules), "rule ids must be unique")
        code, out, _ = run_cli("explain", "py-pickle")
        self.assertEqual(code, 0)
        self.assertIn("CWE-502", out)


if __name__ == "__main__":
    unittest.main()
