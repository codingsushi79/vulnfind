"""Tests for automation: config files, git hooks, diff/staged modes, compare, fix, formats."""

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest

from vulnfind import automation, cli, fixer, gitutil
from vulnfind.models import Finding, ScanResult, Severity
from vulnfind.reporters import FORMATTERS, format_for_path

from helpers import TempProject


def slurp(path):
    with open(path) as fh:
        return fh.read()


def dump(obj, path):
    with open(path, "w") as fh:
        json.dump(obj, fh)


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(args))
    return code, out.getvalue(), err.getvalue()


class GitRepo:
    def __enter__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "t@example.com")
        self.git("config", "user.name", "Tester")
        self.write("app.py", "x = 1\n")
        self.git("add", ".")
        self.git("commit", "-qm", "init")
        return self

    def __exit__(self, *exc):
        self.tmp.cleanup()

    def git(self, *args):
        return subprocess.run(["git", "-C", self.root, *args], capture_output=True, text=True)

    def write(self, rel, text):
        with open(os.path.join(self.root, rel), "w") as fh:
            fh.write(text)


SECRET = 'KEY = "ghp_aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6"\n'


class ConfigTest(unittest.TestCase):
    def test_config_file_and_flag_precedence(self):
        with TempProject({"app.py": "x = eval(y)\n", ".vulnfind.json": json.dumps({"scanners": "secrets", "fail-on": "none"})}) as root:
            code, out, _ = run_cli(root, "--offline", "--no-progress", "-f", "json")
            self.assertEqual((code, json.loads(out)["findings"]), (0, []))  # config: secrets only, never fail
            code, out, _ = run_cli(root, "--offline", "--no-progress", "-f", "json", "--scanners", "code", "--fail-on", "high")
            self.assertEqual(code, 1)  # flags win
            self.assertEqual(json.loads(out)["findings"][0]["rule_id"], "PY-EVAL")

    def test_bad_config_is_a_clear_error(self):
        with TempProject({".vulnfind.json": json.dumps({"failon": "high"})}) as root:
            code, _, err = run_cli(root, "--offline", "--no-progress")
            self.assertEqual(code, 2)
            self.assertIn("unknown option 'failon'", err)

    def test_init_creates_files(self):
        with TempProject({}) as root:
            run_cli("init", root)
            self.assertTrue(os.path.isfile(os.path.join(root, ".vulnfind.json")))
            self.assertTrue(os.path.isfile(os.path.join(root, ".vulnfindignore")))
            automation.load_config(os.path.join(root, ".vulnfind.json"))  # the generated file must load


class GitModesTest(unittest.TestCase):
    def test_staged_scans_index_content(self):
        with GitRepo() as r:
            r.write("cfg.py", SECRET)
            r.git("add", "cfg.py")
            r.write("cfg.py", "KEY = os.environ['KEY']\n")  # working tree is clean, index is not
            self.assertEqual(gitutil.staged_files(r.root), {"cfg.py"})
            code, out, _ = run_cli(r.root, "--staged", "--offline", "--no-progress", "-f", "json")
            self.assertEqual(code, 1)
            self.assertEqual([f["rule_id"] for f in json.loads(out)["findings"]], ["SECRET-GITHUB-TOKEN"])

    def test_diff_only_reports_changed_files(self):
        with GitRepo() as r:
            r.write("old.py", "x = eval(y)\n")
            r.git("add", ".")
            r.git("commit", "-qm", "old")
            r.git("checkout", "-qb", "feature")
            r.write("new.py", "z = eval(w)\n")
            files = {f["file"] for f in json.loads(run_cli(r.root, "--diff", "main", "--offline", "--no-progress", "-f", "json")[1])["findings"]}
            self.assertEqual(files, {"new.py"})

    def test_hook_install_blocks_and_uninstall_restores(self):
        with GitRepo() as r:
            hooks = os.path.join(r.root, ".git", "hooks")
            os.makedirs(hooks, exist_ok=True)
            with open(os.path.join(hooks, "pre-commit"), "w") as fh:
                fh.write("#!/bin/sh\necho existing-hook\n")
            path = gitutil.install_hook(r.root)
            gitutil.install_hook(r.root)  # idempotent
            text = slurp(path)
            self.assertEqual(text.count(gitutil.HOOK_MARK), 1)
            self.assertIn("existing-hook", text)
            self.assertTrue(os.access(path, os.X_OK))
            gitutil.uninstall_hook(r.root)
            text = slurp(path)
            self.assertNotIn(gitutil.HOOK_MARK, text)
            self.assertIn("existing-hook", text)


class CompareTest(unittest.TestCase):
    def test_new_and_fixed(self):
        def report(*fps):
            return {"findings": [{"fingerprint": fp, "severity": "HIGH", "title": fp, "file": "a.py", "line": 1} for fp in fps]}
        diff = automation.compare(report("a", "b"), report("b", "c"))
        self.assertEqual([f["fingerprint"] for f in diff["new"]], ["c"])
        self.assertEqual([f["fingerprint"] for f in diff["fixed"]], ["a"])
        with tempfile.TemporaryDirectory() as d:
            old, new = os.path.join(d, "old.json"), os.path.join(d, "new.json")
            dump(report("a"), old)
            dump(report("a", "c"), new)
            self.assertEqual(run_cli("compare", old, new)[0], 1)
            self.assertEqual(run_cli("compare", new, old)[0], 0)  # only fixes: success


def dep(manifest, eco, name, version, fixed, aliases=None):
    return Finding(aliases[0] if aliases else "CVE-1", "t", Severity.HIGH, "dependency", manifest,
                   extra={"package": name, "version": version, "ecosystem": eco, "fixed": fixed, "aliases": aliases or ["CVE-1"]})


class FixerTest(unittest.TestCase):
    def test_requirements_package_json_overrides_go(self):
        files = {
            "requirements.txt": "Django==3.2.0\nPyYAML[extra] == 5.3  # pinned\nflask>=2\n",
            "package.json": '{\n  "name": "x",\n  "dependencies": {\n    "lodash": "^4.17.20"\n  }\n}\n',
            "package-lock.json": "{}",
            "go.mod": "module x\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.6.3\n)\n",
        }
        with TempProject(files) as root:
            res = ScanResult(root=root, findings=[
                dep("requirements.txt", "PyPI", "django", "3.2.0", "3.2.14"),
                dep("requirements.txt", "PyPI", "django", "3.2.0", "4.2.16"),
                dep("requirements.txt", "PyPI", "pyyaml", "5.3", "5.4"),
                dep("package-lock.json", "npm", "lodash", "4.17.20", "4.17.21"),
                dep("package-lock.json", "npm", "qs", "6.7.0", "6.7.3"),
                dep("go.mod", "Go", "github.com/gin-gonic/gin", "1.6.3", "1.9.1"),
                dep("Cargo.lock", "crates.io", "smallvec", "1.6.0", "1.6.1"),
            ])
            pl = fixer.plan(res)
            fixer.apply(pl)
            read = lambda p: slurp(os.path.join(root, p))
            self.assertIn("Django==4.2.16", read("requirements.txt"))
            self.assertIn("PyYAML[extra] == 5.4  # pinned", read("requirements.txt"))
            pj = json.loads(read("package.json"))
            self.assertEqual(pj["dependencies"]["lodash"], "^4.17.21")
            self.assertEqual(pj["overrides"], {"qs": "6.7.3"})
            self.assertIn("github.com/gin-gonic/gin v1.9.1", read("go.mod"))
            self.assertTrue(any("cargo update -p smallvec" in c for c in pl.commands))
            self.assertIn("npm install", pl.commands)


class FormatsTest(unittest.TestCase):
    def setUp(self):
        self.res = ScanResult(root="/x", findings=[
            Finding("PY-EVAL", "Use of eval, really", Severity.HIGH, "code", "a,b.py", 3, description="d\nmore", fix="f")])

    def test_github_annotations_escape(self):
        out = FORMATTERS["github"](self.res)
        self.assertTrue(out.startswith("::error file=a%2Cb.py,line=3,title=[HIGH] PY-EVAL%3A Use of eval%2C really::d%0Amore"))

    def test_junit_is_valid_xml(self):
        import xml.etree.ElementTree as ET
        root = ET.fromstring(FORMATTERS["junit"](self.res))
        self.assertEqual(root.get("failures"), "1")

    def test_csv_and_path_inference(self):
        self.assertIn("PY-EVAL", FORMATTERS["csv"](self.res).splitlines()[1])
        self.assertEqual(format_for_path("out/sbom.cdx.json"), "sbom")
        self.assertEqual(format_for_path("r.xml"), "junit")


if __name__ == "__main__":
    unittest.main()
