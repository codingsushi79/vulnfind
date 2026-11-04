"""Remote repositories, custom rules, self-update, GitHub Action / workflow sanity."""

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest

from vulnfind import cli, customrules, remote, selfupdate
from vulnfind.engine import ScanOptions, scan

from helpers import TempProject

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(args))
    return code, out.getvalue(), err.getvalue()


class RemoteTest(unittest.TestCase):
    def test_url_recognition(self):
        yes = ["github.com/a/b", "https://github.com/a/b", "https://github.com/a/b.git", "https://gitlab.com/g/p/",
               "git@github.com:a/b.git", "https://git.example.org/team/x.git", "https://github.com/a/b/tree/feature/x"]
        no = ["https://example.com", "https://github.com", "./repo", "/abs/path", "https://github.com/a"]
        self.assertTrue(all(remote.is_repo_url(u) for u in yes), [u for u in yes if not remote.is_repo_url(u)])
        self.assertFalse(any(remote.is_repo_url(u) for u in no), [u for u in no if remote.is_repo_url(u)])
        self.assertEqual(remote.normalise("https://github.com/a/b/tree/dev"), ("https://github.com/a/b.git", "dev"))

    def test_clone_scan_and_cleanup(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "src")
            os.makedirs(src)
            g = lambda *a: subprocess.run(["git", "-C", src, *a], check=True, capture_output=True)
            g("init", "-q")
            g("config", "user.email", "t@example.com")
            g("config", "user.name", "T")
            with open(os.path.join(src, "app.py"), "w") as fh:
                fh.write("import os\nfrom flask import request\nos.system('ls ' + request.args['d'])\n")
            g("add", ".")
            g("commit", "-qm", "x")
            bare = os.path.join(d, "repo.git")
            subprocess.run(["git", "clone", "-q", "--bare", src, bare], check=True, capture_output=True)
            with remote.Clone(bare) as path:
                res = scan(path, ScanOptions(offline=True))
                cloned = path
            self.assertFalse(os.path.exists(cloned))
            self.assertIn("PY-TAINT-CMDI", {f.rule_id for f in res.findings})

    def test_bad_clone_is_clear_error(self):
        with self.assertRaises(ValueError):
            with remote.Clone("/nonexistent/repo.git"):
                pass


class CustomRulesTest(unittest.TestCase):
    def test_inline_and_project_rules(self):
        files = {
            "src/app.py": "internal_admin_api(user)\n# internal_admin_api(x) in a comment\n",
            "src/app.js": "internal_admin_api(1)\n",
            ".vulnfind/rules/acme.json": json.dumps({"rules": [{"id": "acme-no-debug-flag", "title": "Debug flag",
                                                                "severity": "low", "pattern": "ACME_DEBUG\\s*=\\s*1"}]}),
            "settings.env": "ACME_DEBUG = 1\n",
            ".vulnfind.json": json.dumps({"rules": [{"id": "ACME-INTERNAL-API", "title": "Internal admin API", "severity": "high",
                                                     "pattern": "internal_admin_api\\(", "extensions": [".py"]}]}),
        }
        with TempProject(files) as root:
            code, out, _ = run_cli(root, "--offline", "--no-progress", "-f", "json", "--fail-on", "high")
            found = {(f["rule_id"], f["file"], f["line"]) for f in json.loads(out)["findings"]}
            self.assertIn(("ACME-INTERNAL-API", "src/app.py", 1), found)
            self.assertNotIn(("ACME-INTERNAL-API", "src/app.py", 2), found)  # comment skipped
            self.assertNotIn(("ACME-INTERNAL-API", "src/app.js", 1), found)  # extension filter
            self.assertIn(("ACME-NO-DEBUG-FLAG", "settings.env", 1), found)
            self.assertEqual(code, 1)

    def test_validation_errors(self):
        for bad, msg in (({"id": "X", "title": "t"}, "missing 'pattern'"), ({"id": "X", "title": "t", "pattern": "("}, "invalid regex"),
                         ({"id": "X", "title": "t", "pattern": "a", "severity": "huge"}, "unknown severity")):
            with self.assertRaises(ValueError) as cm:
                customrules.parse(bad, "test")
            self.assertIn(msg, str(cm.exception))
        with TempProject({".vulnfind.json": json.dumps({"rules": [{"id": "X", "title": "t", "pattern": "("}]})}) as root:
            code, _, err = run_cli(root, "--offline", "--no-progress")
            self.assertEqual(code, 2)
            self.assertIn("invalid regex", err)


class SelfUpdateTest(unittest.TestCase):
    def test_upgrade_commands(self):
        self.assertIsNone(selfupdate.upgrade_command("editable", "/src"))
        cmd = selfupdate.upgrade_command("git", "https://github.com/codingsushi79/vulnfind")
        self.assertIn("git+https://github.com/codingsushi79/vulnfind", cmd)


class WorkflowFilesTest(unittest.TestCase):
    def test_repo_ci_files_pass_vulnfind_itself(self):
        res = scan(ROOT, ScanOptions(offline=True, scanners=["config"]))
        bad = [f for f in res.findings if f.file.startswith((".github/", "action.yml"))]
        self.assertEqual(bad, [], [(f.rule_id, f.file, f.line) for f in bad])

    def test_action_inputs_never_interpolated_into_scripts(self):
        with open(os.path.join(ROOT, "action.yml")) as fh:
            text = fh.read()
        run_blocks = text.split("run: |")[1:]
        for block in run_blocks:
            self.assertNotIn("${{ inputs.", block.split("\n    - ")[0])


if __name__ == "__main__":
    unittest.main()
