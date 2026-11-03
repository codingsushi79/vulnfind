"""Tests for the in-depth analyses: taint tracking, git history, dependency context, enrichment."""

import json
import os
import subprocess
import tempfile
import unittest

from vulnfind import depgraph, enrich, manifests
from vulnfind.models import Finding, Package, Severity
from vulnfind.scanners import code, taint_js, taint_python

from helpers import ids, source

FLASK_APP = '''
import os, pickle, subprocess, requests
from flask import Flask, request, redirect, render_template_string
app = Flask(__name__)

def build(name):
    return "SELECT * FROM u WHERE name = '%s'" % name

def run_tool(arg):
    subprocess.run("tool " + arg, shell=True)

@app.route("/a")
def a(db):
    q = build(request.args.get("name"))
    db.cursor().execute(q)

@app.route("/b/<fname>")
def b(fname):
    return open(os.path.join("/srv", fname)).read()

@app.route("/c")
def c():
    run_tool(request.args["t"])
    requests.get(request.form["url"], timeout=3)
    render_template_string("Hi " + request.args.get("n"))
    return redirect(request.args.get("next"))

@app.route("/safe")
def safe(db):
    n = int(request.args.get("n"))
    os.system("echo %d" % n)
    x = request.args.get("x")
    x = "constant"
    eval(x)
    db.cursor().execute("SELECT * FROM t WHERE id = %s", (request.args.get("id"),))
    subprocess.run(["ls", request.args.get("dir")])
'''


class PythonTaintTest(unittest.TestCase):
    def setUp(self):
        self.found = {(f.rule_id, f.line) for f in taint_python.findings(FLASK_APP, "app.py")}

    def test_flows_through_helpers_and_routes(self):
        self.assertIn(("PY-TAINT-SQLI", 15), self.found)       # via helper return value
        self.assertIn(("PY-TAINT-PATH", 19), self.found)       # route parameter
        self.assertIn(("PY-TAINT-CMDI", 23), self.found)       # via helper parameter into shell=True
        self.assertIn(("PY-TAINT-SSRF", 24), self.found)
        self.assertIn(("PY-TAINT-SSTI", 25), self.found)
        self.assertIn(("PY-TAINT-REDIRECT", 26), self.found)

    def test_sanitised_reassigned_and_parameterised_are_clean(self):
        self.assertFalse({line for _, line in self.found} & set(range(28, 37)), self.found)

    def test_flow_trace_and_confidence(self):
        f = next(f for f in taint_python.findings(FLASK_APP, "app.py") if f.rule_id == "PY-TAINT-CMDI")
        self.assertEqual(f.severity, Severity.CRITICAL)
        self.assertTrue(any("run_tool" in step for step in f.extra["flow"]))
        self.assertEqual(f.extra["confidence"], "high")

    def test_cli_input_is_lower_severity(self):
        f = list(taint_python.findings("import os\nt = input()\nos.system('ping ' + t)\n", "tool.py"))[0]
        self.assertEqual((f.rule_id, f.severity), ("PY-TAINT-CMDI", Severity.HIGH))

    def test_syntax_errors_are_ignored(self):
        self.assertEqual(list(taint_python.findings("def broken(:\n", "x.py")), [])

    def test_taint_supersedes_regex_on_same_line(self):
        got = ids(code.scan(source("app.py", "from flask import request\nimport pickle\nx = pickle.loads(request.data)\n")))
        self.assertEqual(got, ["PY-TAINT-DESER"])


JS_APP = """app.get('/a', async (req, res) => {
  const { id, name: userName } = req.query;
  const sql = `SELECT * FROM users WHERE id = ${id}`;
  await db.query(sql);
  res.sendFile(path.join('/srv', userName));
  res.send(`<h1>${userName}</h1>`);
});
app.post('/b', (req, res) => {
  const n = parseInt(req.body.n);
  db.query(`SELECT * FROM t WHERE id = ${n}`);
  exec('ping ' + req.body.host);
  const m = /^Bearer (.+)$/.exec(req.headers.authorization);
  fetch('/api/local');
  res.redirect(new URL('/', req.url));
});
function other() {
  const id = 5;
  db.query(`SELECT ${id}`);
}
"""


class JsTaintTest(unittest.TestCase):
    def test_flows(self):
        found = {(f.rule_id, f.line) for f in taint_js.findings(JS_APP, "s.js")}
        self.assertEqual(found, {("JS-TAINT-SQLI", 4), ("JS-TAINT-PATH", 5), ("JS-TAINT-XSS", 6), ("JS-TAINT-CMDI", 11)})


class HistoryTest(unittest.TestCase):
    def test_deleted_secret_found_in_history(self):
        from vulnfind.scanners import history
        with tempfile.TemporaryDirectory() as root:
            def git(*a):
                subprocess.run(["git", "-C", root, *a], check=True, capture_output=True)
            git("init", "-q")
            git("config", "user.email", "t@example.com")
            git("config", "user.name", "Tester")
            with open(os.path.join(root, "cfg.py"), "w") as fh:
                fh.write('T = "ghp_aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6"\n')
            git("add", ".")
            git("commit", "-qm", "add token")
            with open(os.path.join(root, "cfg.py"), "w") as fh:
                fh.write("T = os.environ['T']\n")
            git("commit", "-qam", "remove token")
            found = history.scan(root)
            self.assertEqual([(f.rule_id, f.file, f.line) for f in found], [("SECRET-GITHUB-TOKEN", "cfg.py", 1)])
            self.assertEqual(found[0].extra["subject"], "add token")
            self.assertEqual(history.count_commits(root, None), 2)


class DepContextTest(unittest.TestCase):
    def test_npm_chains(self):
        lock = json.dumps({"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"express": "^4"}},
            "node_modules/express": {"version": "4.17.1", "dependencies": {"body-parser": "1"}},
            "node_modules/body-parser": {"version": "1.19.0", "dependencies": {"qs": "6"}},
            "node_modules/qs": {"version": "6.7.0"},
            "node_modules/orphan": {"version": "1.0.0"},
        }})
        pk = {p.name: p for p in manifests.parse_package_lock(lock, "package-lock.json")}
        self.assertTrue(pk["express"].direct)
        self.assertEqual(pk["qs"].via, ["express", "body-parser"])
        self.assertFalse(pk["qs"].direct)
        self.assertIsNone(pk["orphan"].direct)

    def test_reachability(self):
        py = depgraph.extract_imports(".py", "import yaml\nfrom bs4 import BeautifulSoup\nimport os, requests\n")
        js = depgraph.extract_imports(".ts", "import x from '@scope/pkg/sub'\nconst l = require('lodash/template')\nimport './local'\n")
        imports = {py[0]: py[1], js[0]: js[1]}
        check = lambda name, eco: depgraph.is_imported(Package(name, "1", eco, "x"), imports)
        self.assertTrue(check("PyYAML", "PyPI"))
        self.assertTrue(check("beautifulsoup4", "PyPI"))
        self.assertTrue(check("requests", "PyPI"))
        self.assertFalse(check("django", "PyPI"))
        self.assertTrue(check("@scope/pkg", "npm"))
        self.assertTrue(check("lodash", "npm"))
        self.assertIsNone(check("serde", "crates.io"))  # no Rust sources scanned: unknown

    def test_typosquats(self):
        self.assertEqual(depgraph.typosquat_target("reqeusts", "PyPI"), "requests")
        self.assertEqual(depgraph.typosquat_target("expres", "npm"), "express")
        self.assertEqual(depgraph.typosquat_target("crossenv", "npm"), "cross-env")
        for legit in ("requests", "preact", "mysql2", "left-pad", "fastapi"):
            self.assertIsNone(depgraph.typosquat_target(legit, "npm" if legit in ("preact", "mysql2", "left-pad") else "PyPI"))


class EnrichTest(unittest.TestCase):
    def test_kev_and_epss_drive_priority(self):
        def dep(cve, sev):
            return Finding(cve, "t", sev, "dependency", "package-lock.json",
                           extra={"aliases": [cve], "package": "p", "version": "1", "fixed": "2", "direct": True})
        exploited, quiet = dep("CVE-2021-44228", Severity.HIGH), dep("CVE-2000-0001", Severity.HIGH)
        enrich.load_kev = lambda use_cache=True: {"CVE-2021-44228": {"date_added": "2021-12-10", "ransomware": True}}
        enrich.load_epss = lambda cves, use_cache=True: {"CVE-2021-44228": {"epss": 0.97, "percentile": 0.999}}
        try:
            enrich.enrich([exploited, quiet])
        finally:
            import importlib
            importlib.reload(enrich)
        enrich.prioritise([exploited, quiet])
        self.assertEqual(exploited.severity, Severity.CRITICAL)
        self.assertTrue(exploited.extra["kev"]["ransomware"])
        self.assertGreater(exploited.extra["priority"], quiet.extra["priority"])
        self.assertEqual(exploited.extra["priority"], 100)


if __name__ == "__main__":
    unittest.main()
