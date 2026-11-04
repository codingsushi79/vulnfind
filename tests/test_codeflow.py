"""Go/PHP taint, cross-file Python taint, route inventory and missing-auth detection."""

import json
import unittest

from vulnfind.engine import ScanOptions, scan
from vulnfind.scanners import routes, taint_lines

from helpers import TempProject

GO = '''package main
import ("database/sql"; "fmt"; "net/http"; "os/exec"; "strconv")
func h(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	name := r.URL.Query().Get("name")
	db.Query(fmt.Sprintf("SELECT * FROM u WHERE name = '%s'", name))
	db.Query("SELECT * FROM u WHERE name = $1", name)
	id, _ := strconv.Atoi(r.FormValue("id"))
	db.Query(fmt.Sprintf("SELECT * FROM t WHERE id = %d", id))
	exec.Command("sh", "-c", "ping "+r.FormValue("host")).Run()
	http.Redirect(w, r, r.URL.Query().Get("next"), 302)
}
func other(db *sql.DB) {
	name := "x"
	db.Query("SELECT " + name)
}
'''

PHP = '''<?php
$id = $_GET['id'];
mysqli_query($c, "SELECT * FROM u WHERE id = $id");
$n = intval($_GET['n']);
mysqli_query($c, "SELECT * FROM t WHERE n = " . $n);
include($_GET['page'] . ".php");
echo htmlspecialchars($_GET['q'], ENT_QUOTES);
echo 'Hello ' . $_GET['q'];
$stmt = $pdo->prepare('SELECT * FROM u WHERE id = ?');
'''


class LineTaintTest(unittest.TestCase):
    def test_go(self):
        got = [(f.line, f.rule_id) for f in taint_lines.findings(taint_lines.GO, GO, "main.go")]
        self.assertEqual(got, [(5, "GO-TAINT-SQLI"), (9, "GO-TAINT-CMDI"), (10, "GO-TAINT-REDIRECT")])

    def test_php(self):
        got = [(f.line, f.rule_id) for f in taint_lines.findings(taint_lines.PHP, PHP, "index.php")]
        self.assertEqual(got, [(3, "PHP-TAINT-SQLI"), (6, "PHP-TAINT-LFI"), (8, "PHP-TAINT-XSS")])

    def test_supersedes_regex_rules(self):
        with TempProject({"index.php": PHP}) as root:
            ids = [f.rule_id for f in scan(root, ScanOptions(offline=True, scanners=["code"])).findings if f.line == 6]
        self.assertEqual(ids, ["PHP-TAINT-LFI"])


CROSS = {
    "app/__init__.py": "",
    "app/db.py": "def find(conn, name):\n    return conn.execute(\"SELECT * FROM u WHERE n = '%s'\" % name)\n"
                 "def safe(conn, i):\n    return conn.execute('SELECT * FROM u WHERE id = ?', (i,))\n",
    "app/services.py": "from .db import find\ndef lookup(conn, who):\n    return find(conn, who)\n",
    "app/views.py": ("from flask import Flask, request\nfrom app import services\nfrom app.db import safe\napp = Flask(__name__)\n"
                     "@app.route('/u')\ndef u(conn):\n    return services.lookup(conn, request.args['n'])\n"
                     "@app.route('/s')\ndef s(conn):\n    return safe(conn, request.args['i'])\n"),
}


class CrossFileTest(unittest.TestCase):
    def test_flow_across_three_modules(self):
        with TempProject(CROSS) as root:
            res = scan(root, ScanOptions(offline=True, scanners=["code"]))
        sqli = [f for f in res.findings if f.rule_id == "PY-TAINT-SQLI"]
        self.assertEqual([(f.file, f.line) for f in sqli], [("app/views.py", 7)])
        self.assertTrue(any("app/db.py:2" in step for step in sqli[0].extra["flow"]))
        self.assertEqual(sqli[0].extra["route"], "GET /u")

    def test_single_file_mode_misses_it(self):
        with TempProject(CROSS) as root:
            res = scan(root, ScanOptions(offline=True, scanners=["code"], only={"app/views.py"}))
        self.assertFalse([f for f in res.findings if f.rule_id == "PY-TAINT-SQLI"])  # no project context in diff mode for others


class RoutesTest(unittest.TestCase):
    def test_python_frameworks(self):
        src = ("from fastapi import FastAPI, Depends\nrouter = FastAPI()\n"
               "@router.get('/me')\ndef me(user=Depends(get_current_user)):\n    return user\n"
               "@router.delete('/items/{id}')\ndef delete(id: int):\n    return 1\n"
               "@router.post('/login')\ndef login():\n    return 1\n")
        r = {(x.method, x.path): x.auth for x in routes.python_routes(src, "api.py")}
        self.assertEqual(r, {("GET", "/me"): True, ("DELETE", "/items/{id}"): False, ("POST", "/login"): False})
        ids = [(f.extra["route"]) for f in routes.missing_auth_findings(routes.python_routes(src, "api.py"))]
        self.assertEqual(ids, ["DELETE /items/{id}"])

    def test_express_and_router_use(self):
        src = ("const express = require('express');\nconst r = express.Router();\nr.get('/public', (req, res) => res.send('x'));\n"
               "r.post('/orders', requireAuth, (req, res) => res.json(1));\n"
               "r.delete('/orders/:id', (req, res) => res.json(1));\n"
               "const admin = express.Router();\nadmin.use(isAdmin);\nadmin.post('/admin/purge', (req, res) => res.send(1));\n")
        got = {(x.method, x.path): x.auth for x in routes.js_routes(src, "routes.js")}
        self.assertEqual(got[("POST", "/orders")], True)
        self.assertEqual(got[("DELETE", "/orders/:id")], False)
        self.assertEqual(got[("POST", "/admin/purge")], True)

    def test_nextjs_route_handlers(self):
        src = "export async function POST(req) {\n  const s = await getServerSession();\n  return Response.json(1)\n}\nexport async function DELETE(req) {\n  return Response.json(1)\n}\n"
        got = {(x.method, x.path): x.auth for x in routes.js_routes(src, "app/api/users/[id]/route.ts")}
        self.assertEqual(got, {("POST", "/api/users/:id"): True, ("DELETE", "/api/users/:id"): False})

    def test_no_auth_anywhere_means_no_findings(self):
        src = "@app.route('/a', methods=['POST'])\ndef a():\n    return 1\n"
        self.assertEqual(routes.missing_auth_findings(routes.python_routes(src, "x.py")), [])

    def test_routes_command(self):
        import contextlib, io
        from vulnfind import cli
        with TempProject(CROSS) as root:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                cli.main(["routes", root, "--json"])
        self.assertEqual(sorted(r["path"] for r in json.loads(out.getvalue())), ["/s", "/u"])


if __name__ == "__main__":
    unittest.main()
