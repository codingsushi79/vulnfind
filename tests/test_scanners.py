import unittest

from vulnfind.scanners import code, iac, is_suppressed, secrets
from vulnfind.scanners.files import scan as scan_files

from helpers import ids, source


class SecretsTest(unittest.TestCase):
    def scan(self, name, text):
        return list(secrets.scan(source(name, text)))

    def test_provider_tokens(self):
        text = (
            'aws = "AKIAQ3EGRQFAKE7DEMO1"\n'
            'gh = "ghp_aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6"\n'
            "-----BEGIN RSA PRIVATE KEY-----\n"
            'url = "postgres://admin:Sup3rS3cretPw@db:5432/x"\n'
            'stripe = "sk_' 'live_51HfakeDEMOkeyA1b2C3d4E5f6G7h8"\n'
        )
        self.assertEqual(ids(self.scan("a.py", text)),
                         ["SECRET-AWS-ACCESS-KEY", "SECRET-DB-URL", "SECRET-GITHUB-TOKEN", "SECRET-PRIVATE-KEY", "SECRET-STRIPE-LIVE"])

    def test_snippets_are_masked(self):
        f = self.scan("a.py", 'token = "ghp_aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6"\n')[0]
        self.assertNotIn("aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6", f.snippet)
        self.assertIn("ghp_", f.snippet)

    def test_placeholders_and_env_lookups_ignored(self):
        text = (
            'password = "changeme_please"\n'
            'api_key = "your-api-key-here"\n'
            'secret = os.environ["SECRET"]\n'
            'password = "${DB_PASSWORD}"\n'
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
            'db = "postgres://user:<password>@host/db"\n'
            'api_key = "aaaaaaaaaaaaaaaa"\n'
        )
        self.assertEqual(self.scan("config.py", text), [])

    def test_generic_password_and_dotenv(self):
        self.assertEqual(ids(self.scan("s.py", 'db_password = "Winter2026!"\n')), ["SECRET-GENERIC"])
        self.assertEqual(ids(self.scan(".env", "DB_PASSWORD=correct-horse-battery\nDEBUG=true\nAPI_TOKEN=\n")), ["SECRET-DOTENV"])

    def test_url_credentials_hosts(self):
        self.assertEqual(self.scan("README.md", "DATABASE_URL=postgres://user:hunter2pw@host:5432/app\n"), [])
        local = self.scan("docker.yml", "url: postgres://app:hunter2pw@localhost:5432/app\n")
        self.assertEqual([(f.rule_id, f.severity.label) for f in local], [("SECRET-DB-URL", "LOW")])

    def test_lockfiles_skipped(self):
        self.assertEqual(self.scan("package-lock.json", '"x": "ghp_aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6"'), [])


class CodeTest(unittest.TestCase):
    def scan(self, name, text):
        return list(code.scan(source(name, text), deep=False))

    def test_python_rules(self):
        text = (
            'cursor.execute(f"SELECT * FROM t WHERE id = {uid}")\n'
            "subprocess.run(cmd, shell=True)\n"
            "x = eval(user)\n"
            "pickle.loads(data)\n"
            "yaml.load(s)\n"
            "requests.get(u, verify=False, timeout=3)\n"
        )
        self.assertEqual(ids(self.scan("app.py", text)),
                         ["PY-EVAL", "PY-PICKLE", "PY-SQL-INJECTION", "PY-SUBPROCESS-SHELL", "PY-TLS-VERIFY-OFF", "PY-YAML-LOAD"])

    def test_python_safe_variants(self):
        text = (
            "yaml.load(s, Loader=yaml.SafeLoader)\n"
            'cursor.execute("SELECT * FROM t WHERE id = %s", (uid,))\n'
            "ast.literal_eval(x)\n"
            '# eval(user) in a comment\n'
            'msg = "never call eval(x) here"\n'
            "hashlib.md5(b, usedforsecurity=False)\n"
        )
        self.assertEqual(self.scan("app.py", text), [])

    def test_js_rules(self):
        text = (
            "exec(`ls ${req.query.dir}`)\n"
            "el.innerHTML = userHtml;\n"
            "db.query(`SELECT * FROM u WHERE id = ${id}`)\n"
            "res.redirect(req.query.next)\n"
            "https.request({ rejectUnauthorized: false })\n"
        )
        self.assertEqual(ids(self.scan("s.ts", text)),
                         ["JS-CHILD-PROCESS", "JS-OPEN-REDIRECT", "JS-SQL-INJECTION", "JS-TLS-REJECT-OFF", "JS-XSS-INNERHTML"])
        self.assertEqual(self.scan("s.js", "el.innerHTML = '';\nregex.exec(str)\n"), [])

    def test_other_languages(self):
        self.assertIn("GO-TLS-INSECURE", ids(self.scan("m.go", "tls.Config{InsecureSkipVerify: true}")))
        self.assertIn("PHP-SQL-INJECTION", ids(self.scan("i.php", "mysqli_query($c, \"SELECT * FROM u WHERE id=\" . $_GET['id']);")))
        self.assertIn("RB-SQL-INJECTION", ids(self.scan("u.rb", 'User.where("name = \'#{params[:n]}\'")')))
        self.assertIn("C-UNSAFE-FUNC", ids(self.scan("a.c", "strcpy(buf, input);")))
        self.assertIn("JAVA-SQL-INJECTION", ids(self.scan("A.java", 'stmt.executeQuery("SELECT * FROM u WHERE id=" + id);')))

    def test_sql_with_bind_params_is_downgraded(self):
        f = self.scan("db.js", "await c.query(`DELETE FROM ${table} WHERE id=$1`, [id])\n")[0]
        self.assertEqual((f.rule_id, f.severity.label), ("JS-SQL-INJECTION", "MEDIUM"))

    def test_rules_only_apply_to_their_language(self):
        self.assertEqual(self.scan("notes.txt", "eval(x)\nstrcpy(a,b)\n"), [])


class SuppressionTest(unittest.TestCase):
    def test_inline_and_previous_line(self):
        lines = ["x = eval(a)  # vulnfind:ignore", "# vulnfind:ignore PY-EVAL", "y = eval(b)", "z = 1  # vulnfind:ignore", "w = eval(c)"]
        self.assertTrue(is_suppressed(lines, 1, "PY-EVAL"))
        self.assertTrue(is_suppressed(lines, 3, "PY-EVAL"))
        self.assertFalse(is_suppressed(lines, 3, "PY-PICKLE"))
        self.assertFalse(is_suppressed(lines, 5, "PY-EVAL"))  # line above is code, not a comment


class IacTest(unittest.TestCase):
    def scan(self, name, text):
        return list(iac.scan(source(name, text)))

    def test_dockerfile(self):
        text = "FROM python:3.8 AS build\nRUN pip install x\nFROM build\nFROM ubuntu\nENV API_TOKEN=abc123\nCMD x\n"
        got = ids(self.scan("Dockerfile", text))
        for rid in ("DOCKER-ROOT-USER", "DOCKER-LATEST-TAG", "DOCKER-SECRET-ENV", "RUNTIME-EOL", "DOCKER-NO-HEALTHCHECK"):
            self.assertIn(rid, got)
        tags = [f for f in self.scan("Dockerfile", text) if f.rule_id == "DOCKER-LATEST-TAG"]
        self.assertEqual([f.line for f in tags], [4])  # "FROM build" refers to a stage, not an image

    def test_dockerfile_good(self):
        text = "FROM node:22.11-alpine\nUSER node\nHEALTHCHECK CMD wget -q localhost\n"
        self.assertEqual(self.scan("Dockerfile", text), [])

    def test_github_actions(self):
        wf = ("on:\n  pull_request_target:\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n"
              "          ref: ${{ github.event.pull_request.head.sha }}\n      - uses: some/action@v1\n"
              "      - uses: pinned/action@0123456789abcdef0123456789abcdef01234567\n"
              "      - run: echo \"${{ github.event.issue.title }}\"\n")
        got = ids(self.scan(".github/workflows/ci.yml", wf))
        self.assertEqual(got, ["GHA-PWN-REQUEST", "GHA-SCRIPT-INJECTION", "GHA-UNPINNED-ACTION"])

    def test_capabilities(self):
        k8s = "securityContext:\n  capabilities:\n    add:\n      - NET_ADMIN\n    drop:\n      - ALL\n"
        found = self.scan("deploy.yaml", k8s)
        self.assertEqual([(f.rule_id, f.line) for f in found], [("CONTAINER-DANGEROUS-CAP", 4)])

    def test_terraform(self):
        tf = 'cidr_blocks = ["0.0.0.0/0"]\nacl = "public-read"\npublicly_accessible = true\n'
        self.assertEqual(ids(self.scan("main.tf", tf)), ["TF-OPEN-INGRESS", "TF-PUBLIC-BUCKET", "TF-PUBLIC-DB"])

    def test_eol_runtimes(self):
        self.assertEqual(ids(self.scan(".nvmrc", "v18.19.0\n")), ["RUNTIME-EOL"])
        self.assertEqual(self.scan(".nvmrc", "22\n"), [])
        self.assertEqual(ids(self.scan(".python-version", "3.9.18\n")), ["RUNTIME-EOL"])
        self.assertEqual(self.scan(".python-version", "3.12\n"), [])


class FilesTest(unittest.TestCase):
    def test_sensitive_names(self):
        def rid(name):
            return [f.rule_id for f in scan_files(source(name, "x"), None) if f.rule_id != "FILE-WORLD-WRITABLE"]
        self.assertEqual(rid("id_rsa"), ["FILE-SSH-KEY"])
        self.assertEqual(rid("id_rsa.pub"), [])
        self.assertEqual(rid(".env"), ["FILE-ENV"])
        self.assertEqual(rid(".env.production"), ["FILE-ENV"])
        self.assertEqual(rid(".env.example"), [])
        self.assertEqual(rid("terraform.tfstate"), ["FILE-TFSTATE"])
        self.assertEqual(rid("app.py"), [])

    def test_sql_files(self):
        import os
        from helpers import TempProject
        from vulnfind.walker import SourceFile
        with TempProject({"migrations/001_init.sql": "CREATE TABLE x (id int);\n",
                          "backups/prod_dump.sql": "-- Dump\n"}) as root:
            def rid(rel):
                path = os.path.join(root, rel)
                return [f.rule_id for f in scan_files(SourceFile(path, rel, os.path.getsize(path)), None)
                        if f.rule_id != "FILE-WORLD-WRITABLE"]
            self.assertEqual(rid("migrations/001_init.sql"), [])
            self.assertEqual(rid("backups/prod_dump.sql"), ["FILE-DB-DUMP"])


if __name__ == "__main__":
    unittest.main()
