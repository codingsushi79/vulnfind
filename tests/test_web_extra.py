"""Login-aware crawling, OpenAPI scanning, subdomain takeover, browser fallback, monitor."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from email.message import Message

from vulnfind import cli
from vulnfind.web import WebOptions, browser, scan_site, subdomains
from vulnfind.web.client import Response

import web_fixture
from helpers import TempProject


def opts(**kw):
    base = dict(offline=True, dns=False, rate=300, max_pages=15, paths=False, js=False)
    base.update(kw)
    return WebOptions(**base)


class LoginTest(unittest.TestCase):
    def setUp(self):
        web_fixture.Handler.requested = []
        self.srv, self.url = web_fixture.serve()
        os.environ["VF_TEST_USER"], os.environ["VF_TEST_PASS"] = "alice@example.com", "s3cret-pass"

    def tearDown(self):
        self.srv.shutdown()
        os.environ.pop("VF_TEST_USER", None)
        os.environ.pop("VF_TEST_PASS", None)

    def test_authenticated_crawl_reaches_protected_pages(self):
        r = scan_site(self.url + "/dashboard", opts(active=True, login_url=self.url + "/signin",
                                                    login_user_env="VF_TEST_USER", login_pass_env="VF_TEST_PASS"))
        ids = {f.rule_id for f in r.findings}
        self.assertIn("WEB-SESSION-FIXATION", ids)
        self.assertIn("WEB-LOGIN-NO-CSRF", ids)
        xss = [f for f in r.findings if f.rule_id == "WEB-REFLECTED-XSS"]
        self.assertTrue(any("/account" in f.file for f in xss), [f.file for f in xss])  # only reachable when logged in
        self.assertIn("POST /signin", web_fixture.Handler.requested)

    def test_wrong_password_fails_clearly(self):
        os.environ["VF_TEST_PASS"] = "wrong"
        with self.assertRaises(ValueError) as cm:
            scan_site(self.url, opts(login_url=self.url + "/signin", login_user_env="VF_TEST_USER", login_pass_env="VF_TEST_PASS"))
        self.assertIn("login", str(cm.exception))

    def test_missing_env_vars(self):
        with self.assertRaises(ValueError) as cm:
            scan_site(self.url, opts(login_url=self.url + "/signin", login_user_env="NOPE_U", login_pass_env="NOPE_P"))
        self.assertIn("NOPE_U", str(cm.exception))


class OpenApiTest(unittest.TestCase):
    def test_auth_enforcement(self):
        web_fixture.Handler.requested = []
        srv, url = web_fixture.serve()
        try:
            r = scan_site(url, opts(max_pages=1, openapi=url + "/openapi.json"))
        finally:
            srv.shutdown()
        got = {(f.rule_id, f.extra.get("operation")) for f in r.findings if f.rule_id.startswith("API-")}
        self.assertIn(("API-AUTH-NOT-ENFORCED", "GET /api/users"), got)
        self.assertIn(("API-ANONYMOUS-SENSITIVE", "GET /api/admin/stats"), got)
        self.assertNotIn(("API-AUTH-NOT-ENFORCED", "GET /api/items/{id}"), got)  # correctly returns 401
        self.assertFalse([p for p in web_fixture.Handler.requested if p.startswith("POST")])  # never calls non-GET operations
        self.assertIn("/api/items/1", web_fixture.Handler.requested)

    def test_rejects_non_spec(self):
        from vulnfind.web import api
        from vulnfind.web.client import Client
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"hello": 1}, fh)
        try:
            with self.assertRaises(ValueError):
                api.load_spec(Client(), fh.name)
        finally:
            os.unlink(fh.name)


class FakeClient:
    def __init__(self, pages):
        self.pages = pages

    def request(self, url, **kw):
        m = Message()
        body = self.pages.get(url)
        if body is None:
            return Response(url, 0, m, b"", error="unreachable")
        m["Content-Type"] = "text/html"
        return Response(url, 200, m, body.encode())


class SubdomainTest(unittest.TestCase):
    def setUp(self):
        self.dns = {
            "blog.example.com": (["olduser.github.io"], [], False),
            "olduser.github.io": ([], ["185.199.108.153"], False),
            "files.example.com": (["gone-bucket.s3.amazonaws.com"], [], False),
            "gone-bucket.s3.amazonaws.com": ([], ["52.1.1.1"], False),
            "shop.example.com": (["deleted-app.herokuapp.com"], [], True),
            "deleted-app.herokuapp.com": ([], [], True),
            "staging.example.com": ([], ["10.0.0.1"], False),
            "www.example.com": ([], ["93.184.216.34"], False),
        }
        self.orig = (subdomains._resolve, subdomains.discover)
        subdomains._resolve = lambda n: self.dns.get(n, ([], [], True))
        subdomains.discover = lambda d, w: set(self.dns) & {"blog.example.com", "files.example.com", "shop.example.com",
                                                             "staging.example.com", "www.example.com"}

    def tearDown(self):
        subdomains._resolve, subdomains.discover = self.orig

    def test_takeovers_and_forgotten_hosts(self):
        client = FakeClient({"https://blog.example.com/": "<h1>There isn't a GitHub Pages site here.</h1>",
                             "https://files.example.com/": "<Error><Code>NoSuchBucket</Code></Error>",
                             "https://staging.example.com/": "<html>staging build</html>",
                             "https://www.example.com/": "<html>hi</html>"})
        names, found = subdomains.scan("example.com", client)
        got = {(f.rule_id, f.extra.get("service"), f.file) for f in found}
        self.assertIn(("WEB-SUBDOMAIN-TAKEOVER", "GitHub Pages", "dns://blog.example.com"), got)
        self.assertIn(("WEB-SUBDOMAIN-TAKEOVER", "AWS S3", "dns://files.example.com"), got)
        self.assertIn(("WEB-SUBDOMAIN-TAKEOVER", "Heroku", "dns://shop.example.com"), got)
        self.assertIn(("WEB-FORGOTTEN-HOST", None, "https://staging.example.com/"), got)
        self.assertFalse([g for g in got if "www.example.com" in g[2]])

    def test_claimed_resource_is_fine(self):
        client = FakeClient({"https://blog.example.com/": "<html>my real blog</html>"})
        self.dns = {"blog.example.com": (["me.github.io"], [], False), "me.github.io": ([], ["185.199.108.153"], False)}
        subdomains.discover = lambda d, w: {"blog.example.com"}
        _, found = subdomains.scan("example.com", client)
        self.assertEqual(found, [])


class BrowserTest(unittest.TestCase):
    def test_missing_playwright_is_actionable(self):
        if browser.available():
            self.skipTest("playwright installed")
        with self.assertRaises(browser.BrowserUnavailable) as cm:
            browser.render(["http://127.0.0.1:9/"], "http://127.0.0.1:9/")
        self.assertIn("pip install playwright", str(cm.exception))


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(args))
    return code, out.getvalue(), err.getvalue()


class MonitorTest(unittest.TestCase):
    def test_alerts_only_on_changes(self):
        with TempProject({"app.py": "x = 1\n"}) as root, tempfile.TemporaryDirectory() as state:
            code, out, _ = run_cli("monitor", root, "--state-dir", state, "--offline", "--no-progress", "--no-color")
            self.assertEqual(code, 0)
            self.assertIn("first run", out)
            code, out, _ = run_cli("monitor", root, "--state-dir", state, "--offline", "--no-progress", "--no-color")
            self.assertIn("no changes", out)
            with open(os.path.join(root, "app.py"), "a") as fh:
                fh.write("import pickle, flask\ny = pickle.loads(flask.request.data)\n")
            code, out, _ = run_cli("monitor", root, "--state-dir", state, "--offline", "--no-progress", "--no-color")
            self.assertEqual(code, 1)
            self.assertIn("1 new", out)
            self.assertIn("Unsafe deserialization", out)

    def test_print_cron_uses_absolute_paths(self):
        code, out, _ = run_cli("monitor", ".", "https://example.com", "--print-cron", "30 6 * * 1")
        self.assertTrue(out.startswith("30 6 * * 1 "))
        self.assertIn(os.path.abspath("."), out)
        self.assertIn("https://example.com", out)


if __name__ == "__main__":
    unittest.main()
