"""Tests for website scanning against a local deliberately-vulnerable site (no internet needed)."""

import contextlib
import io
import json
import unittest
from email.message import Message

from vulnfind import cli
from vulnfind.models import Severity
from vulnfind.web import WebOptions, checks, dns, libs, scan_site
from vulnfind.web.client import Response

import web_fixture


def opts(**kw):
    base = dict(offline=True, dns=False, rate=200, max_pages=15)
    base.update(kw)
    return WebOptions(**base)


def resp(headers=None, body="<html><body>x</body></html>", url="https://site.test/"):
    m = Message()
    for k, v in (headers or {}).items():
        if isinstance(v, list):
            for item in v:
                m[k] = item
        else:
            m[k] = v
    if "Content-Type" not in m:
        m["Content-Type"] = "text/html"
    return Response(url, 200, m, body.encode())


class LiveSiteTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        web_fixture.Handler.requested = []
        cls.srv, cls.url = web_fixture.serve()
        cls.result = scan_site(cls.url, opts(active=True))
        cls.ids = {f.rule_id for f in cls.result.findings}
        cls.requested = list(web_fixture.Handler.requested)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_finds_planted_vulnerabilities(self):
        expected = {
            "WEB-EXPOSED-GIT", "WEB-EXPOSED-ENV", "WEB-REFLECTED-XSS", "WEB-SQL-ERROR", "WEB-OPEN-REDIRECT",
            "WEB-CORS-REFLECT", "WEB-COOKIE-FLAGS", "WEB-CSP-MISSING", "WEB-CLICKJACKING", "WEB-VERSION-DISCLOSURE",
            "WEB-PASSWORD-OVER-HTTP", "WEB-PASSWORD-IN-URL", "WEB-RISKY-METHODS", "WEB-SOURCEMAP-EXPOSED",
            "SECRET-AWS-ACCESS-KEY", "WEB-ERROR-DISCLOSURE", "WEB-NO-SRI", "WEB-GENERATOR-DISCLOSURE", "WEB-JS-LIBRARY",
        }
        self.assertFalse(expected - self.ids, f"missing: {expected - self.ids}")

    def test_xss_only_on_unescaped_endpoint(self):
        xss = [f for f in self.result.findings if f.rule_id == "WEB-REFLECTED-XSS"]
        self.assertEqual([("/search" in f.file, f.extra["param"]) for f in xss], [(True, "q")])

    def test_crawler_never_follows_state_changing_links(self):
        self.assertFalse([p for p in self.requested if p.startswith("/logout")])

    def test_site_wide_issues_reported_once(self):
        csp = [f for f in self.result.findings if f.rule_id == "WEB-CSP-MISSING"]
        self.assertEqual(len(csp), 1)
        self.assertGreater(csp[0].extra.get("pages_affected", 1), 1)
        self.assertEqual(sum(1 for f in self.result.findings if f.rule_id == "WEB-ERROR-DISCLOSURE"), 1)

    def test_library_version_parsed_cleanly(self):
        libs_found = {(f.extra["package"], f.extra["version"]) for f in self.result.findings if f.rule_id == "WEB-JS-LIBRARY"}
        self.assertEqual(libs_found, {("jquery", "1.12.4")})

    def test_secrets_are_masked(self):
        f = next(f for f in self.result.findings if f.rule_id == "SECRET-AWS-ACCESS-KEY")
        self.assertNotIn("AKIAQ3EGRQFAKE7DEMO1", f.snippet)
        env = next(f for f in self.result.findings if f.rule_id == "WEB-EXPOSED-ENV")
        self.assertNotIn("hunter2", env.snippet)


class PassiveAndSoft404Test(unittest.TestCase):
    def test_passive_mode_sends_no_probes(self):
        web_fixture.Handler.requested = []
        srv, url = web_fixture.serve()
        try:
            r = scan_site(url, opts(active=False))
        finally:
            srv.shutdown()
        ids = {f.rule_id for f in r.findings}
        self.assertFalse(ids & {"WEB-REFLECTED-XSS", "WEB-SQL-ERROR", "WEB-OPEN-REDIRECT"})
        self.assertFalse([p for p in web_fixture.Handler.requested if "vf" in p and "%3C" in p or "%27" in p])

    def test_catch_all_site_produces_no_exposed_file_findings(self):
        srv, url = web_fixture.serve(web_fixture.Soft404Handler)
        try:
            r = scan_site(url, opts(max_pages=2))
        finally:
            srv.shutdown()
        self.assertFalse([f.rule_id for f in r.findings if f.rule_id.startswith(("WEB-EXPOSED", "WEB-PHPINFO", "WEB-SPRING"))])

    def test_unreachable_site_is_a_clear_error(self):
        with self.assertRaises(ValueError):
            scan_site("http://127.0.0.1:9", opts(timeout=2))


class CheckUnitTest(unittest.TestCase):
    def test_csp_quality(self):
        weak = checks.header_checks(resp({"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'"}), True)
        self.assertIn("WEB-CSP-WEAK", {f.rule_id for f in weak})
        nonce = checks.header_checks(resp({"Content-Security-Policy": "script-src 'nonce-abc' 'unsafe-inline' 'strict-dynamic'; frame-ancestors 'none'"}), True)
        self.assertFalse({"WEB-CSP-WEAK", "WEB-CSP-MISSING", "WEB-CLICKJACKING"} & {f.rule_id for f in nonce})

    def test_hsts(self):
        ids = {f.rule_id for f in checks.header_checks(resp({"Strict-Transport-Security": "max-age=300"}), True)}
        self.assertIn("WEB-HSTS-SHORT", ids)
        ids = {f.rule_id for f in checks.header_checks(resp({"Strict-Transport-Security": "max-age=31536000"}), True)}
        self.assertFalse(ids & {"WEB-HSTS-SHORT", "WEB-HSTS-MISSING"})

    def test_cookies(self):
        r = resp({"Set-Cookie": ["session=abc; Path=/", "theme=dark; Secure; HttpOnly; SameSite=Lax",
                                 "old=; Max-Age=0", "tracking=1; SameSite=None"]})
        found = {f.title.split("'")[1]: f for f in checks.cookie_checks([r], True)}
        self.assertEqual(set(found), {"session", "tracking"})
        self.assertEqual(found["session"].severity, Severity.MEDIUM)

    def test_library_fingerprints(self):
        self.assertIn(("angular", "1.5.8"), libs.detect_from_content("/** @license AngularJS v1.5.8 (c) 2010-2016 Google"))
        self.assertIn(("bootstrap", "3.3.7"), libs.detect_from_content("/*! * Bootstrap v3.3.7 (http://getbootstrap.com)"))
        self.assertIn(("lodash", "4.17.15"), libs.detect_from_content("/** @license lodash */ ;(function(){var VERSION = '4.17.15';"))
        self.assertEqual(libs.detect_from_url("https://code.jquery.com/jquery-3.4.1.slim.min.js"), ("jquery", "3.4.1"))
        self.assertEqual(libs.detect_from_url("https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"),
                         ("@popperjs/core", "2.9.2"))

    def test_public_keys_in_frontend_are_low(self):
        found = libs.secret_findings("https://site.test/app.js", 'k="AIzaSyD-1234567890abcdefghijklmnopqrstu"')
        self.assertEqual([(f.rule_id, f.severity) for f in found], [("SECRET-GOOGLE-API-KEY", Severity.LOW)])

    def test_dns_email_checks(self):
        self.assertIsNone(dns.mail_domain("127.0.0.1"))
        self.assertEqual(dns.mail_domain("www.Example.org"), "example.org")
        records = {"example.org": ["v=spf1 include:_spf.google.com +all"], "_dmarc.example.org": []}
        orig = dns.txt
        dns.txt = lambda name, rtype="TXT", timeout=10: [] if rtype == "CAA" else records.get(name, [])
        try:
            ids = {f.rule_id for f in dns.check("www.example.org", [])}
        finally:
            dns.txt = orig
        self.assertEqual(ids, {"WEB-DNS-SPF-PERMISSIVE", "WEB-DNS-NO-DMARC", "WEB-DNS-NO-CAA"})


class WebCliTest(unittest.TestCase):
    def test_url_dispatches_to_web_scan(self):
        srv, url = web_fixture.serve()
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main([url, "--offline", "--no-dns", "--no-progress", "--rate", "200", "--max-pages", "3", "-f", "json"])
        finally:
            srv.shutdown()
        data = json.loads(out.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(data["summary"]["scanners"], ["web"])
        self.assertGreater(data["summary"]["requests_made"], 10)
        self.assertIn("authorised", err.getvalue())


if __name__ == "__main__":
    unittest.main()
