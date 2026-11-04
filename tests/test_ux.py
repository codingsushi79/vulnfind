"""Benchmark, history/trend, plain-language output, triage, and the AI command (fake SDK)."""

import contextlib
import io
import json
import os
import sys
import tempfile
import types
import unittest

from vulnfind import bench, cli, history, plain, triage
from vulnfind.engine import ScanOptions, scan
from vulnfind.models import Finding, ScanResult, Severity

from helpers import TempProject

APP = "from flask import request\nimport os, pickle, hashlib\nx = pickle.loads(request.data)\nos.system('ls ' + request.args['d'])\nhashlib.md5(b'1')\n"


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(args))
    return code, out.getvalue(), err.getvalue()


class BenchTest(unittest.TestCase):
    def test_corpus_scores(self):
        s = bench.run()
        self.assertGreaterEqual(len(s.tp) + len(s.fn), 30)
        self.assertGreaterEqual(s.recall, 0.95, s.fn)
        self.assertGreaterEqual(s.precision, 0.95, s.fp)

    def test_cli_threshold_exit_code(self):
        self.assertEqual(run_cli("bench", "--min-recall", "0.9")[0], 0)
        self.assertEqual(run_cli("bench", "--min-recall", "1.01")[0], 1)


class HistoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = {k: os.environ.get(k) for k in ("XDG_DATA_HOME", "VULNFIND_NO_HISTORY")}
        os.environ["XDG_DATA_HOME"] = self.tmp.name
        os.environ.pop("VULNFIND_NO_HISTORY", None)

    def tearDown(self):
        for k, v in self.env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def test_scans_are_recorded_and_trend_renders(self):
        with TempProject({"app.py": APP}) as root:
            run_cli(root, "--offline", "--no-progress", "-q")
            with open(os.path.join(root, "app.py"), "w") as fh:
                fh.write("x = 1\n")
            run_cli(root, "--offline", "--no-progress", "-q")
            rows = history.load(os.path.abspath(root))
            self.assertEqual(len(rows), 2)
            self.assertGreater(rows[0]["total"], rows[1]["total"])
            code, out, _ = run_cli("trend", root, "--no-color")
            self.assertEqual(code, 0)
            self.assertIn("2 scans", out)
            html_path = os.path.join(self.tmp.name, "t.html")
            run_cli("trend", root, "-o", html_path)
            with open(html_path) as fh:
                page = fh.read()
            self.assertIn("Security trend", page)
            self.assertNotIn("const top", page)  # window.top collision guard
            self.assertIn(os.path.abspath(root), run_cli("trend", "--list")[1])

    def test_no_record_flag(self):
        with TempProject({"app.py": "x = 1\n"}) as root:
            run_cli(root, "--offline", "--no-progress", "-q", "--no-record")
            self.assertEqual(history.load(os.path.abspath(root)), [])

    def test_sparkline(self):
        self.assertEqual(history.sparkline([0, 0]), "▁▁")
        self.assertEqual(history.sparkline([1, 8])[-1], "█")


class PlainTest(unittest.TestCase):
    def test_explanations(self):
        sqli = Finding("PY-TAINT-SQLI", "SQL injection", Severity.CRITICAL, "code", "a.py", 1, cwe="CWE-89",
                       extra={"route_auth": False})
        text = plain.explain(sqli)
        self.assertIn("database", text)
        self.assertIn("without logging in", text)
        self.assertIn("urgent", text)
        dep = Finding("CVE-1", "x", Severity.HIGH, "dependency", "p", extra={"package": "lodash", "version": "4.17.20", "fixed": "4.17.21",
                                                                         "kev": {"cve": "CVE-1"}})
        self.assertIn("already exploiting", plain.explain(dep))
        self.assertIn("4.17.21", plain.explain(dep))

    def test_cli_flag(self):
        with TempProject({"app.py": APP}) as root:
            out = run_cli(root, "--offline", "--no-progress", "--no-color", "--plain")[1]
        self.assertIn("Someone could", out)


class TriageTest(unittest.TestCase):
    def test_decisions_persist_and_hide_findings(self):
        with TempProject({"app.py": APP}) as root:
            res = scan(root, ScanOptions(offline=True))
            n = len(res.findings)
            answers = iter(["o", "a", "", "internal only", "p", "validated upstream", "r", "cache keys only"] + ["s"] * 20)
            out = io.StringIO()
            stats = triage.run(root, res.findings, ask=lambda q: next(answers), out=out)
            self.assertEqual((stats["accepted"], stats["false-positive"], stats["rule-ignored"]), (1, 1, 1))
            self.assertIn("app.py:", out.getvalue())  # 'o' printed the location
            with open(os.path.join(root, triage.BASELINE)) as fh:
                data = json.load(fh)
            self.assertEqual(sorted(d["status"] for d in data["findings"]), ["accepted", "false-positive"])
            self.assertEqual(data["findings"][0]["reason"] if data["findings"][0]["status"] == "accepted" else data["findings"][1]["reason"],
                             "internal only")  # empty reason was re-asked
            again = scan(root, ScanOptions(offline=True))
            self.assertLessEqual(len(again.findings), n - 3)
            # decided findings are already filtered out of `again`; feeding the originals back finds nothing new to ask about
            out2 = io.StringIO()
            asked = []
            triage.run(root, [f for f in res.findings if f.rule_id != "PY-WEAK-HASH"][:2], ask=lambda q: asked.append(q) or "s", out=out2)
            self.assertIn("Nothing to triage", out2.getvalue())
            self.assertEqual(asked, [])


def _fake_anthropic(stop_reason="end_turn", text="## Verdict\nReal issue", fail=None):
    mod = types.ModuleType("anthropic")

    class APIError(Exception):
        def __init__(self, message="err", status_code=500):
            super().__init__(message)
            self.message, self.status_code = message, status_code
    for name in ("AuthenticationError", "PermissionDeniedError", "RateLimitError", "APIStatusError", "APIConnectionError"):
        setattr(mod, name, type(name, (APIError,), {}))
    calls = []

    class Stream:
        def __init__(self, kw):
            self.kw = kw

        def __enter__(self):
            if fail:
                raise getattr(mod, fail)("boom")
            return self

        def __exit__(self, *a):
            return False

        def get_final_message(self):
            return types.SimpleNamespace(stop_reason=stop_reason, content=[types.SimpleNamespace(type="thinking"),
                                                                           types.SimpleNamespace(type="text", text=text)])

    class Messages:
        def stream(self, **kw):
            calls.append(kw)
            return Stream(kw)

    class Anthropic:
        def __init__(self):
            self.beta = types.SimpleNamespace(messages=Messages())
    mod.Anthropic = Anthropic
    mod.calls = calls
    return mod


class AITest(unittest.TestCase):
    def tearDown(self):
        sys.modules.pop("anthropic", None)

    def test_request_shape_and_context(self):
        fake = _fake_anthropic()
        sys.modules["anthropic"] = fake
        from vulnfind import ai
        with TempProject({"app.py": APP}) as root:
            res = scan(root, ScanOptions(offline=True))
            out = list(ai.explain(res.findings[:1], root))
        kw = fake.calls[0]
        self.assertEqual(kw["model"], "claude-opus-5-5")
        self.assertEqual(kw["thinking"], {"type": "adaptive"})
        self.assertEqual((kw["fallbacks"], kw["betas"]), ("default", ["server-side-fallback-2026-07-01"]))
        prompt = kw["messages"][0]["content"]
        self.assertIn("pickle.loads(request.data)", prompt)  # surrounding source is included
        self.assertIn(">", prompt)
        self.assertEqual(out[0][1], "## Verdict\nReal issue")  # thinking blocks skipped

    def test_refusal_and_auth_errors(self):
        from vulnfind import ai
        sys.modules["anthropic"] = _fake_anthropic(stop_reason="refusal")
        f = Finding("X", "t", Severity.HIGH, "code", "a.py", 1)
        self.assertIn("declined", list(ai.explain([f], "/nonexistent"))[0][1])
        sys.modules["anthropic"] = _fake_anthropic(fail="AuthenticationError")
        with self.assertRaises(ai.AIUnavailable):
            list(ai.explain([f], "/nonexistent"))

    def test_missing_sdk_fails_before_scanning(self):
        sys.modules["anthropic"] = None  # import raises ImportError
        code, _, err = run_cli("ai", ".", "--offline")
        self.assertEqual(code, 2)
        self.assertIn("pip install", err)


if __name__ == "__main__":
    unittest.main()
