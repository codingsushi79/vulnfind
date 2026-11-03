import unittest

from vulnfind.cvss import cvss2_score, cvss3_score, score_vector
from vulnfind.models import Finding, ScanResult, Severity
from vulnfind.walker import PathMatcher, line_index, locate


class CvssTest(unittest.TestCase):
    def test_v3_known_scores(self):
        self.assertEqual(cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)
        self.assertEqual(cvss3_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"), 6.5)
        self.assertEqual(cvss3_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1)
        self.assertEqual(cvss3_score("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0)

    def test_v2_and_dispatch(self):
        self.assertEqual(cvss2_score("AV:N/AC:L/Au:N/C:P/I:P/A:P"), 7.5)
        self.assertEqual(score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertIsNone(score_vector("garbage"))
        v4 = score_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
        self.assertGreaterEqual(v4, 9.0)


class SeverityTest(unittest.TestCase):
    def test_parse_and_score(self):
        self.assertEqual(Severity.parse("moderate"), Severity.MEDIUM)
        self.assertEqual(Severity.from_score(9.8), Severity.CRITICAL)
        self.assertEqual(Severity.from_score(7.0), Severity.HIGH)
        self.assertEqual(Severity.from_score(3.9), Severity.LOW)
        self.assertEqual(Severity.INFO.lowered(), Severity.INFO)
        with self.assertRaises(ValueError):
            Severity.parse("bogus")

    def test_grade(self):
        r = ScanResult(root="/x")
        self.assertEqual(r.grade, "A")
        r.findings.append(Finding("X", "t", Severity.CRITICAL, "code", "a.py"))
        self.assertEqual(r.grade, "F")

    def test_fingerprint_ignores_line_numbers(self):
        a = Finding("R", "t", Severity.LOW, "code", "a.py", line=3, snippet="eval(x)")
        b = Finding("R", "t", Severity.LOW, "code", "a.py", line=30, snippet="  eval(x)")
        self.assertEqual(a.fingerprint, b.fingerprint)


class PathMatcherTest(unittest.TestCase):
    def test_gitignore_semantics(self):
        m = PathMatcher(["*.log", "build/", "/root-only.txt", "docs/**/*.md", "!keep.log", "**/fixtures"])
        self.assertTrue(m.matches("a/b/debug.log"))
        self.assertFalse(m.matches("a/keep.log"))
        self.assertTrue(m.matches("build/x.js"))
        self.assertTrue(m.matches("pkg/build", is_dir=True))
        self.assertFalse(m.matches("build"))  # dir-only pattern vs file
        self.assertTrue(m.matches("root-only.txt"))
        self.assertFalse(m.matches("sub/root-only.txt"))
        self.assertTrue(m.matches("docs/a/b/c.md"))
        self.assertTrue(m.matches("docs/c.md"))
        self.assertTrue(m.matches("tests/fixtures/x.py"))

    def test_locate(self):
        text = "ab\ncd\n\nef"
        idx = line_index(text)
        self.assertEqual(locate(idx, 0), (1, 1))
        self.assertEqual(locate(idx, 4), (2, 2))
        self.assertEqual(locate(idx, 7), (4, 1))


if __name__ == "__main__":
    unittest.main()
