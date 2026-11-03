import json
import unittest

from vulnfind import manifests as m


def names(pkgs):
    return sorted((p.name, p.version) for p in pkgs)


class ManifestTest(unittest.TestCase):
    def test_package_lock_v3(self):
        text = json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "app"},
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/a/node_modules/@scope/b": {"version": "1.0.0", "dev": True},
            "packages/local": {"link": True},
        }})
        pkgs = m.parse_package_lock(text, "package-lock.json")
        self.assertEqual(names(pkgs), [("@scope/b", "1.0.0"), ("lodash", "4.17.20")])
        self.assertTrue(next(p for p in pkgs if p.name == "@scope/b").dev)

    def test_package_lock_v1(self):
        text = json.dumps({"lockfileVersion": 1, "dependencies": {
            "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}}})
        self.assertEqual(names(m.parse_package_lock(text, "p")), [("a", "1.0.0"), ("b", "2.0.0")])

    def test_yarn_v1_and_berry(self):
        v1 = 'lodash@^4.17.15, lodash@^4.17.20:\n  version "4.17.20"\n  resolved "x"\n\n"@babel/core@^7.0.0":\n  version "7.1.0"\n'
        self.assertEqual(names(m.parse_yarn_lock(v1, "y")), [("@babel/core", "7.1.0"), ("lodash", "4.17.20")])
        berry = '"lodash@npm:^4.17.20":\n  version: 4.17.21\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n'
        self.assertEqual(names(m.parse_yarn_lock(berry, "y")), [("lodash", "4.17.21")])

    def test_pnpm(self):
        text = "lockfileVersion: '9.0'\n\npackages:\n\n  lodash@4.17.20:\n    resolution: {}\n\n  '@babel/core@7.1.0':\n    resolution: {}\n\n  /minimist@1.2.5:\n    x: y\n"
        self.assertEqual(names(m.parse_pnpm_lock(text, "p")), [("@babel/core", "7.1.0"), ("lodash", "4.17.20"), ("minimist", "1.2.5")])

    def test_package_json_marks_ranges_approximate(self):
        text = json.dumps({"dependencies": {"a": "^1.2.3", "b": "1.0.0", "c": "latest", "d": "git+https://x"}})
        pkgs = m.parse_package_json(text, "package.json")
        self.assertEqual(names(pkgs), [("a", "1.2.3"), ("b", "1.0.0")])
        self.assertTrue(next(p for p in pkgs if p.name == "a").approximate)

    def test_requirements(self):
        text = "Django==3.2.0\nrequests[socks]==2.25.0 ; python_version > '3'\nflask>=2\n# comment\nPyYAML===5.3 --hash=sha256:abc\n"
        self.assertEqual(names(m.parse_requirements(text, "r")), [("django", "3.2.0"), ("pyyaml", "5.3"), ("requests", "2.25.0")])

    def test_poetry_and_cargo(self):
        poetry = '[[package]]\nname = "Jinja2"\nversion = "2.11.2"\ndescription = "x"\n\n[[package]]\nname = "idna"\nversion = "2.8"\n'
        self.assertEqual(names(m.parse_poetry_lock(poetry, "p")), [("idna", "2.8"), ("jinja2", "2.11.2")])
        cargo = '[[package]]\nname = "myapp"\nversion = "0.1.0"\n\n[[package]]\nname = "smallvec"\nversion = "1.6.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
        self.assertEqual(names(m.parse_cargo_lock(cargo, "c")), [("smallvec", "1.6.0")])

    def test_go_mod(self):
        text = "module x\n\ngo 1.22.3\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.6.3\n\tgolang.org/x/net v0.1.0 // indirect\n)\nrequire github.com/a/b v2.0.0+incompatible\nreplace golang.org/x/net => ../net\n"
        got = names(m.parse_go_mod(text, "go.mod"))
        self.assertIn(("github.com/gin-gonic/gin", "1.6.3"), got)
        self.assertIn(("github.com/a/b", "2.0.0"), got)
        self.assertIn(("stdlib", "1.22.3"), got)
        self.assertNotIn("golang.org/x/net", [n for n, _ in got])

    def test_gemfile_and_composer(self):
        gem = "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.10.0-x86_64-linux)\n      racc (~> 1.4)\n    rails (5.2.0)\n\nPLATFORMS\n  ruby\n"
        self.assertEqual(names(m.parse_gemfile_lock(gem, "g")), [("nokogiri", "1.10.0"), ("rails", "5.2.0")])
        comp = json.dumps({"packages": [{"name": "guzzlehttp/guzzle", "version": "v7.0.0"}], "packages-dev": []})
        self.assertEqual(names(m.parse_composer_lock(comp, "c")), [("guzzlehttp/guzzle", "7.0.0")])

    def test_pom_with_properties(self):
        pom = """<project xmlns="http://maven.apache.org/POM/4.0.0"><properties><log4j.version>2.14.1</log4j.version></properties>
        <dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId>
        <version>${log4j.version}</version></dependency><dependency><groupId>x</groupId><artifactId>y</artifactId>
        <version>${unknown}</version></dependency></dependencies></project>"""
        self.assertEqual(names(m.parse_pom(pom, "pom.xml")), [("org.apache.logging.log4j:log4j-core", "2.14.1")])

    def test_csproj_and_pubspec(self):
        cs = '<ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup>'
        self.assertEqual(names(m.parse_csproj(cs, "a.csproj")), [("Newtonsoft.Json", "12.0.1")])
        pub = 'packages:\n  http:\n    dependency: "direct main"\n    source: hosted\n    version: "0.13.5"\n  local:\n    source: path\n    version: "1.0.0"\n'
        self.assertEqual(names(m.parse_pubspec_lock(pub, "p")), [("http", "0.13.5")])

    def test_purl(self):
        from vulnfind.models import Package
        self.assertEqual(Package("@a/b", "1.0.0", "npm", "x").purl, "pkg:npm/%40a/b@1.0.0")
        self.assertEqual(Package("g:a", "1", "Maven", "x").purl, "pkg:maven/g/a@1")


if __name__ == "__main__":
    unittest.main()
