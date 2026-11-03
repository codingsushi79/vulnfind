# vulnfind

A zero-dependency security scanner for any project folder. One command checks:

| Scanner | What it finds |
|---|---|
| **deps** | Known CVEs / GHSA advisories / malicious packages in your dependencies, via [OSV.dev](https://osv.dev) (GitHub Advisories, NVD, PyPA, RustSec, Go vulndb, RubySec…). Shows CVSS score and the exact upgrade command. |
| **secrets** | 30+ credential formats (AWS, GitHub, GitLab, Stripe, Slack, OpenAI, Anthropic, Google, npm, PyPI, SendGrid, private keys, DB URLs, JWTs…) plus generic passwords/API keys, filtered by entropy and placeholder detection. Secrets are always masked in output. |
| **code** | ~75 insecure-code rules for Python, JavaScript/TypeScript, Go, Java/Kotlin, C#, PHP, Ruby, C/C++, shell and HTML templates: SQL/command/code injection, XSS, unsafe deserialization, path traversal, SSRF, open redirects, disabled TLS verification, weak crypto, insecure randomness, debug mode… |
| **config** | Dockerfile, docker-compose, Kubernetes, Terraform, GitHub Actions (pwn requests, script injection, unpinned actions), nginx, weak TLS, and **end-of-life runtimes** (Python, Node, PHP, Ruby, Go). |
| **files** | Committed key stores, SSH keys, `.env` files, Terraform state, git credentials, DB dumps, heap dumps, world-writable files — with git awareness (tracked vs. ignored vs. about-to-be-committed). |

Supported lockfiles/manifests: `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (v1 + berry), `pnpm-lock.yaml`, `bun.lock`, `package.json` (fallback), `requirements*.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `pdm.lock`, `go.mod`, `Cargo.lock`, `Gemfile.lock`, `composer.lock`, `pom.xml`, `gradle.lockfile`, `*.csproj`, `packages.lock.json`, `packages.config`, `pubspec.lock`, `mix.lock`.

## Install

Needs Python 3.8+ and nothing else.

```bash
pipx install /path/to/vulnfind
```

or, without installing:

```bash
python3 -m vulnfind /path/to/project
```

## Usage

```bash
vulnfind                                # scan the current folder
vulnfind ~/code/my-app -v               # full descriptions, references, every CVE
vulnfind --scanners deps                # only dependency CVEs
vulnfind --skip code,files              # everything except code + file checks
vulnfind --min-severity high            # hide low/medium noise
vulnfind -o report.html                 # interactive HTML report
vulnfind -o results.sarif               # SARIF for GitHub code scanning
vulnfind -f json | jq '.summary'        # JSON to stdout
vulnfind -f markdown > SECURITY.md      # Markdown (great for PR comments)
vulnfind sbom -o sbom.cdx.json          # CycloneDX SBOM (+ known vulns)
vulnfind rules                          # list all built-in rules
vulnfind explain GHA-PWN-REQUEST        # details + fix for one rule
```

Try it on the bundled, deliberately vulnerable demo app:

```bash
python3 -m vulnfind demo/vulnerable-app
```

Each run ends with a summary and a security grade (A–F, any critical finding is an F).

### Exit codes (for CI)

| Code | Meaning |
|---|---|
| 0 | No findings at or above `--fail-on` (default `high`) |
| 1 | At least one finding at or above `--fail-on` |
| 2 | Usage or runtime error |

Use `--fail-on critical` to gate only on criticals, or `--fail-on none` to never fail.

## Handling findings

**Inline**: put a comment on the same line, or on its own line directly above:

```python
result = eval(trusted_expr)  # vulnfind:ignore PY-EVAL
```

`nosec` and `gitleaks:allow` are also honoured. Without a rule ID, the comment suppresses every rule on that line.

**Project-wide**: create a `.vulnfindignore` (`vulnfind init` writes a template):

```gitignore
docs/                        # paths, .gitignore syntax
**/*.min.js
rule:PY-REQUESTS-NO-TIMEOUT  # disable a rule
vuln:CVE-2023-12345          # accept an advisory (CVE, GHSA, PYSEC…) - say why!
```

**Baseline** (adopt in an existing codebase without fixing everything first):

```bash
vulnfind --write-baseline .vulnfind-baseline.json
vulnfind --baseline .vulnfind-baseline.json   # only reports new findings
```

Baseline fingerprints ignore line numbers, so they survive unrelated edits.

### Noise control built in

- `.gitignore` is respected (via `git ls-files` when in a repo); `node_modules`, `vendor`, `dist`, `build`, `.venv` and similar folders are skipped. Use `--no-gitignore` / `--include-vendor` to change that.
- Code rules ignore comments and matches inside string literals.
- Findings under `tests/`, `examples/`, `fixtures/`, `docs/`… are lowered one severity level (`--no-test-downgrade` to disable).
- SQL-injection hits on queries that already use bind parameters are lowered, since the interpolated part is usually a table or column name.
- Placeholder secrets (`changeme`, `your-api-key`, `${VAR}`, `AKIA…EXAMPLE`, `@host:5432`) are skipped; credentials pointing at `localhost` or Docker service names are reported as LOW.
- `--no-dev` ignores vulnerabilities in dev-only dependencies.

## GitHub Actions

```yaml
name: security
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  vulnfind:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install ./path/to/vulnfind   # or from your package index
      - run: vulnfind --fail-on high -o vulnfind.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: vulnfind.sarif }
```

## Privacy and network use

Only the **deps** scanner uses the network. It sends package names and versions (never source code) to `api.osv.dev`. Advisory details are cached in `~/.cache/vulnfind` for 24 hours. Use `--offline` to skip the lookup (dependencies are still inventoried, and the SBOM still works), or `--no-cache` to force fresh data. Point `VULNFIND_OSV_API` at a mirror if you need to.

## Limitations

This is a fast, pattern-based scanner, not a full data-flow analyser. It can't tell whether a flagged `eval` really receives user input, so read code findings as "look here" rather than proof. Dependency results are only as precise as your lockfile: commit one. CVSS v4-only advisories get an approximate score.

## Development

```bash
python3 -m unittest discover -s tests
```

Rules are plain data in `vulnfind/scanners/{secrets,code,iac,files}.py`. To add one, append a `Rule(...)` with an ID, severity, regex, description, fix and the file extensions it applies to.
