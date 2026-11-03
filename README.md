# vulnfind

[github.com/codingsushi79/vulnfind](https://github.com/codingsushi79/vulnfind)

A zero-dependency security scanner for project folders **and websites**, with ranked results that tell you what to fix first.

```bash
vulnfind ~/code/my-app            # scan code
vulnfind https://my-site.com      # scan a website you own
```

## What it finds

| Scanner | Depth |
|---|---|
| **deps** | Known CVEs, GHSA advisories and **malicious packages** from [OSV.dev](https://osv.dev) across 10 ecosystems. Each advisory is enriched with **CISA KEV** (exploited in the wild, ransomware use) and **EPSS** (probability of exploitation in the next 30 days). Shows the **dependency chain** (`express › body-parser › qs`), whether it's direct or transitive, and whether your code **actually imports it**. Also detects **typosquats** (`reqeusts`, `crossenv`), missing lockfiles and unpinned requirements. |
| **secrets** | 45+ credential formats (AWS, GitHub, GitLab, Stripe, Slack, OpenAI, Anthropic, Google, npm, PyPI, Docker Hub, Vault, Terraform Cloud, Grafana, Sentry, Notion, Atlassian, private keys, DB URLs, JWTs…) plus generic passwords, filtered by entropy and placeholder detection. With `--history`, every commit is checked, so a secret that was "deleted" but still sits in git history is found, along with the commit that introduced it. Output is always masked. |
| **code** | **Data-flow (taint) analysis.** For Python it uses the AST: request data, route parameters and CLI input are traced through variables, f-strings and helper functions (arguments *and* return values) into SQL, shell, `eval`, `pickle`/`yaml`, template, filesystem, HTTP and redirect sinks. For JS/TS it's scope-aware variable tracking from `req.query`/`req.body`/`location.search`… into `exec`, SQL, `fs`, `fetch`, `innerHTML`, `res.send`, `RegExp`, Mongo queries, `_.merge`. Sanitisers (`int()`, `shlex.quote`, `parseInt`, `DOMPurify`…) are understood. On top of that, ~100 pattern rules for Python, JS/TS, Go, Java/Kotlin, C#, PHP, Ruby, C/C++, shell and templates (CSRF off, insecure cookies, Electron, `NEXT_PUBLIC_*SECRET`, zip-slip, JWT without verification…). |
| **config** | Dockerfile (root user, unpinned base, secrets in `ENV`, `COPY .` without `.dockerignore`), compose & Kubernetes (privileged, host namespaces, docker.sock, dangerous capabilities, unpinned images), Terraform (SSH/RDP/DB ports open to the world, public buckets/DBs, IMDSv1, wildcard IAM), GitHub Actions (pwn requests, script injection, unpinned actions, self-hosted runners on PRs), pip dependency confusion, HTTP registries, weak TLS, and **end-of-life runtimes**. |
| **files** | Key stores, SSH keys, `.env`, Terraform state, git credentials, DB/heap dumps, world-writable files. Each one is marked as tracked, git-ignored, or *about to be committed*. |

| **web** | `vulnfind <url>` scans a live site: TLS certificate & protocol versions, HTTPS redirect, security headers (CSP quality, HSTS, clickjacking, nosniff…), cookie flags, CORS misconfiguration, risky HTTP methods, debug/error pages (Werkzeug, Django, Laravel, Rails…), ~50 **exposed-file probes** (`.git`, `.env`, backups, DB dumps, `phpinfo`, Spring actuator, source maps…), mixed content, missing SRI, password forms over HTTP, **vulnerable JavaScript libraries** served to visitors (OSV + KEV/EPSS), **secrets in served JS**, and SPF/DMARC/CAA. With `--active`, it also confirms reflected XSS, SQL errors and open redirects. See [Website scanning](#website-scanning). |

Every finding gets a **priority score (0–100)** combining severity, exploitation evidence (KEV/EPSS), reachability, confidence and context, and the report opens with **"Fix these first"**.

## Install

Python 3.8+ only, no third-party packages.

```bash
uv tool install git+https://github.com/codingsushi79/vulnfind       # or: pipx install git+https://github.com/codingsushi79/vulnfind
```

## Everyday use

```bash
vulnfind                              # scan the current folder (live progress on stderr)
vulnfind -v                           # + full descriptions, data flows, references, every CVE
vulnfind --history                    # + secrets anywhere in git history
vulnfind ~/code/*                     # many projects -> one summary table
vulnfind --scanners deps,secrets      # pick scanners (or --skip code)
vulnfind --min-severity high          # hide the noise
vulnfind explain CVE-2021-44228       # details for an advisory or rule
vulnfind fix                          # dry run: dependency upgrades as a diff
vulnfind fix --apply                  # write them (requirements.txt, package.json + npm/yarn/pnpm overrides, go.mod)
vulnfind watch                        # re-scan on save, prints new / resolved issues
vulnfind sbom -o sbom.cdx.json        # CycloneDX SBOM incl. vulnerabilities
```

Try it on the bundled, deliberately vulnerable demo: `vulnfind demo/vulnerable-app`.

## Website scanning

**Only scan sites you own or have written permission to test.**

```bash
vulnfind https://example.com                        # passive scan (same as `vulnfind web …`)
vulnfind web https://staging.example.com --active   # + confirm XSS / SQL errors / open redirects
vulnfind web https://app.example.com -H "Authorization: Bearer $TOKEN" --cookie "session=…" --max-pages 100
vulnfind web https://example.com https://shop.example.com   # several sites, one table
vulnfind web https://example.com -o site.html --fail-on high --notify https://hooks.slack.com/...
```

What it's careful about:

- **Passive by default.** It only sends GET/OPTIONS requests, crawls same-origin pages only, and never follows logout/delete/unsubscribe-style links.
- **Rate-limited and capped.** `--rate` (8 req/s), `--max-requests` (600), `--timeout`.
- **No soft-404 false positives.** An exposed-file hit must match a content signature (a real `.git/HEAD`, a real `KEY=value` env file…) and differ from a random-path baseline. Binary files are checked with a 4 KB `Range` request.
- **Narrow `--active` mode.** It sends harmless markers to GET parameters the crawl already found, never submits POST forms, and stops at `--active-budget` (150) requests.
- **Untrusted certificates** are reported, and the scan continues so the rest of the site is still checked (`--insecure` skips verification entirely).

All the usual machinery applies: priority ranking, every output format, `--fail-on`, `--baseline`, `--notify`, `--quiet-ok`. That makes a nightly cron job like `vulnfind https://example.com --quiet-ok --notify $SLACK_URL` a cheap external monitor.

Try it locally: `python3 tests/web_fixture.py 8090` starts a deliberately vulnerable site, then run `vulnfind http://127.0.0.1:8090 --active`.

## Automation

| Need | Command |
|---|---|
| Block bad commits | `vulnfind hook install`: a pre-commit hook that scans the **staged content** for secrets and high-risk code, and keeps any hook you already had. `hook uninstall` removes only its own part. |
| pre-commit framework | `vulnfind ci pre-commit` prints a config; this repo also ships `.pre-commit-hooks.yaml`. |
| GitHub Actions | `vulnfind ci github --write`: PRs scan only changed files and annotate the diff inline; pushes and a nightly cron run a full scan with history, upload SARIF to the Security tab, and attach an HTML report. |
| GitLab CI | `vulnfind ci gitlab --write`: JUnit test report + HTML artifact, MR-diff mode. |
| PR / branch scans | `vulnfind --diff origin/main` (changed + untracked files only) · `vulnfind --staged` |
| Gate on regressions | `vulnfind -o before.json` … `vulnfind -o after.json` … `vulnfind compare before.json after.json` exits 1 if a new finding ≥ `--fail-on`. |
| Alerts | `--notify URL` posts a summary to Slack, Discord or Teams (auto-detected) or any JSON webhook. Only for projects with failing findings, unless `--notify-always`. |
| Cron / scheduled | `vulnfind ~/code/* --quiet-ok --notify https://hooks.slack.com/...` is silent unless something fails. |
| Config as code | `vulnfind init` writes `.vulnfind.json` (defaults for every flag; flags still win) and `.vulnfindignore`. |

### Output formats

`-f/--format` for stdout, `-o FILE` (repeatable) with format from the extension:

| Format | Flag / extension | For |
|---|---|---|
| table | default | humans |
| json | `-f json`, `.json` | scripts, `compare` |
| sarif | `.sarif` | GitHub code scanning, IDEs |
| github | `-f github` | inline PR annotations in Actions |
| junit | `.xml` | GitLab/Jenkins/Azure test reports |
| html | `.html` | interactive, filterable report |
| markdown | `.md` | PR comments, job summaries |
| csv | `.csv` | spreadsheets |
| sbom | `.cdx.json` | CycloneDX 1.5 |

### Exit codes

`0` clean · `1` findings at or above `--fail-on` (default `high`; `none` disables) · `2` usage/runtime error.

## Handling findings

- **Inline:** `# vulnfind:ignore [RULE-ID]` on the line or on its own line directly above (`nosec`, `gitleaks:allow` also work).
- **Project-wide** in `.vulnfindignore`: paths (gitignore syntax), `rule:ID`, `vuln:CVE-…`.
- **Baseline:** `--write-baseline base.json`, then `--baseline base.json` reports only new issues. Fingerprints ignore line numbers.

Noise control is built in: `.gitignore` is honoured via `git ls-files`, vendored/build folders are skipped, code rules ignore comments and string literals, confirmed data flows replace the weaker pattern hit on the same line, findings in `tests/`/`examples/`/`docs/` drop one severity level, SQL that already uses bind parameters is downgraded, and placeholder or localhost credentials are skipped or marked LOW.

## Performance

File scanning runs across CPU cores (`-j N`), secret regexes only run on files containing their keyword, and advisory, KEV and EPSS data is cached for 24h in `~/.cache/vulnfind` (`vulnfind cache info|clear`). Use `--no-deep` to skip taint analysis.

## Privacy & network

Folder scans: only dependency checks touch the network. Package **names and versions** go to `api.osv.dev` and CVE IDs to `api.first.org` (EPSS), and the public CISA KEV feed is downloaded. Source code never leaves your machine.

Website scans: requests go to the target site. Detected JS library names and versions go to OSV, and the domain's TXT/CAA records are looked up via DNS-over-HTTPS at `cloudflare-dns.com` (override with `VULNFIND_DOH_URL`, or skip with `--no-dns`).

`--offline` disables all third-party lookups (`--no-enrich` disables only KEV/EPSS). `--notify` sends findings to the URL you give it.

## Limitations

Website scanning is a fast baseline, not a full penetration test: it doesn't log in by itself (pass `-H`/`--cookie`), execute JavaScript (single-page apps that render links client-side crawl shallowly), fuzz POST forms, or find business-logic flaws. Taint analysis works within a single file, and the JS engine works line by line rather than from a full parse, so cross-module flows and unusual code shapes can be missed. Pattern rules can't prove exploitability. Treat code findings as "look here", and the data-flow ones as "look here first". Dependency precision depends on your lockfile. CVSS v4-only advisories get an approximate score.

## Development

```bash
python3 -m unittest discover -s tests     # 90 tests, no dependencies (web tests use a local fixture site)
```

Rules are data: add a `Rule(...)` in `vulnfind/scanners/{secrets,code,iac}.py`, a taint sink in `taint_python.py` / `taint_js.py`, or a file pattern in `files.py`.
