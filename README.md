# vulnfind

[github.com/codingsushi79/vulnfind](https://github.com/codingsushi79/vulnfind)

A zero-dependency security scanner for **code, websites, container images and cloud accounts**, with ranked results that tell you what to fix first.

```bash
vulnfind ~/code/my-app                 # your code
vulnfind github.com/owner/repo         # someone's repo, by URL (shallow clone, nothing executed)
vulnfind https://my-site.com           # a website you own
vulnfind image my-app:latest           # a container image
vulnfind k8s · vulnfind cloud aws      # a live cluster / cloud account (read-only)
```

Python 3.8+. The core needs no third-party packages; the optional AI explanations use the official `anthropic` SDK.

```bash
uv tool install git+https://github.com/codingsushi79/vulnfind      # or: pipx install git+https://github.com/codingsushi79/vulnfind
```

## What it finds

### In your code (`vulnfind <folder>`)

| Scanner | Depth |
|---|---|
| **deps** | Known CVEs, GHSA advisories and malicious packages from [OSV.dev](https://osv.dev) across 10 ecosystems, enriched with **CISA KEV** (exploited in the wild) and **EPSS** (exploit probability). For each package it shows the dependency chain (`express › body-parser › qs`), whether it's direct, whether your code imports it, and **whether your code calls the vulnerable function** (exact symbols for Go; names from the advisory text otherwise, labelled as a heuristic). Plus typosquats, suspicious npm install scripts, deprecated and abandoned packages, license conflicts (GPL/AGPL in a permissive or proprietary project), missing lockfiles and unpinned requirements. |
| **secrets** | 45+ credential formats plus generic passwords, filtered by entropy and placeholder detection, always masked in output. `--history` checks every commit, so deleted-but-still-in-git secrets are found along with the commit that added them. |
| **code** | **Data-flow analysis.** Python (AST, **across files**: views → services → db), JavaScript/TypeScript, Go and PHP: user input is traced through variables, string building and helper functions into SQL, shell, eval, deserialization, templates, the filesystem, outbound HTTP, redirects and HTML. Sanitizers and constants are understood, so their lines aren't flagged. **Route inventory and missing-auth detection** for Flask, FastAPI, Django REST, Express-style routers and Next.js (`vulnfind routes`); auth helpers are recognized one call deep. Each data flow says whether an anonymous user can reach it. ~100 more pattern rules across 10 languages. |
| **config** | Dockerfile, compose, Kubernetes, Terraform **and Terraform plan JSON**, GitHub Actions (pwn requests, script injection, unpinned actions), pip dependency confusion, end-of-life runtimes… |
| **files** | Key stores, `.env`, Terraform state, dumps, world-writable files, with git awareness (tracked, ignored, about to be committed). |

### On a website (`vulnfind <url>`, see [Website scanning](#website-scanning))

TLS and certificates, security headers, cookies, CORS, debug pages, ~50 exposed-file probes, **server software CVEs** from version banners (NVD), vulnerable front-end JS libraries, secrets in served JS, SPF/DMARC/CAA, **login-aware crawling**, **OpenAPI-driven API auth testing**, optional headless-browser rendering, and **subdomain takeover detection**. With `--active`, it also confirms reflected XSS, SQL errors and open redirects.

### In infrastructure

| Command | What it checks (read-only) |
|---|---|
| `vulnfind image <ref>` | Reads a container image layer by layer without running it. Checks: OS packages (Debian/Ubuntu dpkg, Alpine apk, RPM), npm/Python/**Java JARs incl. fat JARs**, **Go binaries' embedded modules**, servers compiled from source (Apache, nginx, PHP, Node, Redis, Postgres → NVD), secrets left in the image, root user, secrets in `ENV`, end-of-life base OS. |
| `vulnfind k8s` | Workloads (privileged, host namespaces, sensitive hostPath, dangerous capabilities, root, missing limits, unpinned images, plain-text secrets in env), cluster-admin bindings (incl. anonymous), Ingress without TLS, namespaces without NetworkPolicy. Uses your `kubectl` context. |
| `vulnfind cloud aws` | Root MFA and keys, IAM users without MFA, old access keys, public S3 (policy, ACL, Block Public Access), security groups exposing admin/database ports, public or unencrypted RDS, IMDSv1, missing CloudTrail. Uses your `aws` CLI. |
| `vulnfind cloud gcp` | Firewall rules, public IAM bindings, primitive roles on service accounts, public buckets, Cloud SQL exposure and SSL. Uses your `gcloud` CLI. |
| `vulnfind tfplan plan.json` | The same Terraform checks on the planned changes (`terraform show -json plan.out`); folder scans pick plan files up automatically. |

Every finding gets a **priority score (0–100)** combining severity, exploitation evidence, reachability (imported? function called? reachable without login?), confidence and context. Every report opens with **"Fix these first"**.

## Everyday use

```bash
vulnfind                              # scan the current folder (live progress on stderr)
vulnfind -v                           # full descriptions, data flows, references, every CVE
vulnfind --plain                      # plain-language explanations for non-security readers
vulnfind --history                    # + secrets anywhere in git history
vulnfind ~/code/*                     # many projects -> one summary table
vulnfind routes                       # HTTP endpoints and whether each requires auth
vulnfind triage                       # walk findings: accept / false positive / ignore rule
vulnfind trend -o trend.html          # how findings changed across past scans (chart)
vulnfind fix --apply                  # upgrade vulnerable deps (requirements, package.json + overrides, go.mod)
vulnfind ai --top 3                   # Claude explains the top findings and drafts patches (optional)
vulnfind watch                        # re-scan on save
vulnfind explain CVE-2021-44228       # an advisory or any rule
```

### Triage once, share the decisions

`vulnfind triage` saves every decision, with a reason, who made it and when, in `.vulnfind-baseline.json`. Commit that file: later scans, CI and teammates load it automatically, so accepted risks and false positives stay hidden until the code changes. `rule:ID` entries go to `.vulnfindignore`.

### AI explanations (optional)

`vulnfind ai` sends the highest-priority findings to Claude (`claude-opus-5-5`) together with ±30 lines of the surrounding source, including every file a cross-file flow passes through. For each finding it returns a verdict (real issue vs. likely false positive), the concrete impact, a minimal unified-diff fix, and a way to verify it. Setup: `pip install "vulnfind[ai]"` plus `ANTHROPIC_API_KEY` or `ant auth login`. Requests enable the server-side refusal fallback (`fallbacks: "default"`), because security-analysis prompts can occasionally trip safety classifiers on benign code. **Nothing is sent unless you run this command.**

### VS Code

[`editors/vscode`](editors/vscode) is a small extension (needs vulnfind 3.0+ on PATH):
- **Inline findings** with severity colors.
- **Data-flow steps** shown as related locations.
- **A quick fix** that inserts `vulnfind:ignore RULE-ID`.
- **A status-bar counter**; clicking it runs a full scan including dependency CVEs.

## Website scanning

**Only scan sites you own or have written permission to test.**

```bash
vulnfind https://example.com                                   # passive
vulnfind web https://staging.example.com --active              # + confirm XSS / SQL errors / open redirects
VULNFIND_USER=qa@example.com VULNFIND_PASSWORD=… \
  vulnfind web https://app.example.com --login-url https://app.example.com/login      # crawl behind login
vulnfind web https://api.example.com --openapi https://api.example.com/openapi.json   # API auth testing
vulnfind web https://spa.example.com --browser                 # render JS (needs: pip install playwright)
vulnfind subdomains example.com                                # CT-log discovery + takeover check
```

What it's careful about:
- **Passive by default.** GET/OPTIONS only, same-origin crawling, and it skips logout/delete-style links. It's rate-limited and capped (`--rate`, `--max-requests`).
- **No soft-404 false positives.** An exposed-file hit must match a content signature and differ from a random-path baseline.
- **Login safety.** Credentials come from environment variables only, so they never land in shell history. It refuses to send them over plain HTTP, to an untrusted certificate (unless `--insecure`), or to a form that posts to another origin. It also reports two login weaknesses: no CSRF token, and a session ID that isn't rotated at login.
- **OpenAPI testing is read-only.** It sends GET operations only, without credentials. An operation the spec says requires auth but that answers anyway is flagged HIGH.
- **Narrow `--active` mode.** It sends harmless markers to GET parameters the crawl already found, never submits POST forms, and stops at a budget.
- **Version-based server CVEs.** Matched from the advertised version, never by sending exploits. Distro builds that may carry backported fixes are marked medium confidence.

## Automation

| Need | Command |
|---|---|
| CI for any repo | `uses: codingsushi79/vulnfind@main` (this repo is a GitHub Action: SARIF upload, PR-diff mode, job summary, `grade` / `findings` outputs), or `vulnfind ci github --write` for a full workflow. |
| Block bad commits | `vulnfind hook install` scans **staged content** and keeps any hook you already had. Also available through the pre-commit framework (`.pre-commit-hooks.yaml`). |
| Monitor over time | `vulnfind monitor ~/code/app https://app.example.com image:app:latest --notify $SLACK` alerts only on **new** findings since the previous run. `--print-cron` gives a crontab line. |
| PR / branch scans | `vulnfind --diff origin/main` · `vulnfind --staged` |
| Gate on regressions | `vulnfind compare before.json after.json` exits 1 if anything new reaches `--fail-on`. |
| Alerts | `--notify URL` posts to Slack, Discord, Teams or any JSON webhook. `--quiet-ok` stays silent unless something fails. |
| Config as code | `vulnfind init` writes `.vulnfind.json` (defaults for every flag, plus **custom rules**) and `.vulnfindignore`. |
| Stay current | `vulnfind update` upgrades vulnfind using whatever installed it (uv, pipx or pip). |

### Custom rules

Add your own regex rules inline in `.vulnfind.json` (`"rules": [...]`), per project in `.vulnfind/rules/*.json`, or for every project in `~/.config/vulnfind/rules/*.json`:

```json
{"rules": [{"id": "ACME-NO-INTERNAL-API", "title": "Internal admin API called from a handler", "severity": "high",
            "pattern": "internal_admin_api\\(", "extensions": [".py"], "fix": "Go through the permission-checked service"}]}
```

### Output formats

`-f` for stdout, or `-o FILE` (repeatable), with the format taken from the extension: table · json · sarif · github (inline PR annotations) · junit (`.xml`) · html · markdown · csv · CycloneDX SBOM (`.cdx.json`).

Exit codes: `0` clean · `1` findings at or above `--fail-on` (default `high`) · `2` usage/runtime error.

## Accuracy

`vulnfind bench` measures recall and precision on a labelled corpus. In each file, `expect: RULE` marks a line that must be flagged and `safe` marks one that must not. The corpus covers data flows in four languages, secrets, Dockerfile and GitHub Actions issues, plus deliberate traps: sanitized values, constants, parameterized queries, `RegExp#exec`, placeholder credentials, multi-line templates. Current result: **100% recall, 100% precision (39/39, 0 false positives on 21 safe lines)**. CI fails below 90%. The corpus is small and hand-written, so treat it as a regression guard, not a guarantee. Real-world findings deserve the same review you'd give any scanner.

Noise control is built in:
- **Comments and strings:** code rules ignore both.
- **Confirmed and cleared lines:** a confirmed data flow replaces the weaker pattern hit on the same line, and lines the flow engines prove clean are dropped.
- **Context:** findings in tests, examples and docs drop one level; bind-parameter SQL is downgraded; placeholder and localhost credentials are skipped.
- **Auth checks:** missing-auth findings need evidence that the project uses auth elsewhere.

## Privacy & network

- **Folder scans:** package names and versions go to OSV.dev and deps.dev, CVE IDs to FIRST (EPSS), and the CISA KEV feed is downloaded. Source code never leaves your machine.
- **Website scans:** requests go to the target. Library and server versions go to OSV and NVD (set `NVD_API_KEY` for faster lookups), DNS lookups to `cloudflare-dns.com`, and the domain to crt.sh / CertSpotter for `subdomains`.
- **Image, k8s and cloud:** these use your local Docker, kubectl, aws and gcloud tools, read-only. vulnfind never handles cloud credentials itself.
- **`vulnfind ai`:** sends findings and nearby source to the Claude API, only when you run it.
- **History:** a one-line summary per scan (counts and grade, no findings) in `~/.local/share/vulnfind` (`--no-record` or `VULNFIND_NO_HISTORY=1` turns it off).
- **Turning it off:** `--offline` disables third-party lookups.

## Limitations

- **Code:** data-flow analysis covers Python across files, and JS, Go and PHP within a file. The JS/Go/PHP engines read code line by line, so unusual code shapes can be missed.
- **Web:** a fast baseline, not a penetration test. It doesn't fuzz POST forms or find business-logic flaws, and server CVEs need a visible version banner.
- **Images:** Go binaries built with `(devel)` main modules can't be version-matched, and RHEL/UBI OS packages are inventoried but not CVE-checked (OSV has no feed).
- **Tested against recorded output:** the AWS/GCP/kubectl audits (no live accounts were available while building them), Playwright rendering (not installed here) and the AI command (exercised with a stub SDK).

## Development

```bash
python3 -m unittest discover -s tests     # 152 tests, no dependencies (web tests use a local fixture site)
python3 -m vulnfind bench                 # precision / recall on the labelled corpus
python3 tests/web_fixture.py 8090         # a deliberately vulnerable local website to scan
```

Rules are data: `vulnfind/scanners/{secrets,code,iac,files}.py`, taint sinks in `taint_python.py` / `taint_js.py` / `taint_lines.py`, web probes in `vulnfind/web/paths.py`. Add a labelled case to `vulnfind/bench/cases/` with every new rule.
