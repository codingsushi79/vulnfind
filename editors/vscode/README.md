# vulnfind for VS Code

Shows [vulnfind](https://github.com/codingsushi79/vulnfind) findings inline as you work:

- injection bugs with their full data flow (Python, JS/TS, Go, PHP) as related locations
- leaked secrets, risky Docker/Kubernetes/Terraform/GitHub Actions config
- a status-bar counter; click it for a full scan including dependency CVEs
- quick fix: insert a `vulnfind:ignore RULE-ID` comment (please add the reason)

Requires vulnfind **3.0 or newer** on your PATH (`uv tool install git+https://github.com/codingsushi79/vulnfind`)
or set `vulnfind.executable`. On-save scans run `secrets,code,config` (fast, offline); dependency checks
run only from the status bar / "Scan workspace incl. dependency CVEs" command.

Not published to the Marketplace yet - install locally:

    cd editors/vscode && npx @vscode/vsce package && code --install-extension vulnfind-0.1.0.vsix
