# openaudit

Audit everything you ship (code, sites, running apps, containers, infrastructure and mobile builds) from your terminal or your AI agent.

openaudit runs 23 built-in auditors, wraps 34 established scanners (including Vercel's AI-driven deepsec) when they're installed, and covers the judgment-heavy work (authorization review, keyboard and screen-reader journeys, privacy data flows and more) with 10 **playbooks** that AI agents execute. Everything lands in one scored report: terminal, JSON, SARIF, Markdown or a self-contained HTML page.

```bash
bunx openaudit .                          # a codebase
bunx openaudit https://example.com        # a live site (add --browser for Playwright + axe-core)
bunx openaudit ./app-release.apk          # a mobile build (.apk, .aab, .ipa)
bunx openaudit image:nginx:1.27           # a container image
```

## What it checks

| Target | Built-in auditors | Wrapped tools (used when installed) |
|---|---|---|
| Codebase | secrets, static security (SAST), vulnerable dependencies (OSV.dev), accessibility, performance, quality, repo hygiene | **Secrets:** gitleaks, TruffleHog. **SAST:** Semgrep, Bandit, gosec, Brakeman, CodeQL\*. **Dependencies:** osv-scanner, Trivy, npm/pnpm/bun audit, pip-audit, cargo-audit, govulncheck\*, Grype\*. **Supply chain:** OpenSSF Scorecard, Syft licences\*. **Quality and licences:** jscpd, knip\*, ScanCode\*. **AI review:** deepsec\* |
| URL | security headers, TLS, SEO, accessibility, performance, exposed files, privacy and trackers | Lighthouse, pa11y, OWASP ZAP baseline\*, testssl.sh\* |
| Running web app (`--browser`) | axe-core in Chromium, console errors, failed and mixed-content requests, Core Web Vitals | |
| Containers | Dockerfile, Compose, image (root user, age, size, secrets) | Trivy, hadolint, Dockle\* |
| Infrastructure as code | GitHub Actions, Kubernetes, Terraform | zizmor, actionlint, kube-linter, Checkov, KICS\*, Kubescape\* |
| Mobile | Android manifest (incl. binary AXML in APKs), iOS Info.plist (incl. binary plists in IPAs), embedded secrets | |

\* Opt-in: slow, noisy, sends more traffic to the target, spends money, or runs project code. Select it with `--only <id>`, e.g. `--only code.codeql` or `--only agent.deepsec`.

Findings are grouped into security, accessibility, performance, SEO, privacy, best practices, reliability, maintainability, supply chain and compliance. Each category gets a 0–100 score and a grade. `bunx openaudit list` shows every auditor and playbook, and `bunx openaudit doctor` shows which optional tools are available.

## With AI agents

Some audits need judgment rather than patterns. openaudit is built so agents can drive it end to end:

- **MCP server.** `claude mcp add openaudit -- bunx openaudit mcp` (or the equivalent `mcp.json` in Cursor or VS Code) gives an agent `run_audit`, `get_finding`, `compare_reports` and more, plus the playbook tools `list_playbooks`, `get_playbook` and `submit_findings`. Your agent does the review with its own tools, and its findings merge into the same scored report. No extra API key is needed.
- **Headless agentic auditors.** `openaudit . --agentic` runs the playbooks through the Claude Agent SDK. The agent gets read-only tools, confined to the project and the target origin. It uses `ANTHROPIC_API_KEY` or an existing Claude Code login.
- **AI triage.** `--ai` turns the findings into a prioritised fix plan. Only finding metadata is sent, never file contents.
- **Agent mode CLI.** `--json` prints a single JSON report to stdout, and `openaudit schema` gives its JSON Schema.
- **Skill.** [`skills/openaudit/SKILL.md`](skills/openaudit/SKILL.md) teaches an agent the loop: baseline, triage, playbooks, fix, then verify with `compare_reports`.

Details are in [`apps/cli/README.md`](apps/cli/README.md) (CLI, CI, MCP setup) and [`packages/agent/README.md`](packages/agent/README.md) (playbooks, data handling).

## In CI

```yaml
- run: bunx openaudit . --format sarif,markdown --out openaudit-report --fail-on high
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: openaudit-report/openaudit-report.sarif
```

`--fail-on <severity>` sets the exit code. `--baseline previous.json` reports only new findings, and `openaudit.config.json` (created by `openaudit init`) holds suppressions. This repository audits itself in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Safety

openaudit treats every target as hostile:
- **Files:** reads are confined to the project root and never follow symlinks out of it.
- **HTTP:** user-supplied headers go only to the exact target origin, and credentials are stripped on cross-origin redirects.
- **Agents:** openaudit's own agents have no shell, and the browser is held to the target origin at the network layer. deepsec's reviewer does get a sandboxed shell, which is why it is opt-in.
- **Wrapped tools:** tools never build or install the target, and they run from temporary directories so project config can't redirect them (e.g. pnpm hook files, pa11y config). A config file inside the target can narrow an audit but can't enable opt-in auditors.
- **Hosted URL-audit API:** connections are pinned to DNS-validated public IPs.
- **Evidence:** secrets in evidence are redacted.

URL auditors send only low-volume GET/HEAD requests. **Only audit systems you own or are authorised to test.** Report vulnerabilities via [SECURITY.md](SECURITY.md).

## Repository layout

| Path | What |
|---|---|
| `packages/core` | Report model (the public contract), engine, target detection, reporters |
| `packages/auditors` | Built-in and external-tool auditors: `codebase`, `web`, `infra`, `mobile` |
| `packages/agent` | Playbooks, agentic auditors (Claude Agent SDK), AI insights |
| `packages/mcp` | MCP server |
| `apps/cli` | The `openaudit` binary |
| `apps/server`, `packages/api` | Hono + oRPC HTTP API (`/api-reference` for OpenAPI docs) |
| `apps/web` | Website: landing page, live URL audit, report viewer, docs |

## Development

```bash
bun install
bun run test          # all packages
bun run check-types
bun run check         # Biome
bun run audit -- .    # run the CLI from source
bun run dev           # web on :3001, API on :3000
```

Contributor conventions (auditor contract, Effect 4 notes) are in [AGENTS.md](AGENTS.md).

## License

MIT
