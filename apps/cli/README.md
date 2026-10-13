# openaudit

Audit codebases, live URLs, running web apps, container images, infrastructure as code and mobile builds for **security, accessibility, performance, SEO, privacy, best practices and supply chain** in one command. It is built for both humans and AI agents: there is a JSON mode for scripts, SARIF for code scanning, and an MCP server so Claude Code, Cursor, Codex and other agents can run audits, carry out judgment-heavy playbooks and check their own fixes.

```sh
bunx openaudit                      # audit the current directory
bunx openaudit https://example.com  # audit a live site
```

Requires [Bun](https://bun.sh) 1.4 or later. Install globally with `bun add -g openaudit`, or run it on demand with `bunx openaudit`. `npx openaudit` also works when Bun is on PATH; without Bun it prints how to install it. External scanners (gitleaks, TruffleHog, Semgrep, Trivy, zizmor, pa11y and the others listed by `openaudit list`) are optional. When one is missing, the auditor that wraps it is skipped and tells you how to install it. Run `openaudit doctor` to see what is available.

## Usage

```sh
openaudit [target] [flags]          # same as: openaudit audit [target]
```

`target` is a directory (default `.`), a file, an `http(s)://` URL, `image:<ref>` for a container image, or `cloud:<aws|azure|gcp|kubernetes>` for a live cloud account (opt-in Prowler, using your ambient credentials). openaudit detects what the target contains (Node, Python, Docker, Terraform, Kubernetes, GitHub Actions, Android/iOS, ...) and runs the auditors that apply.

| Flag | Meaning |
| --- | --- |
| `-f, --format <list>` | `terminal` (default), `json`, `sarif`, `markdown`, `html`. Repeatable or comma-separated. More than one format requires `--out`. |
| `-o, --out <dir>` | Write `openaudit-report.<ext>` for each format into `<dir>`. |
| `--json` | Agent mode: the JSON report on stdout and nothing else. No progress output. |
| `--fail-on <severity>` | Exit 1 if any finding is at least `critical`/`high`/`medium`/`low`/`info`. Default `none`. |
| `--only`, `--exclude <patterns>` | Choose auditors by id (`web.headers`), prefix (`web`) or glob (`code.*`). |
| `--category <list>` | Only run auditors in these categories, e.g. `security,accessibility`. |
| `--baseline <report.json>` | Suppress findings already in an earlier JSON report, so only new findings count. |
| `--diff <ref>` | Keep only findings in files changed since the git ref (`<ref>...HEAD`), e.g. `origin/main` on a pull request. Findings with no file are dropped. The report records the ref and the dropped count. |
| `--offline` | Make no network requests except to the target (skips OSV lookups and similar). |
| `--browser`, `--max-pages <n>` | Drive a real Chromium through Playwright for URL targets (needs `playwright-core` and a Chromium). |
| `-H, --header "Name: value"` | Extra header for the target origin only, e.g. an auth cookie for staging. Repeatable. |
| `--agentic`, `--model <id>` | Run the LLM-driven auditors. Needs `ANTHROPIC_API_KEY` or Claude Code auth. |
| `--ai` | Attach an AI-prioritised summary to the report. If this fails, openaudit prints a warning and continues. |
| `--config <path>`, `--no-config` | Use a trusted config file, or ignore the target's `openaudit.config.json`. |
| `--concurrency <n>`, `-q/--quiet`, `--verbose` | |

Other commands:

| Command | |
| --- | --- |
| `openaudit list [--json] [--target-kind url]` | Auditors (id, engine, categories, targets, external tool, on/off by default) and playbooks |
| `openaudit doctor [--json]` | Bun version, external tools on PATH, Playwright/Chromium, AI credentials |
| `openaudit init [--force]` | Write `openaudit.config.json` |
| `openaudit schema [report\|config]` | JSON Schema (draft 2020-12) of the report or the config file |
| `openaudit mcp [--http]` | Start the MCP server on stdio, or over Streamable HTTP with `--http` |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Audit completed and no finding reached `--fail-on` |
| `1` | At least one finding at or above `--fail-on` |
| `2` | Usage error, invalid config, or the target could not be resolved |
| `3` | `--fail-on` was set but an auditor errored or timed out, so the gate could not be fully checked |

Exit code 3 fails closed, so a target cannot pass CI by crashing the auditor that would have flagged it. Pass `--allow-errors` to accept partial results. Skipped auditors (missing tool, offline) never change the exit code; their status and reason are recorded in the report.

### Configuration

`openaudit init` writes `openaudit.config.json`. Flags on the command line take precedence over it.

A config found in the audited target is written by whoever controls the target, so it is only partly trusted. From there, openaudit honours `only` (which can only narrow the default set: it never enables opt-in or agentic auditors), `exclude`, `categories`, `failOn` (except `"none"`), `ignore` and `options.maxPages`, and prints a notice when the config narrows which auditors run. Settings that send data, cost money or add credentials (`options.agentic`, `ai`, `model`, `headers`, `settings`, `browser`, ...) are ignored with a warning. Those settings are accepted only from flags or from a file passed explicitly with `--config <path>`. Every report states how many findings each config or baseline suppressed. Use `--no-config` to ignore the target's config entirely. **When CI audits untrusted changes (pull requests from forks), pass `--fail-on` and `--no-config` explicitly**, because the change itself can edit the config.

```json
{
  "only": [],
  "exclude": ["code.semgrep"],
  "categories": [],
  "failOn": "high",
  "ignore": {
    "rules": ["code.hygiene/ci-missing"],
    "paths": ["test/fixtures/**"],
    "fingerprints": []
  },
  "options": { "maxPages": 10 }
}
```

Every finding has a stable `fingerprint`. To accept a known issue, add its fingerprint to `ignore.fingerprints`, or pass a whole earlier report with `--baseline`.

## Agent mode (`--json`)

```sh
openaudit . --json --fail-on high > report.json; echo $?
openaudit schema > report.schema.json   # validate the output
```

- stdout carries exactly one JSON document, with keys in a stable order (`schemaVersion`, `tool`, `target`, `summary`, `results[].findings[]`). Nothing else is written to stdout, and no progress is shown on stderr.
- Findings are sorted by severity. Each one has `ruleId`, `severity`, `category`, `location` (`file`/`line` or `url`/`selector`), `evidence` (redacted), `remediation`, `references` and a `fingerprint`.
- To check a fix, re-run the audit with `--baseline report.json --fail-on low`. Exit code 0 means no new findings appeared.

## MCP server

The MCP server lets an agent run audits, read findings with the surrounding source code, compare reports to confirm fixes, and work through **playbooks**. Playbooks are judgment-heavy checks, such as authorization, business logic and real-world accessibility, that the agent does with its own code and browser tools. It then reports the results back with `submit_findings`. Playbooks need no API key.

**Claude Code**

```sh
claude mcp add openaudit -- bunx openaudit mcp
```

**Cursor** (`.cursor/mcp.json`) or **VS Code** (`.vscode/mcp.json`, which uses `"servers"` instead of `"mcpServers"`):

```json
{
  "mcpServers": {
    "openaudit": { "command": "bunx", "args": ["openaudit", "mcp"] }
  }
}
```

**Codex** (`~/.codex/config.toml`):

```toml
[mcp_servers.openaudit]
command = "bunx"
args = ["openaudit", "mcp"]
```

Tools: `detect_target`, `list_auditors`, `run_audit`, `get_report` (json, markdown, sarif or html), `get_finding` (with ±5 lines of source), `compare_reports`, `list_playbooks`, `get_playbook` and `submit_findings`. Every tool returns a short markdown summary and also structured content. Reports are kept in memory (the last 20) and, for directory targets, written to `.openaudit/reports/<id>.json`, which is git-ignored automatically. The `audit_project` prompt walks an agent through the whole loop: audit, triage, run the playbooks, submit findings, fix, then compare reports.

### MCP over HTTP

For remote or hosted agents, serve the same tools over MCP Streamable HTTP. Each client gets its own session (`Mcp-Session-Id`), so progress notifications and the report store are per session.

```sh
# Local: loopback only, one allowed project directory. A token is generated,
# printed once and saved to ~/.config/openaudit/mcp-token (mode 0600).
openaudit mcp --http --root ~/code/my-app

# Remote: needs a token (at least 16 characters)
OPENAUDIT_MCP_TOKEN=$(openssl rand -hex 24) openaudit mcp --http --host 0.0.0.0 --port 7337 --root /srv/repos
```

Endpoints: `POST/GET/DELETE /mcp` and an unauthenticated `GET /health`. Flags (all but `--http` apply only with it):

| Flag | |
| --- | --- |
| `--host <addr>` | Bind address (default `127.0.0.1`) |
| `--port <n>` | Port (default `7337`; `0` picks a free one) |
| `--token <t>` | Bearer token; falls back to `OPENAUDIT_MCP_TOKEN`. On loopback one is generated if omitted; a non-loopback host refuses to start without one (16+ characters) |
| `--root <dir>` | Directory that file and directory targets must resolve inside (repeatable) |
| `--allow-origin <origin>` | Browser `Origin` allowed to connect (repeatable) |
| `--allow-host <host[:port]>` | Extra `Host` header value accepted (repeatable) |
| `--allow-cloud` | Accept `cloud:<provider>` targets, which use the server's own credentials |
| `--persist-reports` | Save reports under `<root>/.openaudit/reports` as stdio does. Off over HTTP, where `get_report` html returns the document inline |
| `--allow-images` | Accept `image:<ref>` targets on a non-loopback bind (their registry host is still checked) |
| `--allow-agentic` | Let clients run agentic auditors, which spend the server's `ANTHROPIC_API_KEY` (refused by default) |
| `--allow-private-targets` | Allow URL targets on private, loopback, link-local or metadata addresses on a non-loopback bind |

**Claude Code**

```sh
claude mcp add --transport http openaudit http://127.0.0.1:7337/mcp \
  --header "Authorization: Bearer $(cat ~/.config/openaudit/mcp-token)"
```

**Generic `mcp.json`** (clients with remote-server support; the exact key names vary a little by client):

```json
{
  "mcpServers": {
    "openaudit": {
      "type": "http",
      "url": "http://127.0.0.1:7337/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

Security model:

- Every request needs a bearer token, even on loopback (other local users can reach `127.0.0.1`). It is compared in constant time and never logged; a generated one is printed once at startup and saved to a user-only file. The server binds `127.0.0.1` by default, and any other host refuses to start without an explicit token. Put a TLS-terminating proxy in front of a remote server, since the token travels in a header.
- `Host` must match the bind address and port (DNS-rebinding protection), and a request with an `Origin` header is rejected unless it was allow-listed with `--allow-origin`. Requests without `Origin` (non-browser clients) pass.
- Local targets are refused unless they resolve (via realpath, so `..` and symlinks cannot escape) inside a `--root`. With no `--root`, only `http(s)` URLs and `image:<registry-ref>` targets are accepted (an OCI reference such as `nginx:1.27` or `ghcr.io/org/repo@sha256:…`; transport forms like `docker-archive:`, `oci-dir:`, `dir:`, `file:` or `podman:`, and a bare `registry:` or `docker:` prefix, are refused, and Trivy is forced to `--image-src remote`); `cloud:` needs `--allow-cloud`. Stdio is unchanged and trusts its local client.
- Reports live in memory, scoped to the session that created them (other sessions get "Unknown reportId"), and are not written into served directories unless `--persist-reports` is set. Source context for findings is read only from regular files that resolve inside the report's root.
- Requests are capped at 4 MiB, at 32 concurrent sessions, and sessions idle for 30 minutes expire. `DELETE /mcp`, SIGINT and SIGTERM close sessions cleanly.
- Agentic auditors (`agentic: true`) are refused unless `--allow-agentic` is set, so remote clients cannot spend the server owner's API key. Stdio is unchanged.
- On a non-loopback bind, URL targets must resolve to public addresses (SSRF guard shared with the hosted API): private, loopback, link-local, metadata (169.254.169.254) and unique-local IPv6 addresses are refused, as are ports other than 80, 443, 8080 and 8443. Every request and redirect hop is DNS-validated and pinned to the checked IP, and `web.tls` dials that IP too. To make pinning possible, guarded URL audits run only the built-in `web.*` auditors: no browser, Lighthouse or external tools. Loopback binds and `--allow-private-targets` skip the guard and run everything. `image:` targets are refused on such binds unless `--allow-images` is set, and then the registry host (Docker Hub when the reference has none) is validated like a URL, including the port rules. Residual risk: Trivy and Dockle resolve the registry themselves, so that check cannot be pinned and a DNS-rebinding registry could still reach a private address.

## CI: GitHub code scanning

The simplest setup is the bundled GitHub Action (`action.yml` at the repository root). On pull requests it audits only the files the PR changed, uploads SARIF, attaches the reports (HTML, JSON, SARIF, Markdown) as an artifact, writes a job summary and fails on findings at or above `fail-on`. Inputs: `target`, `fail-on`, `diff` (defaults to the PR base; `none` audits everything), `only`, `exclude`, `config`, `upload-sarif`, `upload-report`. Outputs: `score`, `grade`, `report-dir`. Check out with `fetch-depth: 0` so the base branch's history is available. The job needs `security-events: write`.

To run the CLI directly instead:

```yaml
- uses: oven-sh/setup-bun@v2
- name: openaudit
  run: bunx openaudit . --format sarif,markdown --out openaudit --fail-on high
- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: openaudit/openaudit-report.sarif
    category: openaudit
- name: Job summary
  if: always()
  run: cat openaudit/openaudit-report.md >> "$GITHUB_STEP_SUMMARY"
```

Run the audit from the repository root, so that SARIF file paths line up with the files in the repository. The job needs the `security-events: write` permission to upload SARIF.
