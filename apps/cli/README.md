# openaudit

Audit codebases, live URLs, running web apps, container images, infrastructure as code and mobile builds for **security, accessibility, performance, SEO, privacy, best practices and supply chain** in one command. It is built for both humans and AI agents: there is a JSON mode for scripts, SARIF for code scanning, and an MCP server so Claude Code, Cursor, Codex and other agents can run audits, carry out judgment-heavy playbooks and check their own fixes.

```sh
bunx openaudit                      # audit the current directory
bunx openaudit https://example.com  # audit a live site
```

Requires [Bun](https://bun.sh) 1.2 or later. External scanners (gitleaks, semgrep, osv-scanner, trivy, hadolint, checkov, lighthouse) are optional. When one is missing, the auditor that wraps it is skipped and tells you how to install it. Run `openaudit doctor` to see what is available.

## Usage

```sh
openaudit [target] [flags]          # same as: openaudit audit [target]
```

`target` is a directory (default `.`), a file, an `http(s)://` URL, or `image:<ref>` for a container image. openaudit detects what the target contains (Node, Python, Docker, Terraform, Kubernetes, GitHub Actions, Android/iOS, ...) and runs the auditors that apply.

| Flag | Meaning |
| --- | --- |
| `-f, --format <list>` | `terminal` (default), `json`, `sarif`, `markdown`, `html`. Repeatable or comma-separated. More than one format requires `--out`. |
| `-o, --out <dir>` | Write `openaudit-report.<ext>` for each format into `<dir>`. |
| `--json` | Agent mode: the JSON report on stdout and nothing else. No progress output. |
| `--fail-on <severity>` | Exit 1 if any finding is at least `critical`/`high`/`medium`/`low`/`info`. Default `none`. |
| `--only`, `--exclude <patterns>` | Choose auditors by id (`web.headers`), prefix (`web`) or glob (`code.*`). |
| `--category <list>` | Only run auditors in these categories, e.g. `security,accessibility`. |
| `--baseline <report.json>` | Suppress findings already in an earlier JSON report, so only new findings count. |
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
| `openaudit mcp` | Start the MCP server on stdio |

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

A config found in the audited target is written by whoever controls the target, so it is only partly trusted. From there, openaudit honours `only`, `exclude`, `categories`, `failOn` (except `"none"`), `ignore` and `options.maxPages`, and prints a notice when the config narrows which auditors run. Settings that send data, cost money or add credentials (`options.agentic`, `ai`, `model`, `headers`, `settings`, `browser`, ...) are ignored with a warning. Those settings are accepted only from flags or from a file passed explicitly with `--config <path>`. Every report states how many findings each config or baseline suppressed. Use `--no-config` to ignore the target's config entirely. **When CI audits untrusted changes (pull requests from forks), pass `--fail-on` and `--no-config` explicitly**, because the change itself can edit the config.

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

## CI: GitHub code scanning

```yaml
- uses: oven-sh/setup-bun@v2
- name: openaudit
  run: bunx openaudit . --format sarif,markdown --out openaudit --fail-on high
- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: openaudit/openaudit-report.sarif
    category: openaudit
- name: Job summary
  if: always()
  run: cat openaudit/openaudit-report.md >> "$GITHUB_STEP_SUMMARY"
```

Run the audit from the repository root, so that SARIF file paths line up with the files in the repository. The job needs the `security-events: write` permission to upload SARIF.
