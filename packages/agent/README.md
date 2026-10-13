# @openaudit/agent

Agentic auditing for openaudit. Deterministic auditors catch patterns; this package covers the parts of an audit that need judgment — tracing data flows, reasoning about authorization, walking user journeys with a keyboard, weighing architecture trade-offs — using Claude.

It provides:

- **Playbooks** (`playbooks`, `getPlaybook`, `renderPlaybook`): judgment-heavy audit procedures written as markdown for any capable coding agent.
- **Agentic auditors** (`agenticAuditors`): one opt-in auditor per playbook that runs the playbook headlessly with the Claude Agent SDK.
- **AI insights** (`aiInsights`): a summary and a prioritised fix list for a finished report, from the Claude Messages API.

## Playbooks

| id | targets | needs | focus |
| --- | --- | --- | --- |
| `agent.authz` | codebase | code | route inventory, missing auth, IDOR, tenant isolation, privilege escalation, sessions/JWT, password reset, rate limiting |
| `agent.injection` | codebase | code | source → sink review: SQL/NoSQL, command, SSRF, XSS, path traversal, SSTI, deserialization |
| `agent.secrets-config` | codebase, container, iac | code | secrets in logs/bundles/CI/images, debug modes, env handling, broad IAM |
| `agent.performance` | codebase | code | N+1, missing indexes, unbounded queries, blocking work, caching, bundles, leaks, waterfalls |
| `agent.privacy` | codebase, url | code, network | PII inventory and flows, logging, third parties, consent, retention/deletion, data-subject rights |
| `agent.a11y-journeys` | webapp, url | browser | keyboard and screen-reader journeys, focus, dialogs, errors, live regions, reflow, zoom, motion |
| `agent.webapp-security` | webapp, url | browser | sessions, logout, CSRF, cookies in practice, cross-account access with test accounts, error leakage, login throttling |
| `agent.ux-content` | url, webapp | network | content quality and search intent, Nielsen heuristics, broken journeys, copy, mobile layout |
| `agent.mobile` | mobile | code (shell for host agents) | OWASP MASVS: storage, network/pinning, deep links, WebViews and JS bridges, logging |
| `agent.iac-architecture` | iac, container | code | blast radius, least privilege, segmentation, backup/DR, secrets management, image/action supply chain |

Every playbook has a scope, a method, an evidence standard, a severity rubric, a "what NOT to report" list, reporting fields and a checklist.

## Two ways to run agentic audits

### 1. Headless, inside openaudit (`openaudit --agentic`)

Agentic auditors are off by default. `--agentic` (or `options.agentic: true`) enables all of the ones that apply to the target, and selecting one by id (for example `agent.authz` in the auditor selection) runs just that one.

Each auditor starts a Claude Agent SDK session (`query()`) with:

- **A system prompt** made of an openaudit preamble, the playbook and its checklist, and a description of the target.
- **Read-only tools.** `Read`, `Grep` and `Glob` for local targets, with the project root as the working directory. There is no shell: `Bash` is disallowed for every playbook. `WebFetch`, `WebSearch`, `Write`, `Edit` and `NotebookEdit` are also disallowed. The tool guard below enforces this.
- **An in-process MCP server, `openaudit`.** Its `report_finding` tool validates each finding (schema, and that the file exists), prefixes the rule id with the playbook id, masks common token formats and caps the number of findings. Its `finish` tool closes the run. URL targets also get `http_get`, a same-origin GET/HEAD that returns raw headers and HTML, sends the configured `options.headers` and redacts cookie values.
- **A browser, only if you ask for one.** With `--browser`, playbooks that need a browser get the Playwright MCP server (`npx -y @playwright/mcp@0.0.83 --headless`, pinned), with script evaluation and file upload disabled. Without `--browser` they fall back to `http_get` and report an `info` finding, `<id>/reduced-coverage`.
- **A tool guard on every call.** One policy runs as a PreToolUse hook, which fires on every tool call, and as `canUseTool`. It assumes the audited code or site may prompt-inject the agent, so it holds even against an adversarial model:
  - `Read`/`Grep`/`Glob` paths (including a `Glob` pattern's base directory) are resolved against the project root with symlinks followed (`realpath`). Anything that ends up outside the root is denied, including `~`, `..`, absolute paths and symlinks pointing out. `report_finding` applies the same check to finding locations.
  - Network access exists only through `http_get` and the browser. Both are pinned to the target's exact origin (scheme, host and port); URLs that fail to parse are denied. Local-file runs have no network tool at all.
  - Browser tools that run arbitrary code or touch local files (`browser_evaluate`, `browser_run_code_unsafe`, `browser_file_upload`, `browser_install`) are denied.
  - Any other tool, including Bash, WebFetch, WebSearch, writes and MCP servers other than `openaudit`/`playwright`, is denied.
- **Isolation.** `settingSources: []`, `strictMcpConfig` and `persistSession: false`, so your own CLAUDE.md, hooks, plugins, MCP servers and permission rules do not apply, and no transcripts are saved.
- **Cost bounds.** `maxTurns` (default 40) and an optional `maxBudgetUsd`. If the run stops early, the findings collected so far are kept and an `info` finding, `<id>/incomplete`, says so. Interrupting the audit, or hitting the engine's 20-minute agentic timeout, aborts the SDK session.

Settings go in `options.settings`, either under `"agent"` (shared by all agentic auditors) or under an auditor id:

```jsonc
{
  "settings": {
    "agent": { "maxTurns": 60, "maxBudgetUsd": 5 },
    "agent.webapp-security": {
      "instructions": "Test accounts: alice@test.example / bob@test.example (passwords in the staging vault). Do not touch /billing.",
      "storageState": "./auth.json"
    }
  }
}
```

The available keys are `maxTurns`, `maxBudgetUsd`, `effort` (`low` to `max`, default `high`), `maxFindings` (default 40), `instructions` and `storageState` (a Playwright storage-state file for a logged-in test account; it must live inside the project, or the working directory for URL targets). Arbitrary Playwright flags are not accepted, because several of them execute code.

### 2. Host agent over MCP

The openaudit MCP server serves these playbooks to the agent you already use (Claude Code, Cursor and others). The host agent calls `get_playbook`, does the work with its own tools and permissions, and sends results with `submit_findings`. The playbook text is the same in both modes, and its reporting section matches the `report_finding` fields.

### 3. Vercel deepsec (`--only agent.deepsec`)

`agent.deepsec` wraps [deepsec](https://github.com/vercel-labs/deepsec): a regex pass finds candidate files, then deepsec's own agent reviews the riskiest ones. It is opt-in and runs only when selected explicitly; a config inside the target cannot enable it. Requirements and limits:

- **Install and auth.** A local `deepsec` binary (`npm i -g deepsec@2.3.10`) and an API credential in the environment (`ANTHROPIC_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`, `OPENAI_API_KEY`, or `AI_GATEWAY_API_KEY`). Without a credential it is skipped. It never falls back to deepsec's use of a logged-in `claude`/`codex` CLI.
- **Cost.** `deepsec process` has no cost flag, so openaudit reviews files in chunks of 5 and stops once deepsec's recorded spend reaches `maxCostUsd` (default `5`) or `maxDuration` (default `30m`). The cap can overshoot by one chunk. Set these under `settings["agent.deepsec"]` in a `--config` file, along with `maxFiles`, `diff` (`true` for `origin/main`, or a git ref: reviews files changed between that ref and `HEAD`, committed changes only, for CI), `provider` and `model`.
- **Trust.** Unlike openaudit's agents, deepsec's reviewer gets `Bash` inside the Agent SDK's OS sandbox, and deepsec continues without the sandbox if it can't start. Run it only on code you trust. openaudit keeps deepsec's state and config lookup in a temp directory, never the target, and overrides `.git/config` keys that make git run commands.

## Model, auth and cost

- **Model.** The default is `claude-opus-5-5`. Override it with `options.model` (the CLI's model option) or `OPENAUDIT_MODEL`.
- **Auth for agentic auditors.** These use `ANTHROPIC_API_KEY`, or an existing Claude Code login, through the Agent SDK. If the SDK cannot start or authenticate, the auditor is **skipped** with a hint; it does not fail the audit.
- **Auth for AI insights.** These need `ANTHROPIC_API_KEY` (or `ANTHROPIC_AUTH_TOKEN`). Without one they fail with a clear error.
- **Cost.** Agentic runs are real multi-turn agent sessions, and their cost grows with the size of the target and the turn limit. Use `maxTurns`, `maxBudgetUsd`, a smaller model, or select fewer auditors to bound spend. The log line for each run shows its turns and estimated cost.
- **Fallback.** For models that support it, AI insights opt into server-side refusal fallback (`fallbacks: "default"`).

## What is sent to the model

- **Agentic auditors.** Claude reads whatever files inside the project root, and whatever pages on the target origin, it chooses to open with the tools above. That content goes to Anthropic as part of the session. It cannot read files outside the root (such as `~/.ssh` or `~/.aws`), and it has no direct way to send data to another host: there is no shell and no WebFetch, and `http_get` and explicit browser navigation are same-origin only. Local-file runs have no network tool at all; for the browser caveat, see Responsible use. Finding evidence is capped at 2,000 characters and common token formats are masked. Only run them on code and sites you are allowed to share with Anthropic under your agreement. `options.headers` values are never put in the prompt; `http_get` attaches them outside the model's view.
- **AI insights.** Only finding metadata is sent: rule id, title, severity, category, location (file:line, or a URL without its query string), a truncated message, confidence and fingerprint, plus the report's scores and target kinds and technologies. Evidence, remediation text, file contents and local absolute paths are **never** sent, and common token formats are masked. Large reports are compacted: at most 8 findings per rule and 250 in total are described individually, and the rest are summarised per rule.

## Responsible use

Only audit systems you own or are explicitly authorised to test. The web playbooks tell the agent to:

- use only the test accounts you provide
- avoid destructive or data-modifying actions on real data
- avoid denial of service and brute force; login throttling is probed with at most 5 attempts
- stay on the target origin

The headless auditors enforce what they can, as hard tool permissions rather than prompt instructions:

- no shell and no writes
- file access confined to the real project root
- `http_get` and browser navigation pinned to the target origin, with a request cap on `http_get`
- blocked browser script evaluation and file upload

Two limits remain:

- The browser is confined to the target origin at the network layer. An init-page guard (`src/browser-guard.ts`) aborts every request to another origin and walks redirect chains hop by hop, so links, redirects and page scripts cannot load other sites. Navigation URLs that embed another URL are refused too. Only an allowlist of observation and interaction tools is available (no script evaluation, file upload or file output). The browser runs `--isolated`, without your API keys in its environment.
- **Residual risk:** the guard runs inside the Playwright MCP process, which is not a sandbox. For hostile targets, run browser playbooks in a container or VM whose egress is limited to the target.
- These controls are not an OS sandbox.

Run agentic audits against staging environments and test accounts.
