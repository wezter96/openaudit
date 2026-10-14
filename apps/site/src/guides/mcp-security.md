---
title: "MCP security scanner: audit MCP servers and agent configs"
heading: Audit your MCP servers and AI agent setup
description: Check MCP configs, AGENTS.md and agent permissions for unpinned servers, inlined secrets and hidden prompt injection, with one open-source CLI.
order: 1
---
Run `openaudit .` in your repo. The [code.agent-config](/auditors/code.agent-config/) auditor reads your MCP configs, agent instruction files and agent permission settings, and reports what an attacker could abuse. It only parses files. Nothing in them is executed.

## What can go wrong

- An MCP config launches `npx -y some-server` with no version, so every start runs whatever the registry serves that day.
- A token sits in plain text in `.mcp.json`, and anyone who can read the repo can use it.
- An AGENTS.md or Cursor rule hides an instruction in an HTML comment or invisible Unicode. The agent reads it. Your reviewer doesn't see it.
- Committed settings pre-approve every shell command, so one prompt injection in an issue or web page becomes code execution.

## What openaudit checks

[code.agent-config](/auditors/code.agent-config/) covers AGENTS.md, GEMINI.md, Cursor, Copilot, Windsurf and Cline rules, `.mcp.json`, Cursor and Claude Desktop MCP configs, `.claude/settings.json`, Gemini CLI settings and `.codex/config.toml`. Rule ids include:

- `mcp-unpinned-server`: an npm package or Docker image launched without an exact version.
- `mcp-plaintext-http`: a remote MCP server reached over `http://`.
- `mcp-inline-credential`: a literal credential in a server's config.
- `mcp-auto-approve`: `enableAllProjectMcpServers: true` in Claude Code settings.
- `mcp-server-trusted`: `trust: true` on a Gemini CLI MCP server.
- `broad-permission` and `permission-bypass-mode`: every Bash command pre-approved, `bypassPermissions`, or a Codex config with `sandbox_mode = "danger-full-access"`.
- `hidden-instruction`, `instruction-disables-safety` and the `hidden-unicode-*` rules: the prompt-injection checks for instruction files.

Findings carry OWASP Top 10 for LLM Applications tags: `owasp-llm01` (prompt injection), `owasp-llm03` (supply chain) and `owasp-llm06` (excessive agency). [code.unicode](/auditors/code.unicode/) also scans code and docs for hidden Unicode.

For your MCP server's own code, the agent playbooks add a judgment review. [agent.injection](/auditors/agent.injection/) traces input to sinks such as SQL, shell commands, SSRF and file paths. [agent.authz](/auditors/agent.authz/) looks for missing auth and privilege escalation. [agent.secrets-config](/auditors/agent.secrets-config/) looks for secrets in logs, bundles and CI, and for over-broad IAM.

## How to run it

Only the agent config checks:

```sh
openaudit . --only code.agent-config
```

The playbooks headlessly with Claude. They're opt-in and need `ANTHROPIC_API_KEY` or a Claude Code login:

```sh
openaudit . --agentic --only agent.injection,agent.authz,agent.secrets-config
```

Or let the agent you already use run them. Add openaudit as an MCP server in Claude Code:

```sh
claude mcp add openaudit -- bunx @openaudit/cli mcp
```

Cursor and Codex take the same `bunx @openaudit/cli mcp` command in their MCP config. Your agent calls `get_playbook`, reviews the code with its own tools and sends results back with `submit_findings`. That route needs no extra API key.

In CI, `--fail-on high` makes the run exit 1 on high or critical findings.

## What it doesn't cover

- It doesn't connect to a running MCP server or probe a remote MCP endpoint. These checks read files in the repo.
- It doesn't inspect tool descriptions that a server returns at runtime.
- It can't tell whether a pinned package is safe, only that it's pinned.
- The playbooks aren't MCP-specific. They review your server as ordinary code.
- The hidden-instruction rules are heuristics with low confidence. Read the raw file before you act.

## Next steps

- [Agents and MCP setup](/docs/agents/)
- [CLI flags](/docs/cli/)
- [Running in CI](/docs/ci/)
- [What openaudit sends where](/docs/safety/)
- [All auditors](/auditors/)
