---
title: "AI generated code security: scan it before you ship"
heading: Is your AI-generated code safe to ship?
description: What to check in code from Cursor, Claude Code or Copilot, and how to scan it for secrets, injection, risky dependencies and hidden Unicode.
order: 2
---
Treat generated code like a pull request from a stranger: read it, then scan it. openaudit scans your repository and your deployed site for the mistakes worth catching in AI-written code, from leaked keys to hidden Unicode.

## What goes wrong in AI-written code

The bugs aren't new. They're the classic ones, accepted in bulk:

- An API key pasted into a config file or a committed `.env`. Deleting it later doesn't remove it from git history.
- SQL or shell commands built from strings, and user input rendered as raw HTML.
- Permissive CORS, or TLS and JWT verification switched off to make an error go away.
- A dependency with known vulnerabilities, or a package name the assistant made up that someone else has since registered.
- A deployed app with no Content-Security-Policy or HSTS header.
- Invisible characters copied in from a prompt, a pasted snippet or an agent rules file.

## What openaudit checks

- **Secrets.** [`code.secrets`](/auditors/code.secrets/) finds committed credentials and tracked `.env` files. The opt-in [`code.secrets-history`](/auditors/code.secrets-history/) runs gitleaks over the full git history for secrets that were committed and later removed.
- **Injection and XSS.** [`code.security`](/auditors/code.security/) looks for injection, XSS, weak crypto, disabled TLS or JWT checks, permissive CORS, open redirects and path traversal in JS/TS, Python, Go, PHP, Ruby, Java and C#. [`code.semgrep`](/auditors/code.semgrep/) adds Semgrep when it's installed.
- **Dependencies.** [`code.dependencies`](/auditors/code.dependencies/) checks every pinned version against OSV.dev. [`code.lockfiles`](/auditors/code.lockfiles/) flags lockfiles out of date with `package.json`, missing integrity hashes, unexpected registries and install scripts. The opt-in [`code.dependency-health`](/auditors/code.dependency-health/) flags deprecated, yanked and archived packages. The opt-in [`code.guarddog`](/auditors/code.guarddog/) checks npm and PyPI packages for malware and typosquatting.
- **Headers.** [`web.headers`](/auditors/web.headers/) checks CSP, HSTS, framing, CORS and cookie flags on your live URL.
- **Hidden Unicode.** [`code.unicode`](/auditors/code.unicode/) finds Trojan Source bidi controls, zero-width characters, hidden text in Unicode tag characters and look-alike identifiers.
- **Agent setup.** [`code.agent-config`](/auditors/code.agent-config/) finds hidden instructions in AGENTS.md and Cursor or Copilot rules, unpinned MCP servers and over-broad agent permissions.

## Audit, fix, verify

Audit the code and the deployed site, and check git history once:

```bash
bunx @openaudit/cli . -f html -o report
bunx @openaudit/cli https://your-app.example
bunx @openaudit/cli . --only code.secrets-history
```

Save a JSON report, fix the findings, then rerun against it. Exit code 0 means the fix added no new findings:

```bash
bunx @openaudit/cli . --json > before.json
bunx @openaudit/cli . --baseline before.json --fail-on low
```

On pull requests, report only the changed files and fail the build on serious findings:

```bash
bunx @openaudit/cli . --diff origin/main --fail-on high
```

Your coding agent can also check its own work. Add the MCP server and it gets `run_audit`, `get_finding` and `compare_reports`, plus playbooks such as [`agent.injection`](/auditors/agent.injection/) and [`agent.authz`](/auditors/agent.authz/) that it runs with its own tools. No extra API key is needed.

```bash
claude mcp add openaudit -- bunx @openaudit/cli mcp
```

## What it doesn't cover

- Rules match patterns. They can't tell whether your business logic is right or every route checks who's calling. The `agent.authz` playbook has an agent review that, but read its result yourself.
- openaudit can't tell whether a package is the one you meant. Check unfamiliar names yourself.
- It never builds, installs or runs your code, so it doesn't replace your tests.
- Scanners that aren't installed are skipped and listed in the report. Run `bunx @openaudit/cli doctor` to see what's missing.

## Next steps

Start with the [CLI reference](/docs/cli/), add the gate to your pipeline with the [CI guide](/docs/ci/), and set up your coding agent with the [agents guide](/docs/agents/). Or open [openaudit's report on itself](/report/) to see a finished one.
