---
name: openaudit
description: Audit a project with openaudit — security, accessibility, performance, SEO, privacy, supply chain — for a codebase, URL, running web app, container, IaC or mobile build. Use when asked to audit, scan, or harden a project, check a site's headers/a11y/SEO, verify fixes against a previous audit, or run an openaudit playbook.
---

# openaudit

openaudit produces a scored report of findings. Each finding has a `ruleId`, `severity`, `category`, `location`, `remediation` and a stable `fingerprint`. Deterministic auditors catch patterns; **playbooks** cover what needs judgment, and you execute them.

Prefer the MCP tools (`run_audit`, `get_playbook`, `submit_findings`, `compare_reports`, …) when the `openaudit` server is connected. Otherwise use the CLI in agent mode: `bunx openaudit <target> --json` prints one JSON report to stdout. `bunx openaudit list --json` and `bunx openaudit doctor --json` show auditors and available tooling.

Targets: a directory, a file, `.apk`/`.aab`/`.ipa`, `http(s)://…` (add `--browser` / `browser: true` for a real-browser pass), or `image:<ref>`. Only audit systems the user owns or is authorised to test.

## Loop

1. **Baseline.** Run the audit. Done when you hold a `reportId` (MCP) or a saved report JSON.
2. **Triage.** Group findings by root cause and rank by real-world risk, not raw count. Treat `confidence: "low"` as leads to verify in the source before acting. Done when every critical/high finding is classified *confirmed* or *false positive* with a one-line reason.
3. **Playbooks.** For each playbook whose targets match (`list_playbooks`), call `get_playbook`, work through every checklist item with your own tools, and submit what you found with `submit_findings`. Done when every checklist item is checked or explicitly marked not applicable.
4. **Fix** (only when the user asked for fixes). Make the smallest change that removes the root cause, and fix whole groups together.
5. **Verify.** Re-run the audit and call `compare_reports` (CLI: `--baseline old.json`). Done when every finding you targeted appears under *fixed* and nothing new appears.

Report back the score delta, what was fixed, what is left and why, and any false positives worth suppressing with `openaudit.config.json` → `ignore`.
