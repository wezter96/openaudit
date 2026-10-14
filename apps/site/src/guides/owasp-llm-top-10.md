---
title: "OWASP LLM Top 10 checklist: what openaudit checks"
heading: Check an LLM or agent app against the OWASP LLM Top 10
description: Which OWASP Top 10 for LLM Applications 2025 risks openaudit checks automatically, which need a manual review, and how to find them in the report.
order: 3
---
openaudit checks three of the ten risks automatically: LLM01 Prompt Injection, LLM03 Supply Chain and LLM06 Excessive Agency. All three come from one auditor, [code.agent-config](/auditors/code.agent-config/), which reads the AI agent configuration committed to your repo. The other seven aren't checked automatically, so plan a manual review for them.

## Coverage by category

| ID | Risk (2025) | What openaudit checks |
| --- | --- | --- |
| LLM01 | Prompt Injection | [code.agent-config](/auditors/code.agent-config/): `hidden-instruction`, `hidden-unicode-invisible-text`, `hidden-unicode-bidi`, `hidden-unicode-zero-width`, `instruction-file-unscanned` |
| LLM02 | Sensitive Information Disclosure | Not checked automatically. The [agent.privacy](/auditors/agent.privacy/) playbook looks at prompt contents sent to LLM APIs, but its findings aren't tagged LLM02. |
| LLM03 | Supply Chain | [code.agent-config](/auditors/code.agent-config/): `mcp-unpinned-server` |
| LLM04 | Data and Model Poisoning | Not checked automatically |
| LLM05 | Improper Output Handling | Not checked automatically |
| LLM06 | Excessive Agency | [code.agent-config](/auditors/code.agent-config/): `broad-permission`, `permission-bypass-mode`, `mcp-auto-approve`, `mcp-server-trusted`, `instruction-disables-safety` |
| LLM07 | System Prompt Leakage | Not checked automatically |
| LLM08 | Vector and Embedding Weaknesses | Not checked automatically |
| LLM09 | Misinformation | Not checked automatically |
| LLM10 | Unbounded Consumption | Not checked automatically |

## What the tagged checks look at

The LLM checks read files. They don't call your model, send test prompts or watch a running app.

For LLM01, code.agent-config scans AGENTS.md, GEMINI.md and the Cursor, Copilot, Windsurf and Cline rule files. It flags instructions hidden in HTML comments, collapsed `<details>` blocks and hidden elements, and invisible, zero-width or bidirectional Unicode that a reviewer won't see but an agent will read. A file it can't read in full gets `instruction-file-unscanned`, so a gap is reported instead of skipped.

For LLM03, it flags MCP servers launched from an npm or PyPI package, or a Docker image, with no exact version.

For LLM06, it flags committed settings that give an agent more power than it needs: every Bash command pre-approved, Claude Code's `bypassPermissions`, a Codex config that disables the sandbox, all project MCP servers approved without a prompt, or a Gemini CLI server marked `trust: true`. It also flags instruction files that tell the agent to skip its safety controls.

[code.unicode](/auditors/code.unicode/) scans all code and docs for hidden Unicode. Its `tag-characters` rule carries a `prompt-injection` tag, but no `owasp-llm01` tag.

## What it doesn't cover

Your app's own prompts, retrieval pipeline and model output aren't in scope. openaudit has no check for system prompt leakage, poisoned training or RAG data, embedding store access, unsafe use of model output, hallucinated answers, or token and cost limits. The [agent.injection](/auditors/agent.injection/) and [agent.authz](/auditors/agent.authz/) playbooks review your code as ordinary code. They aren't written for LLM risks, and their findings carry no LLM tags.

## How to run it

Run only the LLM-tagged checks:

```sh
bunx @openaudit/cli . --only code.agent-config
```

Write an HTML report next to a full audit:

```sh
bunx @openaudit/cli . -f html -o report
```

List the LLM findings from the JSON report with jq:

```sh
bunx @openaudit/cli . --json --only code.agent-config \
  | jq '[.results[].findings[] | select(any(.tags[]?; startswith("owasp-llm"))) | {ruleId, tags}]'
```

Add `--fail-on high` in CI to exit 1 on high or critical findings.

## Finding the mapping in the report

The report's OWASP and CWE view lists the OWASP Top 10 (2021) and the CWE Top 25 (2024). It has no LLM Top 10 list. To see LLM findings:

- Open a finding. Its Tags list shows `owasp-llm01`, `owasp-llm03` or `owasp-llm06`, and its References link to the matching OWASP GenAI risk page.
- Type `owasp-llm` in the findings search box. It matches tag text.
- In SARIF output the tags land in each result's properties, so code scanning tools can filter on them.

The hidden Unicode findings also carry `cwe-451`, so they show up under A04 Insecure Design in the OWASP view.

## Next steps

- [CLI flags](/docs/cli/)
- [Reading the report](/docs/report/)
- [Running in CI](/docs/ci/)
- [Agents and MCP setup](/docs/agents/)
- [All auditors](/auditors/)
