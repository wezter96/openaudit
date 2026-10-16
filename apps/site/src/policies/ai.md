---
title: AI transparency
heading: AI transparency
description: Where openaudit and openaudit.se use AI, how AI-written report content is labelled, and how the project's code and text are written.
order: 3
---

Last updated 16 October 2026.

Article 50 of the EU AI Act sets transparency duties for AI systems that talk to people and for AI-generated content. This page says where AI is and isn't involved, so you don't have to guess.

## On this site

- **No AI talks to you here.** openaudit.se has no chatbot. The [MCP endpoint](/docs/sandbox/#public-mcp-endpoint), and the WebMCP tools the pages offer to an agent in your browser, answer from the site's own files. Neither is an AI model.
- **The live report has no AI content.** The [report](/report/) comes from openaudit's built-in auditors and wrapped scanners. No model writes its findings or its summary.
- **No AI-generated images.** Social cards are drawn by code when the site is built, and the report images are screenshots.
- **Code and text are written with AI help.** Most of openaudit, this site and its docs is written with an AI coding assistant (Claude, through Claude Code) and committed by the maintainer, who is responsible for it. Those commits say so in a `Co-Authored-By` line, so the [commit history](https://github.com/wezter96/openaudit/commits/main/) shows which ones.

## In openaudit's reports

openaudit only uses a model when you ask it to, with your own key.

- **Agentic auditors.** `--agentic` runs judgment-heavy playbooks, such as authorisation review and screen-reader journeys, through a model. Their findings come from auditors whose engine is `agentic`, shown as Agent in the [auditor catalogue](/auditors/).
- **Findings from your agent.** An agent connected over MCP can add a playbook's findings to a report with `submit_findings`. They are recorded with the engine `agentic` and the note "Findings submitted by the host agent via MCP".
- **AI insights.** `--ai` adds a prioritised summary written by a model. The HTML report shows it under AI insights, names the model and warns that AI output can be wrong. The JSON report keeps it under `ai`, with the model's id.

Everything else in a report comes from deterministic rules and tools, the same way every time.

## Changes

This page is built from [a file in the repository](https://github.com/wezter96/openaudit/blob/main/apps/site/src/policies/ai.md), so every change to it is in the commit history.
