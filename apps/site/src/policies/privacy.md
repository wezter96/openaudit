---
title: Privacy policy
heading: Privacy policy
description: What openaudit.se collects when you visit, call its MCP endpoint or register a verified badge. The openaudit CLI sends nothing to us.
order: 1
---

Last updated 16 October 2026.

openaudit.se is the website of [openaudit](https://github.com/wezter96/openaudit), an open-source project maintained by Anton Wester in Sweden, who is the controller of the personal data described here. Send questions and requests to [contact@antonwester.se](mailto:contact@antonwester.se).

## In short

- No cookies, trackers or ads, and no third-party scripts or fonts.
- Page views are counted without IP addresses, user agent strings or cookies.
- The openaudit CLI, MCP server, GitHub Action and Docker image run on your own machine or runner and send nothing to us.
- A verified badge stores your repository name, an optional site address and scan results, plus a keyed hash of your IP address for rate limiting, never the address itself.

## Visiting the site

Cloudflare hosts the site as our processor. To deliver pages and protect the site from attacks, it handles your IP address and the headers your browser sends; see [Cloudflare's privacy policy](https://www.cloudflare.com/privacypolicy/). Our own request logs are turned off.

For each page you view, as HTML or Markdown, the site writes one data point to Cloudflare's Workers Analytics Engine:

| Field | Example |
| --- | --- |
| Page | `/docs/cli/` |
| Version | HTML or Markdown |
| Visitor | person or bot, and the bot's name, such as `claudebot` |
| Referring site | the host only, such as `github.com` |
| Country | `SE` |
| Device | mobile or desktop |

No IP address, user agent string or cookie is stored, so a view can't be tied to you or to your other views. Cloudflare deletes the data points after three months. We use them to see which pages people and agents read, which is our legitimate interest (GDPR Article 6(1)(f)).

## The MCP endpoint and agent files

`https://openaudit.se/mcp` answers from the site's own files. We don't store the tool calls you make or their arguments. Agent files such as `llms.txt` are static files.

## Settings in your browser

The theme you pick, and a badge registration you haven't finished, are kept in your browser's local storage and never sent to us. The [cookie policy](/cookies/) lists them.

## Verified badges

When you register a [verified badge](/badge/), we store in Cloudflare D1 and R2:

- the GitHub repository (`owner/name`) and, if you give one, your site's address;
- the verification code, whether the repository and site are verified, and when they were last checked;
- a SHA-256 hash of your manage token, never the token itself;
- a hash of your IP address keyed with a secret and the date, so one address can register at most five badges a day. It can't be turned back into the address and changes every day. The rate-limit records hold only that hash and a time;
- the results of the weekly scans of your public repository and site, keeping the last five.

We process this to provide the badge you asked for (Article 6(1)(b)) and to prevent abuse (Article 6(1)(f)). Registrations that are never verified are deleted after seven days. You can remove a badge at any time with its manage token: its scans and reports are deleted and every field except the repository name is cleared. The name stays so the badge can show that it was removed.

## The openaudit tool

openaudit runs where you run it and has no telemetry. Some auditors look things up in public services as part of their checks, such as package names and versions in the [OSV](https://osv.dev/) vulnerability database; `--offline` turns that off. With `--agentic` or `--ai`, code excerpts and findings go to the model provider you configure, with your own key and under that provider's terms. [What is sent to the model](/docs/safety/#what-is-sent-to-the-model) has the details.

## Your rights

Under the GDPR you can ask for a copy of the personal data we hold about you, and ask us to correct or delete it, restrict how we use it, or stop using it. Page views can't be linked to you, so there is nothing to look up there. For a badge, the manage token shows that the registration is yours. If you think we handle your data wrongly, you can complain to the Swedish Authority for Privacy Protection, [IMY](https://www.imy.se/en/).

## Changes

This page is built from [a file in the repository](https://github.com/wezter96/openaudit/blob/main/apps/site/src/policies/privacy.md), so every change to it is in the commit history.
