# Homepage rework: a story for people building with AI

Date: 2026-10-14. Status: approved in conversation, waiting for the written spec's review.

## Why

The home page speaks to developers who live in a terminal. The owner wants it to win people who build with AI (founders and makers shipping with Cursor, Claude Code, Lovable or Codex) who can't judge if their code is safe. It should name their problem, show why openaudit solves it, and be much shorter. Deep technical sections move to a page of their own.

## Decisions made

- **Audience first:** people building with AI. Developers still get everything, one click away.
- **Main action:** hand it to your AI. The hero offers one sentence to copy into an agent. The terminal command stays, but below it, for developers.
- **Structure (approach A):** a short, story-led home plus a new `/developers/` page that takes the technical sections almost as they are.
- **Look:** keep the paper, ink and brand-blue system (it matches the report). Borrow only mason.tools' structure: an eyebrow label over each section, two-tone headlines with the second half in `--accent`, short sections, one strong closing action.
- **Copy:** follows the `human-writing` rules already used on the site: no dashes, contractions, short sentences, plain words.

## Home page, in order

1. **Hero.** H1: "Your AI writes the code. Who checks it?" Sub-line: openaudit checks what you ship for security holes, leaked keys, slow pages and accessibility problems, then hands your AI the list to fix. Main action: a copy box holding the handoff sentence (below), with a one-line hint ("Paste this into Cursor, Claude Code, Codex or any agent that can run commands"). Secondary: "See a live report". Badges: Free · Open source · Runs on your machine. The dial stays on the right, with its bigger labels. `PITCH` stays as the tagline for OG cards, the footer and llms.txt.
2. **The problem** (eyebrow "The problem"). Headline in two tones, e.g. "AI ships fast. Its mistakes ship too." Three short cards, each one real risk and its cost in plain words:
   - a leaked API key that someone else runs up a bill on;
   - an admin page anyone can open, because nothing checks who's asking;
   - a site that fails accessibility rules, which the European Accessibility Act has enforced in the EU since 28 June 2025.
3. **How it works** (eyebrow "How it works"). Three numbered steps: hand it to your AI; it runs 103 checks and 52 free scanners in one go; your AI fixes what matters and runs it again to prove it. The playing terminal session sits beside the steps. This replaces "Built for agents" and "One issue, one finding" on the home page.
4. **What you get** (eyebrow "What you get"). The report showcase, cut to the screenshot plus one line ("One grade per area, and a fix for every finding"), with "See a live report" and a note that every report has Copy for AI.
5. **Why trust it** (eyebrow "Why trust it"). One band with four short points: free, open source (MIT), runs on your machine so code doesn't leave it, and it never runs the code it scans. Links to `/docs/safety/`. Keeps the OpenSverige line, smaller.
6. **Questions.** The FAQ, rewritten for this reader (does it upload my code, do I need to know how to code, is it free, what does the grade mean).
7. **Closing action.** "Put it to work." The handoff copy box again, plus "For developers" as a secondary link.

Removed from the home page: the proof stat strip (its numbers move into "How it works"), the ten-area tabs, the coverage matrix, the merge flow, the integrations tabs, the safety guard list and the licence fold.

## The handoff sentence

> Audit this project with openaudit (https://openaudit.se/llms.txt). Fix what matters most, then run it again to check.

For this to work, llms.txt gains a short section near the top, "If someone asked you to audit their project": install Bun if it's missing, run `bunx @openaudit/cli . --json`, read the findings by severity, fix, re-run, compare. The MCP route and `SKILL.md` are linked from there. One shared constant holds the sentence so the hero, the closing action and the docs can't drift apart.

## `/developers/` page

A new page, in the nav as "Developers", between Docs and Auditors. It reuses the existing components with their current behaviour: the ten-area tabs, the coverage matrix (unfolded here), the merge flow, the integrations tabs, the MCP and agent details, the safety guards (unfolded) and the terminal command. Its head: "Everything under the hood", with the CLI command up top. It has a Markdown version like every other page and is listed in llms.txt and the sitemap.

## Components

- New: `home/Problem.astro`, `home/Steps.astro`, `home/Trust.astro`, `Handoff.astro` (the copy box, reusing `Command.astro`'s copy behaviour), `pages/developers.astro`.
- Changed: `Hero.astro` (new copy, handoff box, badges), `Faq.astro` (new questions), `Showcase.astro` (shorter), `index.astro` (new order), `nav.ts` (Developers), `llm.ts` (llms.txt section and the new page).
- Moved, unchanged: `Areas`, `Coverage`, `Flow`, `Integrations`, `Safety`, the `Agents` points and command. `Proof` and `Open` are dropped from the home page; `Open`'s community line moves into `Trust`.
- Styles: an `.eyebrow` label and a `.two-tone` headline rule in `global.css`.

## Checks

- postbuild's landing word limit stays at 1,700. The new home should land near 900 words.
- `check:ui` gets `/developers/` in its page list. The existing checks (no sideways scroll, menus on screen, theme toggle, console errors) cover the rest at 375 to 1280 px in WebKit and Chromium.
- Self-audit stays at 100. Every internal link resolves (postbuild already checks).
- Before and after full-page screenshots at 1280 and 375 px go to the owner for review on the branch preview before main.

## Not in scope

- The free URL scan and its API (part 3) get their own design. The hero leaves room for a URL box later but ships without one.
- Illustrations or a dark theme.
- Changes to the report's look.

## Risks

- The handoff only works where the agent can run commands. Browser-only builders (Lovable, Bolt) can't run it today; the hint line says which agents work, and the URL scan is the later answer for them.
- npm has only `@openaudit/cli` 0.1.0 until the owner sets up the Trusted Publisher, so `bunx` may fetch an old version. Fixing the npm publish comes before launch posts that point people here.
