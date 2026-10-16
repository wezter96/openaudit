# openaudit website

The public website for openaudit: a landing page, the docs, the auditor catalogue, and openaudit's live audit of its own repository. It is a static [Astro](https://astro.build) site. It is served at `https://openaudit.se` by a Cloudflare Worker.

Nothing on the site is hand-copied from the rest of the repository. At build time it reads:

| Page | Built from |
| --- | --- |
| `/` | `README.md` (pitch, languages, targets), `integrations/README.md` and `apps/cli/README.md` (snippets), the auditor registry, `packages/core/src/scoring.ts`, and the self-audit's scores (hero dial and proof strip). The short landing copy lives in the components; `postbuild` fails above 1,700 words |
| `/docs/*` | Sections of `README.md`, `apps/cli/README.md`, `packages/agent/README.md`, `integrations/README.md`, `CONTRIBUTING.md` and `SECURITY.md`; `action.yml` (Action inputs and outputs); `openaudit --help` and `openaudit schema config`; `scoring.ts` (scoring examples); the HTTP API's OpenAPI document (`/docs/api/`); `src/docs/sandbox.md` (`/docs/sandbox/`). Titles and descriptions are in `DOCS` (`src/lib/site.ts`) |
| `/auditors/`, `/auditors/<id>/` | `allAuditors()` from `apps/cli/src/audit.ts` and the playbooks in `packages/agent` |
| `/guides/<slug>/` | `src/guides/*.md`: short pages that each answer one search (MCP security, AI-generated code, OWASP LLM Top 10, open-source scanner). Front matter holds the title, H1 and description; `src/lib/guides.ts` fails the build on an over-long title or description, or a dash used as punctuation. Listed in the footer and `llms.txt` |
| `/privacy/`, `/cookies/`, `/ai/` | `src/policies/*.md`: the privacy policy, cookie policy and AI transparency notice, with the guides' front matter and checks (`src/lib/policies.ts`). Listed in the footer's bottom row and `llms.txt`. Keep them true to what the Worker and badge service store |
| `/report/` | The CLI's self-audit, re-rendered from its `openaudit-report.json` by core's `toHostedHtml`: a small `index.html` that loads its stylesheet and script as files and links the downloads (JSON, SARIF, Markdown, CSV and the self-contained `openaudit-report.html`) and the AI prompt next to it, so the page stays under the large HTML check |
| `/architecture/`, `/architecture.html` | Retired; the Worker redirects them to `/auditors/` |
| `/schema/config.json`, `/schema/report-v1.json` | `openaudit schema config` and `openaudit schema report`. `openaudit init` writes `https://openaudit.se/schema/config.json` into configs, so keep these paths |
| `<page>index.md` | A Markdown version of every page (`/index.md`, `/docs/cli/index.md`, `/auditors/<id>/index.md`, …) composed in `src/lib/llm.ts` from the same sources and data as the HTML. The report's is the CLI's `openaudit-report.md`. Each page links it with `rel="alternate"` |
| `/llms.txt`, `/llms-full.txt` | `src/lib/llm.ts`: the llmstxt.org index, and the README pitch, docs and auditor catalogue in one file |
| `/data/catalogue.json`, `/data/docs.json` | The registry with playbooks, and the docs split at their headings with install snippets, for the remote MCP server and the WebMCP tools |
| `/openapi.json` | The self-hosted HTTP API (`apps/server`), generated from its router by `packages/api/src/openapi.ts`. openaudit.se does not serve that API |
| `/.well-known/*`, `/auth.md` | `scripts/agents.ts`: MCP server card (also `server-cards.json`) and the `/.well-known/mcp` manifest (also served at `/.well-known/mcp.json`), the agent skills index with `skills/openaudit/SKILL.md`, the RFC 9727 API catalog, the AI catalog, and `auth.md` (no credentials needed anywhere) |

The example findings on the landing page use real rule ids, titles and severities from `packages/auditors`; their file locations are illustrative.

## Develop

```sh
bun install                      # at the repository root
cd apps/site
bun run dev                      # http://localhost:4321/, hot reload: use it for copy and styles
bun run build                    # dist/
bunx astro preview               # serves dist/; note the port it prints
bun run check:ui <url>           # WebKit + Chromium checks, about 30 s (see below)
bun run check-types              # astro check, strict
bun run test                     # the Worker's tests (worker/*.test.ts)
```

`scripts/check-ui.ts` opens the main pages at phone, tablet and desktop widths in WebKit and Chromium and fails on: sideways scrolling, no link home on screen at the bottom of a page, a footer that doesn't fit on screen at the bottom, an overlay menu that moves the page, and console errors. Point it at a local preview, a branch preview or `https://openaudit.se`. Install the browsers once with `bunx playwright install webkit chromium`.

`scripts/prepare.ts` runs before `dev`, `build` and `check-types`. It writes `src/generated/*.json`, the JSON Schemas into `public/schema/`, and copies the report and the report screenshots into `public/`. All of that output is gitignored. If `public/report/` holds no report yet, `prepare` audits the repository (about 10 seconds). `bun scripts/prepare.ts --fresh` re-runs the audit.

`scripts/postbuild.ts` runs after `astro build`. It:

- renders an Open Graph image for every page (`dist/og/*.png`, from each page's `og:title`) and the PNG favicons;
- adds a Content-Security-Policy `<meta>` to every page, holding the hashes of that page's inline styles and scripts (so the policy holds on hosts that cannot send headers);
- writes `_headers` for hosts that can send headers (Cloudflare): the same policy plus HSTS, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` and cache rules;
- adds canonical, Open Graph, Markdown and AI catalog links and the site's navigation bar to the copied `/report/` page, and hashes the bar into its CSP;
- writes `robots.txt` (with `Content-Signal: search=yes, ai-input=yes, ai-train=yes` and an `Agentmap`; the content signals are the owner's choice and live in `postbuild.ts`), `.well-known/security.txt` and `CNAME` when `CUSTOM_DOMAIN` is set;
- writes the agent discovery files (`scripts/agents.ts`);
- fails the build if any internal link or asset reference does not resolve, including each page's Markdown version, the links in `llms.txt` and the discovery files, and the heading anchors the docs search returns.

## Visitors

The Worker counts page views anonymously (`worker/visits.ts`): one Workers Analytics Engine data point per HTML or Markdown view, with the path, human or bot (and the bot's name), the referring host, the country and phone or desktop. No IP address, user agent string or cookie is stored, and the page loads no analytics script. `HEAD` requests and prefetches aren't counted.

```sh
CLOUDFLARE_ACCOUNT_ID=… CLOUDFLARE_API_TOKEN=… bun run stats 30   # last 30 days
```

The token needs "Account Analytics: Read". These are page views, not people.

## Where it is served

The base URL comes from two environment variables, read by `astro.config.ts` and `scripts/postbuild.ts`:

| Variable | Default | Example for GitHub Pages |
| --- | --- | --- |
| `SITE_URL` | `https://openaudit.se` | `https://wezter96.github.io` |
| `BASE_PATH` | `/` | `/openaudit` |
| `CUSTOM_DOMAIN` | unset | a custom domain on Pages (writes `dist/CNAME`) |

Every internal link goes through `u()` in `src/lib/site.ts`, so it follows the base path. Canonical URLs, the sitemap, Open Graph URLs and `robots.txt` follow `SITE_URL`.

## Deploy

`.github/workflows/site.yml` runs on every push (and by hand):

- `deploy` builds the site with the last self-audit (from the Actions cache). On `main` it runs `wrangler deploy`, so a change is live in about a minute. On any other branch it uploads a preview version (`wrangler versions upload --preview-alias <branch>`) and prints its URL in the job summary.
- `report` (main only) audits the commit inside `ghcr.io/wezter96/openaudit:edge-full`, caches the report for the next deploy and deploys again, unless a newer commit has reached `main` meanwhile.
- `ui` runs `check:ui` against what was published: on `main` after `report`, so it sees the fresh report; elsewhere right after the preview upload.

Without the Cloudflare secrets, the deploy steps fail.

`wrangler.jsonc` deploys a Worker named `openaudit-site` that serves `dist/` as static assets, with `_headers` applied. `worker/index.ts` runs first on every request. It:

- sends `www.openaudit.se` to the apex with a 301;
- answers `https://openaudit.se/mcp`, a read-only MCP server (`worker/mcp.ts`): stateless Streamable HTTP, JSON-RPC over POST with plain JSON replies, no sessions or SSE (GET is 405). Its tools (`list_auditors`, `get_auditor`, `search_docs`, `get_config_schema`, `get_install_instructions`) read `/data/*.json` and `/schema/config.json` from the build. Bodies over 64 KB and batches over 16 messages are refused, and arguments are validated against each tool's schema. It cannot run audits; `bunx @openaudit/cli mcp` does. The Server Card is also served at `/mcp/server-card`, and the manifest at `/.well-known/mcp`;
- serves a page's Markdown version at the page's own URL when `Accept` ranks `text/markdown` at least as high as `text/html`, with `x-markdown-tokens` (characters / 4) and `Vary: Accept`. HTML stays the default;
- adds a `Link` header to HTML (`api-catalog`, `service-desc`, `service-doc`, `describedby`, `ai-catalog` and the page's Markdown `alternate`) and `Vary: Accept`;
- gives `llms*.txt`, `*.md`, `/.well-known/*`, `/data/*.json` and `/openapi.json` their content types and `Access-Control-Allow-Origin: *` (`worker/agents.ts`).

Pages also register read-only WebMCP tools (`search_auditors`, `get_auditor`, `open_docs_page`, in `src/scripts/webmcp.ts`) when the browser has `document.modelContext`; elsewhere the module is never loaded.

Both hostnames are custom domains, so Cloudflare creates their DNS records and certificates on the first deploy.

One-time setup:

1. Add `openaudit.se` to a Cloudflare account as a zone, and point the registrar's nameservers at Cloudflare. Remove any existing `A`, `AAAA` or `CNAME` records for `openaudit.se` and `www`: custom domains create their own, and they fail if a record already exists.
2. Create an API token (My Profile > API Tokens > Create Custom Token) with:
   - Account > **Workers Scripts** > Edit
   - Zone > **Workers Routes** > Edit, limited to `openaudit.se`
   - Zone > **Zone** > Read, limited to `openaudit.se`

   If the first deploy fails with an authorisation error while attaching the custom domains, create the token from Cloudflare's "Edit Cloudflare Workers" template instead. It includes these scopes and a few more.
3. Copy the account ID from the zone's overview page.
4. In GitHub, add the repository secrets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`.
5. Push to `main`, or run the Site workflow by hand.

To deploy from your own machine instead: `bun run build && bunx wrangler login && bunx wrangler deploy`. To try the Cloudflare behaviour locally after a build, run `bunx wrangler dev`.

The Worker runs on every request (for the redirect, Markdown negotiation and headers). On the Workers Free plan that means 100,000 requests a day.

## Quality gates

- **Lighthouse.** Every page, including `/report/`, scores 100 in Performance, Accessibility, Best Practices and SEO on desktop and mobile. Build, serve `dist/`, and run:

  ```sh
  bunx unlighthouse-ci --site http://localhost:<port>/ --urls <every page> --desktop --budget 100
  bunx unlighthouse-ci --site http://localhost:<port>/ --urls <every page> --mobile --budget 100
  ```

  Pass the pages explicitly so none is missed; `find dist -name index.html` lists them. Run with `puppeteerClusterOptions: { maxConcurrency: 1 }` or `2` in an `unlighthouse.config.ts`, so parallel runs don't slow each other's timings.
- **openaudit itself.** `bun ../cli/src/bin.ts http://localhost:<port>/ --browser --max-pages 20` should report nothing above `info` on the site's own pages.
- **Types and lint.** `bun run check-types` here, and `bunx biome ci .` at the repository root. `apps/site/biome.json` extends the root config, lints `.astro` files with Biome's HTML support, and ignores generated output.

## Design

The site uses the HTML report's "Calibration sheet" language (`packages/core/src/reporters/html/style.ts`): cool fog paper with a dot grid, hairline rules instead of cards, a system sans set large and tight over a monospace data layer, one ultramarine accent, the report's severity ramp and glyphs, and its grade dial. The dial geometry in `src/lib/dial.ts` matches `viz.ts`.

Motion uses the report's spring curves:

- **Load.** The landing page has one choreographed load. The headline rises out of its masks while the dial draws itself: scale, area arcs one by one, ring, bead, grade, and the score counting up.
- **Scroll.** Sections settle as they scroll in, through CSS scroll-driven animations (`animation-timeline: view()`). Browsers without them fall back to an IntersectionObserver.
- **Set pieces.** The three-step merge diagram, the report callout pins and the agent session play once when they arrive.
- **Interaction.** The areas module's panels ease between heights.
- **Fallbacks.** Every animation starts from a final state already in the markup, so the page is complete without JavaScript and with `prefers-reduced-motion`.

There are no web fonts, trackers or third-party requests. The landing page ships about 7 KB of JavaScript, under 4 KB compressed.
