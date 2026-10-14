# openaudit website

The public website for openaudit: a landing page, the docs, the auditor catalogue, and openaudit's live audit of its own repository. It is a static [Astro](https://astro.build) site. It is published to GitHub Pages at `https://wezter96.github.io/openaudit/` for now, and is ready to move to `https://openaudit.se`.

Nothing on the site is hand-copied from the rest of the repository. At build time it reads:

| Page | Built from |
| --- | --- |
| `/` | `README.md` (pitch, areas, languages, targets, safety, community), `integrations/README.md` and `apps/cli/README.md` (snippets), the auditor registry, `packages/core/src/scoring.ts`, and the self-audit's scores (hero dial and proof strip) |
| `/docs/*` | Sections of `README.md`, `apps/cli/README.md`, `packages/agent/README.md`, `integrations/README.md`, `CONTRIBUTING.md` and `SECURITY.md`; `action.yml` (Action inputs and outputs); `openaudit --help` and `openaudit schema config`; `scoring.ts` (scoring examples) |
| `/auditors/`, `/auditors/<id>/` | `allAuditors()` from `apps/cli/src/audit.ts` and the playbooks in `packages/agent` |
| `/report/` | `openaudit-report.{html,json,sarif,md}` written by the CLI, copied unmodified |
| `/architecture/` | `docs/architecture.html`, copied unmodified |
| `/schema/config.json`, `/schema/report-v1.json` | `openaudit schema config` and `openaudit schema report`. `openaudit init` writes `https://openaudit.se/schema/config.json` into configs, so keep these paths |

The example findings on the landing page use real rule ids, titles and severities from `packages/auditors`; their file locations are illustrative.

## Develop

```sh
bun install                      # at the repository root
cd apps/site
bun run dev                      # http://localhost:4321/openaudit/
bun run build                    # dist/
bun run check-types              # astro check, strict
```

`scripts/prepare.ts` runs before `dev`, `build` and `check-types`. It writes `src/generated/*.json`, the JSON Schemas into `public/schema/`, and copies the report, the architecture page and the report screenshots into `public/`. All of that output is gitignored. If `public/report/` holds no report yet, `prepare` audits the repository (about 10 seconds). `bun scripts/prepare.ts --fresh` re-runs the audit.

`scripts/postbuild.ts` runs after `astro build`. It:

- renders an Open Graph image for every page (`dist/og/*.png`, from each page's `og:title`) and the PNG favicons;
- adds a Content-Security-Policy `<meta>` to every page, holding the hashes of that page's inline styles and scripts (GitHub Pages cannot send headers);
- writes `_headers` for hosts that can send headers (Cloudflare): the same policy plus HSTS, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` and cache rules;
- writes `robots.txt`, `.well-known/security.txt`, a redirect from the old `/architecture.html`, and `CNAME` when `CUSTOM_DOMAIN` is set;
- fails the build if any internal link or asset reference does not resolve.

## Where it is served

The base URL comes from two environment variables, read by `astro.config.ts` and `scripts/postbuild.ts`:

| Variable | Default | For openaudit.se |
| --- | --- | --- |
| `SITE_URL` | `https://wezter96.github.io` | `https://openaudit.se` |
| `BASE_PATH` | `/openaudit` | `/` |
| `CUSTOM_DOMAIN` | unset | `openaudit.se` (writes `dist/CNAME`) |

Every internal link goes through `u()` in `src/lib/site.ts`, so it follows the base path. Canonical URLs, the sitemap, Open Graph URLs and `robots.txt` follow `SITE_URL`.

## Deploy

### GitHub Pages (current)

`.github/workflows/pages.yml` runs on every push to `main`. It audits the repository into `public/report/`, regenerates `docs/architecture.html`, builds the site and deploys `dist/` with `actions/deploy-pages`. Pages must be set to "GitHub Actions" as the source (Settings > Pages).

To move the Pages site to the custom domain, set the repository variables `SITE_URL`, `BASE_PATH` and `CUSTOM_DOMAIN` (Settings > Secrets and variables > Actions > Variables) to the values in the table above. Then point the domain's DNS at GitHub Pages.

### Cloudflare (later)

`.github/workflows/site.yml` builds for `https://openaudit.se` with base `/` and runs `wrangler deploy`. It runs only by hand (`workflow_dispatch`) until the move. Without the Cloudflare secrets, the deploy step is skipped with a notice.

`wrangler.jsonc` deploys a Worker named `openaudit-site` that serves `dist/` as static assets, with `_headers` applied. `worker/index.ts` runs first on every request so it can send `www.openaudit.se` to the apex with a 301. Both hostnames are custom domains, so Cloudflare creates their DNS records and certificates on the first deploy.

One-time setup:

1. Add `openaudit.se` to a Cloudflare account as a zone, and point the registrar's nameservers at Cloudflare. Remove any existing `A`, `AAAA` or `CNAME` records for `openaudit.se` and `www`: custom domains create their own, and they fail if a record already exists.
2. Create an API token (My Profile > API Tokens > Create Custom Token) with:
   - Account > **Workers Scripts** > Edit
   - Zone > **Workers Routes** > Edit, limited to `openaudit.se`
   - Zone > **Zone** > Read, limited to `openaudit.se`

   If the first deploy fails with an authorisation error while attaching the custom domains, create the token from Cloudflare's "Edit Cloudflare Workers" template instead. It includes these scopes and a few more.
3. Copy the account ID from the zone's overview page.
4. In GitHub, add the repository secrets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`.
5. Run the Site workflow by hand. Once it works, switch `site.yml` back to running on push and retire `pages.yml`.

To try the Cloudflare behaviour locally after a build with `SITE_URL=https://openaudit.se BASE_PATH=/`, run `bunx wrangler dev`.

The Worker runs on every request so it can redirect `www`. On the Workers Free plan that means 100,000 requests a day. If that becomes a limit, delete the `www` route and add a Cloudflare Redirect Rule from `www.openaudit.se/*` to `https://openaudit.se/${1}` instead.

## Quality gates

- **Lighthouse.** Every page, including `/report/` and `/architecture/`, scores 100 in Performance, Accessibility, Best Practices and SEO on desktop and mobile. Build, serve `dist/` under `/openaudit/`, and run:

  ```sh
  bunx unlighthouse-ci --site http://localhost:<port>/openaudit/ --urls <every page> --desktop --budget 100
  bunx unlighthouse-ci --site http://localhost:<port>/openaudit/ --urls <every page> --mobile --budget 100
  ```

  A site URL with a path turns off Unlighthouse's crawler and sitemap discovery, so pass the pages explicitly. `find dist -name index.html` lists them. Run with `puppeteerClusterOptions: { maxConcurrency: 1 }` or `2` in an `unlighthouse.config.ts`, so parallel runs don't slow each other's timings.
- **openaudit itself.** `bun ../cli/src/bin.ts http://localhost:<port>/openaudit/ --browser --max-pages 20` should report nothing above `info` on the site's own pages.
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
