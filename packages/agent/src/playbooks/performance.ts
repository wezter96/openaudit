import type { Playbook } from "../playbook";
import { compose, REPORTING } from "./shared";

export const performance: Playbook = {
	id: "agent.performance",
	title: "Performance review",
	summary:
		"Finds performance problems that need understanding of hot paths: N+1 queries, missing indexes, unbounded queries, blocking work, missing caching, heavy client bundles, leaks and render waterfalls.",
	categories: ["performance", "reliability"],
	targets: ["codebase"],
	needs: ["code"],
	checklist: [
		"Identified hot paths: high-traffic routes/pages, list endpoints, background jobs on large tables, startup code",
		"Checked data access in loops for N+1 queries (ORM lazy loading, per-item fetches, awaits in loops)",
		"Compared filters/sorts/joins of hot queries against schema indexes and migrations",
		"Checked list endpoints and queries for missing pagination/limits and SELECT * of large columns",
		"Checked request handlers for synchronous blocking work (sync fs/crypto, CPU-heavy loops, large JSON parse, regex backtracking)",
		"Checked for missing or ineffective caching of expensive, repeatable work and of static assets",
		"Checked client bundles: heavy dependencies, missing code splitting, client components that could be server-rendered, unoptimised images/fonts",
		"Checked for memory leaks: unbounded caches/maps, listeners/intervals not cleaned up, growing module-level arrays",
		"Checked rendering and data-fetching waterfalls (sequential awaits that could be parallel, nested suspense fetches, client-side fetch chains)",
		"Checked outbound calls for missing timeouts, retries without backoff, and missing connection pooling",
	],
	instructions: compose(
		`# Performance review

## Scope

Application code and its data layer: server handlers, ORM/query code, schema and migrations, background jobs, and client-side code (bundling, rendering, data fetching). The goal is problems with **real** impact on latency, throughput, cost or stability at plausible production scale — not micro-optimisations.

## Method

1. **Find the hot paths.** Identify the primary user-facing routes/pages and API endpoints (home, search, listing, dashboard, checkout), endpoints that return collections, webhooks, cron/queue jobs over whole tables, and code executed per request (middleware, auth, layout loaders). Prioritise those.
2. **N+1 queries.** Look for database or HTTP calls inside loops/\`map\`/\`forEach\`, \`await\` in \`for\` loops over query results, ORM lazy relations accessed per item (Django \`.all()\` without \`select_related\`/\`prefetch_related\`, Rails without \`includes\`, Prisma/Drizzle/TypeORM per-row \`find\`, GraphQL resolvers without DataLoader). Report the loop and the per-item query.
3. **Indexes.** Read the schema/migrations (Prisma schema, Drizzle tables, SQL migrations, Django models, ActiveRecord schema). For each hot query, check that its \`WHERE\`, \`JOIN\`, \`ORDER BY\` columns are indexed (composite order matters), that foreign keys used for lookups have indexes (Postgres does not add them automatically), and that \`LIKE '%x%'\` / function-wrapped columns are not expected to use an index. Only report when the table is plausibly large (users, events, orders, logs — not settings).
4. **Unbounded work.** List endpoints without pagination or with client-controlled unbounded \`limit\`; \`SELECT *\` pulling large blobs/JSON; loading whole tables into memory for filtering/counting in application code; exports and reports that build everything in memory; offset pagination deep into large tables.
5. **Blocking the event loop / request thread.** Synchronous filesystem, compression, crypto (\`bcrypt\` sync, \`pbkdf2Sync\`), large \`JSON.parse\`/\`stringify\`, image processing, or catastrophic-backtracking regexes on request paths in single-threaded runtimes; sequential awaits of independent I/O (\`await a(); await b();\` instead of \`Promise.all\`).
6. **Caching.** Repeated expensive computation or third-party calls per request with stable results; missing HTTP caching headers for static/immutable assets; framework caching disabled globally (e.g. \`dynamic = "force-dynamic"\` / \`revalidate = 0\` on pages that could be static); cache keys that make hit rates near zero.
7. **Client bundle & rendering.** Heavy libraries imported in client code where smaller alternatives or lazy loading fit (moment, lodash full import, chart/editor/map libraries on initial route), \`"use client"\` at layout roots forcing whole trees client-side, large JSON/props serialised into HTML, unoptimised images (no dimensions, no lazy loading, huge originals), blocking fonts/scripts in \`<head>\`, re-render storms (context values recreated each render, effects that set state on every render).
8. **Waterfalls.** Server components/loaders that fetch sequentially in nested layouts, client components fetching after mount in chains (parent fetch → child fetch), suspense boundaries that serialise requests.
9. **Leaks & resilience.** Module-level caches/maps without eviction, event listeners/intervals/subscriptions without cleanup, per-request creation of DB clients/pools, outbound HTTP without timeouts, retries without backoff/jitter, missing connection pooling for serverless databases.

## Severity rubric

- **critical** — will take the service down or exhaust resources at normal production load (unbounded query on a large table in a hot path, memory leak per request, sync CPU work blocking all requests).
- **high** — N+1 or missing index on a primary hot path, missing pagination on a large collection, client bundle bloat on the landing route (hundreds of KB of avoidable JS), no timeouts on critical outbound calls.
- **medium** — measurable but bounded slowdowns: secondary-path N+1, avoidable waterfalls, missing caching of expensive repeatable work, oversized images.
- **low** — minor inefficiencies on rarely used paths.
- **info** — scale-dependent risks to keep in mind.

## What NOT to report

- Micro-optimisations without measurable impact (loop style, \`map\` vs \`for\`).
- Missing indexes on small/static tables, admin-only or one-off scripts.
- N+1 on collections that are bounded and tiny by design (e.g. ≤ 5 items).
- Anything you cannot connect to a concrete code path. State your scale assumption ("orders grows with traffic") in the message.`,
		REPORTING,
	),
};
