# openaudit — contributor notes for agents

Bun + TypeScript + **Effect 4** monorepo (Better-T-Stack). Scripts live in `package.json`; run `bun test` inside a package, `bun run check-types` and `bun run check` (Biome) at the root.

## Layout
- `packages/core`: report model (`model.ts`, the public contract with `schemaVersion`), `Auditor` interface, engine, target detection, infrastructure services, reporters.
- `packages/auditors`: deterministic auditors, one folder per area (`codebase`, `web`, `infra`, `mobile`, `cloud`), each registered in that folder's `index.ts`.
- `packages/agent`: playbooks plus agentic auditors (Claude Agent SDK) and AI insights.
- `packages/mcp`: MCP server. `apps/cli`: the `openaudit` binary. `apps/server` + `packages/api`: Hono/oRPC HTTP API. `apps/web`: TanStack Start site.

## Auditor conventions
- `run(ctx)` closes over infrastructure through `AuditContext` (`ctx.workspace`, `ctx.http`, `ctx.exec`), so it has no Effect requirements. Infrastructure is resolved once in the engine.
- A missing tool, key or irrelevant target is a `SkipAudit` (status `skipped`, with the reason shown to users). `AuditorError` is for genuine failures. The engine also converts defects and timeouts per auditor, so one auditor never sinks a run.
- Tag findings so the engine can merge the same issue across tools: advisory ids as lowercase tags (`cve-…`, `ghsa-…`), `secrets` plus `cwe-798` for leaked credentials, `cwe-N` and `wcag-x.y.z` where known, `owasp-aNN` only for the OWASP Top 10 2021, and `owasp-llmNN` for the OWASP Top 10 for LLM Applications 2025 (`owaspLlmUrl`). Merging needs a file and line, or a URL and selector (`packages/core/src/correlate.ts`).
- Rule ids are `<auditor id>/<kebab-rule>`; ids and fingerprints are a stable contract that baselines and suppressions depend on. Rename them only with a migration note.
- Findings carry a location, a remediation and a redacted `evidence` (use `redact`). Mark heuristics `confidence: "low"`.
- External-tool wrappers set `engine: "external"` and `tool`, skip with an install hint, and have parser tests against recorded JSON.
- Wrapped tools must not run target code: no installs or builds, and run from a temp dir when a tool loads config or hooks from its cwd (pnpm's `.pnpmfile.cjs`, pa11y config, deepsec config). Pass hardening as CLI flags, because project config overrides env vars. Git calls on a target use `GIT_HARDENING_ENV` from core and compare commits, never the working tree. Anything slow, costly, traffic-heavy or code-executing is `defaultEnabled: false` (opt-in via `--only`). Shared helpers live in `packages/auditors/src/tool.ts`.
- Targets are untrusted input: read files through `Workspace`, which confines reads to the root and skips symlinks. Send HTTP through `ctx.http`, which scopes user headers to the target origin and strips credentials on cross-origin redirects. URL auditors send only low-volume GET/HEAD requests.

## Commits and parallel branches
- Commit subjects are the release notes (`apps/cli/scripts/release-notes.ts`, see RELEASING.md). Write `type(scope): what changed` for someone reading the release page, and put the why in the body. A breaking change gets `!` or a `BREAKING CHANGE:` footer. Preview the next release's notes with `bun apps/cli/scripts/release-notes.ts HEAD`.
- Many branches run at once, and most conflicts are two of them adding a line at the same spot. In README.md's "What it checks, by target", keep one item per line, in alphabetical order, so two new tools land on different lines.
- A new auditor or wrapped tool updates the counts in the README intro. `apps/cli/test/readme.test.ts` checks them against the registry, and checks that every wrapped tool is named and the lists stay sorted. Don't hard-code a total that features grow anywhere else; compare against the registry.

## Effect 4
APIs differ from v3: `Context.Service<Self, Shape>()("id")`, `Effect.catch`, `Effect.catchDefect`, `Schema.Literals([...])`. When unsure, read the source in `node_modules/.bun/effect@4.0.3/node_modules/effect/src`.

<!-- BEGIN:turborepo-agent-rules -->

# This is NOT the Turborepo you know

Turborepo configuration, task behavior, and CLI commands can vary between installed versions and may differ from your training data. Resolve the `turbo` package from this file's directory or relevant workspace; in monorepos, it may not be visible from the repository root. For example, run `node -p "require.resolve('turbo/package.json')"` from a workspace that depends on `turbo`.

Read `docs/README.md` inside that installed package first, then read the relevant pages from its `docs/` directory before changing Turborepo configuration or commands. Heed deprecation notices. These bundled docs match the installed package version and are available without network access.

This block is written and re-added by `turbo` before repository-scoped commands when an AI agent is detected. In the Turborepo source repository, its template is defined in `crates/turborepo-cli/src/cli/agent_guidance.rs`. Removing the managed block while updates are enabled means a later qualifying invocation will add it again. Set `"agentGuidance": false` in the root `turbo.json` or `turbo.jsonc` to opt out; this does not remove an existing block. Keep the block committed with your work to avoid an uncommitted change on the next agent invocation.
<!-- END:turborepo-agent-rules -->
