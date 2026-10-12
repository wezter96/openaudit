# openaudit — contributor notes for agents

Bun + TypeScript + **Effect 4** monorepo (Better-T-Stack). Scripts live in `package.json`; run `bun test` inside a package, `bun run check-types` and `bun run check` (Biome) at the root.

## Layout
- `packages/core`: report model (`model.ts`, the public contract with `schemaVersion`), `Auditor` interface, engine, target detection, infrastructure services, reporters.
- `packages/auditors`: deterministic auditors, one folder per area (`codebase`, `web`, `infra`, `mobile`), each registered in that folder's `index.ts`.
- `packages/agent`: playbooks plus agentic auditors (Claude Agent SDK) and AI insights.
- `packages/mcp`: MCP server. `apps/cli`: the `openaudit` binary. `apps/server` + `packages/api`: Hono/oRPC HTTP API. `apps/web`: TanStack Start site.

## Auditor conventions
- `run(ctx)` closes over infrastructure through `AuditContext` (`ctx.workspace`, `ctx.http`, `ctx.exec`), so it has no Effect requirements. Infrastructure is resolved once in the engine.
- A missing tool, key or irrelevant target is a `SkipAudit` (status `skipped`, with the reason shown to users). `AuditorError` is for genuine failures. The engine also converts defects and timeouts per auditor, so one auditor never sinks a run.
- Rule ids are `<auditor id>/<kebab-rule>`; ids and fingerprints are a stable contract that baselines and suppressions depend on. Rename them only with a migration note.
- Findings carry a location, a remediation and a redacted `evidence` (use `redact`). Mark heuristics `confidence: "low"`.
- External-tool wrappers set `engine: "external"` and `tool`, skip with an install hint, and have parser tests against recorded JSON.
- Targets are untrusted input: read files through `Workspace`, which confines reads to the root and skips symlinks. Send HTTP through `ctx.http`, which scopes user headers to the target origin and strips credentials on cross-origin redirects. URL auditors send only low-volume GET/HEAD requests.

## Effect 4
APIs differ from v3: `Context.Service<Self, Shape>()("id")`, `Effect.catch`, `Effect.catchDefect`, `Schema.Literals([...])`. When unsure, read the source in `node_modules/.bun/effect@4.0.3/node_modules/effect/src`.
