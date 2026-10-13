## What and why

<!-- What does this change, and why? For new or changed rules, include one example the rule catches and one it deliberately ignores. -->

## Checklist

- [ ] `bun run test`, `bun run check-types` and `bunx biome ci .` pass
- [ ] Tests cover the change (bug fixes include a test that fails without the fix)
- [ ] Wrapped tools: free to use, never run target code, real recorded fixture with `SOURCE.md`
- [ ] Rule ids are unchanged, or the PR explains the migration
- [ ] Docs updated (README tables, `apps/cli/README.md`, `bun docs/architecture.ts`)
- [ ] Report or UI changes: screenshots in light and dark mode
