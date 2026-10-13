# Contributing to openaudit

Thanks for helping. openaudit is only as good as its rules, and every false positive fixed or scanner wrapped makes it better for everyone who runs it.

This guide covers setup, how the code is organised, how to add an auditor, and what a pull request needs. If you work with a coding agent, point it at [AGENTS.md](AGENTS.md): it holds the same conventions in a form agents follow well.

## Ways to contribute

- **Report a false positive or a missed issue.** Use the "False positive / missed finding" issue template and include the rule id and a minimal example.
- **Improve a rule:** sharper detection, better remediation text, correct severity.
- **Add an auditor:** a new built-in check, or a wrapper for a free, open-source scanner.
- **Write or improve a playbook** for work that needs judgment (`packages/agent/src/playbooks`).
- **Docs:** the README, the CLI guide, or the architecture page.

For anything large, such as a new target kind, a change to the report model or a new dependency, open an issue first so we can agree on the shape before you build it.

Security vulnerabilities in openaudit itself go through [SECURITY.md](SECURITY.md), not public issues.

## Setup

```bash
git clone https://github.com/wezter96/openaudit && cd openaudit
bun install                         # Bun 1.4+
bunx playwright install chromium    # only for the browser tests and --browser
```

Run the full check before opening a pull request:

```bash
bun run test           # every package
bun run check-types    # TypeScript, strict
bunx biome ci .        # lint and format; `bun run check` fixes what it can
bun run audit -- .     # openaudit audits itself; it should stay at grade A
```

Tests for one package run from inside it, e.g. `cd packages/auditors && bun test test/web-dns.test.ts`.

External scanners are optional. Tests use recorded output and never need the tools installed, so you only install a scanner when you're wrapping or re-recording it.

## How the code is organised

| Path | What |
|---|---|
| `packages/core` | The report model (`model.ts`, a public contract), the `Auditor` interface, the engine, cross-tool correlation, diff mode, target detection and reporters |
| `packages/auditors` | Deterministic auditors, one folder per area (`codebase`, `web`, `infra`, `mobile`, `cloud`), each registered in that folder's `index.ts`. Shared helpers for wrapped tools are in `src/tool.ts` |
| `packages/agent` | Playbooks, agentic auditors (Claude Agent SDK) and AI insights |
| `packages/mcp` | The MCP server |
| `apps/cli` | The `openaudit` binary |
| `apps/server`, `packages/api`, `apps/web` | HTTP API and website |

The code uses [Effect 4](https://effect.website). Its APIs differ from v3; AGENTS.md lists the ones that trip people up.

## Adding an auditor

An auditor is a value with an id, the targets and areas it covers, and a `run` function that returns findings:

```ts
import { defineAuditor, type FindingInput, requireWorkspace } from "@openaudit/core";
import { Effect } from "effect";

export const envFiles = defineAuditor({
	id: "code.env-files",
	title: "Committed .env files",
	description: "Flags .env files committed to the repository.",
	categories: ["security"],
	targets: ["codebase"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const files = yield* ws.files;
			return files
				.filter((f) => /(^|\/)\.env(\.[\w-]+)?$/.test(f) && !f.endsWith(".example"))
				.map(
					(file): FindingInput => ({
						ruleId: "code.env-files/committed",
						title: ".env file committed",
						severity: "high",
						category: "security",
						message: `${file} is tracked in the repository and may hold secrets.`,
						location: { file },
						remediation: "Remove it from git, rotate any secrets it held and add it to .gitignore.",
						tags: ["cwe-538", "secrets"],
					}),
				);
		}),
});
```

Then:

1. **Put it in the right folder** and add it to that folder's `index.ts`.
2. **Write tests** in `packages/auditors/test/` against fixtures in `test/fixtures/`. Cover what it finds, what it must not flag, and how it skips. `test/helpers.ts` has `runAuditor` and `ruleIds`.
3. **Check it on a real project**, e.g. `bun run audit -- ../some-project --only code.env-files`, and fix the false positives you see.
4. **Regenerate the architecture page** with `bun docs/architecture.ts`.

### Findings

- **Rule ids** are `<auditor id>/<kebab-rule>` and are a stable contract: baselines, suppressions and fingerprints depend on them. Rename one only with a migration note.
- **Every finding** has a location (file and line, or URL and selector), a remediation, and evidence passed through `redact` when it could contain a secret.
- **Severity** reflects real impact: `critical` for directly exploitable or data-exposing issues, `high` for serious weaknesses, `medium` for real problems that need a condition, `low` for hardening and hygiene, and `info` for inventory that never lowers a score.
- **Heuristics** are marked `confidence: "low"`.
- **Tags** let the engine merge the same issue across tools:
  - advisory ids as lowercase tags (`cve-…`, `ghsa-…`)
  - `secrets` plus `cwe-798` for leaked credentials
  - `cwe-N` and `wcag-x.y.z` where known
  - `owasp-aNN` only for the OWASP Top 10 2021
- **Missing prerequisites** (a missing tool, an irrelevant target, no network under `--offline`) skip the auditor with a reason via `skip(...)` or `requireTool(...)`. Use `AuditorError` only for genuine failures.

### Wrapping an external tool

openaudit runs on untrusted code, so wrappers follow stricter rules than a typical integration:

- **Free and open source only.** No tool that needs a paid licence or account to scan private code. The only acceptable cost is token usage for AI features, and those are opt-in.
- **Never run target code.** No installs, builds or project scripts. If a tool loads config, plugins or hooks from the project or the working directory, run it from a temp directory and pass a safe config explicitly.
- **Hardening goes in CLI flags**, because project config files override environment variables.
- **Git calls** use `GIT_HARDENING_ENV` from core and compare commits, never the working tree.
- **Opt-in when needed.** A tool that is slow, costly, sends a lot of traffic, or can execute project code gets `defaultEnabled: false`, and its description says why.
- **Install hint.** When the tool is missing, skip with a hint built by `requireTool(ctx, bin, "Install: …")`.
- **Parser tests on real output.** Record the tool's output on a small sample, normalise machine paths to `/repo`, and note the tool version, the command and the date in the fixture folder's `SOURCE.md`. If you can't run the tool, say so in `SOURCE.md` and in the pull request.

Set `engine: "external"` and `tool: "<binary>"` so `openaudit doctor` and the docs pick it up.

### Changing the report or reporters

The report model in `packages/core/src/model.ts` is a public contract shared by the CLI, MCP, the API and agents. Changes must be backwards compatible (new optional fields only) and mirrored in the zod schemas in `packages/mcp/src/schemas.ts` and `packages/api/src/schemas.ts`.

The HTML report must stay self-contained, with no external requests and a CSP that only allows its hashed inline style and script. It must also pass openaudit's own accessibility checks in light and dark mode, work without JavaScript, and respect `prefers-reduced-motion`. Include before and after screenshots in the pull request.

## Pull requests

- Keep each pull request focused on one change. Commits follow [Conventional Commits](https://www.conventionalcommits.org) with a scope, e.g. `feat(auditors): …` or `fix(core): …`.
- Add or update tests. Bug fixes come with a test that fails without the fix.
- Run the full check from [Setup](#setup).
- Update the docs your change affects: README tables, `apps/cli/README.md` and the architecture page.
- Explain the change in plain language. For new rules, include an example the rule catches and one it deliberately ignores.

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE). Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
