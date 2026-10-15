import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { FindingInput } from "@openaudit/core";
import { Effect } from "effect";

/** Helpers shared by the JavaScript/TypeScript linter wrappers in lint-js.ts. */

/** Workspace-relative POSIX path. */
export type RelativePath = string;
/** Absolute filesystem path. */
export type AbsolutePath = string;
/** A finding's rule id, `<auditor id>/<kebab-rule>`. */
export type RuleId = string;
/** Name of a wrapped tool as shown to users. */
export type ToolName = string;
/** The text of a JSON (or JSONC) document. */
export type JsonText = string;

/** Findings kept per run; the rest collapse into one summary finding. */
const MAX_FINDINGS = 200;

const GENERIC_IGNORES = [
	"**/node_modules/**",
	"**/dist/**",
	"**/build/**",
	"**/coverage/**",
	"**/.next/**",
	"**/vendor/**",
	"**/*.min.js",
];

/** `--ignore-pattern` arguments for build output and vendored code. */
export const IGNORE_ARGS = GENERIC_IGNORES.flatMap((g) => [
	"--ignore-pattern",
	g,
]);

export const capFindings = (
	findings: FindingInput[],
	ruleId: RuleId,
	tool: ToolName,
): FindingInput[] => {
	if (findings.length <= MAX_FINDINGS) return findings;
	const kept = findings.slice(0, MAX_FINDINGS);
	const extra = findings.length - MAX_FINDINGS;
	kept.push({
		ruleId,
		title: `${extra} more ${tool} findings not listed`,
		severity: "info",
		category: "maintainability",
		message: `${tool} reported ${findings.length} findings; only the first ${MAX_FINDINGS} are listed to keep the report readable.`,
		remediation: `Run ${tool} locally for the full list and fix the most common rules first.`,
		confidence: "high",
	});
	return kept;
};

/** Runs `use` with a fresh empty directory that is removed afterwards. */
export const withTempDir = <A, E, R>(
	prefix: string,
	use: (dir: AbsolutePath) => Effect.Effect<A, E, R>,
) =>
	Effect.flatMap(
		// Real path: tools print paths relative to their (resolved) cwd.
		Effect.promise(async () => realpath(await mkdtemp(join(tmpdir(), prefix)))),
		(dir) =>
			use(dir).pipe(
				Effect.ensuring(
					Effect.promise(() => rm(dir, { recursive: true, force: true })),
				),
			),
	);

/** Directory of a workspace path, `""` for the root. */
export const dirOf = (path: RelativePath): RelativePath =>
	dirname(path) === "." ? "" : dirname(path);

export const isPackageJson = (path: RelativePath): boolean =>
	path === "package.json" || path.endsWith("/package.json");
