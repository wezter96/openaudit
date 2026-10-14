import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative } from "node:path";
import {
	type AuditContext,
	AuditorError,
	DEFAULT_IGNORES,
	type Severity,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import { baseName, isRecord, truncate } from "./codebase/util";

/**
 * Shared helpers for external-tool wrappers: running the tool, parsing its
 * JSON, and normalising paths, severities and tags.
 */

export const parseJson = (stdout: string, tool: string) =>
	Effect.try({
		try: () => JSON.parse(stdout) as unknown,
		catch: (cause) =>
			new AuditorError({
				message: `${tool} produced invalid JSON output`,
				cause,
			}),
	});

/** Path relative to the workspace root, POSIX-style. */
export const relPath = (
	root: string,
	file: string | undefined,
): string | undefined => {
	if (!file) return undefined;
	const rel = isAbsolute(file)
		? relative(root, file)
		: file.replace(/^\.\//, "");
	return rel.split("\\").join("/");
};

const IGNORED_DIRS = new Set(DEFAULT_IGNORES);

/**
 * True when a workspace-relative path sits in a directory the built-in
 * auditors skip (dependencies, build output, caches). For tools that walk the
 * whole tree and have no exclude flag.
 */
export const inIgnoredDir = (file: string | undefined): boolean =>
	file?.split("/").some((part) => IGNORED_DIRS.has(part)) === true;

/** Most gitignored paths passed to one tool's own skip flags. */
const MAX_TOOL_IGNORES = 200;

/**
 * Characters a tool could read as pattern syntax, a list separator or a new
 * line. File names come from the target, so a file called `**` must not
 * become "skip everything".
 */
// biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting them
const UNSAFE_SKIP = /[*?[\]{}!\\,\u0000-\u001f\u007f]/;

/**
 * The workspace's gitignored paths (directories end in `/`) for a tool that
 * walks the folder itself, so it never reads them. Paths that a tool could
 * read as a pattern, or as a flag, are left out. Capped and never failing:
 * the engine drops findings in any ignored path a tool still reports.
 */
export const gitignoredPaths = (ws: Workspace) =>
	ws.ignored.pipe(
		Effect.map((paths) =>
			paths
				.filter((p) => !p.startsWith("-") && !UNSAFE_SKIP.test(p))
				.slice(0, MAX_TOOL_IGNORES),
		),
		Effect.catch(() => Effect.succeed([] as ReadonlyArray<string>)),
	);

export const escapeRegex = (s: string): string =>
	s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export const str = (v: unknown): string | undefined =>
	typeof v === "string" ? v : undefined;
export const num = (v: unknown): number | undefined =>
	typeof v === "number" ? v : undefined;
export const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);

/**
 * JSON objects from line-delimited output (NDJSON). Log lines and anything
 * else that is not a JSON object are skipped.
 */
export const jsonLines = (stdout: string): Record<string, unknown>[] =>
	stdout.split("\n").flatMap((line) => {
		const text = line.trim();
		if (!text.startsWith("{")) return [];
		try {
			const item: unknown = JSON.parse(text);
			return isRecord(item) ? [item] : [];
		} catch {
			return [];
		}
	});

export const cweTags = (values: ReadonlyArray<string>) =>
	values.flatMap((v) => {
		const m = /CWE-(\d+)/i.exec(v);
		return m ? [`cwe-${m[1]}`] : [];
	});

/**
 * `owasp-a01` tags always mean the OWASP Top 10 2021. Other editions reuse the
 * same ids for different risks (A01:2017 is Injection), so they are dropped;
 * the CWE tags still map them.
 */
export const owaspTags = (values: ReadonlyArray<string>) =>
	values.flatMap((v) => {
		const m = /^(A\d{2}):2021\b/i.exec(v);
		return m?.[1] ? [`owasp-${m[1].toLowerCase()}`] : [];
	});

export const LABEL_SEVERITY: Record<string, Severity> = {
	CRITICAL: "critical",
	HIGH: "high",
	ERROR: "high",
	MEDIUM: "medium",
	MODERATE: "medium",
	WARNING: "medium",
	LOW: "low",
	INFO: "low",
	UNKNOWN: "info",
};

export const severityOf = (
	label: unknown,
	fallback: Severity = "medium",
): Severity =>
	(typeof label === "string" && LABEL_SEVERITY[label.toUpperCase()]) ||
	fallback;

/** Runs a tool and fails unless its exit code is one of `okCodes`. */
export const runTool = (
	ctx: AuditContext,
	cmd: ReadonlyArray<string>,
	cwd: string,
	okCodes: ReadonlyArray<number>,
) =>
	Effect.flatMap(ctx.exec.run(cmd, { cwd, timeoutMs: 15 * 60_000 }), (res) =>
		okCodes.includes(res.code)
			? Effect.succeed(res)
			: Effect.fail(
					new AuditorError({
						message: `${cmd[0]} exited with code ${res.code}: ${truncate(res.stderr || res.stdout, 300)}`,
					}),
				),
	);

/**
 * Runs a tool with optional extra env; fails with its output, naming the tool
 * by its file name, unless the exit code is in `okCodes`.
 */
export const runCommand = (
	ctx: AuditContext,
	cmd: ReadonlyArray<string>,
	opts: {
		cwd: string;
		okCodes: ReadonlyArray<number>;
		env?: Record<string, string>;
	},
) =>
	Effect.flatMap(
		ctx.exec.run(cmd, {
			cwd: opts.cwd,
			timeoutMs: 15 * 60_000,
			env: opts.env,
		}),
		(res) =>
			opts.okCodes.includes(res.code)
				? Effect.succeed(res)
				: Effect.fail(
						new AuditorError({
							message: `${baseName(cmd[0] ?? "tool")} exited with code ${res.code}: ${truncate(res.stderr || res.stdout, 300)}`,
						}),
					),
	);

/* -------------------------------------------------------------------------- */
/*                                  gitleaks                                  */
/* -------------------------------------------------------------------------- */

/**
 * Runs `fn` with a scratch directory that is always removed afterwards. Use it
 * as the cwd of tools that read config from their working directory.
 */
export const withTempDir = <A, E>(
	prefix: string,
	fn: (dir: string) => Effect.Effect<A, E>,
): Effect.Effect<A, E | AuditorError> =>
	Effect.acquireUseRelease(
		Effect.tryPromise({
			try: () => mkdtemp(join(tmpdir(), prefix)),
			catch: (cause) =>
				new AuditorError({ message: "Could not create temp dir", cause }),
		}),
		fn,
		(dir) => Effect.promise(() => rm(dir, { recursive: true, force: true })),
	);
