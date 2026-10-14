import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative } from "node:path";
import {
	type AuditContext,
	AuditorError,
	DEFAULT_IGNORES,
	type Severity,
} from "@openaudit/core";
import { Effect } from "effect";

import { truncate } from "./codebase/util";

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

export const str = (v: unknown): string | undefined =>
	typeof v === "string" ? v : undefined;
export const num = (v: unknown): number | undefined =>
	typeof v === "number" ? v : undefined;
export const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);

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
