import { isAbsolute, relative } from "node:path";
import {
	type AuditContext,
	AuditorError,
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

export const owaspTags = (values: ReadonlyArray<string>) =>
	values.flatMap((v) => {
		const m = /^(A\d{2}):/i.exec(v);
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
