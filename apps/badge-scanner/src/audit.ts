import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { lastLine, ScanError } from "./errors";
import { childEnv } from "./process";
import type { ProcessRunner, ReportPair } from "./types";

export const CODEBASE_TIMEOUT_MS = 15 * 60_000;
export const SITE_TIMEOUT_MS = 10 * 60_000;
const VERSION_TIMEOUT_MS = 30_000;

/** openaudit exits 0 (clean), 1 (findings) or 3 (some auditors failed) with a report. */
const REPORT_EXIT_CODES: ReadonlySet<number> = new Set([0, 1, 3]);

/** How to start openaudit, e.g. `["openaudit"]` or `["bun", "apps/cli/src/bin.ts"]`. */
export type OpenauditCommand = ReadonlyArray<string>;

/** Splits `OPENAUDIT_BIN` on whitespace, so a dev setup can use `bun path/bin.ts`. */
export const parseCommand = (bin: string | undefined): OpenauditCommand => {
	const parts = (bin ?? "").trim().split(/\s+/).filter(Boolean);
	return parts.length > 0 ? parts : ["openaudit"];
};

/**
 * The audit command: default auditors only (never `--only`, `--agentic` or
 * an opt-in), JSON and HTML written to `out`.
 */
export const auditArgs = (
	command: OpenauditCommand,
	target: string,
	out: string,
): string[] => [...command, target, "--format", "json,html", "--out", out];

/** `openaudit v0.2.1` → `0.2.1`. */
export const parseVersion = (stdout: string): string | undefined =>
	/v?(\d+\.\d+\.\d+[\w.+-]*)/.exec(stdout)?.[1];

export const openauditVersion = async (
	run: ProcessRunner,
	command: OpenauditCommand,
): Promise<string | undefined> => {
	const result = await run([...command, "--version"], {
		env: childEnv(),
		timeoutMs: VERSION_TIMEOUT_MS,
	});
	return result.code === 0 ? parseVersion(result.stdout) : undefined;
};

const readReports = async (out: string): Promise<ReportPair | undefined> => {
	try {
		const [json, html] = await Promise.all([
			readFile(join(out, "openaudit-report.json"), "utf8"),
			readFile(join(out, "openaudit-report.html"), "utf8"),
		]);
		return { json, html };
	} catch {
		return undefined;
	}
};

export interface AuditRun {
	readonly command: OpenauditCommand;
	/** A directory or an https URL. */
	readonly target: string;
	/** An empty directory for the reports. */
	readonly out: string;
	/** The working directory; never the cloned repository. */
	readonly cwd: string;
	readonly timeoutMs: number;
	/** `codebase` or `site`, for error messages. */
	readonly label: string;
}

/** Runs one audit and returns its reports. */
export const runAudit = async (
	run: ProcessRunner,
	audit: AuditRun,
): Promise<ReportPair> => {
	const result = await run(auditArgs(audit.command, audit.target, audit.out), {
		cwd: audit.cwd,
		env: childEnv(),
		timeoutMs: audit.timeoutMs,
	});
	if (result.timedOut)
		throw new ScanError(`openaudit ${audit.label} scan timed out`);
	const reports = REPORT_EXIT_CODES.has(result.code)
		? await readReports(audit.out)
		: undefined;
	if (!reports)
		throw new ScanError(
			`openaudit ${audit.label} scan failed (exit ${result.code}): ${lastLine(result.stderr)}`,
		);
	return reports;
};
