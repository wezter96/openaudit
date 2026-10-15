import { lstat, readFile } from "node:fs/promises";
import { join } from "node:path";

import { lastLine, ScanError } from "./errors";
import type { Exec, ReportPair } from "./types";

export const CODEBASE_TIMEOUT_MS = 15 * 60_000;
export const SITE_TIMEOUT_MS = 10 * 60_000;
const VERSION_TIMEOUT_MS = 30_000;
/** A report file bigger than this cannot be uploaded anyway. */
const MAX_REPORT_FILE_BYTES = 25 * 1024 * 1024;

/** openaudit exits 0 (clean), 1 (findings) or 3 (some auditors failed) with a report. */
const REPORT_EXIT_CODES: ReadonlySet<number> = new Set([0, 1, 3]);

/** How to start openaudit, e.g. `["openaudit"]` or `["bun", "apps/cli/src/bin.ts"]`. */
export type OpenauditCommand = ReadonlyArray<string>;

/** Splits `OPENAUDIT_BIN` on whitespace, so a dev setup can use `bun path/bin.ts`. */
export const parseCommand = (bin: string | undefined): OpenauditCommand => {
	const parts = (bin ?? "").trim().split(/\s+/).filter(Boolean);
	return parts.length > 0 ? parts : ["openaudit"];
};

const isUrlTarget = (target: string) => target.startsWith("https://");

/**
 * The audit command: default auditors only (never `--only`, `--agentic`,
 * `--config` or an opt-in), JSON and HTML written to `out`. A codebase scan
 * lets openaudit read the repo's own config, which can only narrow the run
 * and whose suppressions the report discloses; a site scan reads none.
 */
export const auditArgs = (
	command: OpenauditCommand,
	target: string,
	out: string,
): string[] => [
	...command,
	target,
	"--format",
	"json,html",
	"--out",
	out,
	...(isUrlTarget(target) ? ["--no-config"] : []),
];

/** `openaudit v0.2.1` → `0.2.1`. */
export const parseVersion = (stdout: string): string | undefined =>
	/v?(\d+\.\d+\.\d+[\w.+-]*)/.exec(stdout)?.[1];

export const openauditVersion = async (
	exec: Exec,
	command: OpenauditCommand,
): Promise<string | undefined> => {
	const result = await exec.run([...command, "--version"], {
		env: exec.env,
		timeoutMs: VERSION_TIMEOUT_MS,
	});
	return result.code === 0 ? parseVersion(result.stdout) : undefined;
};

/** A report file openaudit wrote into our out dir: a plain file, never a link. */
const readReportFile = async (path: string): Promise<string | undefined> => {
	const stat = await lstat(path).catch(() => undefined);
	if (!stat?.isFile() || stat.size > MAX_REPORT_FILE_BYTES) return undefined;
	return readFile(path, "utf8");
};

const parseJson = (text: string): unknown => {
	try {
		return JSON.parse(text);
	} catch {
		return undefined;
	}
};

/**
 * Whether `json` is an openaudit report of exactly `target`, so a report
 * from anywhere else (or for another target) is never published.
 */
export const isReportOf = (json: string, target: string): boolean => {
	const report = parseJson(json) as
		| {
				tool?: { name?: unknown };
				target?: { input?: unknown; type?: unknown };
		  }
		| undefined;
	const type = isUrlTarget(target) ? "url" : "directory";
	return (
		report?.tool?.name === "openaudit" &&
		report.target?.input === target &&
		report.target.type === type
	);
};

const readReports = async (
	out: string,
	target: string,
): Promise<ReportPair | undefined> => {
	const json = await readReportFile(join(out, "openaudit-report.json"));
	const html = await readReportFile(join(out, "openaudit-report.html"));
	if (json === undefined || html === undefined) return undefined;
	if (!isReportOf(json, target))
		throw new ScanError(
			"openaudit wrote an invalid report or one for another target",
		);
	return { json, html };
};

export interface AuditRun {
	readonly command: OpenauditCommand;
	/** A directory or an https URL. */
	readonly target: string;
	/** An empty directory for the reports, outside the clone. */
	readonly out: string;
	/** The working directory; never the cloned repository. */
	readonly cwd: string;
	readonly timeoutMs: number;
	/** `codebase` or `site`, for error messages. */
	readonly label: string;
}

/** Runs one audit and returns its reports, read only from `audit.out`. */
export const runAudit = async (
	exec: Exec,
	audit: AuditRun,
): Promise<ReportPair> => {
	const result = await exec.run(
		auditArgs(audit.command, audit.target, audit.out),
		{ cwd: audit.cwd, env: exec.env, timeoutMs: audit.timeoutMs },
	);
	if (result.timedOut)
		throw new ScanError(`openaudit ${audit.label} scan timed out`);
	const reports = REPORT_EXIT_CODES.has(result.code)
		? await readReports(audit.out, audit.target)
		: undefined;
	if (!reports)
		throw new ScanError(
			`openaudit ${audit.label} scan failed (exit ${result.code}): ${lastLine(result.stderr)}`,
		);
	return reports;
};
