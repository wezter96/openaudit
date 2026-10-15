import type { Job, JobReport, ReportFiles } from "@openaudit/badge/api";

/** A claimed scan, as `POST /api/scanner/claim` returns it. */
export type { Job };
/** The body of `POST /api/scanner/jobs/:id`. */
export type JobResult = JobReport;
/** The JSON and HTML report of one openaudit run. */
export type ReportPair = ReportFiles;

/** The scanner half of the badge API. */
export interface ScannerClient {
	readonly claim: () => Promise<Job | null>;
	readonly report: (scanId: string, result: JobResult) => Promise<void>;
}

export interface RunOptions {
	readonly cwd?: string;
	readonly env?: Record<string, string | undefined>;
	readonly timeoutMs: number;
}

export interface RunResult {
	readonly code: number;
	readonly stdout: string;
	readonly stderr: string;
	readonly timedOut: boolean;
}

/** Runs a command to completion. Injectable so tests never spawn anything. */
export type ProcessRunner = (
	cmd: ReadonlyArray<string>,
	options: RunOptions,
) => Promise<RunResult>;
