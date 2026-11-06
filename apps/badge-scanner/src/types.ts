import type {
	Job,
	JobReport,
	QuickJob,
	QuickReport,
	ReportFiles,
} from "@openaudit/badge/api";

/** A claimed scan, as `POST /api/scanner/claim` returns it. */
export type { Job, QuickJob, QuickReport };
/** The body of `POST /api/scanner/jobs/:id`. */
export type JobResult = JobReport;
/** The JSON and HTML report of one openaudit run. */
export type ReportPair = ReportFiles;

/** The scanner half of the badge API. */
export interface ScannerClient {
	readonly claim: () => Promise<Job | null>;
	readonly report: (scanId: string, result: JobResult) => Promise<void>;
	/** The oldest queued quick audit of a public site, or null. */
	readonly claimQuick: () => Promise<QuickJob | null>;
	readonly reportQuick: (id: string, result: QuickReport) => Promise<void>;
}

/** A child process environment: built by `childEnv`, never `process.env`. */
export type ChildEnv = Readonly<Record<string, string>>;

export interface RunOptions {
	readonly cwd?: string;
	readonly env: ChildEnv;
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

/** How one job runs commands: the runner and the job's minimal environment. */
export interface Exec {
	readonly run: ProcessRunner;
	readonly env: ChildEnv;
}
