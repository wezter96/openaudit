/** A claimed scan, as `POST /api/scanner/claim` returns it. */
export interface Job {
	/** The scan id. */
	readonly id: string;
	readonly projectId: string;
	/** `owner/name` on GitHub. */
	readonly repo: string;
	/** Only present when the site is verified. */
	readonly site?: string | undefined;
	/** The verification code the repo's `.openaudit-badge` must contain. */
	readonly code: string;
}

/** The JSON and HTML report of one openaudit run. */
export interface ReportPair {
	readonly json: string;
	readonly html: string;
}

/** The body of `POST /api/scanner/jobs/:id`. */
export interface JobResult {
	readonly status: "ok" | "failed";
	readonly error?: string;
	readonly commit?: string;
	readonly openauditVersion?: string;
	readonly codebase?: ReportPair;
	readonly site?: ReportPair;
}

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
