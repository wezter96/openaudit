import { publicError } from "./errors";
import { type JobDeps, runJob, runQuickJob } from "./job";
import type { ScannerClient } from "./types";

/** Short, so a quick audit someone is waiting for starts soon. */
export const IDLE_DELAY_MS = 15_000;
const BACKOFF_BASE_MS = 60_000;
const MAX_BACKOFF_MS = 15 * 60_000;

export interface LoopDeps extends JobDeps {
	readonly client: ScannerClient;
	readonly sleep?: (ms: number) => Promise<void>;
	readonly log?: (line: string) => void;
}

/** The wait after `failures` API errors in a row: 1, 2, 4 ... minutes, capped. */
export const backoffMs = (failures: number): number =>
	Math.min(BACKOFF_BASE_MS * 2 ** Math.max(0, failures - 1), MAX_BACKOFF_MS);

/** Runs one queued quick audit, if there is one. */
const quickTick = async (deps: LoopDeps): Promise<boolean> => {
	const job = await deps.client.claimQuick();
	if (!job) return false;
	const log = deps.log ?? console.log;
	log(`quick ${job.id}: ${job.site}`);
	const result = await runQuickJob(job, deps);
	log(
		`quick ${job.id}: ${result.status}${result.error ? ` (${result.error})` : ""}`,
	);
	await deps.client.reportQuick(job.id, result);
	return true;
};

/**
 * Claims one job, runs it and reports it: a quick audit first, since someone
 * is waiting for it, else a badge scan. Returns whether there was a job, so
 * the loop knows to ask again right away.
 */
export const tick = async (deps: LoopDeps): Promise<boolean> => {
	if (await quickTick(deps)) return true;
	const job = await deps.client.claim();
	if (!job) return false;
	const log = deps.log ?? console.log;
	log(`scan ${job.id}: ${job.repo}${job.site ? ` + ${job.site}` : ""}`);
	const result = await runJob(job, deps);
	log(
		`scan ${job.id}: ${result.status}${result.error ? ` (${result.error})` : ""}`,
	);
	await deps.client.report(job.id, result);
	return true;
};

/** What to wait before the next tick, and the new count of failures in a row. */
const afterTick = async (
	deps: LoopDeps,
	failures: number,
): Promise<{ delay: number; failures: number }> => {
	try {
		return { delay: (await tick(deps)) ? 0 : IDLE_DELAY_MS, failures: 0 };
	} catch (cause) {
		const log = deps.log ?? console.error;
		log(`scanner API error: ${publicError(cause, deps.secrets ?? [])}`);
		return { delay: backoffMs(failures + 1), failures: failures + 1 };
	}
};

/** One job at a time, forever (or until `signal` aborts). */
export const runLoop = async (
	deps: LoopDeps,
	signal?: AbortSignal,
): Promise<void> => {
	const sleep = deps.sleep ?? Bun.sleep;
	let failures = 0;
	while (!signal?.aborted) {
		const next = await afterTick(deps, failures);
		failures = next.failures;
		if (next.delay > 0 && !signal?.aborted) await sleep(next.delay);
	}
};
