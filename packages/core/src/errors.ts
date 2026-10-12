import { Data } from "effect";

/** An auditor failed unexpectedly. Reported as status `error`. */
export class AuditorError extends Data.TaggedError("AuditorError")<{
	readonly message: string;
	readonly cause?: unknown;
}> {}

/**
 * An auditor cannot run in this environment (missing tool, offline, no API
 * key, irrelevant target). Reported as status `skipped` with the reason.
 */
export class SkipAudit extends Data.TaggedError("SkipAudit")<{
	readonly reason: string;
}> {}

/** The audit target could not be resolved. */
export class TargetError extends Data.TaggedError("TargetError")<{
	readonly message: string;
}> {}
