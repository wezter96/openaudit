import { MAX_ERROR_LENGTH } from "@openaudit/badge/api";

/** A failure with a message that is safe to publish on the verification page. */
export class ScanError extends Error {
	readonly _tag = "ScanError";
	constructor(message: string) {
		super(message);
		this.name = "ScanError";
	}
}

/**
 * The message to report: secrets replaced, whitespace collapsed and cut to
 * {@link MAX_ERROR_LENGTH}. Anything that is not a `ScanError` may carry
 * internals, so only its message is used, and still scrubbed.
 */
export const publicError = (
	cause: unknown,
	secrets: ReadonlyArray<string>,
): string => {
	let text = cause instanceof Error ? cause.message : String(cause);
	for (const secret of secrets)
		if (secret) text = text.split(secret).join("[redacted]");
	text = text.replace(/\s+/g, " ").trim() || "scan failed";
	return text.length > MAX_ERROR_LENGTH
		? `${text.slice(0, MAX_ERROR_LENGTH - 1)}…`
		: text;
};

/** The last line of a tool's stderr, for a short error message. */
export const lastLine = (stderr: string): string =>
	stderr.trim().split("\n").at(-1)?.trim() ?? "";
