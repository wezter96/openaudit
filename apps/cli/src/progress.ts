import {
	type AuditEvent,
	type AuditorResult,
	type AuditorStatus,
	sanitizeText,
} from "@openaudit/core";

const FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

const paint = (color: boolean, code: string, text: string) =>
	color ? `\x1b[${code}m${text}\x1b[0m` : text;

/** Colour code and mark per finished auditor's status. */
const MARKS: Record<AuditorStatus, readonly [string, string]> = {
	passed: ["32", "✓"],
	failed: ["31", "✗"],
	skipped: ["2", "–"],
	error: ["31", "!"],
};

const markOf = (color: boolean, status: AuditorStatus) => {
	const [code, text] = MARKS[status];
	return paint(color, code, text);
};

/** Skip reasons and errors can quote target content: strip escapes. */
const detailOf = (r: AuditorResult): string => {
	const raw = sanitizeText(
		r.status === "skipped" || r.status === "error"
			? `${r.status}${r.message ? `: ${r.message}` : ""}`
			: `${r.findings.length} finding${r.findings.length === 1 ? "" : "s"}`,
	);
	return raw.length > 100 ? `${raw.slice(0, 99)}…` : raw;
};

/**
 * Live progress on stderr: one permanent line per finished auditor plus a
 * spinner line listing what is still running. Never writes to stdout.
 */
export const createProgress = (options: {
	readonly color: boolean;
	readonly write?: (text: string) => void;
}) => {
	const write = options.write ?? ((t: string) => process.stderr.write(t));
	const c = options.color;
	const running = new Set<string>();
	let frame = 0;
	let done = 0;
	let timer: ReturnType<typeof setInterval> | undefined;

	const status = () => {
		if (!running.size) return;
		const names = sanitizeText([...running].slice(0, 3).join(", "));
		const more = running.size > 3 ? ` +${running.size - 3}` : "";
		write(
			`\r\x1b[K${paint(c, "36", FRAMES[frame++ % FRAMES.length] ?? "")} ${paint(c, "2", `[${done} done] ${names}${more}`)}`,
		);
	};

	const onEvent = (event: AuditEvent) => {
		switch (event.type) {
			case "target":
				write(
					`${paint(c, "2", sanitizeText(`Auditing ${event.target.input} (${event.target.kinds.join(", ")})`))}\n`,
				);
				timer ??= setInterval(status, 80);
				break;
			case "start":
				running.add(event.auditor.id);
				status();
				break;
			case "finish": {
				const r = event.result;
				running.delete(r.auditor);
				done++;
				const mark = markOf(c, r.status);
				const detail = detailOf(r);
				write(
					`\r\x1b[K${mark} ${sanitizeText(r.auditor)} ${paint(c, "2", `${detail} · ${r.durationMs}ms`)}\n`,
				);
				status();
				break;
			}
		}
	};

	const stop = () => {
		if (timer) clearInterval(timer);
		timer = undefined;
		write("\r\x1b[K");
	};

	return { onEvent, stop };
};
