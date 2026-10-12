import type { AuditEvent } from "@openaudit/core";

const FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

const paint = (color: boolean, code: string, text: string) =>
	color ? `\x1b[${code}m${text}\x1b[0m` : text;

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
		const names = [...running].slice(0, 3).join(", ");
		const more = running.size > 3 ? ` +${running.size - 3}` : "";
		write(
			`\r\x1b[K${paint(c, "36", FRAMES[frame++ % FRAMES.length] ?? "")} ${paint(c, "2", `[${done} done] ${names}${more}`)}`,
		);
	};

	const onEvent = (event: AuditEvent) => {
		switch (event.type) {
			case "target":
				write(
					`${paint(c, "2", `Auditing ${event.target.input} (${event.target.kinds.join(", ")})`)}\n`,
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
				const mark =
					r.status === "passed"
						? paint(c, "32", "✓")
						: r.status === "failed"
							? paint(c, "31", "✗")
							: r.status === "skipped"
								? paint(c, "2", "–")
								: paint(c, "31", "!");
				const raw =
					r.status === "skipped" || r.status === "error"
						? `${r.status}${r.message ? `: ${r.message}` : ""}`
						: `${r.findings.length} finding${r.findings.length === 1 ? "" : "s"}`;
				const detail = raw.length > 100 ? `${raw.slice(0, 99)}…` : raw;
				write(
					`\r\x1b[K${mark} ${r.auditor} ${paint(c, "2", `${detail} · ${r.durationMs}ms`)}\n`,
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
