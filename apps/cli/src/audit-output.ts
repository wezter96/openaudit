import { mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import {
	colorEnabled,
	FORMAT_EXTENSIONS,
	isAtLeast,
	type Report,
	type ReportFormat,
	renderReport,
	type SuppressionSummary,
	sanitizeText,
	suppressedTotal,
	suppressionLine,
} from "@openaudit/core";

import type { AuditFlags, AuditSettings } from "./audit-flags";

/**
 * 3 = `--fail-on` was set but an auditor errored or timed out, so the gate
 * could not be evaluated fully. Failing closed stops a target from passing CI
 * by crashing the auditor that would have flagged it.
 */
export const EXIT = { ok: 0, findings: 1, usage: 2, incomplete: 3 } as const;

export interface Io {
	readonly stdout: (text: string) => void;
	readonly stderr: (text: string) => void;
	readonly stderrIsTTY: boolean;
	readonly cwd: string;
}

/** A finished report with the suppressions it discloses. */
export interface AuditOutput {
	readonly report: Report;
	readonly suppressed: ReadonlyArray<SuppressionSummary>;
}

/** Everything the output steps of one audit need. */
export interface Finished extends AuditOutput {
	readonly flags: AuditFlags;
	readonly io: Io;
	readonly settings: AuditSettings;
}

const stdoutColor = (): boolean =>
	colorEnabled() && process.stdout.isTTY === true;

const printReport = (f: Finished, format: ReportFormat): void => {
	f.io.stdout(
		renderReport(f.report, format, {
			color: stdoutColor(),
			verbose: f.flags.verbose,
			suppressed: f.suppressed,
		}),
	);
};

/** One `openaudit-report.<ext>` per format in the `--out` directory. */
const writeFiles = async (f: Finished, out: string): Promise<void> => {
	const dir = resolve(f.io.cwd, out);
	await mkdir(dir, { recursive: true });
	for (const format of f.settings.formats) {
		const file = join(dir, `openaudit-report.${FORMAT_EXTENSIONS[format]}`);
		await Bun.write(
			file,
			renderReport(f.report, format, {
				color: false,
				verbose: true,
				suppressed: f.suppressed,
			}),
		);
		if (!f.flags.quiet && !f.flags.json) f.io.stderr(`Wrote ${file}\n`);
	}
};

/** Writes the report files and whatever belongs on stdout. */
export const writeOutput = async (f: Finished): Promise<void> => {
	const { flags } = f;
	if (!flags.out) {
		printReport(f, f.settings.formats[0] ?? "terminal");
		return;
	}
	await writeFiles(f, flags.out);
	if (flags.json) f.io.stdout(renderReport(f.report, "json"));
	else if (!flags.quiet) printReport(f, "terminal");
};

/** JSON and SARIF have no place for the suppression notice. */
const disclosedOnStdout = ({ flags, settings }: Finished): boolean => {
	if (flags.json) return false;
	if (flags.out) return !flags.quiet;
	return ["terminal", "markdown", "html"].includes(settings.formats[0] ?? "");
};

/** Suppressions the report on stdout cannot show go to stderr. */
export const discloseSuppressions = (f: Finished): void => {
	if (f.flags.quiet || disclosedOnStdout(f)) return;
	for (const s of f.suppressed)
		if (suppressedTotal(s) > 0)
			f.io.stderr(`openaudit: ${sanitizeText(suppressionLine(s))}\n`);
};

/** Explains the exit code on stderr, unless the output is for machines. */
const explain = ({ flags, io }: Finished, text: string): void => {
	if (!flags.json && !flags.quiet) io.stderr(text);
};

/** The exit code `--fail-on` asks for. */
export const exitCode = (f: Finished): number => {
	const { failOn } = f.settings;
	if (!failOn) return EXIT.ok;
	const breached = f.report.results
		.flatMap((r) => r.findings)
		.filter((x) => x.duplicateOf === undefined)
		.filter((x) => isAtLeast(x.severity, failOn));
	if (breached.length) {
		explain(
			f,
			`openaudit: ${breached.length} finding(s) at or above "${failOn}" (exit 1)\n`,
		);
		return EXIT.findings;
	}
	const errored = f.report.results.filter((r) => r.status === "error");
	if (errored.length && !f.flags.allowErrors) {
		explain(
			f,
			`openaudit: ${sanitizeText(errored.map((r) => r.auditor).join(", "))} errored, so --fail-on could not be fully checked (exit 3; --allow-errors to ignore)\n`,
		);
		return EXIT.incomplete;
	}
	return EXIT.ok;
};
