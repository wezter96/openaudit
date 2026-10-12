import type { Grade, Report, Severity } from "../model";
import {
	formatDuration,
	formatLocation,
	plural,
	type SuppressionSummary,
	sanitizeText,
	sortedFindings,
	suppressedTotal,
	suppressionLine,
	targetLabel,
} from "./shared";

export interface TerminalOptions {
	/** ANSI colours. Defaults to on unless `NO_COLOR` is set. */
	readonly color?: boolean;
	/** List every finding with full detail instead of the top few. */
	readonly verbose?: boolean;
	/** Findings shown when not verbose. Defaults to 10. */
	readonly top?: number;
	/** Suppression counts to disclose (config ignores, baselines). */
	readonly suppressed?: ReadonlyArray<SuppressionSummary>;
}

const CODES = {
	reset: "\x1b[0m",
	bold: "\x1b[1m",
	dim: "\x1b[2m",
	red: "\x1b[31m",
	green: "\x1b[32m",
	yellow: "\x1b[33m",
	blue: "\x1b[34m",
	magenta: "\x1b[35m",
	cyan: "\x1b[36m",
	gray: "\x1b[90m",
	bgRed: "\x1b[41m\x1b[97m",
} as const;
type Style = keyof typeof CODES;

const SEVERITY_STYLE: Record<Severity, Style> = {
	critical: "bgRed",
	high: "red",
	medium: "yellow",
	low: "blue",
	info: "gray",
};

const GRADE_STYLE: Record<Grade, Style> = {
	A: "green",
	B: "green",
	C: "yellow",
	D: "red",
	F: "red",
};

const SEVERITY_TAG: Record<Severity, string> = {
	critical: "CRIT",
	high: "HIGH",
	medium: "MED ",
	low: "LOW ",
	info: "INFO",
};

/** Default colour choice: honours https://no-color.org. */
export const colorEnabled = (): boolean => {
	const env = typeof process === "undefined" ? undefined : process.env;
	return !env?.NO_COLOR;
};

export const toTerminal = (
	report: Report,
	options: TerminalOptions = {},
): string => {
	const color = options.color ?? colorEnabled();
	const paint = (style: Style, text: string) =>
		color ? `${CODES[style]}${text}${CODES.reset}` : text;
	// Every string from the report may come from a hostile repo or site.
	const t = (value: unknown) => sanitizeText(value);
	const block = (value: unknown) =>
		sanitizeText(value, { multiline: true }).replace(/\n/g, "\n     ");
	const { summary } = report;
	const out: string[] = [];

	out.push(
		`${paint("bold", "openaudit")} ${paint("dim", t(report.tool.version))}  ${t(targetLabel(report))} ${paint("dim", `(${t(report.target.kinds.join(", "))})`)}`,
	);
	out.push(
		`${paint("bold", "Score")} ${paint(GRADE_STYLE[summary.grade], `${summary.score}/100 ${summary.grade}`)}   ` +
			(["critical", "high", "medium", "low", "info"] as const)
				.map((s) =>
					summary.counts[s]
						? paint(SEVERITY_STYLE[s], `${summary.counts[s]} ${s}`)
						: paint("dim", `0 ${s}`),
				)
				.join(paint("dim", " · ")),
	);
	if (summary.categories.length) {
		out.push(
			summary.categories
				.map(
					(c) =>
						`${t(c.category)} ${paint(GRADE_STYLE[c.grade], `${c.score}${c.grade}`)}`,
				)
				.join(paint("dim", "  ")),
		);
	}

	const findings = sortedFindings(report);
	const listed = options.verbose
		? findings
		: findings.filter((f) => f.severity !== "info").slice(0, options.top ?? 10);

	if (listed.length) {
		out.push("");
		for (const f of listed) {
			const loc = t(formatLocation(f.location));
			out.push(
				`${paint(SEVERITY_STYLE[f.severity], SEVERITY_TAG[f.severity])} ${paint("bold", t(f.title))} ${paint("dim", t(f.ruleId))}`,
			);
			if (loc) out.push(`     ${paint("cyan", loc)}`);
			if (options.verbose) {
				out.push(`     ${block(f.message)}`);
				if (f.evidence) out.push(`     ${paint("dim", block(f.evidence))}`);
				if (f.remediation)
					out.push(`     ${paint("green", "fix:")} ${block(f.remediation)}`);
				out.push(`     ${paint("dim", `fingerprint ${t(f.fingerprint)}`)}`);
			}
		}
		const hidden = findings.length - listed.length;
		if (hidden > 0) {
			out.push(
				paint(
					"dim",
					`… ${plural(hidden, "more finding")} (use --verbose, or --format html/markdown/json)`,
				),
			);
		}
	} else if (!findings.length) {
		out.push("", paint("green", "No findings."));
	}

	const problems = report.results.filter(
		(r) => r.status === "error" || (options.verbose && r.status === "skipped"),
	);
	if (problems.length) {
		out.push("");
		for (const r of problems) {
			out.push(
				`${paint(r.status === "error" ? "red" : "gray", r.status === "error" ? "error" : "skip ")} ${t(r.auditor)}${r.message ? paint("dim", `: ${t(r.message)}`) : ""}`,
			);
		}
	}

	for (const s of options.suppressed ?? []) {
		if (suppressedTotal(s) > 0)
			out.push("", paint("yellow", t(suppressionLine(s))));
	}

	const a = summary.auditors;
	out.push(
		"",
		paint(
			"dim",
			`${plural(report.results.length, "auditor")}: ${a.passed} passed, ${a.failed} failed, ${a.skipped} skipped, ${a.error} errored in ${formatDuration(report.durationMs)}`,
		),
	);
	return `${out.join("\n")}\n`;
};
