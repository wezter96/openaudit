import type { AuditorResult, Finding, Grade, Report, Severity } from "../model";
import {
	formatDuration,
	formatLocation,
	hasSuppressionNotice,
	plural,
	type SuppressionSummary,
	sanitizeText,
	sortedFindings,
	suppressionDetails,
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

type Paint = (style: Style, text: string) => string;

const painter =
	(color: boolean): Paint =>
	(style, text) =>
		color ? `${CODES[style]}${text}${CODES.reset}` : text;

// Every string from the report may come from a hostile repo or site.
const t = (value: unknown) => sanitizeText(value);
const block = (value: unknown) =>
	sanitizeText(value, { multiline: true }).replace(/\n/g, "\n     ");

export const toTerminal = (
	report: Report,
	options: TerminalOptions = {},
): string => {
	const paint = painter(options.color ?? colorEnabled());
	const out = [
		...headerLines(report, paint),
		...findingsLines(report, options, paint),
		...problemLines(report, options, paint),
		...suppressedLines(options.suppressed ?? [], paint),
		"",
		footerLine(report, paint),
	];
	return `${out.join("\n")}\n`;
};

const headerLines = (report: Report, paint: Paint): string[] => {
	const { summary } = report;
	const lines = [
		`${paint("bold", "openaudit")} ${paint("dim", t(report.tool.version))}  ${t(targetLabel(report))} ${paint("dim", `(${t(report.target.kinds.join(", "))})`)}`,
		`${paint("bold", "Score")} ${paint(GRADE_STYLE[summary.grade], `${summary.score}/100 ${summary.grade}`)}   ` +
			(["critical", "high", "medium", "low", "info"] as const)
				.map((s) =>
					summary.counts[s]
						? paint(SEVERITY_STYLE[s], `${summary.counts[s]} ${s}`)
						: paint("dim", `0 ${s}`),
				)
				.join(paint("dim", " · ")),
	];
	if (summary.categories.length) {
		lines.push(
			summary.categories
				.map(
					(c) =>
						`${t(c.category)} ${paint(GRADE_STYLE[c.grade], `${c.score}${c.grade}`)}`,
				)
				.join(paint("dim", "  ")),
		);
	}
	return lines;
};

const findingsLines = (
	report: Report,
	options: TerminalOptions,
	paint: Paint,
): string[] => {
	const findings = sortedFindings(report);
	const listed = options.verbose
		? findings
		: findings.filter((f) => f.severity !== "info").slice(0, options.top ?? 10);
	if (!listed.length)
		return findings.length ? [] : ["", paint("green", "No findings.")];
	const hidden = findings.length - listed.length;
	return [
		"",
		...listed.flatMap((f) => findingEntry(f, options, paint)),
		...(hidden > 0
			? [
					paint(
						"dim",
						`… ${plural(hidden, "more finding")} (use --verbose, or --format html/markdown/json)`,
					),
				]
			: []),
	];
};

const findingEntry = (
	f: Finding,
	options: TerminalOptions,
	paint: Paint,
): string[] => {
	const loc = t(formatLocation(f.location));
	return [
		`${paint(SEVERITY_STYLE[f.severity], SEVERITY_TAG[f.severity])} ${paint("bold", t(f.title))} ${paint("dim", t(f.ruleId))}`,
		...(loc ? [`     ${paint("cyan", loc)}`] : []),
		...(options.verbose ? findingDetail(f, paint) : []),
	];
};

const findingDetail = (f: Finding, paint: Paint): string[] => {
	const lines = [`     ${block(f.message)}`];
	if (f.evidence) lines.push(`     ${paint("dim", block(f.evidence))}`);
	if (f.remediation)
		lines.push(`     ${paint("green", "fix:")} ${block(f.remediation)}`);
	if (f.alsoReportedBy?.length)
		lines.push(
			`     ${paint("dim", `also reported by ${t(f.alsoReportedBy.join(", "))}`)}`,
		);
	lines.push(`     ${paint("dim", `fingerprint ${t(f.fingerprint)}`)}`);
	return lines;
};

/** Errored auditors, plus skipped ones when verbose. */
const isProblem = (r: AuditorResult, options: TerminalOptions): boolean =>
	r.status === "error" || (r.status === "skipped" && options.verbose === true);

const problemLines = (
	report: Report,
	options: TerminalOptions,
	paint: Paint,
): string[] => {
	const problems = report.results.filter((r) => isProblem(r, options));
	if (!problems.length) return [];
	return [
		"",
		...problems.map((r) => {
			const error = r.status === "error";
			return `${paint(error ? "red" : "gray", error ? "error" : "skip ")} ${t(r.auditor)}${r.message ? paint("dim", `: ${t(r.message)}`) : ""}`;
		}),
	];
};

const suppressedLines = (
	suppressed: ReadonlyArray<SuppressionSummary>,
	paint: Paint,
): string[] =>
	suppressed
		.filter(hasSuppressionNotice)
		.flatMap((s) => [
			"",
			paint("yellow", t(suppressionLine(s))),
			...suppressionDetails(s).map((d) => paint("dim", `  ${t(d)}`)),
		]);

const footerLine = (report: Report, paint: Paint): string => {
	const a = report.summary.auditors;
	return paint(
		"dim",
		`${plural(report.results.length, "auditor")}: ${a.passed} passed, ${a.failed} failed, ${a.skipped} skipped, ${a.error} errored in ${formatDuration(report.durationMs)}`,
	);
};
