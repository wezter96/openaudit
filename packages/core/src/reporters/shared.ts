import type { Finding, Location, Report, Severity } from "../model";
import { severityRank } from "../model";

/**
 * All findings in a report, most severe first, then by rule id and location.
 * Duplicates of another auditor's finding are left out.
 */
export const sortedFindings = (report: Report): Finding[] =>
	report.results
		.flatMap((r) => r.findings)
		.filter((f) => f.duplicateOf === undefined)
		.sort(
			(a, b) =>
				severityRank(a.severity) - severityRank(b.severity) ||
				a.ruleId.localeCompare(b.ruleId) ||
				formatLocation(a.location).localeCompare(formatLocation(b.location)),
		);

/** `src/a.ts:12:3`, a URL (+ selector), or an empty string. */
export const formatLocation = (loc: Location | undefined): string => {
	if (!loc) return "";
	const parts: string[] = [];
	if (loc.file) {
		let file = loc.file;
		if (loc.line !== undefined) file += `:${loc.line}`;
		if (loc.line !== undefined && loc.column !== undefined)
			file += `:${loc.column}`;
		parts.push(file);
	}
	if (loc.url) parts.push(loc.url);
	if (loc.selector) parts.push(loc.selector);
	return parts.join(" ");
};

/** Human label of the audit target. */
/** Last segment of a local path: `/home/me/repos/shop/` → `shop`. */
export const baseName = (path: string): string =>
	path
		.replace(/[\\/]+$/, "")
		.split(/[\\/]/)
		.pop() || path;

/**
 * What a report is about, as shown to people: the URL, `image:<ref>`,
 * `cloud:<provider>`, or the folder or file name. Local paths are reduced to
 * their last segment so shared reports don't reveal the auditor's machine.
 */
export const targetLabel = (report: Report): string => {
	const t = report.target;
	if (t.url) return t.url;
	if (t.image) return `image:${t.image}`;
	if (t.cloud) return `cloud:${t.cloud}`;
	return baseName(t.root ?? t.file ?? t.input);
};

export const SEVERITY_LABEL: Record<Severity, string> = {
	critical: "Critical",
	high: "High",
	medium: "Medium",
	low: "Low",
	info: "Info",
};

export const escapeHtml = (value: unknown): string =>
	// Escapes all five HTML-significant characters, "&" first.
	// nosemgrep: javascript.audit.detect-replaceall-sanitization.detect-replaceall-sanitization
	String(value)
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#39;");

/** Only http(s) links are ever rendered as links. */
export const isWebUrl = (value: string): boolean =>
	/^https?:\/\/[^\s]+$/i.test(value);

export const plural = (n: number, word: string): string =>
	`${n} ${word}${n === 1 ? "" : "s"}`;

export const formatDuration = (ms: number): string =>
	ms < 1000
		? `${Math.round(ms)}ms`
		: ms < 60_000
			? `${(ms / 1000).toFixed(1)}s`
			: `${Math.floor(ms / 60_000)}m${Math.round((ms % 60_000) / 1000)}s`;

/** ESC-introduced sequences: CSI, OSC/DCS/APC/PM/SOS strings, and two-byte escapes. */
const ESCAPE_SEQUENCE =
	// biome-ignore lint/suspicious/noControlCharactersInRegex: matching control characters is the point
	/\x1b(?:\[[0-?]*[ -/]*[@-~]|[\]PX^_][\s\S]*?(?:\x07|\x1b\\|$)|[@-Z\\-_]|[ -/]*[0-~]?)/g;
/** 8-bit CSI sequences and C1 string introducers (OSC, DCS, ...) with their payload. */
const C1_STRING =
	// biome-ignore lint/suspicious/noControlCharactersInRegex: matching control characters is the point
	/\x9b[0-?]*[ -/]*[@-~]|[\x90\x98\x9d\x9e\x9f][\s\S]*?(?:\x07|\x9c|$)/g;
/** C0 (except tab/newline), DEL, C1, and bidi overrides that can disguise text. */
const CONTROL =
	// biome-ignore lint/suspicious/noControlCharactersInRegex: matching control characters is the point
	/[\x00-\x08\x0b-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;

/**
 * Makes untrusted text (from audited repos and sites) safe to print: removes
 * terminal escape sequences (colours, cursor moves, OSC 8 links, OSC 52
 * clipboard writes), control characters and bidi overrides. Newlines become
 * spaces unless `multiline` is set; tabs always become spaces.
 */
export const sanitizeText = (
	value: unknown,
	options: { readonly multiline?: boolean } = {},
): string => {
	const text = String(value)
		.replace(ESCAPE_SEQUENCE, "")
		.replace(C1_STRING, "")
		.replace(/\r\n?/g, "\n")
		.replace(/\t/g, " ")
		.replace(CONTROL, "");
	return options.multiline ? text : text.replace(/\n+/g, " ");
};

/** How many findings one suppression source removed from a report. */
export interface SuppressionSummary {
	/** Where the suppression came from, e.g. a config path or `--baseline report.json`. */
	readonly source: string;
	readonly rules: number;
	readonly paths: number;
	readonly fingerprints: number;
}

export const suppressedTotal = (s: SuppressionSummary): number =>
	s.rules + s.paths + s.fingerprints;

/** "12 findings suppressed by ./openaudit.config.json (10 by rule, 2 by path)". */
export const suppressionLine = (s: SuppressionSummary): string => {
	const parts = (
		[
			["rule", s.rules],
			["path", s.paths],
			["fingerprint", s.fingerprints],
		] as const
	)
		.filter(([, n]) => n > 0)
		.map(([k, n]) => `${n} by ${k}`);
	return `${plural(suppressedTotal(s), "finding")} suppressed by ${s.source} (${parts.join(", ")})`;
};

/**
 * JSON that is safe inside `<script type="application/json">`: `<`, `>` and
 * `&` cannot close the element or open a comment, and U+2028/U+2029 are
 * escaped for older parsers that treat them as line terminators.
 */
export const scriptSafeJson = (value: unknown): string =>
	JSON.stringify(value)
		.replaceAll("<", "\\u003c")
		.replaceAll(">", "\\u003e")
		.replaceAll("&", "\\u0026")
		.replaceAll("\u2028", "\\u2028")
		.replaceAll("\u2029", "\\u2029");
