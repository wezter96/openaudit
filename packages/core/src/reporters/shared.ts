import type { Finding, Location, Report, Severity } from "../model";
import { severityRank } from "../model";

/** All findings in a report, most severe first, then by rule id and location. */
export const sortedFindings = (report: Report): Finding[] =>
	report.results
		.flatMap((r) => r.findings)
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
export const targetLabel = (report: Report): string =>
	report.target.url ??
	(report.target.image ? `image:${report.target.image}` : undefined) ??
	report.target.input;

export const SEVERITY_LABEL: Record<Severity, string> = {
	critical: "Critical",
	high: "High",
	medium: "Medium",
	low: "Low",
	info: "Info",
};

export const escapeHtml = (value: unknown): string =>
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
