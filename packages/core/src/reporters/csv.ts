import type { Finding, Report } from "../model";
import { sanitizeText, sortedFindings } from "./shared";

/** Columns of the findings CSV, in order. */
export const CSV_COLUMNS = [
	"severity",
	"category",
	"title",
	"ruleId",
	"auditor",
	"file",
	"line",
	"url",
	"selector",
	"message",
	"remediation",
	"confidence",
	"alsoReportedBy",
	"fingerprint",
] as const;

/**
 * One RFC 4180 cell. Cells a spreadsheet would read as a formula (leading
 * `=`, `+`, `-`, `@`, tab or CR) get a `'` prefix, since findings quote
 * untrusted code and pages.
 */
export const csvCell = (value: unknown): string => {
	let text =
		value === undefined || value === null
			? ""
			: sanitizeText(value, { multiline: true });
	if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
	return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
};

const row = (f: Finding): ReadonlyArray<unknown> => [
	f.severity,
	f.category,
	f.title,
	f.ruleId,
	f.auditor,
	f.location?.file,
	f.location?.line,
	f.location?.url,
	f.location?.selector,
	f.message,
	f.remediation,
	f.confidence,
	f.alsoReportedBy?.join(" "),
	f.fingerprint,
];

/** Findings as CSV: a header, then one row per non-duplicate finding, most severe first. */
export const toCsv = (report: Report): string =>
	[
		CSV_COLUMNS.join(","),
		...sortedFindings(report)
			.filter((f) => f.duplicateOf === undefined)
			.map((f) => row(f).map(csvCell).join(",")),
	]
		.map((line) => `${line}\r\n`)
		.join("");
