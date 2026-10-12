import type { Report } from "../model";

export interface JsonOptions {
	/** Indentation; 0 produces a single line. Defaults to 2. */
	readonly indent?: number;
}

/**
 * Keys that lead their object, in this order, so humans and agents see the
 * important fields first. Every other key follows alphabetically, which makes
 * the output byte-stable regardless of how the report was assembled.
 */
const KEY_ORDER = [
	"schemaVersion",
	"tool",
	"target",
	"startedAt",
	"finishedAt",
	"durationMs",
	"summary",
	"ai",
	"results",
	// findings lead with their rule, auditor results with their auditor
	"ruleId",
	"auditor",
	"title",
	"engine",
	"categories",
	"status",
	"message",
	"severity",
	"category",
	"location",
	"evidence",
	"remediation",
	"references",
	"confidence",
	"tags",
	"fingerprint",
	// summaries
	"score",
	"grade",
	"counts",
	"critical",
	"high",
	"medium",
	"low",
	"info",
	// targets and locations
	"input",
	"type",
	"kinds",
	"root",
	"url",
	"file",
	"image",
	"line",
	"column",
	"selector",
	"name",
	"version",
];
const RANK = new Map(KEY_ORDER.map((k, i) => [k, i]));

const compareKeys = (a: string, b: string): number => {
	const ra = RANK.get(a) ?? Number.POSITIVE_INFINITY;
	const rb = RANK.get(b) ?? Number.POSITIVE_INFINITY;
	if (ra !== rb) return ra - rb;
	return a < b ? -1 : a > b ? 1 : 0;
};

/** Deep copy with object keys in canonical order and `undefined` dropped. */
export const canonicalize = (value: unknown): unknown => {
	if (Array.isArray(value)) return value.map(canonicalize);
	if (value && typeof value === "object") {
		const out: Record<string, unknown> = {};
		for (const key of Object.keys(value).sort(compareKeys)) {
			const v = (value as Record<string, unknown>)[key];
			if (v !== undefined) out[key] = canonicalize(v);
		}
		return out;
	}
	return value;
};

export const toJson = (report: Report, options: JsonOptions = {}): string =>
	`${JSON.stringify(canonicalize(report), null, options.indent ?? 2)}\n`;
