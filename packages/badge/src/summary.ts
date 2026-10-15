/**
 * Turns an openaudit JSON report (packages/core/src/model.ts) into the few
 * numbers a badge and its verification page show. Only the fields read here
 * are decoded, so newer reports with more fields still summarise.
 */
import { Option, Schema } from "effect";
import { Grade, type TargetSummary } from "./api";

/** The text of an openaudit JSON report. */
export type ReportJson = string;

const Count = Schema.Int.check(Schema.isGreaterThanOrEqualTo(0));
const Score = Schema.Number.check(
	Schema.isBetween({ minimum: 0, maximum: 100 }),
);

const ReportInput = Schema.Struct({
	schemaVersion: Schema.Literal("1"),
	tool: Schema.Struct({ version: Schema.String }),
	summary: Schema.Struct({
		score: Score,
		grade: Grade,
		counts: Schema.Struct({
			critical: Count,
			high: Count,
			medium: Count,
			low: Count,
			info: Count,
		}),
		categories: Schema.Array(
			Schema.Struct({ category: Schema.String, score: Score, grade: Grade }),
		),
		auditors: Schema.Struct({
			passed: Count,
			failed: Count,
			skipped: Count,
			error: Count,
		}),
	}),
	suppressed: Schema.optional(
		Schema.Array(
			Schema.Struct({
				source: Schema.String,
				rules: Count,
				paths: Count,
				fingerprints: Count,
				entries: Schema.optional(
					Schema.Array(
						Schema.Struct({
							kind: Schema.String,
							value: Schema.String,
							reason: Schema.optional(Schema.String),
							count: Count,
						}),
					),
				),
			}),
		),
	),
});
type ReportInput = typeof ReportInput.Type;
type Suppression = NonNullable<ReportInput["suppressed"]>[number];

const decode = Schema.decodeUnknownOption(Schema.fromJsonString(ReportInput));

/** A config file path, as opposed to a `--baseline` or `--diff` flag. */
const isConfigSource = (s: Suppression) =>
	!s.source.startsWith("--") && s.source !== ".gitignore";

const removed = (s: Suppression) => s.rules + s.paths + s.fingerprints;

/** Entries listed on the verification page, at most. */
const MAX_ENTRIES = 50;
/** Characters kept of an entry's value or reason. */
const MAX_TEXT = 300;

const cut = (text: string) => text.slice(0, MAX_TEXT);

const entriesOf = (config: ReadonlyArray<Suppression>) =>
	config
		.flatMap((s) => s.entries ?? [])
		.slice(0, MAX_ENTRIES)
		.map((e) => ({
			kind: cut(e.kind),
			value: cut(e.value),
			reason: e.reason === undefined ? null : cut(e.reason),
			count: e.count,
		}));

const toSummary = (report: ReportInput): TargetSummary => {
	const config = (report.suppressed ?? []).filter(isConfigSource);
	return {
		score: Math.round(report.summary.score),
		grade: report.summary.grade,
		severities: report.summary.counts,
		categories: report.summary.categories.map(({ category, score, grade }) => ({
			category,
			score: Math.round(score),
			grade,
		})),
		auditors: report.summary.auditors,
		suppressed: config.reduce((sum, s) => sum + removed(s), 0),
		hiddenBy: entriesOf(config),
		openauditVersion: report.tool.version,
	};
};

/** The report's summary, or undefined when it isn't an openaudit report. */
export const summarize = (json: ReportJson): TargetSummary | undefined =>
	Option.getOrUndefined(Option.map(decode(json), toSummary));
