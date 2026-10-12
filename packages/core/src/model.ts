import { Schema } from "effect";

/**
 * The report model is the public contract of openaudit. CLI output, the MCP
 * server, the HTTP API and agents all exchange these shapes, so changes here
 * must stay backwards compatible within a `schemaVersion`.
 */

export const SCHEMA_VERSION = "1" as const;

export const Severity = Schema.Literals([
	"critical",
	"high",
	"medium",
	"low",
	"info",
]);
export type Severity = typeof Severity.Type;

export const SEVERITIES: ReadonlyArray<Severity> = [
	"critical",
	"high",
	"medium",
	"low",
	"info",
];

export const severityRank = (s: Severity): number => SEVERITIES.indexOf(s);

/** True when `s` is at least as severe as `threshold`. */
export const isAtLeast = (s: Severity, threshold: Severity): boolean =>
	severityRank(s) <= severityRank(threshold);

export const Category = Schema.Literals([
	"security",
	"accessibility",
	"performance",
	"seo",
	"privacy",
	"best-practices",
	"reliability",
	"maintainability",
	"supply-chain",
	"compliance",
]);
export type Category = typeof Category.Type;

export const CATEGORIES: ReadonlyArray<Category> = [
	"security",
	"accessibility",
	"performance",
	"seo",
	"privacy",
	"best-practices",
	"reliability",
	"maintainability",
	"supply-chain",
	"compliance",
];

export const TargetKind = Schema.Literals([
	"codebase",
	"url",
	"webapp",
	"container",
	"iac",
	"mobile",
]);
export type TargetKind = typeof TargetKind.Type;

export const Confidence = Schema.Literals(["high", "medium", "low"]);
export type Confidence = typeof Confidence.Type;

export const Location = Schema.Struct({
	file: Schema.optional(Schema.String),
	line: Schema.optional(Schema.Number),
	column: Schema.optional(Schema.Number),
	url: Schema.optional(Schema.String),
	selector: Schema.optional(Schema.String),
});
export type Location = typeof Location.Type;

export const Finding = Schema.Struct({
	/** Stable rule identifier, e.g. `web.headers/csp-missing`. */
	ruleId: Schema.String,
	title: Schema.String,
	severity: Severity,
	category: Category,
	message: Schema.String,
	location: Schema.optional(Location),
	/** Short, already-redacted snippet that shows the problem. */
	evidence: Schema.optional(Schema.String),
	remediation: Schema.optional(Schema.String),
	references: Schema.optional(Schema.Array(Schema.String)),
	confidence: Schema.optional(Confidence),
	/** Free-form tags such as `cwe-79`, `owasp-a05`, `wcag-1.1.1`. */
	tags: Schema.optional(Schema.Array(Schema.String)),
	/** Id of the auditor that produced the finding (set by the engine). */
	auditor: Schema.String,
	/** Stable hash of rule + location + evidence, for baselines and dedupe. */
	fingerprint: Schema.String,
});
export type Finding = typeof Finding.Type;

/** What an auditor returns; the engine fills in `auditor` and `fingerprint`. */
export type FindingInput = Omit<Finding, "auditor" | "fingerprint"> & {
	readonly fingerprint?: string;
};

export const AuditorStatus = Schema.Literals([
	"passed",
	"failed",
	"skipped",
	"error",
]);
export type AuditorStatus = typeof AuditorStatus.Type;

export const AuditorEngine = Schema.Literals([
	"builtin",
	"external",
	"agentic",
]);
export type AuditorEngine = typeof AuditorEngine.Type;

export const AuditorResult = Schema.Struct({
	auditor: Schema.String,
	title: Schema.String,
	engine: AuditorEngine,
	categories: Schema.Array(Category),
	status: AuditorStatus,
	/** Why the auditor was skipped or errored. */
	message: Schema.optional(Schema.String),
	durationMs: Schema.Number,
	findings: Schema.Array(Finding),
});
export type AuditorResult = typeof AuditorResult.Type;

export const SeverityCounts = Schema.Struct({
	critical: Schema.Number,
	high: Schema.Number,
	medium: Schema.Number,
	low: Schema.Number,
	info: Schema.Number,
});
export type SeverityCounts = typeof SeverityCounts.Type;

export const Grade = Schema.Literals(["A", "B", "C", "D", "F"]);
export type Grade = typeof Grade.Type;

export const CategorySummary = Schema.Struct({
	category: Category,
	score: Schema.Number,
	grade: Grade,
	counts: SeverityCounts,
});
export type CategorySummary = typeof CategorySummary.Type;

export const Summary = Schema.Struct({
	score: Schema.Number,
	grade: Grade,
	counts: SeverityCounts,
	categories: Schema.Array(CategorySummary),
	auditors: Schema.Struct({
		passed: Schema.Number,
		failed: Schema.Number,
		skipped: Schema.Number,
		error: Schema.Number,
	}),
});
export type Summary = typeof Summary.Type;

export const TargetInfo = Schema.Struct({
	input: Schema.String,
	type: Schema.Literals(["directory", "file", "url", "image"]),
	kinds: Schema.Array(TargetKind),
	root: Schema.optional(Schema.String),
	url: Schema.optional(Schema.String),
	file: Schema.optional(Schema.String),
	image: Schema.optional(Schema.String),
	/** Detected technologies, e.g. `node`, `python`, `react`, `terraform`. */
	technologies: Schema.Array(Schema.String),
});
export type TargetInfo = typeof TargetInfo.Type;

export const AiInsights = Schema.Struct({
	model: Schema.String,
	summary: Schema.String,
	priorities: Schema.Array(
		Schema.Struct({
			title: Schema.String,
			why: Schema.String,
			fix: Schema.String,
			fingerprints: Schema.Array(Schema.String),
		}),
	),
});
export type AiInsights = typeof AiInsights.Type;

export const Report = Schema.Struct({
	schemaVersion: Schema.Literal(SCHEMA_VERSION),
	tool: Schema.Struct({ name: Schema.String, version: Schema.String }),
	target: TargetInfo,
	startedAt: Schema.String,
	finishedAt: Schema.String,
	durationMs: Schema.Number,
	summary: Summary,
	results: Schema.Array(AuditorResult),
	ai: Schema.optional(AiInsights),
});
export type Report = typeof Report.Type;
