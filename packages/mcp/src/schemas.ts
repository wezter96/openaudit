import { CATEGORIES, SEVERITIES, type TargetKind } from "@openaudit/core";
import { z } from "zod";

/*
 * Zod mirrors of the core report model (packages/core/src/model.ts). MCP
 * clients see these as tool input/output JSON Schemas; a test keeps them in
 * sync with the Effect schema by validating real reports against both.
 */

const TARGET_KINDS: ReadonlyArray<TargetKind> = [
	"codebase",
	"url",
	"webapp",
	"container",
	"iac",
	"mobile",
];

export const severity = z.enum(SEVERITIES as [string, ...string[]]);
export const category = z.enum(CATEGORIES as [string, ...string[]]);
export const targetKind = z.enum(TARGET_KINDS as [string, ...string[]]);

export const location = z.object({
	file: z
		.string()
		.optional()
		.describe("Path relative to the target root (POSIX separators)"),
	line: z.number().int().min(1).optional().describe("1-based line"),
	column: z.number().int().min(1).optional().describe("1-based column"),
	url: z.string().optional().describe("Page or endpoint URL"),
	selector: z.string().optional().describe("CSS selector of the element"),
});

/** What a host agent submits for a playbook (auditor/fingerprint are filled in). */
export const findingInput = z.object({
	ruleId: z
		.string()
		.min(1)
		.describe(
			"Stable kebab-case rule id. Prefixed with `<playbookId>/` when missing, e.g. `agent.authz/idor-orders`.",
		),
	title: z.string().min(1).describe("Short, specific title"),
	severity,
	category,
	message: z
		.string()
		.min(1)
		.describe("What is wrong, where, and why it matters"),
	location: location.optional(),
	evidence: z
		.string()
		.max(2000)
		.optional()
		.describe("Short snippet proving the issue. Redact secrets."),
	remediation: z.string().optional().describe("Concrete fix"),
	references: z.array(z.string()).optional().describe("URLs, CWE ids, ..."),
	confidence: z.enum(["high", "medium", "low"]).optional(),
	tags: z
		.array(z.string())
		.optional()
		.describe("e.g. cwe-639, owasp-a01, wcag-2.4.7"),
});
export type FindingInputShape = z.infer<typeof findingInput>;

export const finding = findingInput.extend({
	auditor: z.string(),
	fingerprint: z.string(),
});

const counts = z.object({
	critical: z.number(),
	high: z.number(),
	medium: z.number(),
	low: z.number(),
	info: z.number(),
});
const grade = z.enum(["A", "B", "C", "D", "F"]);

export const summary = z.object({
	score: z.number(),
	grade,
	counts,
	categories: z.array(z.object({ category, score: z.number(), grade, counts })),
	auditors: z.object({
		passed: z.number(),
		failed: z.number(),
		skipped: z.number(),
		error: z.number(),
	}),
});

export const targetInfo = z.object({
	input: z.string(),
	type: z.enum(["directory", "file", "url", "image"]),
	kinds: z.array(targetKind),
	root: z.string().optional(),
	url: z.string().optional(),
	file: z.string().optional(),
	image: z.string().optional(),
	technologies: z.array(z.string()),
});

export const auditorResult = z.object({
	auditor: z.string(),
	title: z.string(),
	engine: z.enum(["builtin", "external", "agentic"]),
	categories: z.array(category),
	status: z.enum(["passed", "failed", "skipped", "error"]),
	message: z.string().optional(),
	durationMs: z.number(),
	findings: z.array(finding),
});

export const report = z.object({
	schemaVersion: z.literal("1"),
	tool: z.object({ name: z.string(), version: z.string() }),
	target: targetInfo,
	startedAt: z.string(),
	finishedAt: z.string(),
	durationMs: z.number(),
	summary,
	results: z.array(auditorResult),
	ai: z
		.object({
			model: z.string(),
			summary: z.string(),
			priorities: z.array(
				z.object({
					title: z.string(),
					why: z.string(),
					fix: z.string(),
					fingerprints: z.array(z.string()),
				}),
			),
		})
		.optional(),
});

export const auditorInfo = z.object({
	id: z.string(),
	title: z.string(),
	description: z.string(),
	engine: z.enum(["builtin", "external", "agentic"]),
	categories: z.array(category),
	targets: z.array(targetKind),
	tool: z.string().optional(),
	network: z.boolean(),
	defaultEnabled: z.boolean(),
});

export const playbookInfo = z.object({
	id: z.string(),
	title: z.string(),
	summary: z.string(),
	categories: z.array(category),
	targets: z.array(targetKind),
	needs: z.array(z.string()),
});
