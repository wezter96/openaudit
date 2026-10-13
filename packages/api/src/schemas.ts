import type { Playbook } from "@openaudit/agent";
import type { Report } from "@openaudit/core/model";
import { z } from "zod";

/**
 * Zod mirrors of the report model in `@openaudit/core/model` (Effect Schema).
 * oRPC needs zod to validate outputs and generate the OpenAPI document; the
 * type assertions at the bottom fail compilation if the two drift apart.
 */

export const SeveritySchema = z.enum([
	"critical",
	"high",
	"medium",
	"low",
	"info",
]);

export const CategorySchema = z.enum([
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

export const TargetKindSchema = z.enum([
	"codebase",
	"url",
	"webapp",
	"container",
	"iac",
	"mobile",
	"cloud",
]);

export const EngineSchema = z.enum(["builtin", "external", "agentic"]);

const GradeSchema = z.enum(["A", "B", "C", "D", "F"]);

const SeverityCountsSchema = z.object({
	critical: z.number(),
	high: z.number(),
	medium: z.number(),
	low: z.number(),
	info: z.number(),
});

export const FindingSchema = z.object({
	ruleId: z.string(),
	title: z.string(),
	severity: SeveritySchema,
	category: CategorySchema,
	message: z.string(),
	location: z
		.object({
			file: z.string().optional(),
			line: z.number().optional(),
			column: z.number().optional(),
			url: z.string().optional(),
			selector: z.string().optional(),
		})
		.optional(),
	evidence: z.string().optional(),
	remediation: z.string().optional(),
	references: z.array(z.string()).optional(),
	confidence: z.enum(["high", "medium", "low"]).optional(),
	tags: z.array(z.string()).optional(),
	auditor: z.string(),
	fingerprint: z.string(),
	alsoReportedBy: z.array(z.string()).optional(),
	duplicateOf: z.string().optional(),
});

export const ReportSchema = z
	.object({
		schemaVersion: z.literal("1"),
		tool: z.object({ name: z.string(), version: z.string() }),
		target: z.object({
			input: z.string(),
			type: z.enum(["directory", "file", "url", "image", "cloud"]),
			kinds: z.array(TargetKindSchema),
			root: z.string().optional(),
			url: z.string().optional(),
			file: z.string().optional(),
			image: z.string().optional(),
			cloud: z.string().optional(),
			technologies: z.array(z.string()),
		}),
		startedAt: z.string(),
		finishedAt: z.string(),
		durationMs: z.number(),
		summary: z.object({
			score: z.number(),
			grade: GradeSchema,
			counts: SeverityCountsSchema,
			categories: z.array(
				z.object({
					category: CategorySchema,
					score: z.number(),
					grade: GradeSchema,
					counts: SeverityCountsSchema,
				}),
			),
			auditors: z.object({
				passed: z.number(),
				failed: z.number(),
				skipped: z.number(),
				error: z.number(),
			}),
		}),
		results: z.array(
			z.object({
				auditor: z.string(),
				title: z.string(),
				engine: EngineSchema,
				categories: z.array(CategorySchema),
				status: z.enum(["passed", "failed", "skipped", "error"]),
				message: z.string().optional(),
				durationMs: z.number(),
				findings: z.array(FindingSchema),
			}),
		),
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
	})
	.meta({ id: "Report", description: "An openaudit report (schemaVersion 1)" });

export const AuditorInfoSchema = z
	.object({
		id: z.string(),
		title: z.string(),
		description: z.string(),
		engine: EngineSchema,
		categories: z.array(CategorySchema),
		targets: z.array(TargetKindSchema),
		tool: z.string().optional(),
		network: z.boolean(),
		defaultEnabled: z.boolean(),
	})
	.meta({ id: "AuditorInfo" });

const PlaybookNeedSchema = z.enum(["code", "browser", "shell", "network"]);

export const PlaybookSummarySchema = z
	.object({
		id: z.string(),
		title: z.string(),
		summary: z.string(),
		categories: z.array(CategorySchema),
		targets: z.array(TargetKindSchema),
		needs: z.array(PlaybookNeedSchema),
		checklist: z.array(z.string()),
	})
	.meta({ id: "PlaybookSummary" });

export const PlaybookSchema = PlaybookSummarySchema.extend({
	instructions: z.string(),
}).meta({ id: "Playbook" });

/* ------------------------- compile-time drift checks ------------------------ */

type DeepMutable<T> =
	T extends ReadonlyArray<infer U>
		? DeepMutable<U>[]
		: T extends object
			? { -readonly [K in keyof T]: DeepMutable<T[K]> }
			: T;
type Assert<_T extends true> = true;
type Same<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;

export type _ReportInSync = Assert<
	Same<z.infer<typeof ReportSchema>, DeepMutable<Report>>
>;
export type _PlaybookInSync = Assert<
	Same<z.infer<typeof PlaybookSchema>, DeepMutable<Playbook>>
>;
