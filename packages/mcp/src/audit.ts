import type { RequestHandlerExtra } from "@modelcontextprotocol/sdk/shared/protocol.js";
import type {
	ServerNotification,
	ServerRequest,
} from "@modelcontextprotocol/sdk/types.js";
import type * as Agent from "@openaudit/agent";
import {
	type AuditEvent,
	type AuditOptions,
	type Auditor,
	AuditorError,
	type Category,
	CoreLive,
	changedFilesSince,
	DEFAULT_GUARDED_LIMITS,
	Exec,
	type GuardOptions,
	guardedHttpLayer,
	type Http,
	isPinnableUrlAuditor,
	limitToChangedFiles,
	type Report,
	resolvePublicUrl,
	type Selection,
	type Severity,
	SsrfError,
	selectAuditors,
	toJson,
	Workspaces,
} from "@openaudit/core";
import { Effect, Layer } from "effect";
import { z } from "zod";
import { textResult } from "./helpers";
import {
	breaches,
	type ReportId,
	type SaveResult,
	saveFields,
	saveNote,
} from "./reports";
import * as S from "./schemas";
import { reportSummaryText } from "./text";

/** Definition of the `run_audit` tool. */
export const RUN_AUDIT_TOOL = {
	title: "Run audit",
	description:
		"Audit a directory, file, http(s) URL, image:<ref> or cloud:<provider>. Returns a summary with the most severe findings (text) and the full report (structuredContent), plus a reportId for get_report, get_finding, submit_findings and compare_reports. Directory targets also get .openaudit/reports/<reportId>.json.",
	inputSchema: {
		target: z
			.string()
			.describe(
				"Absolute path, http(s) URL or image:<ref>. Relative paths resolve against the server's cwd.",
			),
		only: z
			.array(z.string())
			.optional()
			.describe("Auditor ids or patterns: web.headers, web.*, code"),
		exclude: z.array(z.string()).optional(),
		categories: z.array(S.category).optional(),
		offline: z.boolean().optional().describe("No network except to the target"),
		browser: z
			.boolean()
			.optional()
			.describe("Drive a real browser for URL targets"),
		maxPages: z.number().int().min(1).max(500).optional(),
		headers: z
			.record(z.string(), z.string())
			.optional()
			.describe("Extra headers sent only to the target origin"),
		agentic: z
			.boolean()
			.optional()
			.describe("Run built-in agentic auditors (needs ANTHROPIC_API_KEY)"),
		model: z.string().optional(),
		failOn: S.severity
			.optional()
			.describe(
				"Gate: gatePassed is false when any finding is at least this severe",
			),
		concurrency: z.number().int().min(1).max(32).optional(),
		diffBase: z
			.string()
			.optional()
			.describe(
				"Git ref (e.g. origin/main): keep only findings in files changed since it. Directory targets in a git repo only.",
			),
	},
	outputSchema: {
		reportId: S.reportId,
		reportPath: z.string().optional(),
		notSaved: z
			.string()
			.optional()
			.describe("Why the report is kept in memory only"),
		gatePassed: z.boolean(),
		failOn: S.severity.optional(),
		summary: S.summary,
		report: S.report,
	},
	annotations: {
		readOnlyHint: false,
		destructiveHint: false,
		idempotentHint: false,
		openWorldHint: true,
	},
};

export type RunAuditArgs = z.infer<
	z.ZodObject<typeof RUN_AUDIT_TOOL.inputSchema>
>;

type ToolExtra = RequestHandlerExtra<ServerRequest, ServerNotification>;

/** Why run_audit refuses a target, as shown to the client. */
interface Refused {
	readonly refused: string;
}

/** What one run_audit call runs: auditors, their options and their infrastructure. */
export interface AuditPlan {
	readonly auditors: ReadonlyArray<Auditor>;
	readonly options: AuditOptions;
	readonly infra: Layer.Layer<Http | Exec | Workspaces>;
	/** Set with `diffBase`: findings outside these files are dropped. */
	readonly changes?: { readonly base: string; readonly files: string[] };
}

export interface PlanInput {
	/** The resolved target. */
	readonly target: string;
	readonly args: RunAuditArgs;
	readonly auditors: ReadonlyArray<Auditor>;
	readonly guard?: GuardOptions;
	readonly registryOnly: boolean;
}

export const isUrl = (t: string) => /^https?:\/\//i.test(t);

export const selectionOf = (args: RunAuditArgs): Selection => ({
	only: args.only,
	exclude: args.exclude,
	categories: args.categories as Category[] | undefined,
});

const optionsOf = (args: RunAuditArgs): AuditOptions => ({
	offline: args.offline,
	browser: args.browser,
	maxPages: args.maxPages,
	headers: args.headers,
	agentic: args.agentic,
	model: args.model,
	diffBase: args.diffBase,
});

const registryOnlyOptions = (options: AuditOptions): AuditOptions => ({
	...options,
	settings: {
		...options.settings,
		"container.image": { registryOnly: true },
	},
});

const basePlan = (input: PlanInput): AuditPlan => {
	const options = optionsOf(input.args);
	return {
		auditors: input.auditors,
		options:
			input.registryOnly && /^image:/i.test(input.target)
				? registryOnlyOptions(options)
				: options,
		infra: CoreLive,
	};
};

/** Guarded HTTP, no subprocesses. */
const guardedInfra = (guard: GuardOptions) =>
	Layer.mergeAll(
		guardedHttpLayer(guard, DEFAULT_GUARDED_LIMITS),
		Layer.succeed(Exec, {
			which: () => Effect.succeed(undefined),
			run: () =>
				Effect.fail(
					new AuditorError({
						message: "External tools are disabled for guarded URL targets",
					}),
				),
		}),
		Workspaces.layer,
	);

/**
 * Guarded URL audits: validate and pin the target, run only auditors whose
 * traffic goes through the guarded Http service, and allow no subprocesses.
 */
const guardedPlan = async (
	input: PlanInput,
	plan: AuditPlan,
): Promise<AuditPlan | Refused> => {
	const { guard, target } = input;
	if (!guard || !isUrl(target)) return plan;
	if (input.args.browser)
		return {
			refused:
				"browser audits are disabled for URL targets on this server (start it with --allow-private-targets to lift URL restrictions)",
		};
	try {
		const { address } = await resolvePublicUrl(target, guard);
		return {
			auditors: plan.auditors.filter(isPinnableUrlAuditor),
			options: {
				...plan.options,
				browser: false,
				settings: address ? { "web.tls": { connectHost: address } } : undefined,
			},
			infra: guardedInfra(guard),
		};
	} catch (error) {
		if (error instanceof SsrfError) return { refused: error.message };
		throw error;
	}
};

const changedFiles = async (
	target: string,
	diffBase: string | undefined,
): Promise<Pick<AuditPlan, "changes"> | Refused> => {
	if (diffBase === undefined) return {};
	try {
		const files = await changedFilesSince(target, diffBase);
		return { changes: { base: diffBase, files } };
	} catch (error) {
		return { refused: error instanceof Error ? error.message : String(error) };
	}
};

/** Plans a run_audit call, or explains why the target is refused. */
export const planAudit = async (
	input: PlanInput,
): Promise<AuditPlan | Refused> => {
	const plan = await guardedPlan(input, basePlan(input));
	if ("refused" in plan) return plan;
	const changed = await changedFiles(input.target, input.args.diffBase);
	if ("refused" in changed) return changed;
	return { ...plan, ...changed };
};

/** Reports audit progress to clients that sent a progress token. */
export const progressReporter = (
	extra: ToolExtra,
	plan: AuditPlan,
	selection: Selection,
) => {
	const progressToken = extra._meta?.progressToken;
	let total = 0;
	let done = 0;
	const notify = (message: string) => {
		if (progressToken === undefined) return;
		extra
			.sendNotification({
				method: "notifications/progress",
				params: { progressToken, progress: done, total, message },
			})
			.catch(() => {});
	};
	return (event: AuditEvent) => {
		if (event.type === "target") {
			total = selectAuditors(
				plan.auditors,
				event.target.kinds,
				selection,
				plan.options,
			).length;
			notify(`Auditing ${event.target.input} with ${total} auditors`);
		} else if (event.type === "finish") {
			done++;
			notify(
				`${event.result.auditor}: ${event.result.status} (${event.result.findings.length} findings)`,
			);
		}
	};
};

/** The report limited to the files changed since `diffBase`, when one was given. */
export const scopedReport = (report: Report, plan: AuditPlan): Report =>
	plan.changes
		? limitToChangedFiles(report, plan.changes.base, plan.changes.files)
		: report;

export interface AuditOutcome {
	readonly report: Report;
	readonly reportId: ReportId;
	readonly saved: SaveResult | undefined;
	readonly failOn?: Severity;
	readonly playbooks: ReadonlyArray<Agent.Playbook>;
}

const gateLine = (failOn: Severity | undefined, gatePassed: boolean) =>
	failOn
		? `\n\nGate (fail on ${failOn}): ${gatePassed ? "PASSED" : "FAILED"}`
		: "";

const playbooksLine = ({ report, reportId, playbooks }: AuditOutcome) => {
	const books = playbooks.filter((p) =>
		p.targets.some((k) => report.target.kinds.includes(k)),
	);
	return books.length
		? `\n\nPlaybooks for this target: ${books.map((p) => p.id).join(", ")} (get_playbook → submit_findings with reportId ${reportId}).`
		: "";
};

/** The run_audit tool result: summary text plus the full report. */
export const auditResult = (outcome: AuditOutcome) => {
	const { report, reportId, saved, failOn } = outcome;
	const gatePassed = failOn ? !breaches(report, failOn) : true;
	const text =
		reportSummaryText(report, reportId, { saveNote: saveNote(saved) }) +
		gateLine(failOn, gatePassed) +
		playbooksLine(outcome);
	return textResult(text, {
		reportId,
		...saveFields(saved),
		gatePassed,
		...(failOn ? { failOn } : {}),
		summary: report.summary,
		report: JSON.parse(toJson(report)),
	});
};
