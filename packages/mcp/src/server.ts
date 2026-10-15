import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
	McpServer,
	ResourceTemplate,
} from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as Agent from "@openaudit/agent";
import { builtinAuditors } from "@openaudit/auditors";
import {
	type AuditOptions,
	type Auditor,
	type Category,
	CoreLive,
	type Finding,
	type FindingInput,
	type GuardOptions,
	makeWorkspace,
	type Report,
	resolveTarget,
	runAudit,
	type Severity,
	selectAuditors,
	type TargetKind,
	toCsv,
	toHtml,
	toJson,
	toMarkdown,
	toSarif,
	VERSION,
} from "@openaudit/core";
import { Effect } from "effect";
import { z } from "zod";
import {
	auditResult,
	planAudit,
	progressReporter,
	RUN_AUDIT_TOOL,
	scopedReport,
	selectionOf,
} from "./audit";
import {
	auditorInfo,
	errorResult,
	findingExample,
	playbookInfo,
	playbookText,
	run,
	sourceContext,
	textResult,
} from "./helpers";
import {
	auditProjectPrompt,
	MANUAL_PLAYBOOK,
	SERVER_INSTRUCTIONS,
} from "./instructions";
import {
	diffReports,
	isReportId,
	mergeAgentFindings,
	persist,
	type ReportId,
	ReportStore,
	type SaveResult,
	saveFields,
	saveNote,
} from "./reports";
import * as S from "./schemas";
import { countsText, findingLine } from "./text";

type Playbook = Agent.Playbook;

export { MANUAL_PLAYBOOK, SERVER_INSTRUCTIONS };

export interface ServerOptions {
	/** Auditors available to `run_audit`. Defaults to built-in + agentic. */
	readonly auditors?: ReadonlyArray<Auditor>;
	/** Playbooks for agent-in-the-loop audits. Defaults to `@openaudit/agent`'s. */
	readonly playbooks?: ReadonlyArray<Playbook>;
	readonly store?: ReportStore;
	/** Base directory for relative targets. Defaults to `process.cwd()`. */
	readonly cwd?: string;
	/**
	 * Maps a client-supplied target to what gets audited, or throws to refuse it.
	 * Stdio leaves this unset (local trust); the HTTP transport confines paths to roots.
	 */
	readonly resolveInput?: (target: string) => Promise<string>;
	/** Set false where the server owner pays for agentic auditors (HTTP). Default true. */
	readonly allowAgentic?: boolean;
	/**
	 * When set, URL targets must resolve to public addresses and every request
	 * the audit makes is pinned to the validated IP. Only pinnable auditors run.
	 */
	readonly urlGuard?: GuardOptions;
	/** Make image scanners pull from the registry only (never the local daemon). */
	readonly registryImagesOnly?: boolean;
	/** Save reports under the target's `.openaudit/reports` (default true; false over HTTP). */
	readonly persistReports?: boolean;
}

const RENDERERS: Record<
	"json" | "markdown" | "sarif" | "csv" | "html",
	(report: Report) => string
> = {
	json: toJson,
	markdown: toMarkdown,
	sarif: toSarif,
	csv: toCsv,
	html: toHtml,
};

/** Saves the HTML report under the target, or else in a private temp directory. */
const writeHtml = async (
	reportId: ReportId,
	report: Report,
): Promise<string> => {
	const html = toHtml(report);
	const saved = await persist(reportId, report, "html", html);
	if (saved.saved) return saved.path;
	// A private, freshly created directory: nothing to follow or race.
	const dir = await mkdtemp(join(tmpdir(), "openaudit-"));
	const path = join(dir, `${reportId}.html`);
	await writeFile(path, html, { flag: "wx", mode: 0o600 });
	return path;
};

/** get_finding's text: the finding in full, with its source excerpt. */
const findingDetail = (
	finding: Finding,
	source: Awaited<ReturnType<typeof sourceContext>>,
): string => {
	const lines = [
		`# ${finding.title}`,
		`${finding.severity} · ${finding.category} · ${finding.ruleId} · auditor ${finding.auditor}${finding.confidence ? ` · confidence ${finding.confidence}` : ""}`,
		"",
		finding.message,
	];
	if (finding.location)
		lines.push("", `Location: ${JSON.stringify(finding.location)}`);
	if (finding.evidence)
		lines.push("", "Evidence:", "```", finding.evidence, "```");
	if (source)
		lines.push(
			"",
			`Source ${source.file}:${source.startLine}-${source.endLine}:`,
			"```",
			source.text,
			"```",
		);
	if (finding.remediation)
		lines.push("", `Remediation: ${finding.remediation}`);
	if (finding.references?.length)
		lines.push("", "References:", ...finding.references.map((r) => `- ${r}`));
	return lines.join("\n");
};

interface Submission {
	readonly playbookId: string;
	readonly id: ReportId;
	readonly report: Report;
	readonly added: ReadonlyArray<Finding>;
	readonly saved: SaveResult | undefined;
}

/** The submit_findings tool result: what was merged and the new score. */
const submissionResult = ({
	playbookId,
	id,
	report,
	added,
	saved,
}: Submission) => {
	const note = saveNote(saved);
	return textResult(
		[
			`Merged ${added.length} finding(s) from ${playbookId} into report ${id}.`,
			...(note ? [note] : []),
			`Score: ${report.summary.score}/100 (${report.summary.grade}) | ${countsText(report.summary.counts)}`,
			...added.map(findingLine),
		].join("\n"),
		{
			reportId: id,
			...saveFields(saved),
			accepted: added.length,
			fingerprints: added.map((f) => f.fingerprint),
			summary: report.summary,
		},
	);
};

export const createServer = (options: ServerOptions = {}): McpServer => {
	const allowAgentic = options.allowAgentic ?? true;
	const auditors = (
		options.auditors ?? [...builtinAuditors, ...Agent.agenticAuditors]
	).filter((a) => allowAgentic || a.engine !== "agentic");
	const refuseAgentic = (agentic: boolean | undefined) => {
		if (agentic && !allowAgentic)
			throw new Error(
				"agentic auditors are disabled on this server because they spend the server owner's API key (start it with --allow-agentic)",
			);
	};
	const guard = options.urlGuard;
	const registryOnly = options.registryImagesOnly ?? false;
	const playbooks = [
		...(options.playbooks ?? Agent.playbooks),
		MANUAL_PLAYBOOK,
	];
	const persistReports = options.persistReports ?? true;
	const store = options.store ?? new ReportStore(20, persistReports);
	const cwd = options.cwd ?? process.cwd();
	const resolveInput: (target: string) => Promise<string> =
		options.resolveInput ??
		(async (target) =>
			/^https?:\/\/|^image:|^cloud:/i.test(target)
				? target
				: resolve(cwd, target));

	const server = new McpServer(
		{ name: "openaudit", title: "openaudit", version: VERSION },
		{ instructions: SERVER_INSTRUCTIONS },
	);

	const getReport = (id: ReportId) => {
		if (!isReportId(id)) throw new Error("reportId must match ^[a-z0-9-]+$");
		const report = store.get(id);
		if (!report)
			throw new Error(
				`Unknown reportId "${id}". Reports live in memory (last 20); run run_audit again. Known: ${store.ids().join(", ") || "none"}`,
			);
		return report;
	};

	/* ------------------------------- discovery ------------------------------ */

	server.registerTool(
		"list_auditors",
		{
			title: "List auditors",
			description:
				"List openaudit auditors, optionally filtered by target kind or category. Agentic auditors are off unless run_audit is called with agentic: true.",
			inputSchema: {
				targetKind: S.targetKind.optional(),
				category: S.category.optional(),
			},
			outputSchema: { auditors: z.array(S.auditorInfo) },
			annotations: { readOnlyHint: true, openWorldHint: false },
		},
		async ({ targetKind, category }) => {
			const list = auditors
				.filter(
					(a) => !targetKind || a.targets.includes(targetKind as TargetKind),
				)
				.filter((a) => !category || a.categories.includes(category as Category))
				.map(auditorInfo);
			const text = list
				.map(
					(a) =>
						`- ${a.id} [${a.engine}${a.tool ? `: ${a.tool}` : ""}${a.defaultEnabled ? "" : ", opt-in"}] ${a.title} (${a.targets.join(", ")})`,
				)
				.join("\n");
			return textResult(text || "No auditors match.", { auditors: list });
		},
	);

	server.registerTool(
		"detect_target",
		{
			title: "Detect target",
			description:
				"Resolve a target (directory, file, http(s) URL or image:<ref>) into kinds and technologies, and list the auditors run_audit would run.",
			inputSchema: {
				target: z.string().describe("Absolute path, URL or image:<ref>"),
				browser: z.boolean().optional().describe("Treat URLs as web apps"),
				agentic: z.boolean().optional(),
			},
			outputSchema: {
				target: S.targetInfo,
				auditors: z.array(z.string()),
				optIn: z.array(z.string()),
				playbooks: z.array(z.string()),
			},
			annotations: { readOnlyHint: true, openWorldHint: false },
		},
		async ({ target, browser, agentic }) => {
			refuseAgentic(agentic);
			const opts: AuditOptions = { browser, agentic };
			const res = await run(
				resolveTarget(await resolveInput(target), opts, makeWorkspace),
			);
			if (!res.ok) return errorResult(res.error);
			const info = res.value.info;
			const selected = selectAuditors(auditors, info.kinds, {}, opts).map(
				(a) => a.id,
			);
			const optIn = auditors
				.filter(
					(a) =>
						a.targets.some((k) => info.kinds.includes(k)) &&
						!selected.includes(a.id),
				)
				.map((a) => a.id);
			const books = playbooks
				.filter((p) => p.targets.some((k) => info.kinds.includes(k)))
				.map((p) => p.id);
			return textResult(
				[
					`Target ${info.input}: ${info.type}; kinds ${info.kinds.join(", ")}; technologies ${info.technologies.join(", ") || "none detected"}`,
					`Will run (${selected.length}): ${selected.join(", ") || "none"}`,
					optIn.length ? `Opt-in (use only/agentic): ${optIn.join(", ")}` : "",
					`Playbooks: ${books.join(", ")}`,
				]
					.filter(Boolean)
					.join("\n"),
				{ target: info, auditors: selected, optIn, playbooks: books },
			);
		},
	);

	/* --------------------------------- audit -------------------------------- */

	server.registerTool("run_audit", RUN_AUDIT_TOOL, async (args, extra) => {
		refuseAgentic(args.agentic);
		const target = await resolveInput(args.target);
		const plan = await planAudit({
			target,
			args,
			auditors,
			guard,
			registryOnly,
		});
		if ("refused" in plan) return errorResult(plan.refused);
		const selection = selectionOf(args);
		const res = await run(
			runAudit({
				target,
				auditors: plan.auditors,
				options: plan.options,
				selection,
				// Our own saved reports must not be audited on the next run.
				suppress: { paths: [".openaudit/**"] },
				concurrency: args.concurrency,
				onEvent: progressReporter(extra, plan, selection),
			}).pipe(Effect.provide(plan.infra)),
		);
		if (!res.ok) return errorResult(res.error);
		const report = scopedReport(res.value, plan);
		const reportId = ReportStore.newId();
		const saved = await store.put(reportId, report);
		return auditResult({
			report,
			reportId,
			saved,
			failOn: args.failOn as Severity | undefined,
			playbooks,
		});
	});

	server.registerTool(
		"get_report",
		{
			title: "Get report",
			description:
				"Render a stored report as json, markdown (PR comments), sarif (code scanning), csv (spreadsheets) or html. HTML is written to a file and its path returned.",
			inputSchema: {
				reportId: S.reportId,
				format: z
					.enum(["json", "markdown", "sarif", "csv", "html"])
					.default("markdown"),
			},
			outputSchema: {
				reportId: S.reportId,
				format: z.string(),
				content: z.string().optional(),
				path: z.string().optional(),
			},
			annotations: { readOnlyHint: true, openWorldHint: false },
		},
		async ({ reportId, format }) => {
			const report = getReport(reportId);
			// Without server-side files, HTML is handed to the client like the rest.
			if (format === "html" && persistReports) {
				const path = await writeHtml(reportId, report);
				return textResult(`HTML report written to ${path}`, {
					reportId,
					format,
					path,
				});
			}
			const content = RENDERERS[format](report);
			return textResult(content, { reportId, format, content });
		},
	);

	server.registerTool(
		"get_finding",
		{
			title: "Get finding",
			description:
				"Full detail for one finding (by reportId + fingerprint): message, evidence, remediation, references, and ±5 lines of source when it points at a file.",
			inputSchema: { reportId: S.reportId, fingerprint: z.string() },
			outputSchema: {
				finding: S.finding,
				source: z
					.object({
						file: z.string(),
						startLine: z.number(),
						endLine: z.number(),
						text: z.string(),
					})
					.optional(),
			},
			annotations: { readOnlyHint: true, openWorldHint: false },
		},
		async ({ reportId, fingerprint }) => {
			const report = getReport(reportId);
			const finding = report.results
				.flatMap((r) => r.findings)
				.find((f) => f.fingerprint === fingerprint);
			if (!finding)
				return errorResult(
					`No finding with fingerprint ${fingerprint} in report ${reportId}.`,
				);
			const source = await sourceContext(report, finding.location);
			return textResult(findingDetail(finding, source), {
				finding,
				...(source ? { source } : {}),
			});
		},
	);

	server.registerTool(
		"compare_reports",
		{
			title: "Compare reports",
			description:
				"Diff two reports by finding fingerprint: new (in head only), fixed (in base only) and unchanged. Use after fixing issues to verify the fix and catch regressions.",
			inputSchema: {
				baseReportId: S.reportId.describe("Earlier report"),
				headReportId: S.reportId.describe("Later report"),
			},
			outputSchema: {
				new: z.array(S.finding),
				fixed: z.array(S.finding),
				unchanged: z.array(z.string()).describe("Fingerprints"),
				scoreDelta: z.number(),
				base: S.summary,
				head: S.summary,
			},
			annotations: { readOnlyHint: true, openWorldHint: false },
		},
		async ({ baseReportId, headReportId }) => {
			const base = getReport(baseReportId);
			const head = getReport(headReportId);
			const diff = diffReports(base, head);
			const text = [
				`Score ${base.summary.score} → ${head.summary.score} (${diff.scoreDelta >= 0 ? "+" : ""}${diff.scoreDelta})`,
				`Fixed: ${diff.fixed.length} · New: ${diff.new.length} · Unchanged: ${diff.unchanged.length}`,
				...(diff.fixed.length
					? ["", "## Fixed", ...diff.fixed.map(findingLine)]
					: []),
				...(diff.new.length
					? ["", "## New", ...diff.new.map(findingLine)]
					: []),
			].join("\n");
			return textResult(text, {
				new: diff.new,
				fixed: diff.fixed,
				unchanged: diff.unchanged.map((f) => f.fingerprint),
				scoreDelta: diff.scoreDelta,
				base: base.summary,
				head: head.summary,
			});
		},
	);

	/* ------------------------------- playbooks ------------------------------ */

	const findPlaybook = (id: string) => {
		const p = playbooks.find((b) => b.id === id);
		if (!p)
			throw new Error(
				`Unknown playbook "${id}". Available: ${playbooks.map((b) => b.id).join(", ")}`,
			);
		return p;
	};

	/** The report findings are merged into: a stored one, or a new one for `target`. */
	const submissionBase = async (
		reportId: ReportId | undefined,
		target: string | undefined,
	): Promise<{ id: ReportId; base: Report } | { error: string }> => {
		if (reportId) return { id: reportId, base: getReport(reportId) };
		if (!target) return { error: "Pass reportId (from run_audit) or target." };
		const res = await run(
			runAudit({ target: await resolveInput(target), auditors: [] }).pipe(
				Effect.provide(CoreLive),
			),
		);
		if (!res.ok) return { error: res.error };
		return { id: ReportStore.newId(), base: res.value };
	};

	server.registerTool(
		"list_playbooks",
		{
			title: "List playbooks",
			description:
				"Judgment-heavy audit procedures (authorization, business logic, UX accessibility, ...) that you, the host agent, execute with your own code/browser tools and report back via submit_findings. No API key needed.",
			inputSchema: { targetKind: S.targetKind.optional() },
			outputSchema: { playbooks: z.array(S.playbookInfo) },
			annotations: { readOnlyHint: true, openWorldHint: false },
		},
		async ({ targetKind }) => {
			const list = playbooks
				.filter(
					(p) => !targetKind || p.targets.includes(targetKind as TargetKind),
				)
				.map(playbookInfo);
			return textResult(
				list
					.map(
						(p) =>
							`- ${p.id}: ${p.title} (${p.targets.join(", ")}; needs ${p.needs.join(", ")}). ${p.summary}`,
					)
					.join("\n") || "No playbooks match.",
				{ playbooks: list },
			);
		},
	);

	server.registerTool(
		"get_playbook",
		{
			title: "Get playbook",
			description:
				"Instructions, checklist and the exact finding JSON shape for one playbook. Do the work, then call submit_findings.",
			inputSchema: {
				playbookId: z.string(),
				target: z.string().optional(),
				reportId: S.reportId.optional(),
			},
			outputSchema: {
				playbook: S.playbookInfo.extend({
					instructions: z.string(),
					checklist: z.array(z.string()),
				}),
				target: S.targetInfo.optional(),
				findingSchema: z.record(z.string(), z.unknown()),
				example: z.record(z.string(), z.unknown()),
			},
			annotations: { readOnlyHint: true, openWorldHint: false },
		},
		async ({ playbookId, target, reportId }) => {
			const p = findPlaybook(playbookId);
			let info: Report["target"] | undefined = reportId
				? store.get(reportId)?.target
				: undefined;
			if (!info && target) {
				const res = await run(
					resolveTarget(await resolveInput(target), {}, makeWorkspace),
				);
				if (res.ok) info = res.value.info;
			}
			const label = info ? `${info.root ?? info.url ?? info.input}` : target;
			return textResult(playbookText(p, { target: label, reportId }), {
				playbook: {
					...playbookInfo(p),
					instructions: p.instructions,
					checklist: [...p.checklist],
				},
				...(info ? { target: info } : {}),
				findingSchema: z.toJSONSchema(S.findingInput) as Record<
					string,
					unknown
				>,
				example: findingExample(p),
			});
		},
	);

	server.registerTool(
		"submit_findings",
		{
			title: "Submit findings",
			description:
				"Merge findings you produced for a playbook into a report (as an agentic auditor result named after the playbook) and get the recomputed score. Pass reportId from run_audit, or a target to start a new report. Resubmitting the same finding is idempotent.",
			inputSchema: {
				playbookId: z.string(),
				reportId: S.reportId.optional(),
				target: z
					.string()
					.optional()
					.describe("Used when no reportId is given"),
				findings: z.array(S.findingInput),
			},
			outputSchema: {
				reportId: S.reportId,
				reportPath: z.string().optional(),
				notSaved: z.string().optional(),
				accepted: z.number(),
				fingerprints: z.array(z.string()),
				summary: S.summary,
			},
			annotations: {
				readOnlyHint: false,
				destructiveHint: false,
				idempotentHint: true,
				openWorldHint: false,
			},
		},
		async ({ playbookId, reportId, target, findings }) => {
			const p = findPlaybook(playbookId);
			const start = await submissionBase(reportId, target);
			if ("error" in start) return errorResult(start.error);
			const { report, added } = mergeAgentFindings(
				start.base,
				p,
				findings as ReadonlyArray<FindingInput>,
			);
			const saved = await store.put(start.id, report);
			return submissionResult({
				playbookId: p.id,
				id: start.id,
				report,
				added,
				saved,
			});
		},
	);

	/* -------------------------------- prompts ------------------------------- */

	server.registerPrompt(
		"audit_project",
		{
			title: "Audit this project with openaudit",
			description:
				"Walks you through run_audit → triage → playbooks → submit_findings → fix → compare_reports.",
			argsSchema: {
				target: z
					.string()
					.optional()
					.describe("Path or URL (default: the current project)"),
				focus: z
					.string()
					.optional()
					.describe("Optional focus, e.g. security, accessibility"),
			},
		},
		({ target, focus }) => ({
			messages: [
				{
					role: "user",
					content: {
						type: "text",
						text: auditProjectPrompt(target ?? cwd, focus, playbooks),
					},
				},
			],
		}),
	);

	for (const p of playbooks) {
		server.registerPrompt(
			`playbook_${p.id.replace(/[^A-Za-z0-9_-]/g, "_")}`,
			{
				title: `Playbook: ${p.title}`,
				description: p.summary,
				argsSchema: {
					target: z.string().optional(),
					reportId: S.reportId.optional(),
				},
			},
			({ target, reportId }) => ({
				messages: [
					{
						role: "user",
						content: {
							type: "text",
							text: playbookText(p, { target: target ?? cwd, reportId }),
						},
					},
				],
			}),
		);
	}

	/* ------------------------------- resources ------------------------------ */

	server.registerResource(
		"auditors",
		"openaudit://auditors",
		{
			title: "openaudit auditors",
			description: "Every available auditor with its targets and categories",
			mimeType: "application/json",
		},
		async (uri) => ({
			contents: [
				{
					uri: uri.href,
					mimeType: "application/json",
					text: JSON.stringify(
						{
							auditors: auditors.map(auditorInfo),
							playbooks: playbooks.map(playbookInfo),
						},
						null,
						2,
					),
				},
			],
		}),
	);

	server.registerResource(
		"report",
		new ResourceTemplate("openaudit://reports/{id}", {
			list: async () => ({
				resources: store.ids().map((id) => {
					const r = store.get(id);
					return {
						uri: `openaudit://reports/${id}`,
						name: `report ${id}`,
						description: r
							? `${r.target.input}: ${r.summary.score}/100 ${r.summary.grade}`
							: undefined,
						mimeType: "application/json",
					};
				}),
			}),
		}),
		{
			title: "openaudit report",
			description: "A report from run_audit, as JSON",
			mimeType: "application/json",
		},
		async (uri, { id }) => ({
			contents: [
				{
					uri: uri.href,
					mimeType: "application/json",
					text: toJson(getReport(String(id))),
				},
			],
		}),
	);

	return server;
};

/** Serves openaudit over stdio until the client disconnects. */
export const startStdioServer = async (
	options: ServerOptions = {},
): Promise<McpServer> => {
	const server = createServer(options);
	await server.connect(new StdioServerTransport());
	return server;
};
