import { mkdtemp, realpath, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import {
	McpServer,
	ResourceTemplate,
} from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as Agent from "@openaudit/agent";
import { builtinAuditors } from "@openaudit/auditors";
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
	type FindingInput,
	type GuardOptions,
	guardedHttpLayer,
	type Http,
	isPinnableUrlAuditor,
	limitToChangedFiles,
	makeWorkspace,
	type Report,
	resolvePublicUrl,
	resolveTarget,
	runAudit,
	type Severity,
	SsrfError,
	selectAuditors,
	type TargetKind,
	toCsv,
	toHtml,
	toJson,
	toMarkdown,
	toSarif,
	VERSION,
	Workspaces,
} from "@openaudit/core";
import { Effect, Layer } from "effect";
import { z } from "zod";

import {
	breaches,
	diffReports,
	isReportId,
	mergeAgentFindings,
	persist,
	ReportStore,
	saveNote,
} from "./reports";
import * as S from "./schemas";
import { countsText, findingLine, reportSummaryText } from "./text";

type Playbook = Agent.Playbook;

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
}

/** Free-form playbook so host agents can submit issues found outside a playbook. */
export const MANUAL_PLAYBOOK: Playbook = {
	id: "agent.manual",
	title: "Manual review",
	summary:
		"Free-form findings the host agent discovered while reviewing the target.",
	categories: [
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
	],
	targets: ["codebase", "url", "webapp", "container", "iac", "mobile"],
	needs: ["code"],
	instructions: [
		"Record issues you verified yourself that no openaudit auditor reported.",
		"Only submit issues you have evidence for: cite the file and line or URL and selector, and quote a short, redacted snippet as evidence.",
		'Prefer one finding per root cause. Use `confidence: "low"` for suspicions you could not confirm.',
	].join("\n\n"),
	checklist: [
		"Each finding has a precise location",
		"Evidence is short and contains no secrets",
		"Remediation is concrete and actionable",
	],
};

export const SERVER_INSTRUCTIONS = `openaudit audits codebases, URLs, running web apps, containers, IaC and mobile builds (security, accessibility, performance, SEO, privacy, supply chain, ...).
Recommended workflow:
1. detect_target to see what will run, then run_audit (pass an absolute path or URL). Keep the returned reportId.
2. Triage the most severe findings; use get_finding (reportId + fingerprint) for remediation and source context.
3. For judgment-heavy checks (authz, business logic, UX accessibility), call list_playbooks / get_playbook, do the work with your own tools, then submit_findings into the same reportId.
4. Fix issues, run_audit again, and compare_reports(base, head) to confirm what is fixed and that nothing new appeared.
Use get_report for markdown (PR comments), SARIF (code scanning) or HTML. Never paste secrets from evidence into chat.`;

const textResult = (
	text: string,
	structuredContent?: Record<string, unknown>,
) => ({
	content: [{ type: "text" as const, text }],
	...(structuredContent ? { structuredContent } : {}),
});

const errorResult = (message: string) => ({
	content: [{ type: "text" as const, text: message }],
	isError: true,
});

const auditorInfo = (a: Auditor) => ({
	id: a.id,
	title: a.title,
	description: a.description,
	engine: a.engine,
	categories: [...a.categories],
	targets: [...a.targets],
	...(a.tool ? { tool: a.tool } : {}),
	network: a.network === true,
	defaultEnabled: a.engine === "agentic" ? false : a.defaultEnabled !== false,
});

const playbookInfo = (p: Playbook) => ({
	id: p.id,
	title: p.title,
	summary: p.summary,
	categories: [...p.categories],
	targets: [...p.targets],
	needs: [...p.needs],
});

const findingExample = (p: Playbook) => ({
	ruleId: `${p.id}/short-kebab-rule`,
	title: "Order API returns other users' orders",
	severity: "high",
	category: p.categories[0] ?? "security",
	message:
		"GET /api/orders/:id does not check that the order belongs to the session user.",
	location: { file: "src/routes/orders.ts", line: 42 },
	evidence: "const order = await db.order.find(params.id)",
	remediation: "Scope the query by the authenticated user id.",
	references: ["https://cwe.mitre.org/data/definitions/639.html"],
	confidence: "high",
	tags: ["cwe-639"],
});

const playbookText = (
	p: Playbook,
	extra: { target?: string; reportId?: string },
) =>
	[
		`# Playbook ${p.id}: ${p.title}`,
		p.summary,
		extra.target ? `\nTarget: ${extra.target}` : "",
		`Needs: ${p.needs.join(", ")} | Categories: ${p.categories.join(", ")}`,
		"",
		"## Instructions",
		p.instructions,
		"",
		"## Checklist",
		...p.checklist.map((c) => `- [ ] ${c}`),
		"",
		"## Submitting",
		`Call submit_findings with playbookId "${p.id}"${extra.reportId ? `, reportId "${extra.reportId}"` : ", the reportId from run_audit (or a target)"} and a findings array. Each finding:`,
		"```json",
		JSON.stringify(findingExample(p), null, 2),
		"```",
		"Required: ruleId, title, severity (critical|high|medium|low|info), category, message. Submit an empty array when nothing was found, so the report records that the playbook ran.",
	]
		.filter((l) => l !== "")
		.join("\n");

/** Runs an Effect and returns its success, or the failure as an Error. */
const run = <A, E extends { readonly message: string }>(
	effect: Effect.Effect<A, E>,
): Promise<{ ok: true; value: A } | { ok: false; error: string }> =>
	Effect.runPromise(Effect.result(effect)).then((r) =>
		r._tag === "Success"
			? { ok: true as const, value: r.success }
			: { ok: false as const, error: r.failure.message },
	);

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
	const isUrl = (t: string) => /^https?:\/\//i.test(t);
	const playbooks = [
		...(options.playbooks ?? Agent.playbooks),
		MANUAL_PLAYBOOK,
	];
	const store = options.store ?? new ReportStore();
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

	const getReport = (id: string) => {
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

	server.registerTool(
		"run_audit",
		{
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
				offline: z
					.boolean()
					.optional()
					.describe("No network except to the target"),
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
		},
		async (args, extra) => {
			refuseAgentic(args.agentic);
			const progressToken = extra._meta?.progressToken;
			let runAuditors: ReadonlyArray<Auditor> = auditors;
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
			let options: AuditOptions = {
				offline: args.offline,
				browser: args.browser,
				maxPages: args.maxPages,
				headers: args.headers,
				agentic: args.agentic,
				model: args.model,
			};
			const selection = {
				only: args.only,
				exclude: args.exclude,
				categories: args.categories as Category[] | undefined,
			};
			const onEvent = (event: AuditEvent) => {
				if (event.type === "target") {
					total = selectAuditors(
						runAuditors,
						event.target.kinds,
						selection,
						options,
					).length;
					notify(`Auditing ${event.target.input} with ${total} auditors`);
				} else if (event.type === "finish") {
					done++;
					notify(
						`${event.result.auditor}: ${event.result.status} (${event.result.findings.length} findings)`,
					);
				}
			};
			const target = await resolveInput(args.target);
			// Guarded URL audits: validate and pin the target, run only auditors whose
			// traffic goes through the guarded Http service, and allow no subprocesses.
			if (registryOnly && /^image:/i.test(target))
				options = {
					...options,
					settings: {
						...options.settings,
						"container.image": { registryOnly: true },
					},
				};
			let infra: Layer.Layer<Http | Exec | Workspaces> = CoreLive;
			if (guard && isUrl(target)) {
				if (args.browser)
					return errorResult(
						"browser audits are disabled for URL targets on this server (start it with --allow-private-targets to lift URL restrictions)",
					);
				try {
					const { address } = await resolvePublicUrl(target, guard);
					options = {
						...options,
						browser: false,
						settings: address
							? { "web.tls": { connectHost: address } }
							: undefined,
					};
				} catch (error) {
					if (error instanceof SsrfError) return errorResult(error.message);
					throw error;
				}
				runAuditors = auditors.filter(isPinnableUrlAuditor);
				infra = Layer.mergeAll(
					guardedHttpLayer(guard, DEFAULT_GUARDED_LIMITS),
					Layer.succeed(Exec, {
						which: () => Effect.succeed(undefined),
						run: () =>
							Effect.fail(
								new AuditorError({
									message:
										"External tools are disabled for guarded URL targets",
								}),
							),
					}),
					Workspaces.layer,
				);
			}
			let changed: string[] | undefined;
			if (args.diffBase !== undefined) {
				try {
					changed = await changedFilesSince(target, args.diffBase);
				} catch (error) {
					return errorResult(
						error instanceof Error ? error.message : String(error),
					);
				}
			}
			const res = await run(
				runAudit({
					target,
					auditors: runAuditors,
					options,
					selection,
					// Our own saved reports must not be audited on the next run.
					suppress: { paths: [".openaudit/**"] },
					concurrency: args.concurrency,
					onEvent,
				}).pipe(Effect.provide(infra)),
			);
			if (!res.ok) return errorResult(res.error);
			const report =
				changed && args.diffBase !== undefined
					? limitToChangedFiles(res.value, args.diffBase, changed)
					: res.value;
			const reportId = ReportStore.newId();
			const saved = await store.put(reportId, report);
			const reportPath = saved?.saved ? saved.path : undefined;
			const failOn = args.failOn as Severity | undefined;
			const gatePassed = failOn ? !breaches(report, failOn) : true;
			let text = reportSummaryText(report, reportId, {
				saveNote: saveNote(saved),
			});
			if (failOn)
				text += `\n\nGate (fail on ${failOn}): ${gatePassed ? "PASSED" : "FAILED"}`;
			const books = playbooks.filter((p) =>
				p.targets.some((k) => report.target.kinds.includes(k)),
			);
			if (books.length)
				text += `\n\nPlaybooks for this target: ${books.map((p) => p.id).join(", ")} (get_playbook → submit_findings with reportId ${reportId}).`;
			return textResult(text, {
				reportId,
				...(reportPath ? { reportPath } : {}),
				...(saved && !saved.saved ? { notSaved: saved.reason } : {}),
				gatePassed,
				...(failOn ? { failOn } : {}),
				summary: report.summary,
				report: JSON.parse(toJson(report)),
			});
		},
	);

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
			if (format === "html") {
				const html = toHtml(report);
				const saved = await persist(reportId, report, "html", html);
				let path: string;
				if (saved.saved) path = saved.path;
				else {
					// A private, freshly created directory: nothing to follow or race.
					const dir = await mkdtemp(join(tmpdir(), "openaudit-"));
					path = join(dir, `${reportId}.html`);
					await writeFile(path, html, { flag: "wx", mode: 0o600 });
				}
				return textResult(`HTML report written to ${path}`, {
					reportId,
					format,
					path,
				});
			}
			const content =
				format === "json"
					? toJson(report)
					: format === "sarif"
						? toSarif(report)
						: format === "csv"
							? toCsv(report)
							: toMarkdown(report);
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
				lines.push(
					"",
					"References:",
					...finding.references.map((r) => `- ${r}`),
				);
			return textResult(lines.join("\n"), {
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
			let id = reportId;
			let base: Report | undefined;
			if (id) base = getReport(id);
			else if (target) {
				const res = await run(
					runAudit({ target: await resolveInput(target), auditors: [] }).pipe(
						Effect.provide(CoreLive),
					),
				);
				if (!res.ok) return errorResult(res.error);
				base = res.value;
				id = ReportStore.newId();
			} else {
				return errorResult("Pass reportId (from run_audit) or target.");
			}
			const { report, added } = mergeAgentFindings(
				base,
				p,
				findings as ReadonlyArray<FindingInput>,
			);
			const saved = await store.put(id, report);
			const reportPath = saved?.saved ? saved.path : undefined;
			const note = saveNote(saved);
			return textResult(
				[
					`Merged ${added.length} finding(s) from ${p.id} into report ${id}.`,
					...(note ? [note] : []),
					`Score: ${report.summary.score}/100 (${report.summary.grade}) | ${countsText(report.summary.counts)}`,
					...added.map(findingLine),
				].join("\n"),
				{
					reportId: id,
					...(reportPath ? { reportPath } : {}),
					...(saved && !saved.saved ? { notSaved: saved.reason } : {}),
					accepted: added.length,
					fingerprints: added.map((f) => f.fingerprint),
					summary: report.summary,
				},
			);
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

/** ±5 lines around a file finding, confined to the target root. */
const sourceContext = async (
	report: Report,
	loc: { file?: string; line?: number } | undefined,
) => {
	if (!report.target.root || !loc?.file) return undefined;
	// Findings come from untrusted targets: never follow paths or symlinks out of the root.
	const root = await realpath(report.target.root).catch(() => undefined);
	const abs = root
		? await realpath(resolve(root, loc.file)).catch(() => undefined)
		: undefined;
	if (!root || !abs?.startsWith(root.endsWith(sep) ? root : root + sep))
		return undefined;
	const file = Bun.file(abs);
	if (!(await file.exists()) || file.size > 2 * 1024 * 1024) return undefined;
	const lines = (await file.text()).split(/\r?\n/);
	const line = Math.max(1, loc.line ?? 1);
	const startLine = Math.max(1, line - 5);
	const endLine = Math.min(lines.length, line + 5);
	const width = String(endLine).length;
	const text = lines
		.slice(startLine - 1, endLine)
		.map(
			(l, i) =>
				`${startLine + i === loc.line ? ">" : " "} ${String(startLine + i).padStart(width)} | ${l}`,
		)
		.join("\n");
	return { file: loc.file, startLine, endLine, text };
};

const auditProjectPrompt = (
	target: string,
	focus: string | undefined,
	playbooks: ReadonlyArray<Playbook>,
) => `Audit ${target} with the openaudit MCP tools${focus ? `, focusing on ${focus}` : ""}.

1. Call detect_target with target "${target}" to see its kinds, technologies and which auditors will run.
2. Call run_audit with that target${focus ? ` and categories that match "${focus}"` : ""}. Keep the reportId. If auditors were skipped for missing tools, mention how to install them, but do not install anything without asking.
3. Triage: group findings by root cause, discard likely false positives (say why), and use get_finding for remediation and source context on anything critical or high.
4. Judgment work: pick the relevant playbooks (${playbooks.map((p) => p.id).join(", ")}). For each, call get_playbook, follow its instructions and checklist with your own tools, then call submit_findings with the same reportId, even when you found nothing.
5. Propose fixes, most severe first. Apply them only with the user's approval, keeping each change small and explained.
6. Call run_audit again, then compare_reports(base, head) to show what was fixed and confirm nothing new appeared.
7. Finish with a short summary: score before and after, what remains, and what needs a human decision. Use get_report with format markdown if the user wants a PR comment.

Never print secrets from evidence; refer to them by file and line.`;

/** Serves openaudit over stdio until the client disconnects. */
export const startStdioServer = async (
	options: ServerOptions = {},
): Promise<McpServer> => {
	const server = createServer(options);
	await server.connect(new StdioServerTransport());
	return server;
};
