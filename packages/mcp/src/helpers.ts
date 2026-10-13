import { realpath, stat } from "node:fs/promises";
import { resolve, sep } from "node:path";
import type * as Agent from "@openaudit/agent";
import type { Auditor, Report } from "@openaudit/core";
import { Effect } from "effect";

type Playbook = Agent.Playbook;

export const textResult = (
	text: string,
	structuredContent?: Record<string, unknown>,
) => ({
	content: [{ type: "text" as const, text }],
	...(structuredContent ? { structuredContent } : {}),
});

export const errorResult = (message: string) => ({
	content: [{ type: "text" as const, text: message }],
	isError: true,
});

export const auditorInfo = (a: Auditor) => ({
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

export const playbookInfo = (p: Playbook) => ({
	id: p.id,
	title: p.title,
	summary: p.summary,
	categories: [...p.categories],
	targets: [...p.targets],
	needs: [...p.needs],
});

export const findingExample = (p: Playbook) => ({
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

export const playbookText = (
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
export const run = <A, E extends { readonly message: string }>(
	effect: Effect.Effect<A, E>,
): Promise<{ ok: true; value: A } | { ok: false; error: string }> =>
	Effect.runPromise(Effect.result(effect)).then((r) =>
		r._tag === "Success"
			? { ok: true as const, value: r.success }
			: { ok: false as const, error: r.failure.message },
	);

/** ±5 lines around a file finding, confined to the target root. */
export const sourceContext = async (
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
	// Regular files only: a FIFO or device planted in the target would hang the read.
	const info = await stat(abs).catch(() => undefined);
	if (!info?.isFile() || info.size > 2 * 1024 * 1024) return undefined;
	const file = Bun.file(abs);
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
