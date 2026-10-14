import { relative, resolve } from "node:path";
import { createSdkMcpServer, tool } from "@anthropic-ai/claude-agent-sdk";
import {
	type AuditContext,
	type FindingInput,
	redact,
	VERSION,
} from "@openaudit/core";
import { Effect } from "effect";
import { z } from "zod";

import type { Playbook } from "../playbook";
import type { Scope } from "./scope";
import { MAX_BODY_CHARS, MAX_EVIDENCE_CHARS, MAX_HTTP_CALLS } from "./settings";
import { realPath, within } from "./tool-guard";

/* -------------------------------------------------------------------------- */
/*                               Reporting tools                              */
/* -------------------------------------------------------------------------- */

/** A type alias (not an interface) so it is assignable to MCP's CallToolResult. */
export type ToolResult = {
	readonly content: Array<{ type: "text"; text: string }>;
	readonly isError?: boolean;
};
export type ToolHandler = (args: unknown) => Promise<ToolResult>;

const text = (message: string, isError = false): ToolResult => ({
	content: [{ type: "text", text: message }],
	...(isError ? { isError } : {}),
});

const FindingShape = {
	ruleId: z
		.string()
		.min(1)
		.max(100)
		.describe(
			"Short kebab-case rule suffix naming the issue class, e.g. `idor-order-read`. The playbook id is prefixed automatically.",
		),
	title: z.string().min(3).max(200).describe("One specific line."),
	severity: z.enum(["critical", "high", "medium", "low", "info"]),
	category: z.enum([
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
	]),
	message: z
		.string()
		.min(10)
		.max(4_000)
		.describe("What is wrong, how it is reached, and the impact."),
	location: z
		.object({
			file: z
				.string()
				.optional()
				.describe("Path relative to the project root."),
			line: z.number().int().positive().optional(),
			column: z.number().int().positive().optional(),
			url: z.string().optional(),
			selector: z.string().optional(),
		})
		.optional(),
	evidence: z
		.string()
		.max(8_000)
		.optional()
		.describe("Shortest redacted snippet or observation proving the issue."),
	remediation: z.string().max(4_000).optional(),
	references: z.array(z.string()).max(10).optional(),
	confidence: z.enum(["high", "medium", "low"]).optional(),
	tags: z
		.array(z.string())
		.max(10)
		.optional()
		.describe("e.g. cwe-639, owasp-a01, wcag-2.4.3"),
};
const FindingArgs = z.object(FindingShape);

const FinishShape = {
	summary: z.string().max(4_000).describe("What you reviewed and concluded."),
	coverage: z
		.string()
		.max(4_000)
		.optional()
		.describe("What you could not cover and why."),
};
const FinishArgs = z.object(FinishShape);

const HttpShape = {
	url: z.string().describe("Absolute URL or path on the target origin."),
	method: z.enum(["GET", "HEAD"]).optional(),
};
const HttpArgs = z.object(HttpShape);

/** Token formats worth masking even if the agent forgot to. */
const SECRET_PATTERNS: ReadonlyArray<RegExp> = [
	/\b(AKIA|ASIA)[A-Z0-9]{16}\b/g,
	/\b(sk|rk|pk)_(live|test)_[A-Za-z0-9]{10,}\b/g,
	/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,
	/\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g,
	/\bsk-[A-Za-z0-9_-]{20,}\b/g,
	/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
];

export const scrubSecrets = (value: string): string => {
	let out = value.replace(
		/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g,
		"-----BEGIN PRIVATE KEY----- [redacted]",
	);
	for (const re of SECRET_PATTERNS) out = out.replace(re, (m) => redact(m));
	return out;
};

export const truncate = (value: string, max: number) =>
	value.length > max ? `${value.slice(0, max)}…` : value;

const normalizeRuleId = (playbookId: string, raw: string): string => {
	const trimmed = raw.trim();
	const suffix = (
		trimmed.startsWith(`${playbookId}/`)
			? trimmed.slice(playbookId.length + 1)
			: trimmed
	)
		.toLowerCase()
		.replace(/[^a-z0-9/]+/g, "-")
		.replace(/^[-/]+|[-/]+$/g, "");
	return `${playbookId}/${suffix || "finding"}`;
};

interface Session {
	readonly findings: FindingInput[];
	finished: { summary: string; coverage?: string } | undefined;
	httpCalls: number;
	handlers: Readonly<Record<string, ToolHandler>>;
}

export const makeSession = (
	playbook: Playbook,
	ctx: AuditContext,
	scope: Scope,
	maxFindings: number,
): Session => {
	const session: Session = {
		findings: [],
		finished: undefined,
		httpCalls: 0,
		handlers: {},
	};

	const normalizeFile = async (
		file: string,
	): Promise<string | { error: string }> => {
		if (!scope.root || !ctx.workspace) return file;
		const abs = resolve(scope.root, file);
		if (!within(realPath("/", scope.root), realPath(scope.root, file)))
			return { error: `${file} is outside the project root.` };
		const rel = relative(scope.root, abs).split("\\").join("/");
		const exists = await Effect.runPromise(ctx.workspace.exists(rel));
		return exists
			? rel
			: {
					error: `${file} does not exist. Use a path relative to the project root (${scope.root}) that you actually read.`,
				};
	};

	const reportFinding: ToolHandler = async (args) => {
		const parsed = FindingArgs.safeParse(args);
		if (!parsed.success)
			return text(
				`Invalid finding, nothing recorded:\n${z.prettifyError(parsed.error)}`,
				true,
			);
		if (session.findings.length >= maxFindings)
			return text(
				`Finding limit reached (${maxFindings}); nothing recorded. Merge related issues into existing findings' root causes, then call finish.`,
				true,
			);
		const f = parsed.data;
		let location = f.location;
		if (location?.file) {
			const file = await normalizeFile(location.file);
			if (typeof file !== "string") return text(file.error, true);
			location = { ...location, file };
		}
		const finding: FindingInput = {
			ruleId: normalizeRuleId(playbook.id, f.ruleId),
			title: f.title,
			severity: f.severity,
			category: f.category,
			message: scrubSecrets(f.message),
			...(location ? { location } : {}),
			...(f.evidence
				? { evidence: truncate(scrubSecrets(f.evidence), MAX_EVIDENCE_CHARS) }
				: {}),
			...(f.remediation ? { remediation: f.remediation } : {}),
			...(f.references?.length ? { references: f.references } : {}),
			confidence: f.confidence ?? "medium",
			tags: ["agentic", ...(f.tags ?? [])],
		};
		session.findings.push(finding);
		return text(
			`Recorded ${finding.ruleId} (${session.findings.length}/${maxFindings}).`,
		);
	};

	const finish: ToolHandler = async (args) => {
		const parsed = FinishArgs.safeParse(args);
		if (!parsed.success)
			return text(`Invalid input:\n${z.prettifyError(parsed.error)}`, true);
		session.finished = parsed.data;
		return text(
			`Audit complete with ${session.findings.length} finding(s). Stop now; do not call further tools.`,
		);
	};

	const httpGet: ToolHandler = async (args) => {
		const parsed = HttpArgs.safeParse(args);
		if (!parsed.success || !scope.url)
			return text("Invalid input or no URL target.", true);
		if (++session.httpCalls > MAX_HTTP_CALLS)
			return text(`Request limit reached (${MAX_HTTP_CALLS}).`, true);
		let url: URL;
		try {
			url = new URL(parsed.data.url, scope.url);
		} catch {
			return text(`Invalid URL: ${parsed.data.url}`, true);
		}
		if (url.origin !== new URL(scope.url).origin)
			return text(
				`Only the target origin ${new URL(scope.url).origin} may be requested with this tool.`,
				true,
			);
		return Effect.runPromise(
			ctx
				.http(url.toString(), {
					method: parsed.data.method ?? "GET",
					redirect: "manual",
					timeoutMs: 20_000,
					maxBytes: 500_000,
				})
				.pipe(
					Effect.match({
						onFailure: (error) => text(error.message, true),
						onSuccess: (res) => {
							const headers = [...res.headers.entries()]
								.filter(([name]) => name !== "set-cookie")
								.map(([name, value]) => `${name}: ${value}`);
							// Cookie attributes matter for the audit; values never do.
							const cookies = res.cookies.map(
								(c) =>
									`set-cookie: ${c.replace(/^([^=]*)=[^;]*/, "$1=<redacted>")}`,
							);
							return text(
								[
									`HTTP ${res.status} ${res.url} (${res.bytes} bytes, ${Math.round(res.totalMs)} ms)`,
									...headers,
									...cookies,
									"",
									truncate(res.body, MAX_BODY_CHARS),
								].join("\n"),
							);
						},
					}),
				),
		);
	};

	session.handlers = {
		report_finding: reportFinding,
		finish,
		...(scope.url ? { http_get: httpGet } : {}),
	};
	return session;
};

export const reportingServer = (session: Session) => {
	const handler = (name: string) => (args: unknown) =>
		session.handlers[name]?.(args) ??
		Promise.resolve(text("Unknown tool", true));
	return createSdkMcpServer({
		name: "openaudit",
		version: VERSION,
		tools: [
			tool(
				"report_finding",
				"Record one confirmed audit finding. Call it as soon as an issue is confirmed (do not batch until the end). Returns an error if the input is invalid or the file does not exist; fix and retry.",
				FindingShape,
				handler("report_finding"),
			),
			tool(
				"finish",
				"Call exactly once when the audit is complete, with a summary and coverage notes. Then stop.",
				FinishShape,
				handler("finish"),
			),
			...(session.handlers.http_get
				? [
						tool(
							"http_get",
							"GET or HEAD a URL on the target origin and return the raw status line, response headers (cookie values redacted) and body (truncated). Uses the user's configured headers. This is the only way to fetch pages without a browser.",
							HttpShape,
							handler("http_get"),
						),
					]
				: []),
		],
	});
};
