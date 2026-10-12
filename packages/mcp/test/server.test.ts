import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { Playbook } from "@openaudit/agent";
import {
	type Auditor,
	defineAuditor,
	Report as ReportSchema,
} from "@openaudit/core";
import { Effect, Schema } from "effect";

import { createServer } from "../src";
import * as S from "../src/schemas";

const fixtureAuditor: Auditor = defineAuditor({
	id: "test.fixture",
	title: "Fixture auditor",
	description: "Flags TODO comments",
	categories: ["maintainability"],
	targets: ["codebase"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = ctx.workspace;
			if (!ws) return [];
			const text = yield* ws.readText("app.ts");
			if (!text.includes("TODO")) return [];
			return [
				{
					ruleId: "test.fixture/todo",
					title: "TODO left in code",
					severity: "medium" as const,
					category: "maintainability" as const,
					message: "A TODO comment remains.",
					location: { file: "app.ts", line: 3 },
					evidence: "// TODO",
					remediation: "Resolve the TODO.",
				},
			];
		}),
});

const playbook: Playbook = {
	id: "agent.authz",
	title: "Authorization review",
	summary: "Check object-level authorization",
	categories: ["security"],
	targets: ["codebase", "webapp"],
	needs: ["code"],
	instructions: "Look for missing ownership checks.",
	checklist: ["Every route checks ownership"],
};

let dir: string;
let client: Client;

const call = async (name: string, args: Record<string, unknown>) => {
	const res = await client.callTool({ name, arguments: args });
	return res as {
		isError?: boolean;
		content: Array<{ type: string; text: string }>;
		structuredContent: Record<string, unknown>;
	};
};

beforeAll(async () => {
	dir = await mkdtemp(join(tmpdir(), "openaudit-mcp-"));
	await writeFile(
		join(dir, "app.ts"),
		"export const a = 1;\n\n// TODO remove\nexport const b = 2;\n",
	);
	const server = createServer({
		auditors: [fixtureAuditor],
		playbooks: [playbook],
	});
	const [clientT, serverT] = InMemoryTransport.createLinkedPair();
	client = new Client({ name: "test", version: "1.0.0" });
	await Promise.all([server.connect(serverT), client.connect(clientT)]);
});

afterAll(async () => {
	await client.close();
	await rm(dir, { recursive: true, force: true });
});

describe("mcp server", () => {
	test("lists tools with annotations and output schemas", async () => {
		const { tools } = await client.listTools();
		const names = tools.map((t) => t.name).sort();
		expect(names).toEqual([
			"compare_reports",
			"detect_target",
			"get_finding",
			"get_playbook",
			"get_report",
			"list_auditors",
			"list_playbooks",
			"run_audit",
			"submit_findings",
		]);
		const runAudit = tools.find((t) => t.name === "run_audit");
		expect(runAudit?.annotations?.openWorldHint).toBe(true);
		expect(runAudit?.outputSchema).toBeDefined();
		const list = tools.find((t) => t.name === "list_auditors");
		expect(list?.annotations?.readOnlyHint).toBe(true);
		expect(client.getInstructions()).toContain("compare_reports");
	});

	test("exposes prompts and resources", async () => {
		const { prompts } = await client.listPrompts();
		expect(prompts.map((p) => p.name)).toContain("audit_project");
		expect(prompts.map((p) => p.name)).toContain("playbook_agent_authz");
		const prompt = await client.getPrompt({
			name: "audit_project",
			arguments: { target: dir },
		});
		const first = prompt.messages[0]?.content;
		expect(first?.type === "text" && first.text).toContain("run_audit");
		const res = await client.readResource({ uri: "openaudit://auditors" });
		const body = res.contents[0] as { text: string };
		expect(JSON.parse(body.text).auditors[0].id).toBe("test.fixture");
	});

	test("detect_target", async () => {
		const res = await call("detect_target", { target: dir });
		expect(res.isError).toBeFalsy();
		expect(res.structuredContent.auditors).toEqual(["test.fixture"]);
		expect(res.structuredContent.playbooks).toContain("agent.authz");
	});

	let baseId = "";
	let fingerprint = "";

	test("run_audit returns summary, full report and progress", async () => {
		const progress: number[] = [];
		const res = (await client.callTool(
			{ name: "run_audit", arguments: { target: dir, failOn: "medium" } },
			undefined,
			{ onprogress: (p) => progress.push(p.progress) },
		)) as unknown as {
			content: Array<{ text: string }>;
			structuredContent: {
				reportId: string;
				reportPath: string;
				gatePassed: boolean;
				report: unknown;
			};
		};
		const sc = res.structuredContent;
		expect(sc.gatePassed).toBe(false);
		expect(sc.reportPath).toContain(join(".openaudit", "reports"));
		expect(await Bun.file(sc.reportPath).exists()).toBe(true);
		expect(Schema.decodeUnknownExit(ReportSchema)(sc.report)._tag).toBe(
			"Success",
		);
		expect(S.report.safeParse(sc.report).success).toBe(true);
		expect(res.content[0]?.text).toContain("TODO left in code");
		expect(progress.length).toBeGreaterThan(0);
		baseId = sc.reportId;
		const report = sc.report as {
			results: Array<{ findings: Array<{ fingerprint: string }> }>;
		};
		fingerprint = report.results[0]?.findings[0]?.fingerprint ?? "";
	});

	test("get_finding includes source context", async () => {
		const res = await call("get_finding", { reportId: baseId, fingerprint });
		const source = res.structuredContent.source as { text: string };
		expect(source.text).toContain(">");
		expect(source.text).toContain("// TODO remove");
	});

	test("get_report renders markdown, sarif and html", async () => {
		const md = await call("get_report", {
			reportId: baseId,
			format: "markdown",
		});
		expect(md.content[0]?.text).toContain("openaudit");
		const sarif = await call("get_report", {
			reportId: baseId,
			format: "sarif",
		});
		expect(JSON.parse(sarif.content[0]?.text ?? "").version).toBe("2.1.0");
		const html = await call("get_report", { reportId: baseId, format: "html" });
		expect(await Bun.file(html.structuredContent.path as string).exists()).toBe(
			true,
		);
	});

	test("submit_findings merges agent findings and rescored", async () => {
		const before = (
			await call("get_report", { reportId: baseId, format: "json" })
		).structuredContent.content as string;
		const res = await call("submit_findings", {
			reportId: baseId,
			playbookId: "agent.authz",
			findings: [
				{
					ruleId: "idor-orders",
					title: "IDOR on orders",
					severity: "high",
					category: "security",
					message: "Orders are not scoped to the user.",
					location: { file: "app.ts", line: 1 },
				},
			],
		});
		expect(res.isError).toBeFalsy();
		expect(res.structuredContent.accepted).toBe(1);
		const summary = res.structuredContent.summary as {
			counts: { high: number };
			score: number;
		};
		expect(summary.counts.high).toBe(1);
		expect(summary.score).toBeLessThan(JSON.parse(before).summary.score);
		const after = JSON.parse(
			(await call("get_report", { reportId: baseId, format: "json" }))
				.structuredContent.content as string,
		);
		const agentResult = after.results.find(
			(r: { auditor: string }) => r.auditor === "agent.authz",
		);
		expect(agentResult.engine).toBe("agentic");
		expect(agentResult.findings[0].ruleId).toBe("agent.authz/idor-orders");
		// idempotent
		const again = await call("submit_findings", {
			reportId: baseId,
			playbookId: "agent.authz",
			findings: [
				{
					ruleId: "idor-orders",
					title: "IDOR on orders",
					severity: "high",
					category: "security",
					message: "Orders are not scoped to the user.",
					location: { file: "app.ts", line: 1 },
				},
			],
		});
		expect(
			(again.structuredContent.summary as { counts: { high: number } }).counts
				.high,
		).toBe(1);
	});

	test("submit_findings validates input", async () => {
		const res = await call("submit_findings", {
			reportId: baseId,
			playbookId: "agent.authz",
			findings: [{ ruleId: "x", severity: "catastrophic" }],
		});
		expect(res.isError).toBe(true);
	});

	test("compare_reports shows fixed findings", async () => {
		await writeFile(join(dir, "app.ts"), "export const a = 1;\n");
		const head = await call("run_audit", { target: dir });
		const res = await call("compare_reports", {
			baseReportId: baseId,
			headReportId: head.structuredContent.reportId as string,
		});
		const fixed = res.structuredContent.fixed as Array<{ ruleId: string }>;
		expect(fixed.map((f) => f.ruleId).sort()).toEqual([
			"agent.authz/idor-orders",
			"test.fixture/todo",
		]);
		expect(res.structuredContent.new).toEqual([]);
		expect(res.structuredContent.scoreDelta as number).toBeGreaterThan(0);
	});

	test("unknown report ids are tool errors", async () => {
		const res = await call("get_report", { reportId: "nope", format: "json" });
		expect(res.isError).toBe(true);
		expect(res.content[0]?.text).toContain("Unknown reportId");
	});
});
