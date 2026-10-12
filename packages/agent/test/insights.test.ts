import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import type {
	BetaMessage,
	MessageCreateParamsNonStreaming,
} from "@anthropic-ai/sdk/resources/beta/messages/messages";
import {
	type AuditorResult,
	type Finding,
	type Report,
	SCHEMA_VERSION,
	summarize,
} from "@openaudit/core";
import { Effect } from "effect";

import { aiInsights, compactReport, type InsightsClient } from "../src";

const finding = (i: number, overrides: Partial<Finding> = {}): Finding => ({
	ruleId: "code.secrets/aws-key",
	title: `Secret ${i}`,
	severity: "critical",
	category: "security",
	message: "AWS access key committed",
	location: { file: `src/config${i}.ts`, line: i + 1 },
	evidence: "AKIAREALSECRETVALUE1",
	remediation: "Rotate the key",
	auditor: "code.secrets",
	fingerprint: `fp${i}`,
	...overrides,
});

const reportOf = (findings: Finding[]): Report => {
	const results: AuditorResult[] = [
		{
			auditor: "code.secrets",
			title: "Secrets",
			engine: "builtin",
			categories: ["security"],
			status: findings.length ? "failed" : "passed",
			durationMs: 1,
			findings,
		},
	];
	return {
		schemaVersion: SCHEMA_VERSION,
		tool: { name: "openaudit", version: "0.1.0" },
		target: {
			input: "/home/alice/project",
			type: "directory",
			root: "/home/alice/project",
			kinds: ["codebase"],
			technologies: ["node"],
		},
		startedAt: new Date(0).toISOString(),
		finishedAt: new Date(1).toISOString(),
		durationMs: 1,
		summary: summarize(results),
		results,
	};
};

const reply = (
	content: unknown,
	overrides: Partial<BetaMessage> = {},
): BetaMessage =>
	({
		id: "msg_1",
		type: "message",
		role: "assistant",
		model: "claude-opus-5-5",
		content: [{ type: "text", text: JSON.stringify(content) }],
		stop_reason: "end_turn",
		stop_details: null,
		usage: {},
		...overrides,
	}) as unknown as BetaMessage;

const fakeClient = (message: BetaMessage) => {
	const calls: MessageCreateParamsNonStreaming[] = [];
	const client: InsightsClient = {
		create: async (params) => {
			calls.push(params);
			return message;
		},
	};
	return { client, calls };
};

const outcome = (effect: ReturnType<typeof aiInsights>) =>
	Effect.runPromise(
		effect.pipe(
			Effect.match({
				onSuccess: (value) => ({ ok: true as const, value }),
				onFailure: (e) => ({ ok: false as const, message: e.message }),
			}),
		),
	);

describe("aiInsights", () => {
	test("sends metadata only and validates the structured result", async () => {
		const { client, calls } = fakeClient(
			reply({
				summary: "Leaked AWS keys dominate the risk.",
				priorities: [
					{
						title: "Rotate leaked AWS keys",
						why: "Keys grant cloud access",
						fix: "Rotate and move to a secret manager",
						fingerprints: ["fp0", "fp1", "fp1", "not-a-real-fp"],
					},
				],
			}),
		);
		const report = reportOf([finding(0), finding(1)]);
		const out = await outcome(aiInsights(report, { client }));

		expect(out.ok).toBe(true);
		if (!out.ok) return;
		expect(out.value.model).toBe("claude-opus-5-5");
		expect(out.value.priorities[0]?.fingerprints).toEqual(["fp0", "fp1"]);

		const sent = JSON.stringify(calls[0]);
		expect(sent).not.toContain("AKIAREALSECRETVALUE1");
		expect(sent).not.toContain("Rotate the key");
		expect(sent).not.toContain("/home/alice");
		expect(sent).toContain("fp0");
		expect(calls[0]?.model).toBe("claude-opus-5-5");
		expect(calls[0]?.output_config?.format?.type).toBe("json_schema");
		expect(calls[0]?.fallbacks).toBe("default");
	});

	test("model override skips fallbacks for models without them", async () => {
		const { client, calls } = fakeClient(
			reply({ summary: "s", priorities: [] }),
		);
		await outcome(
			aiInsights(reportOf([finding(0)]), { client, model: "claude-haiku-5-5" }),
		);
		expect(calls[0]?.model).toBe("claude-haiku-5-5");
		expect(calls[0]?.fallbacks).toBeUndefined();
	});

	test("caps priorities at ten", async () => {
		const priorities = Array.from({ length: 14 }, (_, i) => ({
			title: `p${i}`,
			why: "w",
			fix: "f",
			fingerprints: ["fp0"],
		}));
		const { client } = fakeClient(reply({ summary: "s", priorities }));
		const out = await outcome(aiInsights(reportOf([finding(0)]), { client }));
		expect(out.ok && out.value.priorities.length).toBe(10);
	});

	test("refusals and schema mismatches are AuditorErrors", async () => {
		const refused = fakeClient(
			reply({}, {
				stop_reason: "refusal",
				stop_details: {
					type: "refusal",
					category: "cyber",
					explanation: null,
				},
			} as Partial<BetaMessage>),
		);
		const r1 = await outcome(
			aiInsights(reportOf([finding(0)]), { client: refused.client }),
		);
		expect(r1).toMatchObject({ ok: false });
		expect((r1 as { message: string }).message).toContain("declined");

		const bad = fakeClient(reply({ nope: true }));
		const r2 = await outcome(
			aiInsights(reportOf([finding(0)]), { client: bad.client }),
		);
		expect((r2 as { message: string }).message).toContain("schema");
	});

	test("empty reports do not call the API", async () => {
		const { client, calls } = fakeClient(reply({}));
		const out = await outcome(aiInsights(reportOf([]), { client }));
		expect(out.ok && out.value.priorities).toEqual([]);
		expect(calls).toHaveLength(0);
	});

	describe("without credentials", () => {
		const saved = {
			key: process.env.ANTHROPIC_API_KEY,
			token: process.env.ANTHROPIC_AUTH_TOKEN,
		};
		beforeEach(() => {
			delete process.env.ANTHROPIC_API_KEY;
			delete process.env.ANTHROPIC_AUTH_TOKEN;
		});
		afterEach(() => {
			if (saved.key !== undefined) process.env.ANTHROPIC_API_KEY = saved.key;
			if (saved.token !== undefined)
				process.env.ANTHROPIC_AUTH_TOKEN = saved.token;
		});

		test("fails with a clear message", async () => {
			const out = await outcome(aiInsights(reportOf([finding(0)])));
			expect(out).toMatchObject({ ok: false });
			expect((out as { message: string }).message).toContain(
				"ANTHROPIC_API_KEY",
			);
		});
	});
});

describe("compactReport", () => {
	test("details a few findings per rule and summarises the rest", () => {
		const findings = Array.from({ length: 30 }, (_, i) => finding(i));
		const compact = compactReport(reportOf(findings));
		expect(compact.findings).toHaveLength(8);
		expect(compact.moreFindingsByRule).toEqual([
			{
				ruleId: "code.secrets/aws-key",
				severity: "critical",
				count: 22,
				fingerprints: findings.slice(8).map((f) => f.fingerprint),
			},
		]);
		expect(compact.totalFindings).toBe(30);
	});

	test("strips query strings from URLs", () => {
		const compact = compactReport(
			reportOf([
				finding(0, {
					location: { url: "https://x.test/reset?token=abc123#frag" },
				}),
			]),
		);
		expect(compact.findings[0]?.location).toBe("https://x.test/reset");
	});
});
