import { describe, expect, test } from "bun:test";
import { Effect } from "effect";

import {
	type Auditor,
	AuditorError,
	CoreLive,
	defineAuditor,
	matchesPattern,
	runAudit,
	SkipAudit,
	selectAuditors,
} from "../src";

const fake = (id: string, overrides: Partial<Auditor> = {}): Auditor =>
	defineAuditor({
		id,
		title: id,
		description: id,
		categories: ["security"],
		targets: ["codebase"],
		engine: "builtin",
		run: () =>
			Effect.succeed([
				{
					ruleId: `${id}/rule`,
					title: "t",
					severity: "high",
					category: "security",
					message: "m",
					location: { file: "a.ts", line: 1 },
				},
			]),
		...overrides,
	});

const run = (
	auditors: Auditor[],
	extra: Partial<Parameters<typeof runAudit>[0]> = {},
) =>
	Effect.runPromise(
		runAudit({ target: import.meta.dir, auditors, ...extra }).pipe(
			Effect.provide(CoreLive),
		),
	);

describe("matchesPattern", () => {
	test("exact, prefix and wildcard", () => {
		expect(matchesPattern("web.headers", "web.headers")).toBe(true);
		expect(matchesPattern("web.headers", "web")).toBe(true);
		expect(matchesPattern("web.headers", "web.*")).toBe(true);
		expect(matchesPattern("webapp.browser", "web")).toBe(false);
	});
});

describe("selectAuditors", () => {
	const auditors = [
		fake("code.a"),
		fake("code.b", { defaultEnabled: false }),
		fake("agent.c", { engine: "agentic" }),
		fake("web.d", { targets: ["url"] }),
	];
	test("filters by target kind and defaults", () => {
		expect(selectAuditors(auditors, ["codebase"]).map((a) => a.id)).toEqual([
			"code.a",
		]);
	});
	test("agentic auditors need opt-in", () => {
		expect(
			selectAuditors(auditors, ["codebase"], {}, { agentic: true }).map(
				(a) => a.id,
			),
		).toEqual(["code.a", "agent.c"]);
	});
	test("explicit selection overrides defaults", () => {
		expect(
			selectAuditors(auditors, ["codebase"], { only: ["code"] }).map(
				(a) => a.id,
			),
		).toEqual(["code.a", "code.b"]);
	});
});

describe("runAudit", () => {
	test("captures skips, errors and defects per auditor", async () => {
		const report = await run([
			fake("code.ok"),
			fake("code.skip", {
				run: () => Effect.fail(new SkipAudit({ reason: "no tool" })),
			}),
			fake("code.err", {
				run: () => Effect.fail(new AuditorError({ message: "boom" })),
			}),
			fake("code.die", { run: () => Effect.die(new Error("kaboom")) }),
		]);
		const status = Object.fromEntries(
			report.results.map((r) => [r.auditor, r.status]),
		);
		expect(status).toEqual({
			"code.ok": "failed",
			"code.skip": "skipped",
			"code.err": "error",
			"code.die": "error",
		});
		expect(report.summary.counts.high).toBe(1);
		expect(report.summary.score).toBe(73);
		expect(report.target.type).toBe("directory");
	});

	test("suppresses by rule and fingerprint", async () => {
		const first = await run([fake("code.ok")]);
		const fp = first.results[0]?.findings[0]?.fingerprint ?? "";
		expect(fp).toHaveLength(16);
		const byFp = await run([fake("code.ok")], {
			suppress: { fingerprints: [fp] },
		});
		expect(byFp.results[0]?.status).toBe("passed");
		const byRule = await run([fake("code.ok")], {
			suppress: { rules: ["code.ok/*"] },
		});
		expect(byRule.summary.counts.high).toBe(0);
	});

	test("times out slow auditors", async () => {
		const report = await run([fake("code.slow", { run: () => Effect.never })], {
			timeoutMs: 50,
		});
		expect(report.results[0]?.status).toBe("error");
		expect(report.results[0]?.message).toContain("Timed out");
	});

	test("rejects missing targets", async () => {
		const result = await Effect.runPromise(
			runAudit({ target: "/definitely/not/here", auditors: [] }).pipe(
				Effect.provide(CoreLive),
				Effect.flip,
			),
		);
		expect(result._tag).toBe("TargetError");
	});

	test("url targets", async () => {
		const report = await Effect.runPromise(
			runAudit({
				target: "https://example.com",
				auditors: [],
				options: { browser: true },
			}).pipe(Effect.provide(CoreLive)),
		);
		expect(report.target.kinds).toEqual(["url", "webapp"]);
	});
});
