import { describe, expect, test } from "bun:test";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { Effect } from "effect";

import {
	candidateFiles,
	DeepsecSettings,
	deepsecCommands,
	makeDeepsecAuditor,
	parseDeepsecExport,
	recordedCostUsd,
} from "../src/deepsec";
import { codebaseContext, fixtureProject, urlContext } from "./helpers";

// Reconstructed from deepsec 2.3.10 `export` source (packages/cli export
// command), not recorded from a live run.
const exported = readFileSync(
	join(import.meta.dir, "fixtures/deepsec/export.json"),
	"utf8",
);

const outcome = (
	auditor: ReturnType<typeof makeDeepsecAuditor>,
	ctx: Parameters<ReturnType<typeof makeDeepsecAuditor>["run"]>[0],
) =>
	Effect.runPromise(
		auditor.run(ctx).pipe(
			Effect.match({
				onSuccess: (findings) => ({ ok: true as const, findings }),
				onFailure: (e) => ({
					ok: false as const,
					tag: e._tag,
					message: e._tag === "SkipAudit" ? e.reason : e.message,
				}),
			}),
		),
	);

const settings = (over: Record<string, unknown> = {}) =>
	DeepsecSettings.parse(over);

describe("parseDeepsecExport", () => {
	const findings = parseDeepsecExport(exported);

	test("drops resolved verdicts and maps the rest", () => {
		expect(findings.map((f) => f.ruleId)).toEqual([
			"agent.deepsec/idor",
			"agent.deepsec/other-code-injection",
			"agent.deepsec/pagination",
			"agent.deepsec/open-redirect",
		]);
	});

	test("maps severity, category and confidence", () => {
		const [idor, inj, bug, redirect] = findings;
		expect(idor?.severity).toBe("high");
		expect(idor?.confidence).toBe("high");
		expect(inj?.severity).toBe("critical");
		expect(inj?.confidence).toBe("medium");
		expect(bug?.severity).toBe("low");
		expect(bug?.category).toBe("reliability");
		expect(redirect?.confidence).toBe("low");
	});

	test("location, remediation, CWE references and tags", () => {
		const idor = findings[0];
		expect(idor?.location).toEqual({ file: "src/api/orders.ts", line: 12 });
		expect(idor?.remediation).toBe(
			"Constrain the query by the authenticated user id.",
		);
		expect(idor?.references).toEqual([
			"https://cwe.mitre.org/data/definitions/639.html",
		]);
		expect(idor?.tags).toEqual(["ai", "deepsec", "cwe-639"]);
		expect(idor?.title.startsWith("[")).toBe(false);
	});

	test("redacts secrets and rejects escaping paths", () => {
		expect(findings[0]?.message).not.toContain("abcdefghijklmnop1234");
		expect(findings[0]?.message).toContain("sk_l");
		expect(findings[2]?.location).toBeUndefined();
	});

	test("tolerates garbage", () => {
		expect(parseDeepsecExport("not json")).toEqual([]);
		expect(parseDeepsecExport({})).toEqual([]);
		expect(parseDeepsecExport([null, 3, { metadata: {} }])).toEqual([]);
	});
});

describe("settings and argv", () => {
	test("defaults", () => {
		expect(settings()).toMatchObject({
			maxCostUsd: 5,
			maxDuration: "30m",
			diff: false,
			maxFiles: 25,
		});
	});

	test("rejects hostile values", () => {
		for (const bad of [
			{ maxCostUsd: -1 },
			{ maxCostUsd: "5" },
			{ maxDuration: "30m; rm -rf /" },
			{ maxDuration: "1d" },
			{ diff: "--output=/etc/passwd" },
			{ diff: "main; id" },
			{ diff: "a..b" },
			{ model: "x --agent pi" },
			{ model: "$(id)" },
			{ provider: "evil" },
			{ thinkingLevel: "max" },
			{ maxFiles: 0 },
		])
			expect(DeepsecSettings.safeParse(bad).success).toBe(false);
	});

	test("full mode argv", () => {
		const c = deepsecCommands(
			settings({ model: "claude-opus-4-8" }),
			{ root: "/work/app", exportFile: "/tmp/x/export.json" },
			"claude",
		);
		expect(c.scan).toEqual([
			"deepsec",
			"scan",
			"--project-id",
			"openaudit",
			"--root",
			"/work/app",
		]);
		const p = c.process(["a.ts", "b.ts"]);
		expect(p.slice(0, 2)).toEqual(["deepsec", "process"]);
		expect(p).toContain("--files");
		expect(p[p.indexOf("--files") + 1]).toBe("a.ts,b.ts");
		expect(p[p.indexOf("--model") + 1]).toBe("claude-opus-4-8");
		expect(p).not.toContain("--diff");
		expect(c.export).toEqual([
			"deepsec",
			"export",
			"--format",
			"json",
			"--project-id",
			"openaudit",
			"--out",
			"/tmp/x/export.json",
		]);
	});

	test("diff mode argv", () => {
		const paths = { root: "/work/app", exportFile: "/t/e.json" };
		const ref = deepsecCommands(settings({ diff: "origin/dev" }), paths);
		const p = ref.process();
		expect(p[p.indexOf("--diff") + 1]).toBe("origin/dev");
		expect(p).not.toContain("--files");
		expect(deepsecCommands(settings({ diff: true }), paths).diffRef).toBe(
			"origin/main",
		);
	});
});

describe("agent.deepsec auditor", () => {
	const withKey = { ANTHROPIC_API_KEY: "sk-ant-test" };

	test("skips non-codebase targets", async () => {
		const r = await outcome(
			makeDeepsecAuditor(withKey),
			urlContext("https://example.com"),
		);
		expect(r).toMatchObject({ ok: false, tag: "SkipAudit" });
	});

	test("skips without the binary and hints how to install", async () => {
		const r = await outcome(
			makeDeepsecAuditor(withKey),
			codebaseContext(fixtureProject()),
		);
		expect(r).toMatchObject({ ok: false, tag: "SkipAudit" });
		expect(r.ok === false && r.message).toContain("npm i -g deepsec@");
	});

	test("skips without credentials", async () => {
		const ctx = codebaseContext(fixtureProject());
		const r = await outcome(makeDeepsecAuditor({}), {
			...ctx,
			exec: { ...ctx.exec, which: () => Effect.succeed("/bin/deepsec") },
		});
		expect(r).toMatchObject({ ok: false, tag: "SkipAudit" });
		expect(r.ok === false && r.message).toContain("ANTHROPIC_API_KEY");
	});

	test("fails on invalid settings instead of building argv", async () => {
		const ctx = codebaseContext(fixtureProject(), {
			settings: { "agent.deepsec": { diff: "x;y" } },
		});
		const r = await outcome(makeDeepsecAuditor(withKey), {
			...ctx,
			exec: { ...ctx.exec, which: () => Effect.succeed("/bin/deepsec") },
		});
		expect(r).toMatchObject({ ok: false, tag: "AuditorError" });
	});

	test("runs scan, chunked process with a cost cap, then export", async () => {
		const calls: string[][] = [];
		const base = codebaseContext(fixtureProject(), {
			settings: { "agent.deepsec": { maxCostUsd: 1, maxFiles: 12 } },
		});
		const record = (dataRoot: string, path: string, rec: object) => {
			const p = join(dataRoot, "openaudit/files", `${path}.json`);
			mkdirSync(dirname(p), { recursive: true });
			writeFileSync(p, JSON.stringify(rec));
		};
		const ctx = {
			...base,
			exec: {
				which: () => Effect.succeed("/bin/deepsec"),
				run: (
					cmd: ReadonlyArray<string>,
					o?: { env?: Record<string, string> },
				) => {
					calls.push([...cmd]);
					const dataRoot = o?.env?.DEEPSEC_DATA_ROOT as string;
					if (cmd[1] === "scan")
						for (let i = 0; i < 12; i++)
							record(dataRoot, `src/f${i}.ts`, {
								filePath: `src/f${i}.ts`,
								candidates: [{}, {}],
								analysisHistory: [],
							});
					if (cmd[1] === "process")
						record(dataRoot, `src/f${calls.length}.ts`, {
							filePath: `src/f${calls.length}.ts`,
							candidates: [{}],
							analysisHistory: [{ costUsd: 0.7 }],
						});
					if (cmd[1] === "export")
						writeFileSync(cmd[cmd.indexOf("--out") + 1] as string, exported);
					return Effect.succeed({
						code: cmd[1] === "process" ? 1 : 0,
						stdout: "",
						stderr: "",
					});
				},
			},
		};
		const r = await outcome(makeDeepsecAuditor(withKey), ctx);
		expect(r.ok).toBe(true);
		expect(r.ok && r.findings.length).toBe(4);
		expect(calls.map((c) => c[1])).toEqual([
			"scan",
			"process",
			"process",
			"export",
		]);
		expect(calls[0]).toContain(base.target.root as string);
	});
});

describe("data dir helpers", () => {
	test("candidateFiles and recordedCostUsd", () => {
		const dir = fixtureProject();
		const put = (p: string, rec: object) => {
			const f = join(dir, "openaudit/files", `${p}.json`);
			mkdirSync(dirname(f), { recursive: true });
			writeFileSync(f, JSON.stringify(rec));
		};
		put("a.ts", { filePath: "a.ts", candidates: [{}] });
		put("b.ts", { filePath: "b.ts", candidates: [{}, {}] });
		put("c,d.ts", { filePath: "c,d.ts", candidates: [{}, {}, {}] });
		put("-x.ts", { filePath: "-x.ts", candidates: [{}, {}, {}] });
		put("e.ts", {
			filePath: "e.ts",
			candidates: [],
			analysisHistory: [{ costUsd: 0.25 }, { costUsd: 0.5 }],
		});
		expect(candidateFiles(dir, 10)).toEqual(["b.ts", "a.ts"]);
		expect(candidateFiles(dir, 1)).toEqual(["b.ts"]);
		expect(recordedCostUsd(dir)).toBeCloseTo(0.75);
	});
});
