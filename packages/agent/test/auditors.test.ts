import { describe, expect, test } from "bun:test";
import { mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Effect } from "effect";

import {
	type ClaudeRunInput,
	type ClaudeRunner,
	getPlaybook,
	makeAgenticAuditor,
	makeToolGuard,
	type Playbook,
	type ToolGuard,
} from "../src";
import {
	PLAYWRIGHT_MCP,
	scrubSecrets,
	storageStateArgs,
} from "../src/auditors";
import {
	assistant,
	codebaseContext,
	fixtureProject,
	result,
	urlContext,
} from "./helpers";

const playbook = (id: string): Playbook => {
	const p = getPlaybook(id);
	if (!p) throw new Error(`missing ${id}`);
	return p;
};

const finding = {
	ruleId: "IDOR order read",
	title: "Order lookup does not check ownership",
	severity: "high",
	category: "security",
	message: "GET /orders/:id loads any order by id without checking the owner.",
	location: { file: "src/app.ts", line: 1 },
	evidence: "db.order.find(req.params.id) // key sk_live_abcdefghijklmnop",
	remediation: "Constrain the query by req.user.id.",
	confidence: "high",
};

/** Runs an auditor, returning findings or the failure tag + message. */
const run = (
	auditor: ReturnType<typeof makeAgenticAuditor>,
	ctx: Parameters<ReturnType<typeof makeAgenticAuditor>["run"]>[0],
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

const findingsOf = (out: Awaited<ReturnType<typeof run>>) => {
	if (!out.ok) throw new Error(`${out.tag}: ${out.message}`);
	return out.findings;
};

describe("agentic auditor (codebase)", () => {
	test("configures a read-only session and collects reported findings", async () => {
		const root = fixtureProject();
		let seen: ClaudeRunInput | undefined;
		const replies: Array<{ isError?: boolean; text?: string }> = [];
		const runner: ClaudeRunner = async function* (input) {
			seen = input;
			yield assistant();
			for (const args of [
				finding,
				{ ...finding, location: { file: "src/missing.ts" } },
				{ ...finding, severity: "catastrophic" },
				{ ...finding, location: { file: join(root, "src/app.ts"), line: 1 } },
			]) {
				const r = await input.tools.report_finding?.(args);
				replies.push({ isError: r?.isError, text: r?.content[0]?.text });
			}
			await input.tools.finish?.({
				summary: "Reviewed routes",
				coverage: "all",
			});
			yield result();
		};
		const auditor = makeAgenticAuditor(playbook("agent.authz"), { runner });
		const out = await run(
			auditor,
			codebaseContext(root, { model: "claude-test" }),
		);

		const findings = findingsOf(out);
		expect(findings).toHaveLength(2);
		expect(findings[0]?.ruleId).toBe("agent.authz/idor-order-read");
		expect(findings[0]?.location?.file).toBe("src/app.ts");
		expect(findings[0]?.evidence).not.toContain("sk_live_abcdefghijklmnop");
		expect(findings[0]?.tags).toContain("agentic");
		// Absolute paths inside the root are normalised to relative ones.
		expect(findings[1]?.location?.file).toBe("src/app.ts");
		expect(replies.map((r) => r.isError ?? false)).toEqual([
			false,
			true,
			true,
			false,
		]);
		expect(replies[1]?.text).toContain("does not exist");

		const options = seen?.options;
		expect(options?.model).toBe("claude-test");
		expect(options?.cwd).toBe(root);
		expect(options?.tools).toEqual(["Read", "Grep", "Glob"]);
		expect(options?.disallowedTools).toEqual(
			expect.arrayContaining([
				"Write",
				"Edit",
				"Bash",
				"WebFetch",
				"WebSearch",
			]),
		);
		expect(options?.maxTurns).toBe(40);
		expect(options?.settingSources).toEqual([]);
		expect(options?.hooks?.PreToolUse).toHaveLength(1);
		expect(Object.keys(options?.mcpServers ?? {})).toEqual(["openaudit"]);
		expect(options?.systemPrompt).toContain("Authentication & authorization");
		expect(options?.systemPrompt).toContain("## Checklist");
		expect(options?.systemPrompt).toContain(root);
		expect(seen?.tools.http_get).toBeUndefined();
	});

	test("per-auditor settings override defaults", async () => {
		const root = fixtureProject();
		let maxTurns: number | undefined;
		let prompt = "";
		const runner: ClaudeRunner = async function* (input) {
			maxTurns = input.options.maxTurns;
			prompt = String(input.options.systemPrompt);
			yield assistant();
			yield result();
		};
		const out = await run(
			makeAgenticAuditor(playbook("agent.authz"), { runner }),
			codebaseContext(root, {
				settings: {
					agent: { maxTurns: 10 },
					"agent.authz": { maxTurns: 5, instructions: "Focus on /admin" },
				},
			}),
		);
		expect(out.ok).toBe(true);
		expect(maxTurns).toBe(5);
		expect(prompt).toContain("Focus on /admin");
	});

	test("invalid settings are an AuditorError", async () => {
		const out = await run(
			makeAgenticAuditor(playbook("agent.authz"), {
				runner: async function* () {},
			}),
			codebaseContext(fixtureProject(), {
				settings: { "agent.authz": { maxTurns: "lots" } },
			}),
		);
		expect(out).toMatchObject({ ok: false, tag: "AuditorError" });
	});

	test("authentication failures skip with a hint", async () => {
		const runner: ClaudeRunner = async function* () {
			yield assistant("authentication_failed");
			yield result("error_during_execution");
		};
		const out = await run(
			makeAgenticAuditor(playbook("agent.authz"), { runner }),
			codebaseContext(fixtureProject()),
		);
		expect(out).toMatchObject({ ok: false, tag: "SkipAudit" });
		expect((out as { message: string }).message).toContain("ANTHROPIC_API_KEY");
	});

	test("an SDK that fails to start skips instead of erroring", async () => {
		// biome-ignore lint/correctness/useYield: simulates a spawn failure
		const runner: ClaudeRunner = async function* () {
			throw new Error("Claude Code executable not found");
		};
		const out = await run(
			makeAgenticAuditor(playbook("agent.authz"), { runner }),
			codebaseContext(fixtureProject()),
		);
		expect(out).toMatchObject({ ok: false, tag: "SkipAudit" });
		expect((out as { message: string }).message).toContain(
			"executable not found",
		);
	});

	test("hitting maxTurns keeps partial findings and notes it", async () => {
		const runner: ClaudeRunner = async function* (input) {
			yield assistant();
			await input.tools.report_finding?.(finding);
			yield result("error_max_turns");
		};
		const out = await run(
			makeAgenticAuditor(playbook("agent.authz"), { runner }),
			codebaseContext(fixtureProject()),
		);
		const findings = findingsOf(out);
		expect(findings.map((f) => f.ruleId)).toEqual([
			"agent.authz/idor-order-read",
			"agent.authz/incomplete",
		]);
		expect(findings[1]?.severity).toBe("info");
	});

	test("enforces the finding cap", async () => {
		const replies: boolean[] = [];
		const runner: ClaudeRunner = async function* (input) {
			yield assistant();
			for (let i = 0; i < 3; i++)
				replies.push(
					(await input.tools.report_finding?.({ ...finding, ruleId: `r${i}` }))
						?.isError ?? false,
				);
			yield result();
		};
		const out = await run(
			makeAgenticAuditor(playbook("agent.authz"), { runner }),
			codebaseContext(fixtureProject(), {
				settings: { "agent.authz": { maxFindings: 2 } },
			}),
		);
		expect(findingsOf(out)).toHaveLength(2);
		expect(replies).toEqual([false, false, true]);
	});

	test("interruption aborts the SDK session", async () => {
		let signal: AbortSignal | undefined;
		const runner: ClaudeRunner = async function* (input) {
			signal = input.options.abortController?.signal;
			yield assistant();
			await new Promise((resolve) =>
				signal?.addEventListener("abort", resolve),
			);
		};
		await Effect.runPromise(
			makeAgenticAuditor(playbook("agent.authz"), { runner })
				.run(codebaseContext(fixtureProject()))
				.pipe(Effect.timeout("50 millis"), Effect.ignore),
		);
		expect(signal?.aborted).toBe(true);
	});

	test("skips when the target has neither files nor a URL", async () => {
		const ctx = urlContext("https://example.com/");
		const out = await run(
			makeAgenticAuditor(playbook("agent.authz"), {
				runner: async function* () {},
			}),
			{ ...ctx, target: { ...ctx.target, type: "image", kinds: ["codebase"] } },
		);
		expect(out).toMatchObject({ ok: false, tag: "SkipAudit" });
	});
});

describe("agentic auditor (web)", () => {
	test("without --browser it uses http_get and notes reduced coverage", async () => {
		const ctx = urlContext("https://app.example.com/", {}, () => ({
			cookies: ["sid=supersecretvalue; Path=/; HttpOnly"],
		}));
		let input: ClaudeRunInput | undefined;
		const texts: string[] = [];
		const runner: ClaudeRunner = async function* (i) {
			input = i;
			yield assistant();
			for (const url of ["/login", "https://evil.example.net/"])
				texts.push((await i.tools.http_get?.({ url }))?.content[0]?.text ?? "");
			yield result();
		};
		const out = await run(
			makeAgenticAuditor(playbook("agent.a11y-journeys"), { runner }),
			ctx,
		);
		const findings = findingsOf(out);
		expect(findings.map((f) => f.ruleId)).toEqual([
			"agent.a11y-journeys/reduced-coverage",
		]);
		expect(input?.options.tools).toEqual([]);
		expect(input?.options.disallowedTools).toContain("WebFetch");
		expect(input?.options.cwd).toBeUndefined();
		expect(Object.keys(input?.options.mcpServers ?? {})).toEqual(["openaudit"]);
		expect(ctx.requests).toEqual(["https://app.example.com/login"]);
		expect(texts[0]).toContain("set-cookie: sid=<redacted>; Path=/; HttpOnly");
		expect(texts[0]).not.toContain("supersecretvalue");
		expect(texts[1]).toContain("Only the target origin");
	});

	test("with --browser it attaches the Playwright MCP server", async () => {
		let input: ClaudeRunInput | undefined;
		const runner: ClaudeRunner = async function* (i) {
			input = i;
			yield assistant();
			yield result();
		};
		const out = await run(
			makeAgenticAuditor(playbook("agent.webapp-security"), { runner }),
			urlContext("https://app.example.com/", {
				browser: true,
				settings: {
					"agent.webapp-security": {
						// Ignored: free-form args are not accepted, and this path escapes the cwd.
						playwrightArgs: ["--init-script=/tmp/evil.js"],
						storageState: "../../../etc/passwd",
					},
				},
			}),
		);
		expect(findingsOf(out)).toEqual([]);
		expect(input?.options.mcpServers?.playwright).toEqual({
			type: "stdio",
			command: "npx",
			args: [
				"-y",
				PLAYWRIGHT_MCP,
				"--headless",
				"--isolated",
				"--block-service-workers",
				"--allowed-origins=https://app.example.com",
			],
		});
	});
});

describe("tool guard", () => {
	// A project with a secret outside it, reachable via symlinks inside it.
	const outside = mkdtempSync(join(tmpdir(), "openaudit-outside-"));
	writeFileSync(join(outside, "id_rsa"), "PRIVATE");
	const root = fixtureProject();
	symlinkSync(join(outside, "id_rsa"), join(root, "key-link"));
	symlinkSync(outside, join(root, "dir-link"));
	writeFileSync(join(root, "src/b.ts"), "ok");

	const codeGuard = makeToolGuard({
		root,
		url: undefined,
		browser: false,
		reducedCoverage: false,
	});
	const webGuard = makeToolGuard({
		root: undefined,
		url: "https://app.example.com/start",
		browser: true,
		reducedCoverage: false,
	});
	const allowed = (guard: ToolGuard, name: string, input: object) =>
		guard.decide(name, input).allow;

	test("Bash, WebFetch, WebSearch and writes are always denied", () => {
		for (const guard of [codeGuard, webGuard]) {
			expect(allowed(guard, "Bash", { command: "git log -5" })).toBe(false);
			expect(allowed(guard, "Bash", { command: "ls" })).toBe(false);
			expect(
				allowed(guard, "WebFetch", { url: "https://app.example.com/" }),
			).toBe(false);
			expect(allowed(guard, "WebSearch", { query: "x" })).toBe(false);
			expect(allowed(guard, "Write", { file_path: join(root, "a") })).toBe(
				false,
			);
			expect(allowed(guard, "Edit", { file_path: join(root, "a") })).toBe(
				false,
			);
			expect(allowed(guard, "mcp__other__tool", {})).toBe(false);
			expect(allowed(guard, "mcp__openaudit__report_finding", {})).toBe(true);
		}
	});

	test("Read/Grep/Glob are confined to the real project root", () => {
		expect(
			allowed(codeGuard, "Read", { file_path: join(root, "src/app.ts") }),
		).toBe(true);
		expect(allowed(codeGuard, "Read", { file_path: "src/app.ts" })).toBe(true);
		expect(allowed(codeGuard, "Read", { file_path: "src/not-yet.ts" })).toBe(
			true,
		);
		expect(allowed(codeGuard, "Grep", { pattern: "x" })).toBe(true);
		expect(allowed(codeGuard, "Glob", { pattern: "src/**/*.ts" })).toBe(true);

		expect(allowed(codeGuard, "Read", { file_path: "../outside" })).toBe(false);
		expect(allowed(codeGuard, "Read", { file_path: "/etc/passwd" })).toBe(
			false,
		);
		expect(allowed(codeGuard, "Read", { file_path: "~/.ssh/id_rsa" })).toBe(
			false,
		);
		expect(
			allowed(codeGuard, "Read", { file_path: join(root, "key-link") }),
		).toBe(false);
		expect(allowed(codeGuard, "Read", { file_path: "dir-link/id_rsa" })).toBe(
			false,
		);
		expect(allowed(codeGuard, "Grep", { path: "dir-link" })).toBe(false);
		expect(allowed(codeGuard, "Grep", { path: "../" })).toBe(false);
		expect(allowed(codeGuard, "Glob", { pattern: "/etc/*" })).toBe(false);
		expect(allowed(codeGuard, "Glob", { pattern: "../../**/.aws/*" })).toBe(
			false,
		);
		expect(allowed(codeGuard, "Glob", { path: "dir-link", pattern: "*" })).toBe(
			false,
		);
		// Patterns the path check doesn't see on its own.
		expect(allowed(codeGuard, "Glob", { pattern: "src/../../**" })).toBe(false);
		expect(allowed(codeGuard, "Grep", { pattern: "x", glob: "../**" })).toBe(
			false,
		);
		expect(allowed(codeGuard, "Grep", { pattern: "x", glob: "/etc/*" })).toBe(
			false,
		);
		expect(allowed(codeGuard, "Grep", { pattern: "x", glob: "*.ts" })).toBe(
			true,
		);
		// No files at all in URL runs.
		expect(allowed(webGuard, "Read", { file_path: "/etc/hosts" })).toBe(false);
	});

	test("the browser is pinned to the target origin", () => {
		const nav = "mcp__playwright__browser_navigate";
		expect(
			allowed(webGuard, nav, { url: "https://app.example.com/login" }),
		).toBe(true);
		expect(
			allowed(webGuard, nav, { url: "https://evil.example.net/?d=x" }),
		).toBe(false);
		expect(
			allowed(webGuard, nav, { url: "https://app.example.com.evil.net/" }),
		).toBe(false);
		expect(allowed(webGuard, nav, { url: "not a url" })).toBe(false);
		expect(allowed(webGuard, nav, { url: "/relative" })).toBe(false);
		expect(
			allowed(webGuard, "mcp__playwright__browser_click", { ref: "e1" }),
		).toBe(true);
		expect(
			allowed(webGuard, "mcp__playwright__browser_run_code_unsafe", {}),
		).toBe(false);
		expect(allowed(webGuard, "mcp__playwright__browser_evaluate", {})).toBe(
			false,
		);
		// Allowlist: unknown or future tools are denied.
		for (const name of [
			"browser_file_upload",
			"browser_pdf_save",
			"browser_new_tool",
		])
			expect(allowed(webGuard, `mcp__playwright__${name}`, {})).toBe(false);
		expect(allowed(codeGuard, nav, { url: "https://app.example.com/" })).toBe(
			false,
		);
	});

	test("canUseTool and the PreToolUse hook enforce the same decisions", async () => {
		const options = {
			signal: new AbortController().signal,
			toolUseID: "t",
		} as Parameters<ToolGuard["canUseTool"]>[2];
		const behavior = async (name: string, input: Record<string, unknown>) =>
			(await codeGuard.canUseTool(name, input, options))?.behavior;
		expect(await behavior("Read", { file_path: "src/app.ts" })).toBe("allow");
		expect(await behavior("Read", { file_path: "key-link" })).toBe("deny");
		expect(await behavior("Bash", { command: "ls" })).toBe("deny");

		const hook = (tool_name: string, tool_input: unknown) =>
			codeGuard.preToolUse(
				{
					hook_event_name: "PreToolUse",
					tool_name,
					tool_input,
					tool_use_id: "t",
				} as Parameters<ToolGuard["preToolUse"]>[0],
				"t",
				{ signal: new AbortController().signal },
			);
		expect(await hook("Read", { file_path: "src/app.ts" })).toEqual({});
		expect(await hook("Read", { file_path: "dir-link/id_rsa" })).toMatchObject({
			hookSpecificOutput: { permissionDecision: "deny" },
		});
		expect(await hook("Bash", { command: "ls" })).toMatchObject({
			hookSpecificOutput: { permissionDecision: "deny" },
		});
	});

	test("report_finding refuses files that escape the root via symlinks", async () => {
		const replies: Array<boolean | undefined> = [];
		const runner: ClaudeRunner = async function* (input) {
			yield assistant();
			for (const file of ["src/b.ts", "key-link", "../outside"])
				replies.push(
					(
						await input.tools.report_finding?.({
							...finding,
							location: { file },
						})
					)?.isError,
				);
			yield result();
		};
		await run(
			makeAgenticAuditor(playbook("agent.authz"), { runner }),
			codebaseContext(root),
		);
		expect(replies).toEqual([undefined, true, true]);
	});

	test("scrubSecrets masks common token formats", () => {
		const out = scrubSecrets(
			"key AKIAABCDEFGHIJKLMNOP and ghp_abcdefghijklmnopqrstuvwxyz0123 ok",
		);
		expect(out).not.toContain("AKIAABCDEFGHIJKLMNOP");
		expect(out).not.toContain("ghp_abcdefghijklmnopqrstuvwxyz0123");
		expect(out).toContain("AKIA");
		expect(out).toEndWith(" ok");
	});
});

describe("storageStateArgs", () => {
	const root = mkdtempSync(join(tmpdir(), "openaudit-state-"));
	writeFileSync(join(root, "auth.json"), "{}");
	test("accepts files inside the root only", () => {
		expect(storageStateArgs("auth.json", root)).toEqual([
			`--storage-state=${realpathSync(join(root, "auth.json"))}`,
		]);
		expect(storageStateArgs("../../etc/passwd", root)).toEqual([]);
		expect(storageStateArgs("missing.json", root)).toEqual([]);
		expect(storageStateArgs(undefined, root)).toEqual([]);
	});
});
