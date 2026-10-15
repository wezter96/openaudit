import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Report, VERSION } from "@openaudit/core";
import { Schema } from "effect";

import { parseConfig } from "../src/config";

const BIN = join(import.meta.dir, "..", "src", "bin.ts");

const cli = async (args: string[], cwd: string) => {
	const proc = Bun.spawn(["bun", BIN, ...args], {
		cwd,
		stdout: "pipe",
		stderr: "pipe",
		env: { ...process.env, NO_COLOR: "1" },
	});
	const [stdout, stderr, code] = await Promise.all([
		new Response(proc.stdout).text(),
		new Response(proc.stderr).text(),
		proc.exited,
	]);
	return { stdout, stderr, code };
};

let dir: string;

// A tiny project that trips the hygiene auditor: no README, LICENSE,
// .gitignore (medium) or lockfile (medium).
beforeAll(async () => {
	dir = await mkdtemp(join(tmpdir(), "openaudit-cli-"));
	await writeFile(
		join(dir, "package.json"),
		JSON.stringify({ name: "fixture", version: "1.0.0" }),
	);
	await writeFile(join(dir, "index.js"), "console.log('hi');\n");
});

afterAll(async () => {
	await rm(dir, { recursive: true, force: true });
});

const HYGIENE = ["--only", "code.hygiene"];

describe("openaudit audit", () => {
	test("--json prints only a schema-valid report on stdout", async () => {
		const { stdout, stderr, code } = await cli(
			[".", "--json", ...HYGIENE],
			dir,
		);
		expect(code).toBe(0);
		expect(stderr).toBe("");
		const report = JSON.parse(stdout);
		expect(Schema.decodeUnknownExit(Report)(report)._tag).toBe("Success");
		expect(report.results.map((r: { auditor: string }) => r.auditor)).toEqual([
			"code.hygiene",
		]);
		const rules = report.results[0].findings.map(
			(f: { ruleId: string }) => f.ruleId,
		);
		expect(rules).toContain("code.hygiene/lockfile-missing");
	});

	test("--fail-on sets the exit code", async () => {
		expect(
			(await cli(["--fail-on", "medium", "-q", ...HYGIENE], dir)).code,
		).toBe(1);
		expect(
			(await cli(["--fail-on", "critical", "-q", ...HYGIENE], dir)).code,
		).toBe(0);
		expect(
			(await cli(["audit", ".", "--fail-on", "low", "--json", ...HYGIENE], dir))
				.code,
		).toBe(1);
	});

	test("usage and target errors exit 2", async () => {
		const bad = await cli(["--fail-on", "severe", ...HYGIENE], dir);
		expect(bad.code).toBe(2);
		expect(bad.stderr).toContain("Invalid --fail-on");
		const missing = await cli(["./does-not-exist", "--json"], dir);
		expect(missing.code).toBe(2);
		expect(missing.stdout).toBe("");
		expect(missing.stderr).toContain("Target not found");
		expect((await cli(["--no-such-flag"], dir)).code).toBe(2);
		expect((await cli(["-f", "json,sarif", ...HYGIENE], dir)).code).toBe(2);
	});

	test("--out writes one file per format", async () => {
		const out = join(dir, "reports");
		const { code } = await cli(
			["-f", "json,sarif", "-f", "markdown,html", "-o", out, "-q", ...HYGIENE],
			dir,
		);
		expect(code).toBe(0);
		const sarif = JSON.parse(
			await Bun.file(join(out, "openaudit-report.sarif")).text(),
		);
		expect(sarif.version).toBe("2.1.0");
		expect(await Bun.file(join(out, "openaudit-report.md")).text()).toContain(
			"openaudit",
		);
		expect(await Bun.file(join(out, "openaudit-report.html")).text()).toContain(
			"<!doctype html>",
		);
		await rm(out, { recursive: true });
	});

	test("--baseline suppresses known findings", async () => {
		const first = await cli([".", "--json", ...HYGIENE], dir);
		const baseline = join(dir, "..", `baseline-${Date.now()}.json`);
		await writeFile(baseline, first.stdout);
		const second = await cli(
			[".", "--json", "--baseline", baseline, "--fail-on", "low", ...HYGIENE],
			dir,
		);
		expect(second.code).toBe(0);
		expect(JSON.parse(second.stdout).summary.counts.medium).toBe(0);
		await rm(baseline);
	});
});

describe("--diff", () => {
	test("keeps only findings in files changed since the ref", async () => {
		const repo = await mkdtemp(join(tmpdir(), "openaudit-diff-"));
		const git = (...args: string[]) =>
			Bun.spawnSync(["git", "-C", repo, ...args], {
				env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", HOME: repo },
			});
		const risky = "export const run = (input) => eval(input);\n";
		await writeFile(join(repo, "old.js"), risky);
		git("init", "-q", "-b", "main");
		git("-c", "user.email=t@t", "-c", "user.name=t", "add", ".");
		git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base");
		git("checkout", "-qb", "feature");
		await writeFile(join(repo, "new.js"), risky);
		git("add", ".");
		git(
			"-c",
			"user.email=t@t",
			"-c",
			"user.name=t",
			"commit",
			"-qm",
			"feature",
		);

		const full = await cli([".", "--json", "--only", "code.security"], repo);
		const files = (r: string) =>
			JSON.parse(r)
				.results.flatMap(
					(x: { findings: { location?: { file?: string } }[] }) => x.findings,
				)
				.map((f: { location?: { file?: string } }) => f.location?.file);
		expect(files(full.stdout)).toEqual(
			expect.arrayContaining(["old.js", "new.js"]),
		);

		const diff = await cli(
			[".", "--json", "--only", "code.security", "--diff", "main"],
			repo,
		);
		expect(diff.code).toBe(0);
		const report = JSON.parse(diff.stdout);
		expect([...new Set(files(diff.stdout))]).toEqual(["new.js"]);
		expect(report.diff).toEqual({ base: "main", changedFiles: 1 });
		expect(report.suppressed[0].source).toBe("--diff main");

		const bad = await cli([".", "--diff", "--output=/tmp/x"], repo);
		expect(bad.code).toBe(2);
		await rm(repo, { recursive: true, force: true });
	});

	test("hands the base ref to auditors that compare against it", async () => {
		const repo = await mkdtemp(join(tmpdir(), "openaudit-diff-ref-"));
		await writeFile(
			join(repo, "openapi.yaml"),
			"openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths: {}\n",
		);
		const git = (...args: string[]) =>
			Bun.spawnSync(["git", "-C", repo, ...args], {
				env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", HOME: repo },
			});
		git("init", "-q", "-b", "main");
		git(
			"-c",
			"user.email=t@t",
			"-c",
			"user.name=t",
			"commit",
			"-qm",
			"base",
			"--allow-empty",
		);
		const oasdiff = (r: string) =>
			JSON.parse(r).results.find(
				(x: { auditor: string }) => x.auditor === "code.oasdiff",
			);
		const plain = await cli([".", "--json", "--only", "code.oasdiff"], repo);
		expect(oasdiff(plain.stdout).status).toBe("skipped");
		expect(oasdiff(plain.stdout).message).toContain("Only runs with --diff");
		const diff = await cli(
			[".", "--json", "--only", "code.oasdiff", "--diff", "main"],
			repo,
		);
		// Passed (the spec is new since main), or skipped for a missing oasdiff.
		expect(oasdiff(diff.stdout).message ?? "").not.toContain("--diff");
		await rm(repo, { recursive: true, force: true });
	});
});

describe("openaudit init + config", () => {
	// Runs whole audits, which are slow on shared CI runners.
	test("writes a commented config that the audit command honours", async () => {
		const project = await mkdtemp(join(tmpdir(), "openaudit-init-"));
		await writeFile(join(project, "package.json"), "{}");
		await mkdir(join(project, "test", "fixtures"), { recursive: true });
		await writeFile(join(project, "test", "fixtures", "leak.js"), "x\n");

		const printed = await cli(["init", "--print"], project);
		expect(printed.code).toBe(0);
		expect(printed.stdout).toContain(
			'"$schema": "https://openaudit.se/schema/config.json"',
		);
		expect(
			await Bun.file(join(project, "openaudit.config.jsonc")).exists(),
		).toBe(false);

		const init = await cli(["init"], project);
		expect(init.code).toBe(0);
		const configPath = join(project, "openaudit.config.jsonc");
		const text = await Bun.file(configPath).text();
		expect(text).toBe(printed.stdout);
		expect(text).toContain(
			'{ "path": "**/test/fixtures/**", "reason": "Test fixtures: deliberately broken or vulnerable inputs" }',
		);
		const again = await cli(["init"], project);
		expect(again.code).toBe(2);
		expect(again.stderr).toContain("already exists (use --force to overwrite");
		expect((await cli(["init", "--force"], project)).code).toBe(0);

		// The generated file is used as is, with no warnings.
		const first = await cli(["--json", "--only", "code.hygiene"], project);
		expect(first.stderr).toBe("");
		expect(JSON.parse(first.stdout).results).toHaveLength(1);

		const config = parseConfig(text, configPath);
		const edited = {
			...config,
			failOn: "medium",
			only: ["code.hygiene"],
		};
		await writeFile(configPath, JSON.stringify(edited));
		expect((await cli(["--json"], project)).code).toBe(1);

		await writeFile(
			configPath,
			JSON.stringify({ ...edited, ignore: { rules: ["code.hygiene/*"] } }),
		);
		const ignored = await cli(["--json"], project);
		expect(ignored.code).toBe(0);
		expect(JSON.parse(ignored.stdout).summary.counts.medium).toBe(0);

		await writeFile(configPath, JSON.stringify({ failOn: "sometimes" }));
		const invalid = await cli(["--json"], project);
		expect(invalid.code).toBe(2);
		expect(invalid.stderr).toContain("openaudit.config.jsonc is invalid");

		await writeFile(join(project, "openaudit.config.json"), "{}");
		const both = await cli(["--json"], project);
		expect(both.code).toBe(2);
		expect(both.stderr).toContain("Keep one");
		await rm(project, { recursive: true, force: true });
	}, 30_000);
});

describe("untrusted target config", () => {
	const project = async (config: object) => {
		const root = await mkdtemp(join(tmpdir(), "openaudit-trust-"));
		await writeFile(join(root, "package.json"), "{}");
		await writeFile(
			join(root, "openaudit.config.json"),
			JSON.stringify(config),
		);
		return root;
	};

	test("ignores settings that send data or cost money, with a warning", async () => {
		const root = await project({
			only: ["code.hygiene"],
			options: {
				agentic: true,
				ai: true,
				model: "expensive-model",
				browser: true,
				headers: { Authorization: "Bearer stolen" },
				settings: { "code.hygiene": { x: 1 } },
				maxPages: 3,
			},
		});
		const res = await cli(["--json"], root);
		expect(res.code).toBe(0);
		expect(res.stderr).toContain(
			"ignoring options.browser, options.agentic, options.ai, options.model, options.headers, options.settings",
		);
		expect(res.stderr).not.toContain("maxPages");
		// options.ai was not honoured: no attempt to produce AI insights.
		expect(res.stderr).not.toMatch(/AI insights|--ai/);
		expect(JSON.parse(res.stdout).ai).toBeUndefined();

		// The same file passed explicitly is trusted.
		const trusted = await cli(
			["--json", "--config", join(root, "openaudit.config.json")],
			root,
		);
		expect(trusted.stderr).not.toContain("ignoring");
		expect(trusted.stderr).toMatch(/AI insights|--ai/);
		await rm(root, { recursive: true, force: true });
	});

	test("honours its own licence policy, which only adds findings", async () => {
		const root = await project({
			only: ["code.licenses"],
			failOn: "high",
			options: {
				settings: {
					"code.licenses": { deny: ["GPL-*"] },
					"code.syft-licenses": { sbomOut: "sbom.json" },
				},
			},
		});
		await writeFile(
			join(root, "package-lock.json"),
			JSON.stringify({
				lockfileVersion: 3,
				packages: {
					"": { name: "x" },
					"node_modules/gpl-lib": { version: "1.0.0", license: "GPL-3.0" },
				},
			}),
		);
		const res = await cli(["--json"], root);
		expect(res.stderr).toContain(
			'ignoring options.settings["code.syft-licenses"]',
		);
		expect(res.stderr).not.toContain('options.settings["code.licenses"]');
		const result = JSON.parse(res.stdout).results[0];
		expect(result.auditor).toBe("code.licenses");
		expect(result.findings.map((f: { ruleId: string }) => f.ruleId)).toEqual([
			"code.licenses/denied-license",
		]);
		// A denied licence is high severity, so it trips the gate.
		expect(res.code).toBe(1);
		await rm(root, { recursive: true, force: true });
	});

	test("only narrows: it cannot enable opt-in or agentic auditors", async () => {
		const root = await project({
			only: ["code.hygiene", "code.knip", "code.clippy", "agent"],
		});
		const res = await cli(["--json"], root);
		expect(res.code).toBe(0);
		const ran = JSON.parse(res.stdout).results.map(
			(r: { auditor: string }) => r.auditor,
		);
		expect(ran).toEqual(["code.hygiene"]);
		await rm(root, { recursive: true, force: true });
	});

	test("discloses suppressions", async () => {
		const root = await project({
			only: ["code.hygiene"],
			ignore: {
				rules: ["code.hygiene/lockfile-missing"],
				paths: [".gitignore"],
			},
		});
		const terminal = await cli([], root);
		// Relative to where openaudit runs, never the absolute local path.
		expect(terminal.stdout).toContain(
			"2 findings suppressed by openaudit.config.json (1 by rule, 1 by path)",
		);
		expect(terminal.stdout).not.toContain(await realpath(root));
		const markdown = await cli(["-f", "markdown"], root);
		expect(markdown.stdout).toContain("2 findings suppressed by");
		const json = await cli(["--json", "--fail-on", "medium"], root);
		expect(json.code).toBe(0);
		expect(json.stderr).toContain("2 findings suppressed by");
		expect(JSON.parse(json.stdout).summary.counts.medium).toBe(0);
		expect(JSON.parse(json.stdout).suppressed).toEqual([
			{ source: "openaudit.config.json", rules: 1, paths: 1, fingerprints: 0 },
		]);

		await rm(root, { recursive: true, force: true });
	});

	test("discloses reasons, and expired suppressions stop applying", async () => {
		const root = await project({
			only: ["code.hygiene"],
			ignore: {
				paths: [
					{ path: ".gitignore", reason: "Generated", until: "2999-12-31" },
				],
				rules: [
					{
						rule: "code.hygiene/lockfile-missing",
						reason: "No dependencies yet",
						until: "2000-01-01",
					},
				],
			},
		});
		const json = await cli(["--json", "--fail-on", "medium"], root);
		expect(json.stderr).toContain(
			'1 suppression(s) expired and no longer apply: rule code.hygiene/lockfile-missing (until 2000-01-01). Fix the findings, or remove the entries or move their "until" dates.',
		);
		// The lockfile finding is back and trips the gate.
		expect(json.code).toBe(1);
		const report = JSON.parse(json.stdout);
		const rules = report.results[0].findings.map(
			(f: { ruleId: string }) => f.ruleId,
		);
		expect(rules).toContain("code.hygiene/lockfile-missing");
		expect(report.suppressed).toEqual([
			{
				source: "openaudit.config.json",
				rules: 0,
				paths: 1,
				fingerprints: 0,
				entries: [
					{
						kind: "path",
						value: ".gitignore",
						reason: "Generated",
						until: "2999-12-31",
						count: 1,
					},
				],
				expired: [
					{
						kind: "rule",
						value: "code.hygiene/lockfile-missing",
						reason: "No dependencies yet",
						until: "2000-01-01",
					},
				],
			},
		]);
		const terminal = await cli([], root);
		expect(terminal.stdout).toContain(
			"1 by path .gitignore (until 2999-12-31): Generated",
		);
		await rm(root, { recursive: true, force: true });
	});

	test("--no-config bypasses suppressions", async () => {
		const root = await project({
			only: ["code.hygiene"],
			ignore: { rules: ["code.hygiene/lockfile-missing"] },
		});
		const bypass = await cli(
			[
				"--json",
				"--no-config",
				"--only",
				"code.hygiene",
				"--fail-on",
				"medium",
			],
			root,
		);
		expect(bypass.code).toBe(1);
		expect(bypass.stderr).toBe("");
		await rm(root, { recursive: true, force: true });
	});
});

describe("progress output", () => {
	test("strips terminal escapes from auditor messages", async () => {
		const { createProgress } = await import("../src/progress");
		let out = "";
		const p = createProgress({ color: false, write: (t) => (out += t) });
		p.onEvent({
			type: "finish",
			result: {
				auditor: "code.x\x1b]52;c;ZXZpbA==\x07",
				title: "x",
				engine: "builtin",
				categories: ["security"],
				status: "skipped",
				message: "tool missing\x1b[2J\x1b]8;;https://evil\x07click\x9b1A",
				durationMs: 1,
				findings: [],
			},
		});
		p.stop();
		// Only the progress renderer's own line control remains.
		const foreign = out.replaceAll("\r\x1b[K", "");
		// biome-ignore lint/suspicious/noControlCharactersInRegex: asserting their absence
		const control = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/;
		expect(foreign).not.toMatch(control);
		expect(foreign).toContain("code.x skipped: tool missingclick");
	});
});

describe("other commands", () => {
	test("list --json", async () => {
		const { stdout, code } = await cli(["list", "--json"], dir);
		expect(code).toBe(0);
		const out = JSON.parse(stdout);
		const hygiene = out.auditors.find(
			(a: { id: string }) => a.id === "code.hygiene",
		);
		expect(hygiene).toMatchObject({ engine: "builtin", defaultEnabled: true });
		expect(Array.isArray(out.playbooks)).toBe(true);
		const urls = JSON.parse(
			(await cli(["list", "--json", "--target-kind", "url"], dir)).stdout,
		);
		expect(
			urls.auditors.every((a: { targets: string[] }) =>
				a.targets.includes("url"),
			),
		).toBe(true);
	});

	test("doctor --json", async () => {
		const { stdout, code } = await cli(["doctor", "--json"], dir);
		expect(code).toBe(0);
		const out = JSON.parse(stdout);
		expect(out.bun.version).toBe(Bun.version);
		expect(out.tools.map((t: { name: string }) => t.name)).toContain("semgrep");
		expect(typeof out.agentic.anthropicApiKey).toBe("boolean");
	});

	test("schema prints the report JSON Schema", async () => {
		const { stdout, code } = await cli(["schema"], dir);
		expect(code).toBe(0);
		const schema = JSON.parse(stdout);
		expect(schema.$schema).toContain("2020-12");
		expect(schema.required).toContain("results");
	});

	test("--version", async () => {
		const { stdout, code } = await cli(["--version"], dir);
		expect(code).toBe(0);
		expect(stdout).toContain(VERSION);
	});
});

describe("openaudit mcp", () => {
	test("serves MCP over stdio with a clean stdout", async () => {
		const proc = Bun.spawn(["bun", BIN, "mcp"], {
			cwd: dir,
			stdin: "pipe",
			stdout: "pipe",
			stderr: "pipe",
		});
		const send = (msg: object) => {
			proc.stdin.write(`${JSON.stringify(msg)}\n`);
			proc.stdin.flush();
		};
		const reader = proc.stdout.getReader();
		let buffer = "";
		const nextMessage = async (): Promise<Record<string, unknown>> => {
			while (!buffer.includes("\n")) {
				const { value, done } = await reader.read();
				if (done) throw new Error("MCP server closed stdout");
				buffer += new TextDecoder().decode(value);
			}
			const i = buffer.indexOf("\n");
			const line = buffer.slice(0, i);
			buffer = buffer.slice(i + 1);
			return JSON.parse(line);
		};
		try {
			send({
				jsonrpc: "2.0",
				id: 1,
				method: "initialize",
				params: {
					protocolVersion: "2025-06-18",
					capabilities: {},
					clientInfo: { name: "cli-test", version: "1.0.0" },
				},
			});
			const init = (await nextMessage()) as {
				result: { serverInfo: { name: string }; instructions: string };
			};
			expect(init.result.serverInfo.name).toBe("openaudit");
			expect(init.result.instructions).toContain("run_audit");
			send({ jsonrpc: "2.0", method: "notifications/initialized" });
			send({ jsonrpc: "2.0", id: 2, method: "tools/list" });
			const list = (await nextMessage()) as {
				result: { tools: Array<{ name: string }> };
			};
			expect(list.result.tools.map((t) => t.name)).toContain("submit_findings");
		} finally {
			proc.kill();
			await proc.exited;
		}
	});
});
