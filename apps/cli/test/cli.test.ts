import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Report } from "@openaudit/core";
import { Schema } from "effect";

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

describe("openaudit init + config", () => {
	test("writes a config that the audit command honours", async () => {
		const project = await mkdtemp(join(tmpdir(), "openaudit-init-"));
		await writeFile(join(project, "package.json"), "{}");
		const init = await cli(["init"], project);
		expect(init.code).toBe(0);
		const configPath = join(project, "openaudit.config.json");
		const config = JSON.parse(await Bun.file(configPath).text());
		expect(config.failOn).toBe("high");
		expect(config.ignore.rules).toEqual([]);
		expect((await cli(["init"], project)).code).toBe(2);

		config.failOn = "medium";
		config.only = ["code.hygiene"];
		await writeFile(configPath, JSON.stringify(config));
		expect((await cli(["--json"], project)).code).toBe(1);

		config.ignore.rules = ["code.hygiene/*"];
		await writeFile(configPath, JSON.stringify(config));
		const ignored = await cli(["--json"], project);
		expect(ignored.code).toBe(0);
		expect(JSON.parse(ignored.stdout).summary.counts.medium).toBe(0);

		await writeFile(configPath, JSON.stringify({ failOn: "sometimes" }));
		const invalid = await cli(["--json"], project);
		expect(invalid.code).toBe(2);
		expect(invalid.stderr).toContain("openaudit.config.json is invalid");
		await rm(project, { recursive: true, force: true });
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
		expect(stdout).toContain("0.1.0");
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
