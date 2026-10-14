import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	type Auditor,
	Exec,
	type ExecOptions,
	type ExecResult,
	Http,
	type Report,
	runAudit,
	Workspaces,
} from "@openaudit/core";
import { Effect, Layer } from "effect";

import {
	guarddog,
	guarddogNpmManifest,
	guarddogRequirements,
	parseGuarddogReport,
} from "../src/codebase/supply-chain-tools";
import { fixture } from "./helpers";

const text = (name: string) =>
	readFileSync(fixture("codebase", "external", name), "utf8");
const sample = (name: string): unknown => JSON.parse(text(`${name}.json`));
const manifestDir = fixture("codebase", "supply", "guarddog");
const manifest = (name: string) =>
	readFileSync(join(manifestDir, name), "utf8");

const summary = (
	findings: ReadonlyArray<{
		ruleId: string;
		severity: string;
		confidence?: string;
		location?: { file?: string; line?: number };
	}>,
) =>
	findings.map(
		(f) =>
			`${f.ruleId} ${f.severity}/${f.confidence} ${f.location?.file}:${f.location?.line ?? "-"}`,
	);

/* -------------------------------- manifests ------------------------------- */

describe("guarddog manifests", () => {
	test("package.json: registry dependencies only, with their declaring lines", () => {
		const m = guarddogNpmManifest(
			[
				"{",
				'  "name": "app",',
				'  "dependencies": {',
				'    "left-pad": "^1.3.0",',
				'    "local": "workspace:*",',
				'    "shared": "catalog:",',
				'    "vendored": "file:../vendored",',
				'    "fork": "github:someone/fork",',
				'    "remote": "https://example.com/x.tgz",',
				'    "../evil": "1.0.0",',
				'    "alias": "npm:@scope/real@^2.0.0"',
				"  },",
				'  "optionalDependencies": { "fsevents": "2.3.3" },',
				'  "devDependencies": {',
				'    "typescript": "5.6.3"',
				"  }",
				"}",
			].join("\n"),
		);
		expect(m && JSON.parse(m.content)).toEqual({
			dependencies: {
				"left-pad": "^1.3.0",
				alias: "npm:@scope/real@^2.0.0",
				fsevents: "2.3.3",
			},
			devDependencies: { typescript: "5.6.3" },
		});
		expect(Object.fromEntries(m?.lines ?? [])).toEqual({
			"left-pad": 4,
			"@scope/real": 11,
			fsevents: 13,
			typescript: 15,
		});
	});

	test("package.json without registry dependencies or not JSON: nothing to verify", () => {
		expect(
			guarddogNpmManifest('{"dependencies":{"a":"workspace:*"}}'),
		).toBeUndefined();
		expect(guarddogNpmManifest('{"name":"x"}')).toBeUndefined();
		expect(guarddogNpmManifest("{ not json")).toBeUndefined();
	});

	test("requirements: plain requirements kept; options, includes, URLs and markers dropped", () => {
		const m = guarddogRequirements(
			[
				"# comment",
				"-r base.txt",
				"--index-url https://pypi.example.invalid/simple",
				"Django[argon2]>=4.2 ; python_version >= '3.10'",
				"requests==2.32.3 \\",
				"    --hash=sha256:abc",
				"-e git+https://github.com/x/y#egg=y",
				"evil @ https://example.com/evil.tar.gz",
				"zope.interface",
				"not a requirement!",
			].join("\n"),
		);
		expect(m?.content).toBe("Django>=4.2\nrequests==2.32.3\nzope.interface\n");
		expect(Object.fromEntries(m?.lines ?? [])).toEqual({
			django: 4,
			requests: 5,
			"zope-interface": 9,
		});
		expect(guarddogRequirements("# only comments\n-r other.txt\n")).toBe(
			undefined,
		);
		// A line built to make a backtracking matcher explode fails fast.
		const started = performance.now();
		expect(
			guarddogRequirements(`a==${"1!=".repeat(5000)}1 ${" ,".repeat(5000)}@`),
		).toBeUndefined();
		expect(performance.now() - started).toBeLessThan(500);
	});
});

/* --------------------------------- parser --------------------------------- */

describe("guarddog report", () => {
	const npm = () => ({
		ecosystem: "npm" as const,
		file: "package.json",
		lines: guarddogNpmManifest(manifest("package.json"))?.lines ?? new Map(),
	});
	const pypi = () => ({
		ecosystem: "pypi" as const,
		file: "requirements.txt",
		lines:
			guarddogRequirements(manifest("requirements.txt"))?.lines ?? new Map(),
	});

	test("recorded guarddog 3.2.0 npm verify: flagged packages only, code risks folded into one finding", () => {
		const findings = parseGuarddogReport(sample("guarddog-npm"), npm());
		// typescript and left-pad have capabilities but no risks; the
		// workspace entry only carries a download error.
		expect(summary(findings)).toEqual([
			"code.guarddog/suspicious-code medium/low package.json:5",
			"code.guarddog/typosquatting medium/low package.json:6",
			"code.guarddog/typosquatting medium/low package.json:9",
			"code.guarddog/suspicious-code medium/low package.json:15",
			"code.guarddog/suspicious-code high/low package.json:16",
		]);
		const [coreJs, crossenv, , vite, wrangler] = findings;
		expect(coreJs?.title).toBe("core-js@3.38.1: suspicious code (GuardDog)");
		expect(coreJs?.message).toBe(
			"GuardDog rates core-js@3.38.1 suspicious (risk score 5.5/10). Source-code heuristics: process hooks (package/package.json:71).",
		);
		expect(coreJs?.evidence).toBe(
			'package/package.json:71: "postinstall": "node -e \\',
		);
		expect(coreJs?.tags).toEqual(["owasp-a08", "cwe-506"]);
		expect(coreJs?.category).toBe("supply-chain");
		expect(coreJs?.references).toEqual([
			"https://github.com/DataDog/guarddog",
			"https://www.npmjs.com/package/core-js/v/3.38.1",
		]);
		expect(crossenv?.message).toContain("typosquatting attempt: cross-env");
		expect(crossenv?.tags).toEqual(["owasp-a08"]);
		expect(crossenv?.remediation).toContain("crossenv");
		// Most severe heuristics first, repeated locations counted.
		expect(vite?.message).toContain(
			"Source-code heuristics: runtime obfuscation base64exec (package/dist/node/chunks/node.js:2481);",
		);
		expect(vite?.message).toContain(
			"filesystem read (package/dist/node/module-runner.js:790, +4)",
		);
		expect(wrangler?.title).toBe("wrangler@4.151.0: high risk code (GuardDog)");
		expect(wrangler?.message).toStartWith(
			"GuardDog rates wrangler@4.151.0 high risk (risk score 10/10).",
		);
		expect(wrangler?.message).toEndWith("; +5 more.");
	});

	test("recorded guarddog 3.2.0 pypi verify", () => {
		const findings = parseGuarddogReport(sample("guarddog-pypi"), pypi());
		expect(summary(findings)).toEqual([
			"code.guarddog/suspicious-code medium/low requirements.txt:3",
		]);
		expect(findings[0]?.references).toEqual([
			"https://github.com/DataDog/guarddog",
			"https://pypi.org/project/beautifulsoup/3.2.2/",
			"https://inspector.pypi.io/project/beautifulsoup/3.2.2/",
		]);
	});

	test("packages GuardDog rates low risk are not reported", () => {
		// The recorded entries relabelled: GuardDog labels scores below 5 low.
		const json = structuredClone(sample("guarddog-npm")) as Array<{
			result: { risk_score?: { label: string } };
		}>;
		for (const entry of json)
			if (entry.result.risk_score) entry.result.risk_score.label = "low";
		expect(parseGuarddogReport(json, npm())).toEqual([]);
	});

	test("garbage is ignored", () => {
		expect(parseGuarddogReport({}, npm())).toEqual([]);
		expect(parseGuarddogReport([null, { result: 3 }], npm())).toEqual([]);
	});
});

/* ------------------------------ auditor runs ------------------------------ */

const runWithExec = (
	auditor: Auditor,
	target: string,
	which: (bin: string) => string | undefined,
	run: (
		cmd: ReadonlyArray<string>,
		options?: ExecOptions,
	) => Promise<ExecResult>,
	options: Parameters<typeof runAudit>[0]["options"] = {},
): Promise<Report> =>
	Effect.runPromise(
		runAudit({
			target,
			auditors: [auditor],
			options,
			selection: { only: [auditor.id] },
		}).pipe(
			Effect.provide(
				Layer.mergeAll(
					Workspaces.layer,
					Http.layer,
					Layer.succeed(Exec, {
						which: (bin: string) => Effect.succeed(which(bin)),
						run: (cmd, opts) => Effect.promise(() => run(cmd, opts)),
					}),
				),
			),
		),
	);

const present = (bin: string) => `/usr/local/bin/${bin}`;
const unreachable = () => Promise.reject(new Error("tool must not run"));

describe("guarddog auditor", () => {
	test("opt-in and networked", () => {
		expect(guarddog.defaultEnabled).toBe(false);
		expect(guarddog.network).toBe(true);
		expect(guarddog.engine).toBe("external");
		expect(guarddog.tool).toBe("guarddog");
	});

	test("no supported manifest: skipped before the tool is required", async () => {
		const report = await runWithExec(
			guarddog,
			fixture("codebase", "supply", "empty"),
			() => undefined,
			unreachable,
		);
		expect(report.results[0]?.status).toBe("skipped");
		expect(report.results[0]?.message).toContain("package.json");
		expect(report.results[0]?.message).not.toContain("not found on PATH");
	});

	test("tool missing: skipped with an install hint", async () => {
		const report = await runWithExec(
			guarddog,
			manifestDir,
			() => undefined,
			unreachable,
		);
		expect(report.results[0]?.status).toBe("skipped");
		expect(report.results[0]?.message).toContain("not found on PATH");
		expect(report.results[0]?.message).toContain("Install");
	});

	test("--offline: skipped by the engine", async () => {
		const report = await runWithExec(
			guarddog,
			manifestDir,
			present,
			unreachable,
			{
				offline: true,
			},
		);
		expect(report.results[0]?.status).toBe("skipped");
	});

	test("only local dependencies: skipped without running the tool", async () => {
		const root = await mkdtemp(join(tmpdir(), "openaudit-guarddog-"));
		await writeFile(
			join(root, "package.json"),
			'{"dependencies":{"lib":"workspace:*"}}',
		);
		const report = await runWithExec(guarddog, root, present, unreachable);
		await rm(root, { recursive: true, force: true });
		expect(report.results[0]?.status).toBe("skipped");
		expect(report.results[0]?.message).toContain("registry");
	});

	test("verifies a sanitised copy of each manifest from a scratch directory", async () => {
		const calls: Array<{
			cmd: ReadonlyArray<string>;
			cwd?: string;
			input: string;
		}> = [];
		const report = await runWithExec(
			guarddog,
			manifestDir,
			present,
			async (cmd, options) => {
				const input = await readFile(cmd[5] ?? "", "utf8");
				calls.push({ cmd, cwd: options?.cwd, input });
				const eco = cmd[3];
				return {
					code: 0,
					stdout: text(`guarddog-${eco}.json`),
					stderr: "",
				};
			},
		);
		expect(report.results[0]?.status).toBe("failed");
		expect(calls.map((c) => c.cmd.slice(0, 5))).toEqual([
			["/usr/local/bin/guarddog", "--log-level", "error", "npm", "verify"],
			["/usr/local/bin/guarddog", "--log-level", "error", "pypi", "verify"],
		]);
		for (const call of calls) {
			expect(call.cwd).toBeDefined();
			expect(call.cwd).not.toBe(manifestDir);
			expect(call.cmd[5]?.startsWith(`${call.cwd}/`)).toBe(true);
			expect(call.cmd.slice(6, 8)).toEqual(["--output-format", "json"]);
		}
		expect(calls[0]?.cmd.at(-1)).toBe("--include-dev-dependencies");
		expect(JSON.parse(calls[0]?.input ?? "")).toEqual({
			dependencies: {
				"core-js": "3.38.1",
				crossenv: "^0.0.2-security",
				electorn: "*",
				"left-pad": "1.3.0",
				loadsh: "0.0.4",
				lodahs: "*",
			},
			devDependencies: {
				typescript: "5.6.3",
				vite: "8.3.4",
				wrangler: "4.151.0",
			},
		});
		expect(calls[1]?.input).toBe(
			"requests==2.32.3\nbeautifulsoup==3.2.2\ncolorama==0.4.6\nreqeusts\n",
		);
		const findings = report.results[0]?.findings ?? [];
		// The engine orders findings by severity.
		expect(
			findings.map(
				(f) => `${f.ruleId} ${f.location?.file}:${f.location?.line}`,
			),
		).toEqual([
			"code.guarddog/suspicious-code package.json:16",
			"code.guarddog/suspicious-code package.json:5",
			"code.guarddog/typosquatting package.json:6",
			"code.guarddog/typosquatting package.json:9",
			"code.guarddog/suspicious-code package.json:15",
			"code.guarddog/suspicious-code requirements.txt:3",
		]);
	});

	test("a failing run is an error, not an empty result", async () => {
		const report = await runWithExec(
			guarddog,
			manifestDir,
			present,
			async () => ({
				code: 1,
				stdout: "",
				stderr: "Traceback: boom",
			}),
		);
		expect(report.results[0]?.status).toBe("error");
		expect(report.results[0]?.message).toContain("boom");
	});
});
