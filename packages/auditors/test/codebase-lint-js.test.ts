import { describe, expect, test } from "bun:test";
import { readFileSync, realpathSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
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
	biome,
	eslint,
	finalizeTscFindings,
	lintJsAuditors,
	oxlint,
	parseBiomeReport,
	parseEslintReport,
	parseOxlintReport,
	parseTscOutput,
	sanitizeOxlintConfig,
	selectTsconfigs,
	type TscDiagnostic,
	tscFindings,
	typecheck,
} from "../src/codebase/lint-js";
import { fixture } from "./helpers";

const recorded = (name: string) =>
	readFileSync(fixture("lint-js", "recorded", name), "utf8");
const recordedJson = (name: string): unknown => JSON.parse(recorded(name));

const summary = (
	findings: ReadonlyArray<{
		ruleId: string;
		severity: string;
		category: string;
		location?: { file?: string; line?: number };
	}>,
) =>
	findings.map(
		(f) =>
			`${f.ruleId.replace(/^code\.\w+\//, "")} ${f.severity} ${f.category} ${f.location?.file ?? "-"}:${f.location?.line ?? "-"}`,
	);

interface Call {
	readonly cmd: ReadonlyArray<string>;
	readonly options: ExecOptions;
}

/** Runs an auditor on `dir` with a fake Exec that records every call. */
const runFake = async (
	auditor: Auditor,
	dir: string,
	which: (bin: string) => string | undefined,
	run: (cmd: ReadonlyArray<string>, options: ExecOptions) => ExecResult,
): Promise<{ report: Report; calls: Call[] }> => {
	const calls: Call[] = [];
	const report = await Effect.runPromise(
		runAudit({
			target: dir,
			auditors: [auditor],
			selection: { only: [auditor.id] },
		}).pipe(
			Effect.provide(
				Layer.mergeAll(
					Workspaces.layer,
					Http.layer,
					Layer.succeed(Exec, {
						which: (bin: string) => Effect.succeed(which(bin)),
						run: (cmd: ReadonlyArray<string>, options: ExecOptions = {}) =>
							Effect.sync(() => {
								calls.push({ cmd, options });
								return run(cmd, options);
							}),
					}),
				),
			),
		),
	);
	return { report, calls };
};

const withProject = async <A>(
	files: Record<string, string>,
	use: (dir: string) => Promise<A>,
): Promise<A> => {
	const dir = await mkdtemp(join(tmpdir(), "openaudit-lintjs-"));
	try {
		for (const [path, text] of Object.entries(files)) {
			await mkdir(dirname(join(dir, path)), { recursive: true });
			await writeFile(join(dir, path), text);
		}
		return await use(dir);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
};

const ok = (stdout: string, code = 0): ExecResult => ({
	code,
	stdout,
	stderr: "",
});
const findingsOf = (report: Report) =>
	report.results.flatMap((r) => r.findings);
const statusOf = (report: Report) => report.results[0]?.status;

describe("auditor metadata", () => {
	test("tools, engines and defaults", () => {
		expect(
			lintJsAuditors.map(
				(a) => `${a.id} ${a.engine} ${a.tool} ${a.defaultEnabled}`,
			),
		).toEqual([
			"code.typecheck external tsc true",
			"code.oxlint external oxlint true",
			"code.biome external biome true",
			"code.eslint external eslint false",
		]);
		expect(eslint.description).toContain("executes code");
	});
});

describe("tsc parser", () => {
	const root = "/repo";
	const cwd = "/tmp/openaudit-tsc-x";

	test("resolves cwd-relative paths against the workspace", () => {
		const diagnostics = parseTscOutput(recorded("tsc.txt"), cwd, root);
		expect(
			diagnostics.map((d) => `${d.file}:${d.line}:${d.column} ${d.code}`),
		).toEqual([
			"src/index.test.ts:3:7 TS2345",
			"src/index.ts:1:25 TS2307",
			"src/index.ts:2:23 TS2307",
			"src/index.ts:4:14 TS2322",
			"src/index.ts:7:9 TS18048",
		]);
	});

	test("paths under a symlinked root map back to the workspace root", () => {
		const [d] = parseTscOutput(
			"../../real/proj/src/a.ts(2,3): error TS2322: bad",
			"/tmp/x",
			"/link/proj",
			"/real/proj",
		);
		expect(d?.file).toBe("src/a.ts");
	});

	test("global diagnostics have no file; continuation lines are dropped", () => {
		const out = [
			"error TS5083: Cannot read file '/x/tsconfig.json'.",
			"src/a.ts(1,1): error TS2322: Type 'A' is not assignable to type 'B'.",
			"  Types of property 'x' are incompatible.",
			"Found 1 error.",
		].join("\n");
		expect(parseTscOutput(out, "/repo", "/repo")).toEqual([
			{ code: "TS5083", message: "Cannot read file '/x/tsconfig.json'." },
			{
				file: "src/a.ts",
				line: 1,
				column: 1,
				code: "TS2322",
				message: "Type 'A' is not assignable to type 'B'.",
			},
		]);
	});

	test("findings: unresolved modules collapse; test files are low", () => {
		const findings = tscFindings(
			parseTscOutput(recorded("tsc.txt"), cwd, root),
			"tsconfig.json",
		);
		expect(summary(findings)).toEqual([
			"unresolved-modules medium reliability src/index.ts:1",
			"type-error low reliability src/index.test.ts:3",
			"type-error medium reliability src/index.ts:4",
			"type-error medium reliability src/index.ts:7",
		]);
		const collapsed = findings[0];
		expect(collapsed?.message).toContain("2 imports in 1 files");
		expect(collapsed?.message).toContain(
			"some-missing-package, another-missing-package",
		);
		expect(findings[3]?.title).toBe(
			"TS18048: 'value' is possibly 'undefined'.",
		);
		expect(findings[3]?.tags).toEqual(["ts18048", "typescript"]);
	});

	test("errors inside dependencies are ignored, empty-project notices too", () => {
		const diagnostics: TscDiagnostic[] = [
			{
				file: "node_modules/@types/x/index.d.ts",
				line: 1,
				column: 1,
				code: "TS2300",
				message: "dup",
			},
			{
				file: "../other/a.ts",
				line: 1,
				column: 1,
				code: "TS2300",
				message: "dup",
			},
			{ code: "TS18003", message: "No inputs were found in config file." },
		];
		expect(tscFindings(diagnostics, "tsconfig.json")).toEqual([]);
	});

	test("config errors are reported against the tsconfig", () => {
		const findings = tscFindings(
			[{ code: "TS5058", message: "The specified path does not exist." }],
			"pkg/tsconfig.json",
		);
		expect(summary(findings)).toEqual([
			"config-error low reliability pkg/tsconfig.json:-",
		]);
	});

	test("finalize de-duplicates across configs and caps with a summary", () => {
		const many: TscDiagnostic[] = Array.from({ length: 250 }, (_, i) => ({
			file: `src/f${String(i).padStart(3, "0")}.ts`,
			line: 1,
			column: 1,
			code: "TS2322",
			message: "bad",
		}));
		const once = tscFindings(many, "a/tsconfig.json");
		const twice = [...once, ...tscFindings(many, "b/tsconfig.json")];
		const out = finalizeTscFindings(twice);
		expect(out).toHaveLength(201);
		expect(out[0]?.location?.file).toBe("src/f000.ts");
		expect(out[200]).toMatchObject({
			ruleId: "code.typecheck/more-errors",
			severity: "info",
			title: "50 more tsc findings not listed",
		});
	});

	test("selectTsconfigs keeps project roots and drops solution and base configs", () => {
		const selected = selectTsconfigs(
			[
				{ path: "packages/b/tsconfig.json", text: "{}" },
				{ path: "tsconfig.json", text: '{ "extends": "@scope/base.json" }' },
				{ path: "packages/a/tsconfig.json", text: '{ "include": ["src"] }' },
				{
					path: "packages/c/tsconfig.json",
					text: "{ /* no include, no package.json */ }",
				},
				{
					path: "apps/x/tsconfig.json",
					text: '{ "files": [], "references": [{ "path": "../a" }] }',
				},
			],
			new Set(["packages/b"]),
		);
		expect(selected).toEqual([
			"packages/a/tsconfig.json",
			"packages/b/tsconfig.json",
		]);
		// A lone root config is a project.
		expect(
			selectTsconfigs(
				[{ path: "tsconfig.json", text: '{ "extends": "x" }' }],
				new Set(),
			),
		).toEqual(["tsconfig.json"]);
	});

	test("absolute workspace paths are stripped from messages", () => {
		const [d] = parseTscOutput(
			"src/a.ts(1,1): error TS6142: Module './b' was resolved to '/repo/src/b.tsx', but '--jsx' is not set.",
			"/repo",
			"/repo",
		);
		expect(d?.message).toBe(
			"Module './b' was resolved to 'src/b.tsx', but '--jsx' is not set.",
		);
	});
});

describe("code.typecheck", () => {
	const tsconfig =
		'{ "compilerOptions": { "strict": true }, "include": ["src"] }';

	test("skips when dependencies are not installed", async () => {
		await withProject(
			{
				"package.json": "{}",
				"tsconfig.json": tsconfig,
				"src/a.ts": "export {};",
			},
			async (dir) => {
				const { report, calls } = await runFake(
					typecheck,
					dir,
					() => undefined,
					() => ok(""),
				);
				expect(statusOf(report)).toBe("skipped");
				expect(report.results[0]?.message).toContain("node_modules");
				expect(calls).toEqual([]);
			},
		);
	});

	test("skips without a tsconfig", async () => {
		await withProject({ "a.js": "1" }, async (dir) => {
			const { report } = await runFake(
				typecheck,
				dir,
				() => undefined,
				() => ok(""),
			);
			expect(statusOf(report)).toBe("skipped");
			expect(report.results[0]?.message).toContain("tsconfig");
		});
	});

	test("runs the bundled tsc from a temp cwd with hardening flags and maps its output", async () => {
		await withProject(
			{
				"package.json": "{}",
				"node_modules/dep/index.js": "",
				"tsconfig.json": tsconfig,
				"src/index.ts": "",
				"src/index.test.ts": "",
			},
			async (dir) => {
				const { report, calls } = await runFake(
					typecheck,
					dir,
					(bin) => (bin === "node" ? "/usr/bin/node" : undefined),
					() =>
						ok(
							[
								`${dir}/src/index.ts(4,14): error TS2322: Type 'string' is not assignable to type 'number'.`,
								`${dir}/src/index.test.ts(3,7): error TS2345: bad arg`,
								`${dir}/src/index.ts(1,1): error TS2307: Cannot find module 'zzz' or its corresponding type declarations.`,
							].join("\n"),
							2,
						),
				);
				expect(statusOf(report)).toBe("failed");
				expect(summary(findingsOf(report))).toEqual([
					"unresolved-modules medium reliability src/index.ts:1",
					"type-error medium reliability src/index.ts:4",
					"type-error low reliability src/index.test.ts:3",
				]);
				expect(calls).toHaveLength(1);
				const call = calls[0];
				expect(call?.cmd[0]).toBe("/usr/bin/node");
				expect(call?.cmd[1]).toMatch(/typescript\/bin\/tsc$/);
				expect(call?.cmd.slice(2)).toEqual([
					"-p",
					join(dir, "tsconfig.json"),
					"--noEmit",
					"--pretty",
					"false",
					"--skipLibCheck",
					"--tsBuildInfoFile",
					join(call?.options.cwd ?? "", "0.tsbuildinfo"),
				]);
				expect(call?.options.cwd).not.toBe(dir);
				expect(call?.options.cwd?.startsWith(realpathSync(tmpdir()))).toBe(
					true,
				);
			},
		);
	});

	test("a crashing tsc becomes an error only when every config fails", async () => {
		await withProject(
			{
				"package.json": "{}",
				"node_modules/.keep": "",
				"tsconfig.json": tsconfig,
				"src/a.ts": "",
			},
			async (dir) => {
				const { report } = await runFake(
					typecheck,
					dir,
					() => undefined,
					() => ({
						code: 134,
						stdout: "",
						stderr: "heap out of memory",
					}),
				);
				expect(statusOf(report)).toBe("error");
				expect(report.results[0]?.message).toContain("heap out of memory");
			},
		);
	});
});

describe("oxlint", () => {
	test("sanitizer drops everything that can load code or escape the temp cwd", () => {
		const out = JSON.parse(
			sanitizeOxlintConfig(`{
				// comment
				"jsPlugins": ["./evil.js"],
				"extends": ["./other.json"],
				"ignorePatterns": ["x"],
				"overrides": [{ "files": ["*.ts"], "jsPlugins": ["./evil.js"] }],
				"plugins": ["typescript"],
				"categories": { "suspicious": "warn" },
				"rules": { "no-debugger": "error" },
			}`) ?? "null",
		);
		expect(out).toEqual({
			plugins: ["typescript"],
			categories: { suspicious: "warn" },
			rules: { "no-debugger": "error" },
		});
		expect(sanitizeOxlintConfig("not json")).toBeUndefined();
	});

	test("parser on a recorded oxlint 1.88.0 run", () => {
		const findings = parseOxlintReport(recordedJson("oxlint.json"), "/repo");
		expect(summary(findings)).toEqual([
			"no-unused-vars low maintainability src/index.ts:3",
			"no-debugger medium maintainability src/index.ts:2",
			"oxc-const-comparisons low reliability src/index.ts:4",
			"use-isnan low reliability src/index.ts:5",
		]);
		expect(findings[1]?.message).toContain(
			"`debugger` statement is not allowed",
		);
		expect(findings[1]?.references).toEqual([
			"https://oxc.rs/docs/guide/usage/linter/rules/eslint/no-debugger.html",
		]);
		expect(findings[0]?.location).toEqual({
			file: "src/index.ts",
			line: 3,
			column: 8,
		});
	});

	test("non-eslint plugin rules keep their plugin in the rule id; errors are medium", () => {
		const findings = parseOxlintReport(
			{
				diagnostics: [
					{
						message: "Unexpected any",
						code: "typescript-eslint(no-explicit-any)",
						severity: "error",
						filename: "/repo/a.ts",
						labels: [{ span: { line: 1, column: 2 } }],
					},
					{
						message: "Unexpected token",
						severity: "error",
						filename: "/repo/b.ts",
						labels: [],
					},
				],
			},
			"/repo",
		);
		expect(summary(findings)).toEqual([
			"typescript-eslint-no-explicit-any medium maintainability a.ts:1",
			"parse-error medium reliability b.ts:-",
		]);
	});

	test("skips without the binary and without JS files", async () => {
		await withProject({ "a.ts": "1" }, async (dir) => {
			const { report } = await runFake(
				oxlint,
				dir,
				() => undefined,
				() => ok("{}"),
			);
			expect(statusOf(report)).toBe("skipped");
			expect(report.results[0]?.message).toContain("npm install -g oxlint");
		});
		await withProject({ "a.py": "1" }, async (dir) => {
			const { report } = await runFake(
				oxlint,
				dir,
				() => "/bin/oxlint",
				() => ok("{}"),
			);
			expect(statusOf(report)).toBe("skipped");
		});
	});

	test("passes a sanitized temp config, never the project's", async () => {
		await withProject(
			{
				"a.ts": "debugger;",
				".oxlintrc.json":
					'{ "jsPlugins": ["./evil.js"], "rules": { "no-debugger": "error" } }',
			},
			async (dir) => {
				let configSeen = "";
				const { report, calls } = await runFake(
					oxlint,
					dir,
					() => "/bin/oxlint",
					(cmd) => {
						configSeen = readFileSync(cmd[cmd.indexOf("-c") + 1] ?? "", "utf8");
						return ok(recorded("oxlint.json"), 0);
					},
				);
				expect(statusOf(report)).toBe("failed");
				expect(findingsOf(report)).toHaveLength(4);
				expect(JSON.parse(configSeen)).toEqual({
					rules: { "no-debugger": "error" },
				});
				const call = calls[0];
				expect(call?.cmd[0]).toBe("/bin/oxlint");
				expect(call?.cmd).toContain("--disable-nested-config");
				expect(
					call?.cmd.slice(
						call.cmd.indexOf("--format"),
						call.cmd.indexOf("--format") + 2,
					),
				).toEqual(["--format", "json"]);
				expect(call?.cmd.at(-1)).toBe(dir);
				expect(call?.cmd.join(" ")).not.toContain(join(dir, ".oxlintrc.json"));
				expect(call?.options.cwd).not.toBe(dir);
			},
		);
	});

	test("falls back to defaults when the project config is unusable", async () => {
		await withProject(
			{
				"a.ts": "1",
				".oxlintrc.json": '{ "rules": { "no-such-rule": "error" } }',
			},
			async (dir) => {
				const { report, calls } = await runFake(
					oxlint,
					dir,
					() => "/bin/oxlint",
					(cmd) =>
						cmd.includes("-c")
							? { code: 1, stdout: "", stderr: "Rule 'no-such-rule' not found" }
							: ok(recorded("oxlint.json")),
				);
				expect(calls).toHaveLength(2);
				expect(calls[1]?.cmd).not.toContain("-c");
				expect(findingsOf(report)).toHaveLength(4);
			},
		);
	});
});

describe("biome", () => {
	test("parser on a recorded biome 2.5.15 run", () => {
		const findings = parseBiomeReport(recordedJson("biome.json"), "/repo");
		expect(summary(findings)).toEqual([
			"no-non-null-assertion low maintainability src/index.ts:7",
			"no-unused-variables low reliability src/index.ts:3",
			"no-debugger medium reliability src/index.ts:2",
			"no-double-equals medium reliability src/index.ts:4",
			"no-double-equals medium reliability src/index.ts:4",
			"use-is-nan medium reliability src/index.ts:5",
		]);
		expect(findings[2]?.references).toEqual([
			"https://biomejs.dev/linter/rules/no-debugger",
		]);
	});

	test("only lint, parse and plugin diagnostics become findings", () => {
		const loc = { path: "/repo/a.ts", start: { line: 1, column: 1 } };
		const findings = parseBiomeReport(
			{
				diagnostics: [
					{
						severity: "info",
						category: "deserialize",
						message: "deprecated",
						location: loc,
					},
					{ severity: "error", category: "configuration", message: "bad" },
					{
						severity: "error",
						category: "parse",
						message: "Expected an expression",
						location: loc,
					},
					{
						severity: "warning",
						category: "plugin",
						message: "no console.log",
						location: loc,
					},
				],
			},
			"/repo",
		);
		expect(summary(findings)).toEqual([
			"parse-error medium reliability a.ts:1",
			"plugin medium reliability a.ts:1",
		]);
	});

	test("skips without biome.json or the binary", async () => {
		await withProject({ "a.ts": "1" }, async (dir) => {
			const { report } = await runFake(
				biome,
				dir,
				() => "/bin/biome",
				() => ok("{}"),
			);
			expect(statusOf(report)).toBe("skipped");
			expect(report.results[0]?.message).toContain("biome.json");
		});
		await withProject({ "biome.jsonc": "{}", "a.ts": "1" }, async (dir) => {
			const { report } = await runFake(
				biome,
				dir,
				() => undefined,
				() => ok("{}"),
			);
			expect(statusOf(report)).toBe("skipped");
			expect(report.results[0]?.message).toContain("@biomejs/biome");
		});
	});

	test("runs lint from a temp cwd with the config loaded from the target", async () => {
		await withProject(
			{ "biome.json": "{}", "a.ts": "debugger;" },
			async (dir) => {
				const { report, calls } = await runFake(
					biome,
					dir,
					() => "/bin/biome",
					() => ok(recorded("biome.json"), 1),
				);
				expect(statusOf(report)).toBe("failed");
				// The two identical `==` findings on one line share a fingerprint and merge.
				expect(findingsOf(report)).toHaveLength(5);
				const call = calls[0];
				expect(call?.cmd).toEqual([
					"/bin/biome",
					"lint",
					"--reporter=json",
					"--colors=off",
					"--max-diagnostics=none",
					"--no-errors-on-unmatched",
					`--config-path=${dir}`,
					`--vcs-root=${dir}`,
					dir,
				]);
				expect(call?.options.cwd).not.toBe(dir);
			},
		);
	});

	test("a configuration error (non-JSON output) is an error, not a pass", async () => {
		await withProject({ "biome.json": "{}", "a.ts": "1" }, async (dir) => {
			const { report } = await runFake(
				biome,
				dir,
				() => "/bin/biome",
				() => ({
					code: 1,
					stdout:
						"configuration ━━━ Biome exited because the configuration resulted in errors.",
					stderr: "",
				}),
			);
			expect(statusOf(report)).toBe("error");
		});
	});
});

describe("eslint", () => {
	test("parser on a recorded eslint 10.12.0 run", () => {
		const findings = parseEslintReport(recordedJson("eslint.json"), "/repo");
		expect(summary(findings)).toEqual([
			"parse-error medium reliability bad.js:1",
			"no-unused-vars low maintainability index.js:1",
			"no-debugger medium maintainability index.js:2",
			"no-unused-vars low maintainability index.js:3",
			"eqeqeq medium maintainability index.js:4",
		]);
		expect(findings[0]?.message).toBe("Parsing error: Unexpected token ;");
		// ESLint echoes `source` for files with errors; it must not reach evidence.
		expect(JSON.stringify(findings)).not.toContain("return input.length");
	});

	test("is opt-in and skips without a flat config", async () => {
		await withProject({ ".eslintrc.json": "{}", "a.js": "1" }, async (dir) => {
			const { report } = await runFake(
				eslint,
				dir,
				() => "/bin/eslint",
				() => ok("[]"),
			);
			expect(statusOf(report)).toBe("skipped");
			expect(report.results[0]?.message).toContain("legacy");
		});
		await withProject({ "a.js": "1" }, async (dir) => {
			const { report } = await runFake(
				eslint,
				dir,
				() => "/bin/eslint",
				() => ok("[]"),
			);
			expect(statusOf(report)).toBe("skipped");
			expect(report.results[0]?.message).toContain("eslint.config");
		});
	});

	test("runs from the target root, preferring the project's own eslint", async () => {
		await withProject(
			{
				"eslint.config.mjs": "export default [];",
				"a.js": "1",
				"node_modules/.bin/eslint": "#!/bin/sh\n",
			},
			async (dir) => {
				const { report, calls } = await runFake(
					eslint,
					dir,
					() => "/bin/eslint",
					() => ok(recorded("eslint.json"), 1),
				);
				expect(statusOf(report)).toBe("failed");
				expect(findingsOf(report)).toHaveLength(5);
				expect(calls[0]?.cmd[0]).toBe(join(dir, "node_modules/.bin/eslint"));
				expect(calls[0]?.cmd).toContain("json");
				expect(calls[0]?.options.cwd).toBe(dir);
			},
		);
		await withProject(
			{ "eslint.config.js": "export default [];", "a.js": "1" },
			async (dir) => {
				const { calls } = await runFake(
					eslint,
					dir,
					() => "/bin/eslint",
					() => ok("[]"),
				);
				expect(calls[0]?.cmd[0]).toBe("/bin/eslint");
			},
		);
	});

	test("a fatal config error (exit 2) is an error", async () => {
		await withProject({ "eslint.config.js": "x", "a.js": "1" }, async (dir) => {
			const { report } = await runFake(
				eslint,
				dir,
				() => "/bin/eslint",
				() => ({
					code: 2,
					stdout: "",
					stderr: "Oops! Something went wrong!",
				}),
			);
			expect(statusOf(report)).toBe("error");
		});
	});
});
