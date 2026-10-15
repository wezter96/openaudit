import { describe, expect, test } from "bun:test";
import { readFileSync, realpathSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
	type Auditor,
	correlate,
	Exec,
	type ExecOptions,
	type ExecResult,
	type FindingInput,
	fingerprintOf,
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
		expect(eslint.description).toContain("oxlint");
		for (const a of [oxlint, eslint])
			expect(a.categories).toEqual(
				expect.arrayContaining(["accessibility", "performance", "reliability"]),
			);
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
			sanitizeOxlintConfig(
				`{
				// comment
				"jsPlugins": ["./evil.js"],
				"extends": ["./other.json"],
				"ignorePatterns": ["x"],
				"overrides": [{ "files": ["*.ts"], "jsPlugins": ["./evil.js"] }],
				"plugins": ["typescript"],
				"categories": { "suspicious": "warn" },
				"rules": { "no-debugger": "error" },
			}`,
				"/repo",
			) ?? "null",
		);
		expect(out).toEqual({
			plugins: ["typescript"],
			categories: { suspicious: "warn" },
			rules: { "no-debugger": "error" },
			overrides: [{ files: ["/repo/*.ts"] }],
		});
		expect(sanitizeOxlintConfig("not json", "/repo")).toBeUndefined();
	});

	test("sanitizer anchors override globs at the target root", () => {
		const config = `{ "overrides": [
			{ "files": ["scripts/**", "./e2e/**", "**/*.test.ts"], "rules": { "no-console": "off" } },
			{ "files": [], "rules": { "no-debugger": "off" } },
		] }`;
		expect(
			JSON.parse(sanitizeOxlintConfig(config, "/repo/") ?? "null"),
		).toEqual({
			overrides: [
				{
					files: ["/repo/scripts/**", "/repo/e2e/**", "**/*.test.ts"],
					rules: { "no-console": "off" },
				},
			],
		});
		// A root that is itself a glob would match the wrong files.
		expect(
			JSON.parse(sanitizeOxlintConfig(config, "/tmp/[x]") ?? "null"),
		).toEqual({});
	});

	const realOxlint = Bun.which("oxlint");
	test.skipIf(!realOxlint)(
		"anchored overrides still apply when oxlint runs from a temp dir",
		async () => {
			await withProject(
				{
					"scripts/a.ts": 'console.log("x");\n',
					"src/b.ts": 'console.log("x");\n',
				},
				async (dir) => {
					const root = realpathSync(dir);
					const config = sanitizeOxlintConfig(
						`{ "rules": { "no-console": "error" },
						   "overrides": [{ "files": ["scripts/**"], "rules": { "no-console": "off" } }] }`,
						root,
					);
					// Its own temp dir, as in the auditor: never an ancestor of the root.
					const cwd = realpathSync(
						await mkdtemp(join(tmpdir(), "openaudit-oxlint-")),
					);
					try {
						const configFile = join(cwd, "oxlintrc.json");
						await writeFile(configFile, config ?? "");
						const proc = Bun.spawnSync(
							[
								realOxlint ?? "",
								"--format",
								"json",
								"--disable-nested-config",
								"-c",
								configFile,
								root,
							],
							{ cwd },
						);
						const files = parseOxlintReport(
							JSON.parse(proc.stdout.toString()),
							root,
						).map((f) => f.location?.file);
						expect(files).toEqual(["src/b.ts"]);
					} finally {
						await rm(cwd, { recursive: true, force: true });
					}
				},
			);
		},
	);

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

	test("parser on a recorded oxlint 1.88.0 run with the React, jsx-a11y and Next.js plugins", () => {
		const findings = parseOxlintReport(
			recordedJson("oxlint-react.json"),
			"/repo",
		);
		expect(summary(findings)).toEqual([
			"no-unused-vars low maintainability lib/util.ts:3",
			"no-debugger low maintainability lib/util.ts:2",
			"oxc-const-comparisons low reliability lib/util.ts:4",
			"unicorn-no-useless-spread low maintainability lib/util.ts:4",
			"next-no-head-import-in-document low reliability pages/_document.tsx:1",
			"next-no-sync-scripts low performance pages/_document.tsx:9",
			"jsx-a11y-html-has-lang low accessibility app/layout.tsx:3",
			"jsx-a11y-lang low accessibility app/layout.tsx:3",
			"jsx-a11y-alt-text low accessibility app/page.tsx:4",
			"next-no-img-element low performance app/page.tsx:4",
			"jsx-a11y-click-events-have-key-events low accessibility app/page.tsx:5",
			"jsx-a11y-no-static-element-interactions low accessibility app/page.tsx:5",
			"jsx-a11y-no-noninteractive-tabindex low accessibility app/page.tsx:6",
			"jsx-a11y-tabindex-no-positive low accessibility app/page.tsx:6",
			"jsx-a11y-anchor-is-valid low accessibility app/page.tsx:7",
			"react-set-state-in-effect low reliability components/Counter.tsx:7",
			"react-hooks-rules-of-hooks medium reliability components/Counter.tsx:5",
			"react-hooks-exhaustive-deps low reliability components/Counter.tsx:7",
			"react-hooks-rules-of-hooks medium reliability components/Counter.tsx:6",
			"react-jsx-key low maintainability components/Counter.tsx:17",
		]);
		// Shared ESLint rule ids let correlate merge them with code.eslint's findings.
		expect(findings.map((f) => f.tags)).toEqual([
			["eslint", "eslint:no-unused-vars"],
			["eslint", "eslint:no-debugger"],
			["oxc"],
			["unicorn", "eslint:unicorn/no-useless-spread"],
			["next", "eslint:@next/next/no-head-import-in-document"],
			["next", "eslint:@next/next/no-sync-scripts"],
			["jsx-a11y", "eslint:jsx-a11y/html-has-lang", "wcag-3.1.1"],
			["jsx-a11y", "eslint:jsx-a11y/lang", "wcag-3.1.1"],
			["jsx-a11y", "eslint:jsx-a11y/alt-text", "wcag-1.1.1"],
			["next", "eslint:@next/next/no-img-element"],
			[
				"jsx-a11y",
				"eslint:jsx-a11y/click-events-have-key-events",
				"wcag-2.1.1",
			],
			[
				"jsx-a11y",
				"eslint:jsx-a11y/no-static-element-interactions",
				"wcag-4.1.2",
			],
			["jsx-a11y", "eslint:jsx-a11y/no-noninteractive-tabindex"],
			["jsx-a11y", "eslint:jsx-a11y/tabindex-no-positive", "wcag-2.4.3"],
			["jsx-a11y", "eslint:jsx-a11y/anchor-is-valid", "wcag-2.1.1"],
			// oxlint files React Compiler rules under `react`; ESLint under `react-hooks`.
			["react", "eslint:react-hooks/set-state-in-effect"],
			["react-hooks", "eslint:react-hooks/rules-of-hooks"],
			["react-hooks", "eslint:react-hooks/exhaustive-deps"],
			["react-hooks", "eslint:react-hooks/rules-of-hooks"],
			["react", "eslint:react/jsx-key"],
		]);
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
		expect(findings[0]?.tags).toEqual([
			"typescript-eslint",
			"eslint:@typescript-eslint/no-explicit-any",
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

	/** Runs code.oxlint on a project and returns the config file of each call. */
	const oxlintConfigs = async (
		files: Record<string, string>,
		fail: (config: string) => boolean = () => false,
	) =>
		withProject(files, async (dir) => {
			const configs: Array<unknown> = [];
			await runFake(
				oxlint,
				dir,
				() => "/bin/oxlint",
				(cmd) => {
					const i = cmd.indexOf("-c");
					const config = i === -1 ? "" : readFileSync(cmd[i + 1] ?? "", "utf8");
					configs.push(config ? JSON.parse(config) : undefined);
					return fail(config)
						? { code: 1, stdout: "", stderr: "invalid config" }
						: ok(recorded("oxlint.json"));
				},
			);
			return configs;
		});

	const DEFAULTS = ["eslint", "typescript", "unicorn", "oxc"];
	const HOOKS = { "react/rules-of-hooks": "error" };

	test("enables the React, jsx-a11y and Next.js plugins the project depends on", async () => {
		expect(
			await oxlintConfigs({
				"package.json": JSON.stringify({
					dependencies: { next: "16.0.0", react: "19.2.0" },
				}),
				"app/page.tsx": "",
			}),
		).toEqual([
			{
				plugins: [...DEFAULTS, "react", "jsx-a11y", "nextjs"],
				rules: HOOKS,
			},
		]);
	});

	test("detects frameworks in workspace packages but not in fixtures", async () => {
		expect(
			await oxlintConfigs({
				"package.json": "{}",
				"apps/web/package.json": JSON.stringify({
					devDependencies: { preact: "10.0.0" },
				}),
				"test/fixtures/site/package.json": JSON.stringify({
					dependencies: { next: "16.0.0" },
				}),
				"apps/web/src/a.tsx": "",
			}),
		).toEqual([{ plugins: [...DEFAULTS, "react", "jsx-a11y"], rules: HOOKS }]);
	});

	test("runs with oxlint's defaults when no framework is found", async () => {
		expect(
			await oxlintConfigs({
				"package.json": JSON.stringify({ dependencies: { express: "5" } }),
				"a.ts": "",
			}),
		).toEqual([undefined]);
	});

	test("respects a project config that lists its own plugins", async () => {
		expect(
			await oxlintConfigs({
				"package.json": JSON.stringify({ dependencies: { react: "19" } }),
				".oxlintrc.json": '{ "plugins": ["typescript"], "rules": {} }',
				"a.tsx": "",
			}),
		).toEqual([{ plugins: ["typescript"], rules: {} }]);
	});

	test("adds the framework plugins to a project config without a plugins list", async () => {
		expect(
			await oxlintConfigs({
				"package.json": JSON.stringify({ dependencies: { react: "19" } }),
				".oxlintrc.json":
					'{ "jsPlugins": ["./evil.js"], "rules": { "no-debugger": "error" } }',
				"a.tsx": "",
			}),
		).toEqual([
			{
				rules: { "no-debugger": "error", ...HOOKS },
				plugins: [...DEFAULTS, "react", "jsx-a11y"],
			},
		]);
		// The project's own setting for rules-of-hooks wins.
		expect(
			await oxlintConfigs({
				"package.json": JSON.stringify({ dependencies: { react: "19" } }),
				".oxlintrc.json":
					'{ "rules": { "react-hooks/rules-of-hooks": "off" } }',
				"a.tsx": "",
			}),
		).toEqual([
			{
				rules: { "react-hooks/rules-of-hooks": "off" },
				plugins: [...DEFAULTS, "react", "jsx-a11y"],
			},
		]);
	});

	test("an unusable project config falls back to the framework plugins, then to defaults", async () => {
		const files = {
			"package.json": JSON.stringify({ dependencies: { react: "19" } }),
			".oxlintrc.json": '{ "rules": { "no-such-rule": "error" } }',
			"a.tsx": "",
		};
		expect(
			await oxlintConfigs(files, (c) => c.includes("no-such-rule")),
		).toEqual([
			{
				rules: { "no-such-rule": "error", ...HOOKS },
				plugins: [...DEFAULTS, "react", "jsx-a11y"],
			},
			{ plugins: [...DEFAULTS, "react", "jsx-a11y"], rules: HOOKS },
		]);
		expect(await oxlintConfigs(files, (c) => c !== "")).toHaveLength(3);
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

	test("parser on a recorded eslint 10.12.0 run with React, jsx-a11y and Next.js plugins", () => {
		const findings = parseEslintReport(
			recordedJson("eslint-react.json"),
			"/repo",
		);
		expect(summary(findings)).toEqual([
			"jsx-a11y-html-has-lang medium accessibility app/layout.tsx:3",
			"jsx-a11y-alt-text medium accessibility app/page.tsx:4",
			"next-next-no-img-element low performance app/page.tsx:4",
			"jsx-a11y-click-events-have-key-events medium accessibility app/page.tsx:5",
			"jsx-a11y-no-static-element-interactions medium accessibility app/page.tsx:5",
			"jsx-a11y-no-noninteractive-tabindex medium accessibility app/page.tsx:6",
			"jsx-a11y-tabindex-no-positive medium accessibility app/page.tsx:6",
			"jsx-a11y-anchor-is-valid medium accessibility app/page.tsx:7",
			"react-hooks-rules-of-hooks medium reliability components/Counter.tsx:5",
			"react-hooks-rules-of-hooks medium reliability components/Counter.tsx:6",
			"react-hooks-set-state-in-effect medium reliability components/Counter.tsx:7",
			"react-hooks-exhaustive-deps low reliability components/Counter.tsx:8",
			"react-jsx-key low maintainability components/Counter.tsx:18",
			"no-debugger medium maintainability lib/util.ts:2",
			"typescript-eslint-no-unused-vars medium maintainability lib/util.ts:3",
			"next-next-no-head-import-in-document medium reliability pages/_document.tsx:1",
			"next-next-no-sync-scripts low performance pages/_document.tsx:9",
		]);
		expect(findings[1]?.tags).toEqual([
			"eslint:jsx-a11y/alt-text",
			"wcag-1.1.1",
		]);
		// typescript-eslint's extension of a core rule shares the core rule's tag.
		expect(findings[14]?.tags).toEqual(["eslint:no-unused-vars"]);
		expect(findings[16]?.tags).toEqual(["eslint:@next/next/no-sync-scripts"]);
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

describe("oxlint and eslint together", () => {
	const asFindings = (auditor: string, inputs: ReadonlyArray<FindingInput>) =>
		inputs.map((f) => ({
			...f,
			auditor,
			fingerprint: fingerprintOf(auditor, f),
		}));
	const result = (auditor: string, inputs: ReadonlyArray<FindingInput>) => ({
		auditor,
		title: auditor,
		engine: "external" as const,
		categories: [],
		status: "failed" as const,
		durationMs: 1,
		findings: asFindings(auditor, inputs),
	});

	test("the same rule at the same file and line is one finding", () => {
		const out = correlate([
			result(
				"code.oxlint",
				parseOxlintReport(recordedJson("oxlint-react.json"), "/repo"),
			),
			result(
				"code.eslint",
				parseEslintReport(recordedJson("eslint-react.json"), "/repo"),
			),
		]);
		const all = out.flatMap((r) => r.findings);
		const tag = (f: { tags?: ReadonlyArray<string> }) =>
			f.tags?.find((t) => t.startsWith("eslint:"))?.slice(7);
		const merged = all
			.filter((f) => f.alsoReportedBy)
			.map((f) => `${tag(f)} ${f.location?.file}:${f.location?.line}`)
			.sort();
		expect(merged).toEqual([
			"@next/next/no-head-import-in-document pages/_document.tsx:1",
			"@next/next/no-img-element app/page.tsx:4",
			"@next/next/no-sync-scripts pages/_document.tsx:9",
			"jsx-a11y/alt-text app/page.tsx:4",
			"jsx-a11y/anchor-is-valid app/page.tsx:7",
			"jsx-a11y/click-events-have-key-events app/page.tsx:5",
			"jsx-a11y/html-has-lang app/layout.tsx:3",
			"jsx-a11y/no-noninteractive-tabindex app/page.tsx:6",
			"jsx-a11y/no-static-element-interactions app/page.tsx:5",
			"jsx-a11y/tabindex-no-positive app/page.tsx:6",
			"no-debugger lib/util.ts:2",
			"no-unused-vars lib/util.ts:3",
			"react-hooks/rules-of-hooks components/Counter.tsx:5",
			"react-hooks/rules-of-hooks components/Counter.tsx:6",
			"react-hooks/set-state-in-effect components/Counter.tsx:7",
		]);
		// Every duplicate points at a finding for the same rule, except oxlint's
		// `lang` on <html> without lang, which shares WCAG 3.1.1 with html-has-lang.
		const byFingerprint = new Map(all.map((f) => [f.fingerprint, f]));
		expect(
			all
				.filter((f) => f.duplicateOf)
				.map((f) => {
					const kept = tag(byFingerprint.get(f.duplicateOf ?? "") ?? {});
					return kept === tag(f) ? "same rule" : `${tag(f)} -> ${kept}`;
				})
				.sort(),
		).toEqual([
			"jsx-a11y/lang -> jsx-a11y/html-has-lang",
			...merged.map(() => "same rule"),
		]);
		// The tools disagree on the line of these, so both stay.
		expect(
			all
				.filter((f) => !f.duplicateOf && !f.alsoReportedBy)
				.map((f) => `${f.auditor} ${tag(f) ?? f.ruleId}`)
				.sort(),
		).toEqual([
			"code.eslint react-hooks/exhaustive-deps",
			"code.eslint react/jsx-key",
			"code.oxlint code.oxlint/oxc-const-comparisons",
			"code.oxlint react-hooks/exhaustive-deps",
			"code.oxlint react/jsx-key",
			"code.oxlint unicorn/no-useless-spread",
		]);
	});
});
