import { describe, expect, test } from "bun:test";

import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import {
	aggregateFindings,
	braceNesting,
	checkCiStaticAnalysis,
	checkTsconfig,
	checkTsStrictness,
	expandCiText,
	pythonNesting,
	type QualityStats,
	quality,
	scanQualityFile,
} from "../src/codebase/quality";
import { fixture, runAuditor } from "./helpers";

const emptyStats = (): QualityStats => ({
	todos: new Map(),
	todoFiles: new Map(),
	tsIgnores: [],
	tsExpectErrors: 0,
	anyCount: new Map(),
});

describe("code.quality", () => {
	test("reports maintainability issues for the fixture project", async () => {
		const report = await runAuditor(quality, fixture("codebase", "quality"));
		const findings = report.results.flatMap((r) => r.findings);
		expect(
			findings
				.map(
					(f) =>
						`${f.ruleId.replace("code.quality/", "")} ${f.location?.file ?? "-"}:${f.location?.line ?? "-"}`,
				)
				.sort(),
		).toEqual([
			"deep-nesting src/deep.ts:8",
			"deep-nesting src/script.py:7",
			"engines-missing package.json:1",
			"tests-missing -:-",
			"todo-comments src/deep.ts:-",
			"ts-ignore src/flat.ts:1",
			"ts-no-fallthrough-cases tsconfig.json:3",
			"ts-no-implicit-override tsconfig.json:3",
			"ts-no-unchecked-indexed-access tsconfig.json:3",
			"ts-strict-disabled tsconfig.json:5",
		]);
		const todos = findings.find(
			(f) => f.ruleId === "code.quality/todo-comments",
		);
		expect(todos?.message).toContain("1 TODO, 1 FIXME, 1 HACK");
	});

	test("nesting depth ignores braces in strings, comments and object literals", () => {
		const text = [
			"function f(x) {",
			'  const s = "{{{{";',
			"  // if (a) { if (b) {",
			"  const o = { a: { b: { c: { d: 1 } } } };",
			"  if (x) {",
			"    for (const y of x) {",
			"      if (y) { return o; }",
			"    }",
			"  }",
			"}",
		].join("\n");
		expect(braceNesting(text)).toEqual({ depth: 3, line: 7 });
	});

	test("python nesting tracks indentation", () => {
		expect(
			pythonNesting(
				"def f():\n    if a:\n        pass\n    elif b:\n        for x in y:\n            pass\n",
			),
		).toEqual({
			depth: 2,
			line: 5,
		});
	});

	test("large files and explicit any are aggregated", () => {
		const stats = emptyStats();
		const text = `${"const a: any = 1;\n".repeat(1001)}`;
		const findings = scanQualityFile({ path: "big.ts", text }, stats);
		expect(findings.map((f) => f.ruleId)).toEqual(["code.quality/large-file"]);
		expect(stats.anyCount.get("big.ts")).toBe(1001);
	});

	test("tsconfig strictness", () => {
		expect(
			checkTsconfig({
				path: "tsconfig.json",
				text: '{ "compilerOptions": { "strict": true } }',
			}),
		).toBeUndefined();
		expect(
			checkTsconfig({
				path: "tsconfig.json",
				text: '{ "extends": "./base.json" }',
			}),
		).toBeUndefined();
		expect(
			checkTsconfig({ path: "tsconfig.json", text: "{ }" })?.severity,
		).toBe("low");
		expect(
			checkTsconfig({ path: "tsconfig.build.json", text: "{ }" }),
		).toBeUndefined();
	});
});

const tsconfigs = (files: Record<string, string>) =>
	Object.entries(files).map(([path, text]) => ({ path, text }));

describe("typescript strictness flags", () => {
	test("reports each missing flag once, listing the configs", () => {
		const findings = checkTsStrictness(
			tsconfigs({
				"a/tsconfig.json": '{ "compilerOptions": { "strict": true } }',
				"b/tsconfig.json":
					'{ "compilerOptions": { "noUncheckedIndexedAccess": true, "allowJs": true } }',
			}),
		);
		const byRule = Object.fromEntries(
			findings.map((f) => [f.ruleId.replace("code.quality/", ""), f]),
		);
		expect(Object.keys(byRule).sort()).toEqual([
			"ts-allow-js-without-check-js",
			"ts-no-fallthrough-cases",
			"ts-no-implicit-override",
			"ts-no-unchecked-indexed-access",
		]);
		expect(byRule["ts-no-unchecked-indexed-access"]?.severity).toBe("low");
		expect(byRule["ts-no-unchecked-indexed-access"]?.location?.file).toBe(
			"a/tsconfig.json",
		);
		expect(byRule["ts-no-unchecked-indexed-access"]?.message).toContain(
			"a/tsconfig.json",
		);
		expect(byRule["ts-no-implicit-override"]?.severity).toBe("info");
		expect(byRule["ts-no-implicit-override"]?.message).toContain(
			"2 tsconfig.json files",
		);
		expect(byRule["ts-allow-js-without-check-js"]?.location?.file).toBe(
			"b/tsconfig.json",
		);
	});

	test("follows relative extends and skips unresolvable ones", () => {
		const base =
			'{ "compilerOptions": { "noUncheckedIndexedAccess": true, "noImplicitOverride": true, "noFallthroughCasesInSwitch": true } }';
		expect(
			checkTsStrictness(
				tsconfigs({
					"tsconfig.base.json": base,
					"pkg/tsconfig.json": '{ "extends": "../tsconfig.base.json" }',
				}),
			),
		).toEqual([]);
		// An npm preset may enable anything, so nothing is claimed about it.
		expect(
			checkTsStrictness(
				tsconfigs({
					"tsconfig.json": '{ "extends": "@tsconfig/strictest/tsconfig.json" }',
				}),
			),
		).toEqual([]);
		// Solution-style configs hold no sources of their own.
		expect(
			checkTsStrictness(
				tsconfigs({
					"tsconfig.json": '{ "files": [], "references": [{ "path": "./a" }] }',
				}),
			),
		).toEqual([]);
	});
});

describe("ts escape hatches", () => {
	test("@ts-nocheck is a per-file medium finding; mentions in strings are ignored", () => {
		const stats = emptyStats();
		const nocheck = scanQualityFile(
			{ path: "src/a.ts", text: "// @ts-nocheck\nexport const a = 1;\n" },
			stats,
		);
		expect(nocheck.map((f) => `${f.ruleId} ${f.severity}`)).toEqual([
			"code.quality/ts-nocheck medium",
		]);
		expect(nocheck[0]?.location).toEqual({ file: "src/a.ts", line: 1 });
		expect(stats.tsIgnores).toEqual([]);
		const quoted = scanQualityFile(
			{
				path: "src/b.ts",
				text: 'export const re = /@ts-ignore/;\nexport const s = "// @ts-nocheck";\n',
			},
			stats,
		);
		expect(quoted).toEqual([]);
		expect(stats.tsIgnores).toEqual([]);
	});

	test("many @ts-ignore versus @ts-expect-error is reported once", () => {
		const stats = emptyStats();
		scanQualityFile(
			{
				path: "src/c.ts",
				text: [
					...Array.from({ length: 6 }, () => "// @ts-ignore\nfoo();"),
					"// @ts-expect-error legacy\nbar();",
				].join("\n"),
			},
			stats,
		);
		expect(stats.tsIgnores).toHaveLength(6);
		expect(stats.tsExpectErrors).toBe(1);
		expect(aggregateFindings(stats).map((f) => f.ruleId)).toEqual([
			"code.quality/ts-ignore",
			"code.quality/ts-ignore-over-expect-error",
		]);
		const few = emptyStats();
		few.tsIgnores.push({ path: "a.ts", line: 1 });
		expect(aggregateFindings(few).map((f) => f.ruleId)).toEqual([
			"code.quality/ts-ignore",
		]);
	});
});

const WORKFLOW = (run: string) => ({
	path: ".github/workflows/ci.yml",
	text: `name: CI\non: push\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n      - run: ${run}\n`,
});
const NO_HELPERS = { helpers: [] as { path: string; text: string }[] };
const langs = (entries: Record<string, number>) =>
	new Map(Object.entries(entries));

describe("CI static analysis", () => {
	test("reports each language that CI never checks, low and low-confidence", () => {
		const findings = checkCiStaticAnalysis({
			ci: [WORKFLOW("npm test")],
			scripts: new Map([["test", ["jest"]]]),
			...NO_HELPERS,
			languages: langs({ js: 10, python: 4, rust: 2, go: 3, shell: 5 }),
		});
		expect(findings.map((f) => f.title)).toEqual([
			"CI never type-checks or lints JavaScript/TypeScript",
			"CI never type-checks or lints Python",
			"CI never type-checks or lints Go",
			"CI never type-checks or lints Shell",
		]);
		expect(new Set(findings.map((f) => f.severity))).toEqual(new Set(["low"]));
		expect(new Set(findings.map((f) => f.confidence))).toEqual(
			new Set(["low"]),
		);
		expect(findings[0]?.location?.file).toBe(".github/workflows/ci.yml");
		expect(new Set(findings.map((f) => f.evidence)).size).toBe(4);
	});

	test("recognises direct commands and other-language tools", () => {
		const run = [
			"cargo clippy -- -D warnings",
			"ruff check .",
			"go vet ./...",
			"shellcheck scripts/*.sh",
			"bunx biome ci .",
		]
			.map((c) => `      - run: ${c}`)
			.join("\n");
		expect(
			checkCiStaticAnalysis({
				ci: [{ path: ".gitlab-ci.yml", text: `jobs:\n${run}\n` }],
				scripts: new Map(),
				...NO_HELPERS,
				languages: langs({ js: 9, rust: 9, python: 9, go: 9, shell: 9 }),
			}),
		).toEqual([]);
	});

	test("follows package.json scripts invoked from CI, transitively", () => {
		const input = {
			ci: [WORKFLOW("bun run check")],
			scripts: new Map([
				["check", ["turbo run check-types"]],
				["check-types", ["tsc --noEmit"]],
				["unrelated", ["eslint ."]],
			]),
			...NO_HELPERS,
			languages: langs({ js: 5 }),
		};
		expect(expandCiText(input)).toContain("tsc --noEmit");
		expect(expandCiText(input)).not.toContain("eslint");
		expect(checkCiStaticAnalysis(input)).toEqual([]);
		// The same lint script exists but CI never calls it.
		expect(
			checkCiStaticAnalysis({
				...input,
				ci: [WORKFLOW("bun test")],
				scripts: new Map([
					["lint", ["eslint ."]],
					["test", ["bun test"]],
				]),
			}).map((f) => f.tags),
		).toEqual([["ci", "js"]]);
	});

	test("follows Makefile and ignores commented-out steps", () => {
		const input = {
			ci: [
				{
					path: ".github/workflows/ci.yml",
					text: "steps:\n  # - run: ruff check .\n  - run: make lint\n",
				},
			],
			scripts: new Map<string, string[]>(),
			helpers: [{ path: "Makefile", text: "lint:\n\tmypy src\n" }],
			languages: langs({ python: 6 }),
		};
		expect(checkCiStaticAnalysis(input)).toEqual([]);
		expect(checkCiStaticAnalysis({ ...input, helpers: [] })).toHaveLength(1);
	});

	test("stays quiet without CI config or with only a few files", () => {
		expect(
			checkCiStaticAnalysis({
				ci: [],
				scripts: new Map(),
				...NO_HELPERS,
				languages: langs({ js: 50 }),
			}),
		).toEqual([]);
		expect(
			checkCiStaticAnalysis({
				ci: [WORKFLOW("true")],
				scripts: new Map(),
				...NO_HELPERS,
				languages: langs({ js: 2 }),
			}),
		).toEqual([]);
	});

	test("end to end on a temp project", async () => {
		const dir = await mkdtemp(join(tmpdir(), "openaudit-ci-"));
		try {
			const write = async (path: string, text: string) => {
				await mkdir(dirname(join(dir, path)), { recursive: true });
				await writeFile(join(dir, path), text);
			};
			await write("package.json", '{ "scripts": { "test": "bun test" } }');
			await write(
				".github/workflows/ci.yml",
				"jobs:\n  t:\n    steps:\n      - run: bun test\n",
			);
			for (const n of ["a", "b", "c"]) {
				await write(`src/${n}.ts`, `export const ${n} = 1;\n`);
				await write(`src/${n}.test.ts`, `export const t${n} = 1;\n`);
			}
			const report = await runAuditor(quality, dir);
			const ids = report.results.flatMap((r) =>
				r.findings.map((f) => f.ruleId),
			);
			expect(ids).toContain("code.quality/ci-no-static-analysis");
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});
});
