import { afterAll, describe, expect, test } from "bun:test";

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import ts from "typescript";

import { codeHealth } from "../src/codebase/health";
import { parseRulesFile, rulesFor } from "../src/codebase/health/config";
import { analyzeJs } from "../src/codebase/health/js";
import { directivesBefore } from "../src/codebase/health/lines";
import type { FileMetrics } from "../src/codebase/health/metrics";
import {
	DEFAULT_THRESHOLDS,
	type RuleName,
	type RuleSet,
	scoreOf,
	similarity,
	smellsOf,
} from "../src/codebase/health/rules";
import { runAuditor } from "./helpers";

const tmps: string[] = [];
afterAll(() => {
	for (const dir of tmps) rmSync(dir, { recursive: true, force: true });
});

const analyze = (code: string, path = "a.ts") => analyzeJs(ts, path, code);
const fn = (m: FileMetrics, name: string) => {
	const found = m.functions.find((f) => f.name === name);
	if (!found)
		throw new Error(`no function ${name} in ${m.functions.map((f) => f.name)}`);
	return found;
};

const DEFAULT: RuleSet = { thresholds: DEFAULT_THRESHOLDS, weights: {} };
const rulesIn = (code: string, path = "a.ts") =>
	smellsOf(analyze(code, path), DEFAULT, false).map((s) => s.rule);

/** `n` sequential `if` statements: cyclomatic complexity n + 1. */
const branchy = (name: string, n: number) =>
	`function ${name}(x: number) {\n${Array.from({ length: n }, (_, i) => `\tif (x === ${i}) return ${i};`).join("\n")}\n\treturn -1;\n}\n`;

describe("code.health metrics", () => {
	test("counts branches, logical operators and optional chains, not ?? or template code", () => {
		const m = analyze(
			"const f = (a?: { b?: number }, c = 0) => {\n\tif (a?.b && c) return 1;\n\tconst d = a ?? c;\n\treturn `$" +
				"{d ? 1 : 2}`;\n};\n",
		);
		expect(fn(m, "f").cc).toBe(4);
	});

	test("names units like CodeScene: members, inner functions, test labels and wrapped callbacks", () => {
		const m = analyze(
			[
				"class Lexer { next() { return 1; } }",
				"const grammar = { parse() { return 2; } };",
				"function outer() { const inner = () => { return 3; }; return inner; }",
				'test("adds numbers", () => { expect(1).toBe(1); });',
				"export const auditor = define({ run: (ctx) => gen(function* () { yield 1; }) });",
			].join("\n"),
		);
		expect(m.functions.map((f) => f.name).sort()).toEqual([
			'"adds numbers"',
			"Lexer.next",
			"auditor",
			"grammar.parse",
			"outer",
			"outer.inner",
		]);
	});

	test("lines of code skip blank lines, comments and inner functions", () => {
		const m = analyze(
			"function f() {\n\t// a comment\n\n\t/* block\n\t   comment */\n\tconst g = () => {\n\t\treturn 1;\n\t};\n\treturn g();\n}\n",
		);
		expect(fn(m, "f").loc).toBe(3);
		expect(fn(m, "f.g").loc).toBe(3);
	});

	test("nesting, bumps and complex conditionals", () => {
		const m = analyze(
			[
				"function f(a: number[], b: boolean, c: boolean) {",
				"\tfor (const x of a) { if (x) { if (b) return 1; } }",
				"\tif (b) { while (c) { c = false; } }",
				"\tif (b && c || !b) return 2;",
				"\treturn 0;",
				"}",
			].join("\n"),
		);
		const f = fn(m, "f");
		expect(f.nesting).toBe(3);
		expect(f.bumps.length).toBe(2);
		expect(f.conditionals).toEqual([{ line: 4, endLine: 4, branches: 2 }]);
	});

	test("parameter types", () => {
		const f = fn(
			analyze(
				"function f(a: string, b: number, c: Date, d = 'x', e = 1) { return a; }",
			),
			"f",
		);
		expect(f.params.map((p) => [p.primitive, p.string])).toEqual([
			[true, true],
			[true, false],
			[false, false],
			[true, true],
			[true, false],
		]);
	});

	test("reads CodeScene directives in the comment above a function", () => {
		const text =
			'// keep: parser\n// @codescene(disable:"Complex Method", disable:"Bumpy Road Ahead")\nfunction f() {}\n/* @codescene(disable-all) */\nfunction g() {}\n';
		expect(directivesBefore(text, text.indexOf("function f"))).toEqual([
			"Complex Method",
			"Bumpy Road Ahead",
		]);
		expect(directivesBefore(text, text.indexOf("function g"))).toEqual(["*"]);
	});
});

describe("code.health rules", () => {
	test("complex method from cyclomatic complexity 9", () => {
		expect(rulesIn(branchy("f", 7))).not.toContain("Complex Method");
		expect(rulesIn(branchy("f", 8))).toContain("Complex Method");
	});

	test("a directive switches a smell off for its function", () => {
		const code = `// @codescene(disable:"Complex Method")\n${branchy("f", 12)}`;
		expect(rulesIn(code)).not.toContain("Complex Method");
	});

	test("large method from 70 lines of code, charged once when also complex", () => {
		const body = Array.from(
			{ length: 70 },
			(_, i) => `\tconst v${i} = ${i};`,
		).join("\n");
		const smells = smellsOf(
			analyze(`function f() {\n${body}\n}\n`),
			DEFAULT,
			false,
		);
		const large = smells.find((s) => s.rule === "Large Method");
		expect(large?.impact).toBeCloseTo(0.018 * 72);
	});

	test("excess arguments above 4, constructors above 5", () => {
		expect(rulesIn("function f(a, b, c, d) { return a; }")).toEqual([]);
		expect(rulesIn("function f(a, b, c, d, e) { return a; }")).toEqual([
			"Excess Number of Function Arguments",
		]);
		expect(rulesIn("class A { constructor(a, b, c, d, e) {} }")).toEqual([]);
		expect(rulesIn("class A { constructor(a, b, c, d, e, f) {} }")).toEqual([
			"Constructor Over-Injection",
		]);
	});

	test("deep nesting from four levels", () => {
		const code =
			"function f(a: number[][]) { for (const r of a) { for (const x of r) { if (x) { if (x > 1) return x; } } } return 0; }";
		expect(rulesIn(code)).toContain("Deep, Nested Complexity");
	});

	test("overall complexity needs seven functions", () => {
		const six = Array.from({ length: 6 }, (_, i) => branchy(`f${i}`, 4)).join(
			"",
		);
		const seven = six + branchy("f6", 4);
		expect(rulesIn(six)).not.toContain("Overall Code Complexity");
		expect(rulesIn(seven)).toContain("Overall Code Complexity");
	});

	test("duplicated functions, but not in tests", () => {
		const copy = (name: string) =>
			`function ${name}(items: number[]) {\n\tlet total = 0;\n\tfor (const item of items) {\n\t\ttotal += item;\n\t}\n\tconst avg = total / items.length;\n\tconst max = Math.max(...items);\n\tconst min = Math.min(...items);\n\tconst spread = max - min;\n\treturn { total, avg, spread };\n}\n`;
		const code = copy("a") + copy("b");
		expect(rulesIn(code)).toContain("Code Duplication");
		expect(smellsOf(analyze(code), DEFAULT, true)).toEqual([]);
		expect(similarity(["a", "b"], ["a", "b"])).toBe(1);
		expect(similarity(["a"], ["b"])).toBe(0);
	});

	test("rules file: first matching set, weights and thresholds", () => {
		const sets = parseRulesFile({
			rule_sets: [
				{
					matching_content_path: "test/**",
					rules: [{ name: "Complex Method", weight: 0 }],
					thresholds: [{ name: "function_max_arguments", value: 6 }],
				},
				{ matching_content_path: "**/*", rules: [] },
				{ bogus: true },
			],
		});
		expect(sets.length).toBe(2);
		const forTest = rulesFor("test/a.ts", sets);
		expect(forTest.weights["Complex Method" as RuleName]).toBe(0);
		expect(forTest.thresholds.function_max_arguments).toBe(6);
		expect(rulesFor("src/a.ts", sets).thresholds.function_max_arguments).toBe(
			4,
		);
		const code = `${branchy("f", 12)}function g(a, b, c, d, e) { return a; }\n`;
		expect(smellsOf(analyze(code), forTest, false)).toEqual([]);
	});

	test("score decays from 10 like CodeScene's", () => {
		expect(scoreOf([])).toBe(10);
		const at = (impact: number) =>
			scoreOf([{ rule: "Complex Method", impact, functions: [] }]);
		expect(at(1)).toBeCloseTo(9.69, 1);
		expect(at(4)).toBeCloseTo(8.82, 1);
		expect(at(20)).toBeCloseTo(5.43, 1);
	});
});

const writeTree = async (root: string, files: Record<string, string>) => {
	for (const [path, text] of Object.entries(files)) {
		await mkdir(dirname(join(root, path)), { recursive: true });
		writeFileSync(join(root, path), text);
	}
};

describe("code.health auditor", () => {
	test("reports smells per file and a summary, skipping fixtures and declarations", async () => {
		const root = mkdtempSync(join(tmpdir(), "openaudit-health-"));
		tmps.push(root);
		await writeTree(root, {
			"src/big.ts": branchy("decide", 12),
			"src/ok.ts": "export const add = (a: number, b: number) => a + b;\n",
			"src/types.d.ts": branchy("ignored", 12),
			"test/fixtures/bad.ts": branchy("fixture", 12),
		});
		const report = await runAuditor(codeHealth, root);
		const findings = report.results.flatMap((r) => r.findings);
		const complex = findings.find(
			(f) => f.ruleId === "code.health/complex-method",
		);
		expect(complex?.location).toEqual({ file: "src/big.ts", line: 1 });
		expect(complex?.evidence).toBe("decide");
		expect(complex?.message).toContain("decide (cc = 13)");
		expect(findings.map((f) => f.location?.file)).not.toContain(
			"test/fixtures/bad.ts",
		);
		const summary = findings.find((f) => f.ruleId === "code.health/summary");
		expect(summary?.severity).toBe("info");
		expect(summary?.message).toContain("across 2 files");
	});
});
