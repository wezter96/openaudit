import { describe, expect, test } from "bun:test";

import {
	braceNesting,
	checkTsconfig,
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
