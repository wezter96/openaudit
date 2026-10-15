import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { correlate, type FindingInput, fingerprintOf } from "@openaudit/core";

import {
	biome,
	eslint,
	parseBiomeReport,
	parseEslintReport,
	parseOxlintReport,
} from "../src/codebase/lint-js";
import {
	findingsOf,
	ok,
	recorded,
	recordedJson,
	runFake,
	statusOf,
	summary,
	withProject,
} from "./lint-js-harness";

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
