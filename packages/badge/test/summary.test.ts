import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { summarize } from "../src/summary";

/** A real report: the hosted scan of this repository, with its suppressions. */
const selfAudit = join(import.meta.dir, "fixtures/self-audit.json");

const report = (overrides: Record<string, unknown> = {}) =>
	JSON.stringify({
		schemaVersion: "1",
		tool: { name: "openaudit", version: "0.3.0" },
		summary: {
			score: 95.6,
			grade: "A",
			counts: { critical: 0, high: 1, medium: 2, low: 3, info: 4 },
			categories: [
				{ category: "security", score: 91.2, grade: "A", counts: {} },
			],
			auditors: { passed: 10, failed: 2, skipped: 5, error: 1 },
		},
		results: [],
		...overrides,
	});

describe("summarize", () => {
	test("reads the headline numbers", () => {
		expect(summarize(report())).toEqual({
			score: 96,
			grade: "A",
			severities: { critical: 0, high: 1, medium: 2, low: 3, info: 4 },
			categories: [{ category: "security", score: 91, grade: "A" }],
			auditors: { passed: 10, failed: 2, skipped: 5, error: 1 },
			suppressed: 0,
			hiddenBy: [],
			openauditVersion: "0.3.0",
		});
	});

	test("counts only what the project's config hid", () => {
		const summary = summarize(
			report({
				suppressed: [
					{
						source: "openaudit.config.json",
						rules: 1,
						paths: 2,
						fingerprints: 3,
						entries: [
							{ kind: "path", value: "test/**", reason: "Fixtures", count: 2 },
							{ kind: "rule", value: "x".repeat(400), count: 1 },
						],
					},
					{
						source: "--baseline old.json",
						rules: 0,
						paths: 0,
						fingerprints: 4,
					},
					{ source: ".gitignore", rules: 0, paths: 50, fingerprints: 0 },
					{ source: "--diff main", rules: 0, paths: 9, fingerprints: 0 },
				],
			}),
		);
		expect(summary?.suppressed).toBe(6);
		expect(summary?.hiddenBy).toEqual([
			{ kind: "path", value: "test/**", reason: "Fixtures", count: 2 },
			{ kind: "rule", value: "x".repeat(300), reason: null, count: 1 },
		]);
	});

	test("a baseline is not the project's config", () => {
		const summary = summarize(
			report({
				suppressed: [
					{
						source: "--baseline old.json",
						rules: 1,
						paths: 0,
						fingerprints: 0,
					},
				],
			}),
		);
		expect(summary?.suppressed).toBe(0);
	});

	test("summarises a real self-audit report", async () => {
		const summary = summarize(await Bun.file(selfAudit).text());
		expect(summary?.grade).toMatch(/^[A-F]$/);
		expect(summary?.suppressed).toBeGreaterThan(0);
		expect(summary?.hiddenBy.length).toBeGreaterThan(0);
	});

	test("rejects anything that isn't an openaudit report", () => {
		expect(summarize("not json")).toBeUndefined();
		expect(summarize("{}")).toBeUndefined();
		expect(summarize(report({ schemaVersion: "2" }))).toBeUndefined();
		const bad = JSON.parse(report());
		bad.summary.score = 900;
		expect(summarize(JSON.stringify(bad))).toBeUndefined();
	});
});
