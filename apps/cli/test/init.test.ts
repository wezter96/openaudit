import { describe, expect, test } from "bun:test";
import type { Auditor } from "@openaudit/core";

import { allAuditors } from "../src/audit";
import {
	CONFIG_SCHEMA_URL,
	parseConfig,
	restrictUntrusted,
} from "../src/config";
import { initConfig, noisyPaths, suggestedOptIns } from "../src/init";

const auditors: ReadonlyArray<Auditor> = allAuditors();

describe("noisyPaths", () => {
	test("finds fixtures under test directories, Go testdata and third_party", () => {
		expect(
			noisyPaths([
				"packages/a/test/fixtures/x.json",
				"tests/fixtures/deep/y.py",
				"src/__fixtures__/z.ts",
				"pkg/parse/testdata/in.txt",
				"third_party/lib/a.c",
			]).map(([glob]) => glob),
		).toEqual([
			"**/__fixtures__/**",
			"**/test/fixtures/**",
			"**/testdata/**",
			"**/tests/fixtures/**",
			"**/third_party/**",
		]);
	});

	test("leaves app fixtures (seed data) and file names alone", () => {
		expect(noisyPaths(["app/fixtures/users.json", "src/fixtures.ts"])).toEqual(
			[],
		);
	});
});

describe("suggestedOptIns", () => {
	test("names opt-in auditors for the detected stack that exist", () => {
		const ids = suggestedOptIns(["node", "typescript"], auditors);
		expect(ids).toContain("code.eslint");
		expect(ids).toContain("code.secrets-history");
		expect(ids).not.toContain("code.mypy");
		const known = new Set(auditors.map((a) => a.id));
		expect(ids.every((id) => known.has(id))).toBe(true);
	});
});

describe("initConfig", () => {
	const text = initConfig(
		{
			technologies: ["node", "typescript"],
			files: ["package.json", "test/fixtures/key.pem"],
		},
		auditors,
	);

	test("is a valid config that a target may use without warnings", () => {
		const config = parseConfig(text, "openaudit.config.jsonc");
		expect(config.$schema).toBe(CONFIG_SCHEMA_URL);
		expect(config.failOn).toBe("high");
		expect(config.ignore?.paths).toEqual([
			{
				path: "**/test/fixtures/**",
				reason: "Test fixtures: deliberately broken or vulnerable inputs",
			},
		]);
		expect(restrictUntrusted(config).ignored).toEqual([]);
	});

	test("comments on the licence policy and the stack's opt-in auditors", () => {
		expect(text).toContain(
			'// "settings": { "code.licenses": { "deny": ["AGPL-*", "GPL-*", "SSPL-1.0"] } }',
		);
		expect(text).toMatch(
			/Opt-in auditors that fit this project: [^\n]*code\.eslint/,
		);
		expect(text).toContain("--browser");
		// Short enough to read: no line much wider than the wrap width.
		const widest = Math.max(...text.split("\n").map((l) => l.length));
		expect(widest).toBeLessThan(110);
	});

	test("a project with nothing special gets empty lists", () => {
		const bare = parseConfig(
			initConfig({ technologies: [], files: ["main.c"] }, auditors),
			"x",
		);
		expect(bare.ignore).toEqual({ paths: [], rules: [], fingerprints: [] });
	});
});
