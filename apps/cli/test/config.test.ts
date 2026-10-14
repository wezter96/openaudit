import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	type AuditorResult,
	type Finding,
	type Report,
	Report as ReportSchema,
	summarize,
	toMarkdown,
	toTerminal,
} from "@openaudit/core";
import { Schema } from "effect";

import {
	CONFIG_SCHEMA_URL,
	ConfigError,
	configJsonSchema,
	findConfig,
	isoDay,
	loadConfig,
	parseConfig,
	resolveIgnores,
	restrictUntrusted,
} from "../src/config";
import { applySuppressions } from "../src/suppress";

const parse = (text: string) => parseConfig(text, "openaudit.config.json");
const parseError = (text: string): string => {
	try {
		parse(text);
	} catch (error) {
		expect(error).toBeInstanceOf(ConfigError);
		return (error as ConfigError).message;
	}
	throw new Error("expected a ConfigError");
};

describe("parseConfig", () => {
	test("accepts comments and trailing commas", () => {
		const config = parse(`{
	"$schema": "${CONFIG_SCHEMA_URL}",
	// Gate CI on high findings.
	"failOn": "high",
	"ignore": {
		"paths": [
			"dist/**", /* built output */
		],
	},
}`);
		expect(config.failOn).toBe("high");
		expect(config.ignore?.paths).toEqual(["dist/**"]);
	});

	test("accepts string and object entries side by side", () => {
		const config = parse(
			JSON.stringify({
				ignore: {
					rules: [
						"code.hygiene/ci-missing",
						{ rule: "web.seo/*", reason: "Internal tool", until: "2027-01-31" },
					],
					paths: [
						{ path: "test/fixtures/**", reason: "Deliberately vulnerable" },
					],
					fingerprints: [{ fingerprint: "abcdef0123456789" }],
				},
			}),
		);
		expect(config.ignore?.rules).toHaveLength(2);
		expect(config.ignore?.fingerprints).toEqual([
			{ fingerprint: "abcdef0123456789" },
		]);
	});

	test("rejects malformed entries with a clear message", () => {
		expect(parseError("{ /* open")).toContain("is not valid JSON");
		expect(
			parseError(
				'{"ignore": {"paths": [{"path": "x", "untill": "2027-01-01"}]}}',
			),
		).toContain('ignore.paths[0] has an unknown key "untill"');
		expect(parseError('{"ignore": {"rules": [{"id": "code.x/y"}]}}')).toContain(
			"is invalid",
		);
		expect(
			parseError(
				'{"ignore": {"paths": [{"path": "x", "until": "31/12/2026"}]}}',
			),
		).toContain("YYYY-MM-DD");
		expect(
			parseError(
				'{"ignore": {"paths": [{"path": "x", "until": "2026-02-30"}]}}',
			),
		).toContain("not a real date: 2026-02-30");
	});
});

describe("resolveIgnores", () => {
	const ignore = parse(
		JSON.stringify({
			ignore: {
				rules: ["code.a/*", { rule: "code.b/x", until: "2026-06-30" }],
				paths: [{ path: "vendor/**", reason: "Vendored", until: "2026-07-01" }],
				fingerprints: ["ffffffffffffffff"],
			},
		}),
	).ignore;

	test("an entry applies through its until date, inclusive", () => {
		const onTheDay = resolveIgnores(ignore, "2026-06-30");
		expect(onTheDay.expired).toEqual([]);
		expect(onTheDay.active.map((e) => e.value)).toEqual([
			"code.a/*",
			"code.b/x",
			"vendor/**",
			"ffffffffffffffff",
		]);
	});

	test("and stops the day after", () => {
		const after = resolveIgnores(ignore, "2026-07-01");
		expect(after.expired).toEqual([
			{ kind: "rule", value: "code.b/x", until: "2026-06-30" },
		]);
		const later = resolveIgnores(ignore, "2026-07-02");
		expect(later.expired.map((e) => e.value)).toEqual([
			"code.b/x",
			"vendor/**",
		]);
		expect(later.active).toEqual([
			{ kind: "rule", value: "code.a/*" },
			{ kind: "fingerprint", value: "ffffffffffffffff" },
		]);
	});

	test("compares dates in UTC", () => {
		expect(isoDay(new Date("2026-06-30T23:59:59Z"))).toBe("2026-06-30");
		expect(isoDay(new Date("2026-07-01T01:00:00+02:00"))).toBe("2026-06-30");
	});

	test("an untrusted config keeps its reasons and expiry", () => {
		const untrusted = restrictUntrusted(
			parse(
				JSON.stringify({
					options: { agentic: true },
					ignore: {
						paths: [{ path: "a/**", reason: "Fixtures", until: "2026-01-01" }],
					},
				}),
			),
		);
		expect(untrusted.ignored).toEqual(["options.agentic"]);
		expect(
			resolveIgnores(untrusted.config.ignore, "2026-01-02").expired,
		).toEqual([
			{ kind: "path", value: "a/**", reason: "Fixtures", until: "2026-01-01" },
		]);
	});
});

const finding = (overrides: Partial<Finding>): Finding => ({
	ruleId: "code.x/rule",
	title: "Something",
	severity: "high",
	category: "security",
	message: "Something is wrong.",
	auditor: "code.x",
	fingerprint: "0000000000000000",
	...overrides,
});

const reportOf = (findings: Finding[]): Report => {
	const results: AuditorResult[] = [
		{
			auditor: "code.x",
			title: "X",
			engine: "builtin",
			categories: ["security"],
			status: "failed",
			durationMs: 1,
			findings,
		},
	];
	return {
		schemaVersion: "1",
		tool: { name: "openaudit", version: "0.0.0" },
		target: {
			input: ".",
			type: "directory",
			kinds: ["codebase"],
			technologies: [],
		},
		startedAt: "2026-01-01T00:00:00.000Z",
		finishedAt: "2026-01-01T00:00:01.000Z",
		durationMs: 1000,
		summary: summarize(results),
		results,
	};
};

describe("applySuppressions", () => {
	const report = reportOf([
		finding({
			fingerprint: "1111111111111111",
			location: { file: "test/fixtures/a.js" },
		}),
		finding({
			fingerprint: "2222222222222222",
			location: { file: "test/fixtures/b.js" },
		}),
		finding({ fingerprint: "3333333333333333", ruleId: "code.x/noisy" }),
		finding({
			fingerprint: "4444444444444444",
			location: { file: "src/app.js" },
		}),
	]);
	const { active, expired } = resolveIgnores(
		parse(
			JSON.stringify({
				ignore: {
					paths: [
						{
							path: "test/fixtures/**",
							reason: "Deliberately vulnerable inputs",
						},
						{ path: "src/**", reason: "Old exemption", until: "2026-01-31" },
					],
					rules: ["code.x/noisy"],
				},
			}),
		).ignore,
		"2026-02-01",
	);
	const applied = applySuppressions(report, [
		{ source: "openaudit.config.json", entries: active, expired },
	]);

	test("counts per source and lists reasons per entry", () => {
		expect(applied.suppressed).toEqual([
			{
				source: "openaudit.config.json",
				rules: 1,
				paths: 2,
				fingerprints: 0,
				entries: [
					{
						kind: "path",
						value: "test/fixtures/**",
						reason: "Deliberately vulnerable inputs",
						count: 2,
					},
				],
				expired: [
					{
						kind: "path",
						value: "src/**",
						reason: "Old exemption",
						until: "2026-01-31",
					},
				],
			},
		]);
		// The expired entry no longer hides src/app.js.
		const left = applied.report.results.flatMap((r) => r.findings);
		expect(left.map((f) => f.fingerprint)).toEqual(["4444444444444444"]);
	});

	test("the report stays schema-valid and reporters disclose reasons and expiry", () => {
		const full = { ...applied.report, suppressed: applied.suppressed };
		expect(Schema.decodeUnknownExit(ReportSchema)(full)._tag).toBe("Success");
		const terminal = toTerminal(full, {
			color: false,
			suppressed: applied.suppressed,
		});
		expect(terminal).toContain(
			"3 findings suppressed by openaudit.config.json (1 by rule, 2 by path); 1 suppression expired",
		);
		expect(terminal).toContain(
			"2 by path test/fixtures/**: Deliberately vulnerable inputs",
		);
		expect(terminal).toContain(
			"Expired 2026-01-31, no longer applied: path src/** (Old exemption)",
		);
		const markdown = toMarkdown(full, { suppressed: applied.suppressed });
		expect(markdown).toContain("> - 2 by path test/fixtures/\\*\\*");
	});

	test("a source with only expired entries is still disclosed", () => {
		const onlyExpired = applySuppressions(report, [
			{ source: "openaudit.config.json", entries: [], expired },
		]);
		expect(onlyExpired.suppressed[0]).toMatchObject({ rules: 0, paths: 0 });
		expect(
			toTerminal(onlyExpired.report, {
				color: false,
				suppressed: onlyExpired.suppressed,
			}),
		).toContain(
			"1 suppression in openaudit.config.json expired and no longer apply",
		);
	});

	test("reasons cannot inject terminal escapes", () => {
		const out = applySuppressions(report, [
			{
				source: "c",
				entries: [
					{
						kind: "rule",
						value: "code.x/*",
						reason: "ok\x1b]52;c;ZXZpbA==\x07",
					},
				],
			},
		]);
		const text = toTerminal(out.report, {
			color: false,
			suppressed: out.suppressed,
		});
		expect(text).toContain("4 by rule code.x/*: ok");
		expect(text).not.toContain("\x1b]52");
	});
});

describe("config files", () => {
	let dir: string | undefined;
	afterEach(async () => {
		if (dir) await rm(dir, { recursive: true, force: true });
		dir = undefined;
	});

	test("openaudit.config.jsonc is found, and having both is an error", async () => {
		dir = await mkdtemp(join(tmpdir(), "openaudit-config-"));
		await writeFile(
			join(dir, "openaudit.config.jsonc"),
			'{ // comment\n "failOn": "medium", }',
		);
		const loaded = await loadConfig({ target: dir, cwd: dir });
		expect(loaded.path).toBe(join(dir, "openaudit.config.jsonc"));
		expect(loaded.config.failOn).toBe("medium");
		expect(loaded.trusted).toBe(false);

		await writeFile(join(dir, "openaudit.config.json"), "{}");
		expect(findConfig(dir)).rejects.toThrow(
			"Both openaudit.config.json and openaudit.config.jsonc exist",
		);
	});
});

describe("configJsonSchema", () => {
	const schema = configJsonSchema() as {
		$id: string;
		properties: Record<string, { description?: string; properties?: object }>;
	};

	test("is identified by the URL init writes", () => {
		expect(schema.$id).toBe(CONFIG_SCHEMA_URL);
	});

	test("describes every key, for editor hovers", () => {
		const missing: string[] = [];
		const walk = (props: Record<string, unknown>, path: string) => {
			for (const [k, v] of Object.entries(props)) {
				const p = v as { description?: string; properties?: object };
				if (!p.description) missing.push(`${path}${k}`);
				if (p.properties)
					walk(p.properties as Record<string, unknown>, `${path}${k}.`);
			}
		};
		walk(schema.properties, "");
		expect(missing).toEqual([]);
	});

	test("object entries allow only their own keys", () => {
		type List = {
			items: { anyOf: { type: string; additionalProperties?: boolean }[] };
		};
		const lists = schema.properties.ignore?.properties as Record<string, List>;
		const object = lists.paths?.items.anyOf.find((m) => m.type === "object");
		expect(object?.additionalProperties).toBe(false);
	});
});
