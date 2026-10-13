import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import {
	type Auditor,
	Exec,
	type ExecResult,
	Http,
	type Report,
	runAudit,
	Workspaces,
} from "@openaudit/core";
import { Effect, Layer } from "effect";

import {
	bandit,
	brakeman,
	codeql,
	detectCodeqlLanguages,
	gosec,
	parseBanditReport,
	parseBrakemanReport,
	parseGosecReport,
	parseSarif,
	parseTrufflehogReport,
	trufflehog,
} from "../src/codebase/sast-tools";
import { fixture } from "./helpers";

const text = (name: string) =>
	readFileSync(fixture("codebase", "external", name), "utf8");
const json = (name: string): unknown => JSON.parse(text(name));

const summary = (
	findings: ReadonlyArray<{
		ruleId: string;
		severity: string;
		location?: { file?: string; line?: number };
	}>,
) =>
	findings.map(
		(f) =>
			`${f.ruleId} ${f.severity} ${f.location?.file}:${f.location?.line ?? "-"}`,
	);

describe("trufflehog parser", () => {
	test("redacts secrets and maps verification to severity", () => {
		const findings = parseTrufflehogReport(text("trufflehog.ndjson"), "/repo");
		expect(summary(findings)).toEqual([
			"code.trufflehog/slack high th/config.js:5",
			"code.trufflehog/postgres high th/config.js:4",
		]);
		expect(findings[1]?.confidence).toBe("medium");
		expect(findings[1]?.tags).toEqual([
			"cwe-798",
			"owasp-a07",
			"secrets",
			"postgres",
		]);
		const dump = JSON.stringify(findings);
		expect(dump).not.toContain("supersecretpw");
		expect(dump).not.toContain(
			"xoxb-263594206564-2343594206574-FGqddMF8t08v8N7Oq4vmFFFF",
		);
		expect(findings[1]?.evidence).toStartWith("Postgres: post");
	});

	test("verified secrets are critical; junk lines are ignored", () => {
		const line = JSON.stringify({
			SourceMetadata: {
				Data: { Filesystem: { file: "/repo/a.env", line: 2 } },
			},
			DetectorName: "AWS",
			Verified: true,
			Raw: "AKIAEXAMPLEEXAMPLE12",
		});
		const findings = parseTrufflehogReport(
			`2026-01-01T00:00:00Z info-0 trufflehog running\n${line}\n{broken\n`,
			"/repo",
		);
		expect(summary(findings)).toEqual(["code.trufflehog/aws critical a.env:2"]);
		expect(findings[0]?.confidence).toBe("high");
		expect(findings[0]?.evidence).not.toContain("EXAMPLEEXAMPLE");
	});
});

describe("bandit parser", () => {
	test("maps severity, confidence and CWE", () => {
		const findings = parseBanditReport(json("bandit.json"), "/repo");
		expect(summary(findings)).toEqual([
			"code.bandit/b403-blacklist low py/app.py:1",
			"code.bandit/b602-subprocess-popen-with-shell-equals-true high py/app.py:3",
			"code.bandit/b324-hashlib high py/app.py:5",
			"code.bandit/b301-blacklist medium py/app.py:7",
			"code.bandit/b105-hardcoded-password-string low py/app.py:8",
		]);
		expect(findings[1]?.tags).toEqual(["cwe-78"]);
		expect(findings[1]?.evidence).toBe("subprocess.call(cmd, shell=True)");
		expect(findings[1]?.location?.column).toBe(5);
		expect(findings[1]?.references?.[0]).toContain("bandit.readthedocs.io");
		expect(findings[4]?.confidence).toBe("medium");
		// hardcoded-password snippets are the secret: never surfaced
		expect(findings[4]?.evidence).toBeUndefined();
	});

	test("low confidence lowers severity one step", () => {
		const [f] = parseBanditReport(
			{
				results: [
					{
						filename: "a.py",
						issue_severity: "HIGH",
						issue_confidence: "LOW",
						issue_text: "x",
						test_id: "B000",
						test_name: "x",
						line_number: 1,
					},
				],
			},
			"/repo",
		);
		expect(f?.severity).toBe("medium");
		expect(f?.confidence).toBe("low");
	});
});

describe("gosec parser", () => {
	test("maps issues", () => {
		const findings = parseGosecReport(json("gosec.json"), "/repo");
		expect(summary(findings)).toEqual([
			"code.gosec/g101 medium main.go:10",
			"code.gosec/g702 high main.go:15",
			"code.gosec/g401 medium main.go:13",
			"code.gosec/g204 medium main.go:15",
			"code.gosec/g501 medium main.go:4",
		]);
		expect(findings[1]?.tags?.length).toBeGreaterThan(0);
		expect(findings[0]?.confidence).toBe("low");
		// G101 snippet contains the secret
		expect(findings[0]?.evidence).toBeUndefined();
		expect(JSON.stringify(findings)).not.toContain("wJalrXUtnFEMI");
		expect(findings[2]?.tags).toEqual(["cwe-328"]);
		expect(findings[2]?.evidence).toBe("h := md5.New()");
		expect(findings[2]?.references).toContain(
			"https://securego.io/docs/rules/g401.html",
		);
	});
});

describe("brakeman parser", () => {
	test("maps warnings", () => {
		const findings = parseBrakemanReport(json("brakeman.json"), "/repo");
		expect(summary(findings)).toEqual([
			"code.brakeman/cross-site-scripting high app/views/users/search.html.erb:1",
			"code.brakeman/command-injection high app/controllers/users_controller.rb:8",
			"code.brakeman/redirect high app/controllers/users_controller.rb:9",
			"code.brakeman/unmaintained-dependency medium Gemfile:2",
			"code.brakeman/sql-injection medium app/controllers/users_controller.rb:3",
		]);
		expect(findings[0]?.tags).toEqual(["cwe-79"]);
		expect(findings[0]?.references?.[0]).toBe(
			"https://brakemanscanner.org/docs/warning_types/cross-site_scripting/",
		);
		expect(findings[3]?.category).toBe("supply-chain");
	});

	test("prefixes nested app paths", () => {
		const [f] = parseBrakemanReport(json("brakeman.json"), "/repo", "web");
		expect(f?.location?.file).toBe("web/app/views/users/search.html.erb");
	});
});

describe("SARIF parser", () => {
	test("CodeQL output", () => {
		const findings = parseSarif(json("codeql.sarif"), "/repo", "code.codeql");
		expect(summary(findings)).toEqual([
			"code.codeql/js-xss medium src/client.js:12",
			"code.codeql/js-insecure-randomness high src/util/token.js:4",
			"code.codeql/js-unused-local-variable low src/util/token.js:2",
		]);
		const xss = findings[0];
		expect(xss?.tags).toEqual(["cwe-79", "cwe-116"]);
		expect(xss?.message).toBe(
			"Cross-site scripting vulnerability due to a user-provided value.",
		);
		expect(xss?.remediation).toStartWith(
			"To guard against cross-site scripting",
		);
		expect(xss?.references).toContain(
			"https://codeql.github.com/codeql-query-help/javascript/js-xss/",
		);
		expect(xss?.references).toContain(
			"https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
		);
		expect(xss?.confidence).toBe("high");
		expect(xss?.location?.column).toBe(5);
		expect(findings[1]?.tags).toEqual(["cwe-338", "cwe-327", "cwe-16"]);
		expect(findings[1]?.confidence).toBe("medium");
		expect(findings[2]?.category).toBe("maintainability");
	});

	test("severity bands, extension rules and level fallback", () => {
		const sarif = {
			runs: [
				{
					tool: {
						driver: { name: "CodeQL", rules: [] },
						extensions: [
							{
								name: "codeql/python-queries",
								rules: [
									{
										id: "py/sql-injection",
										shortDescription: {
											text: "SQL query built from user-controlled sources",
										},
										properties: {
											tags: ["security", "external/cwe/cwe-089"],
											"security-severity": "9.8",
											precision: "high",
										},
									},
									{
										id: "py/other",
										properties: { tags: ["security"] },
									},
								],
							},
						],
					},
					results: [
						{
							ruleId: "py/sql-injection",
							rule: {
								id: "py/sql-injection",
								index: 0,
								toolComponent: { index: 0 },
							},
							message: { text: "bad" },
							locations: [
								{
									physicalLocation: {
										artifactLocation: { uri: "file:///repo/app/db.py" },
										region: { startLine: 3 },
									},
								},
							],
						},
						{ ruleId: "py/other", level: "error", message: { text: "x" } },
					],
				},
			],
		};
		const findings = parseSarif(sarif, "/repo", "code.codeql");
		expect(summary(findings)).toEqual([
			"code.codeql/py-sql-injection critical app/db.py:3",
			"code.codeql/py-other high undefined:-",
		]);
		expect(findings[0]?.tags).toEqual(["cwe-89"]);
	});

	test("tolerates unexpected shapes", () => {
		for (const input of [null, {}, { runs: [null, { results: "x" }] }]) {
			expect(parseSarif(input, "/repo", "code.codeql")).toEqual([]);
		}
		for (const parse of [
			parseBanditReport,
			parseGosecReport,
			parseBrakemanReport,
		]) {
			expect(parse(null, "/repo")).toEqual([]);
			expect(parse({ results: 1, Issues: {}, warnings: [3] }, "/repo")).toEqual(
				[],
			);
		}
		expect(parseTrufflehogReport("", "/repo")).toEqual([]);
	});
});

describe("codeql language detection", () => {
	test("only buildless languages are supported", () => {
		const r = detectCodeqlLanguages(["a.ts", "b.py", "c.go", "d.cpp", "e.rb"]);
		expect(r.supported.map((l) => l.id)).toEqual([
			"javascript-typescript",
			"python",
			"ruby",
		]);
		expect(r.unsupported.sort()).toEqual(["cpp", "go"]);
	});
});

/* --------------------------------- auditors -------------------------------- */

const runWith = (
	auditor: Auditor,
	target: string,
	which: (bin: string) => string | undefined,
	run: (cmd: ReadonlyArray<string>, cwd?: string) => Promise<ExecResult>,
	settings?: Record<string, Record<string, unknown>>,
): Promise<Report> =>
	Effect.runPromise(
		runAudit({
			target,
			auditors: [auditor],
			options: { settings },
			selection: { only: [auditor.id] },
		}).pipe(
			Effect.provide(
				Layer.mergeAll(
					Workspaces.layer,
					Http.layer,
					Layer.succeed(Exec, {
						which: (bin: string) => Effect.succeed(which(bin)),
						run: (cmd: ReadonlyArray<string>, options) =>
							Effect.promise(() => run(cmd, options?.cwd)),
					}),
				),
			),
		),
	);

const sast = fixture("codebase", "sast");
const none = fixture("codebase", "external");
const present = (bin: string) => `/usr/local/bin/${bin}`;
const unreachable = () => Promise.reject(new Error("unreachable"));

describe("sast auditors", () => {
	test("metadata", () => {
		for (const a of [trufflehog, bandit, gosec, brakeman, codeql]) {
			expect(a.engine).toBe("external");
			expect(a.targets).toEqual(["codebase"]);
		}
		expect(codeql.defaultEnabled).toBe(false);
		expect(codeql.network).toBe(true);
		expect(trufflehog.description).toContain("verify");
	});

	test("missing tool is a skip with an install hint", async () => {
		for (const a of [trufflehog, bandit, gosec, brakeman, codeql]) {
			const report = await runWith(a, sast, () => undefined, unreachable);
			expect(report.results[0]?.status).toBe("skipped");
			expect(report.results[0]?.message).toContain("not found on PATH");
			expect(report.results[0]?.message).toContain("Install");
		}
	});

	test("irrelevant targets skip before the tool is required", async () => {
		for (const a of [bandit, gosec, brakeman, codeql]) {
			const report = await runWith(a, none, () => undefined, unreachable);
			expect(report.results[0]?.status).toBe("skipped");
			expect(report.results[0]?.message).not.toContain("PATH");
		}
	});

	test("trufflehog disables verification by default", async () => {
		let cmd: ReadonlyArray<string> = [];
		const run = async (c: ReadonlyArray<string>) => {
			cmd = c;
			return { code: 0, stdout: text("trufflehog.ndjson"), stderr: "" };
		};
		const report = await runWith(trufflehog, none, present, run);
		expect(cmd).toContain("--no-verification");
		expect(cmd).toContain("--no-update");
		expect(report.results[0]?.findings).toHaveLength(2);
		await runWith(trufflehog, none, present, run, {
			"code.trufflehog": { verify: true },
		});
		expect(cmd).not.toContain("--no-verification");
	});

	test("bandit parses stdout (exit 1 = findings)", async () => {
		const report = await runWith(bandit, sast, present, async (cmd) => {
			expect(cmd).toContain("json");
			return { code: 1, stdout: text("bandit.json"), stderr: "" };
		});
		expect(report.results[0]?.status).toBe("failed");
		expect(report.results[0]?.findings).toHaveLength(5);
	});

	test("gosec runs in the module dir", async () => {
		let cwd: string | undefined;
		const report = await runWith(gosec, sast, present, async (cmd, dir) => {
			cwd = dir;
			expect(cmd.slice(1)).toEqual([
				"-fmt",
				"json",
				"-quiet",
				"-no-fail",
				"./...",
			]);
			return { code: 0, stdout: text("gosec.json"), stderr: "" };
		});
		expect(cwd).toBe(sast);
		expect(report.results[0]?.findings).toHaveLength(5);
	});

	test("brakeman detects the Rails app", async () => {
		let cmd: ReadonlyArray<string> = [];
		const report = await runWith(brakeman, sast, present, async (c) => {
			cmd = c;
			return { code: 0, stdout: text("brakeman.json"), stderr: "" };
		});
		expect(cmd[cmd.indexOf("-p") + 1]).toBe(sast);
		expect(cmd).toContain("--no-exit-on-warn");
		expect(report.results[0]?.findings).toHaveLength(5);
	});

	test("codeql builds without building and cleans up", async () => {
		const before = readdirSync(tmpdir()).filter((f) =>
			f.startsWith("openaudit-codeql-"),
		);
		const cmds: string[][] = [];
		const report = await runWith(codeql, sast, present, async (cmd) => {
			cmds.push([...cmd]);
			if (cmd[2] === "analyze") {
				const out = cmd[cmd.indexOf("--output") + 1] ?? "";
				await writeFile(out, text("codeql.sarif"));
			}
			return { code: 0, stdout: "", stderr: "" };
		});
		const create = cmds[0] ?? [];
		expect(create.slice(1, 3)).toEqual(["database", "create"]);
		expect(create).toContain("--build-mode=none");
		expect(create).toContain("--db-cluster");
		const langs = create.find((a) => a.startsWith("--language="));
		expect(langs).toBe("--language=javascript-typescript,python,ruby");
		expect(langs).not.toContain("go");
		const analyze = cmds.filter((c) => c[2] === "analyze");
		expect(analyze).toHaveLength(3);
		expect(analyze[0]).toContain(
			"codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
		);
		// The same SARIF is served for all three languages; the engine dedupes.
		expect(report.results[0]?.findings).toHaveLength(3);
		const after = readdirSync(tmpdir()).filter((f) =>
			f.startsWith("openaudit-codeql-"),
		);
		expect(after).toEqual(before);
	});

	test("tool failure is an error", async () => {
		const report = await runWith(bandit, sast, present, async () => ({
			code: 2,
			stdout: "",
			stderr: "boom",
		}));
		expect(report.results[0]?.status).toBe("error");
		expect(report.results[0]?.message).toContain("boom");
	});
});
