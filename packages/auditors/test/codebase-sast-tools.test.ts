import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
	gosec,
	parseBanditReport,
	parseBrakemanReport,
	parseGosecReport,
	parseTrufflehogReport,
	trufflehog,
} from "../src/codebase/sast-tools";
import { fixture } from "./helpers";
import { must } from "./must";

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
		const shell = must(findings[1], "the shell=True finding");
		expect(shell.tags).toEqual(["cwe-78"]);
		expect(shell.evidence).toBe("subprocess.call(cmd, shell=True)");
		expect(must(shell.location, "its location").column).toBe(5);
		expect(shell.references?.[0]).toContain("bandit.readthedocs.io");
		const password = must(findings[4], "the hardcoded password finding");
		expect(password.confidence).toBe("medium");
		// hardcoded-password snippets are the secret: never surfaced
		expect(password.evidence).toBeUndefined();
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
		for (const a of [trufflehog, bandit, gosec, brakeman]) {
			expect(a.engine).toBe("external");
			expect(a.targets).toEqual(["codebase"]);
		}
		expect(trufflehog.description).toContain("verify");
	});

	test("missing tool is a skip with an install hint", async () => {
		for (const a of [trufflehog, bandit, gosec, brakeman]) {
			const report = await runWith(a, sast, () => undefined, unreachable);
			expect(report.results[0]?.status).toBe("skipped");
			expect(report.results[0]?.message).toContain("not found on PATH");
			expect(report.results[0]?.message).toContain("Install");
		}
	});

	test("irrelevant targets skip before the tool is required", async () => {
		for (const a of [bandit, gosec, brakeman]) {
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
		expect(cmd.some((a) => a.startsWith("--exclude-paths="))).toBe(true);
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
			expect(cmd.slice(1)).toEqual(["-fmt", "json", "-no-fail", "./..."]);
			return { code: 0, stdout: text("gosec.json"), stderr: "" };
		});
		expect(cwd).toBe(sast);
		expect(report.results[0]?.findings).toHaveLength(5);
	});

	test("gosec fails when no package of a module loads", async () => {
		// Without this, a module gosec cannot load (here go.mod asks for a newer
		// Go) passed with no findings.
		const report = await runWith(gosec, sast, present, async () => ({
			code: 0,
			stdout: text("gosec-load-error.json"),
			stderr: "",
		}));
		expect(report.results[0]?.status).toBe("error");
		expect(report.results[0]?.message).toContain("go.mod requires go >= 1.99");
	});

	test("brakeman skips a Rails app without app/", async () => {
		const dir = await mkdtemp(join(tmpdir(), "openaudit-brakeman-"));
		try {
			await Bun.write(join(dir, "Gemfile"), 'gem "rails"\n');
			const report = await runWith(brakeman, dir, present, unreachable);
			expect(report.results[0]?.status).toBe("skipped");
			expect(report.results[0]?.message).toContain("app/");
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	test("brakeman detects the Rails app", async () => {
		let cmd: ReadonlyArray<string> = [];
		let config = "";
		const report = await runWith(brakeman, sast, present, async (c) => {
			cmd = c;
			config = await Bun.file(c[c.indexOf("-c") + 1] ?? "").text();
			return { code: 0, stdout: text("brakeman.json"), stderr: "" };
		});
		expect(cmd[cmd.indexOf("-p") + 1]).toBe(sast);
		// An empty config file replaces the app's config/brakeman.yml.
		expect(config).toBe("---\n{}\n");
		expect(cmd).toContain("--no-exit-on-warn");
		expect(report.results[0]?.findings).toHaveLength(5);
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
