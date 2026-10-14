import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { writeFile } from "node:fs/promises";
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
	gitleaks,
	osvScanner,
	parseGitleaksReport,
	parseOsvScannerReport,
	parseSemgrepReport,
	parseTrivyReport,
	semgrep,
	trivyFs,
} from "../src/codebase/external";
import { fixture } from "./helpers";

const sample = (name: string): unknown =>
	JSON.parse(
		readFileSync(fixture("codebase", "external", `${name}.json`), "utf8"),
	);
const sampleText = (name: string) =>
	readFileSync(fixture("codebase", "external", `${name}.json`), "utf8");

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

describe("external tool parsers", () => {
	test("gitleaks", () => {
		const findings = parseGitleaksReport(sample("gitleaks"), "/repo");
		expect(summary(findings)).toEqual([
			"code.gitleaks/aws-access-token high src/config.js:3",
			"code.gitleaks/generic-api-key high settings/prod.py:7",
		]);
		expect(findings[1]?.evidence).toBe('api_key = "REDACTED"');
		expect(findings[1]?.tags).toContain("api");
	});

	test("semgrep", () => {
		const findings = parseSemgrepReport(sample("semgrep"), "/repo");
		expect(summary(findings)).toEqual([
			"code.semgrep/javascript.express.security.audit.express-open-redirect.express-open-redirect medium src/server.js:27",
			"code.semgrep/python.lang.security.audit.subprocess-shell-true.subprocess-shell-true high src/app.py:14",
		]);
		expect(findings[0]?.evidence).toBeUndefined(); // "requires login" is not evidence
		expect(findings[0]?.tags).toEqual(["cwe-601", "owasp-a01"]);
		expect(findings[0]?.confidence).toBe("high");
		// A01:2017 (Injection) is not the 2021 A01 (Broken Access Control).
		expect(findings[1]?.tags).toEqual(["cwe-78", "owasp-a03"]);
		expect(findings[1]?.remediation).toBe("Suggested fix: False");
	});

	test("osv-scanner", () => {
		const findings = parseOsvScannerReport(sample("osv-scanner"), "/repo");
		expect(summary(findings)).toEqual([
			"code.osv-scanner/vulnerable-dependency high package-lock.json:-",
			"code.osv-scanner/vulnerable-dependency medium package-lock.json:-",
		]);
		expect(findings[0]?.remediation).toBe(
			"Upgrade lodash to 4.17.21 or later.",
		);
		expect(findings[0]?.tags).toEqual([
			"owasp-a06",
			"ghsa-35jh-r3h4-6jhm",
			"cve-2021-23337",
		]);
	});

	test("trivy fs", () => {
		const findings = parseTrivyReport(sample("trivy"), "/repo");
		expect(summary(findings)).toEqual([
			"code.trivy-fs/vulnerable-dependency high package-lock.json:-",
			"code.trivy-fs/secret-aws-access-key-id critical src/config.js:3",
			"code.trivy-fs/misconfig-avd-ds-0002 high Dockerfile:1",
		]);
		expect(findings[0]?.remediation).toBe("Upgrade lodash to 4.17.21.");
		expect(findings[0]?.tags).toEqual([
			"owasp-a06",
			"cwe-77",
			"cwe-94",
			"cve-2021-23337",
		]);
	});

	test("parsers tolerate unexpected shapes", () => {
		for (const parse of [
			parseGitleaksReport,
			parseSemgrepReport,
			parseOsvScannerReport,
			parseTrivyReport,
		]) {
			expect(parse(null, "/repo")).toEqual([]);
			expect(parse({ results: "nope", Results: [1, null] }, "/repo")).toEqual(
				[],
			);
		}
	});
});

/** Runs an auditor against the fixture dir with a fake Exec service. */
const runWithExec = (
	auditor: Auditor,
	which: (bin: string) => string | undefined,
	run: (
		cmd: ReadonlyArray<string>,
		opts?: { cwd?: string },
	) => Promise<ExecResult>,
): Promise<Report> =>
	Effect.runPromise(
		runAudit({
			target: fixture("codebase", "external"),
			auditors: [auditor],
			selection: { only: [auditor.id] },
		}).pipe(
			Effect.provide(
				Layer.mergeAll(
					Workspaces.layer,
					Http.layer,
					Layer.succeed(Exec, {
						which: (bin: string) => Effect.succeed(which(bin)),
						run: (cmd: ReadonlyArray<string>, opts?: { cwd?: string }) =>
							Effect.promise(() => run(cmd, opts)),
					}),
				),
			),
		),
	);

describe("external tool auditors", () => {
	test("skip with an install hint when the tool is missing", async () => {
		for (const auditor of [gitleaks, semgrep, osvScanner, trivyFs]) {
			const report = await runWithExec(
				auditor,
				() => undefined,
				() => Promise.reject(new Error("unreachable")),
			);
			expect(report.results[0]?.status).toBe("skipped");
			expect(report.results[0]?.message).toContain("not found on PATH");
			expect(report.results[0]?.message).toContain("Install");
			expect(auditor.engine).toBe("external");
			expect(auditor.defaultEnabled).toBe(true);
		}
	});

	test("gitleaks reads its report file", async () => {
		const report = await runWithExec(
			gitleaks,
			(bin) => `/usr/local/bin/${bin}`,
			async (cmd) => {
				const path = cmd[cmd.indexOf("--report-path") + 1] ?? "";
				expect(cmd).toContain("--redact");
				await writeFile(
					path,
					sampleText("gitleaks").replaceAll(
						"/repo/",
						`${fixture("codebase", "external")}/`,
					),
				);
				return { code: 0, stdout: "", stderr: "" };
			},
		);
		expect(report.results[0]?.status).toBe("failed");
		expect(
			report.results[0]?.findings.map((f) => f.location?.file).sort(),
		).toEqual(["settings/prod.py", "src/config.js"]);
	});

	test("gitleaks ignores build output and dependencies like the built-ins", async () => {
		const root = fixture("codebase", "external");
		const leak = (file: string) => ({
			RuleID: "generic-api-key",
			Description: "Generic API key",
			File: `${root}/${file}`,
			StartLine: 1,
			Secret: "REDACTED",
			Match: "key = REDACTED",
		});
		const report = await runWithExec(
			gitleaks,
			(bin) => `/usr/local/bin/${bin}`,
			async (cmd) => {
				const path = cmd[cmd.indexOf("--report-path") + 1] ?? "";
				await writeFile(
					path,
					JSON.stringify([
						leak("src/config.js"),
						leak("dist/cli.js"),
						leak("node_modules/pkg/index.js"),
					]),
				);
				return { code: 0, stdout: "", stderr: "" };
			},
		);
		expect(report.results[0]?.findings.map((f) => f.location?.file)).toEqual([
			"src/config.js",
		]);
	});

	test("trivy skips dependency and build directories", async () => {
		const misconfig = (Target: string) => ({
			Target,
			Class: "config",
			Type: "dockerfile",
			Misconfigurations: [
				{
					ID: "DS002",
					AVDID: "AVD-DS-0002",
					Title: "Image user should not be 'root'",
					Severity: "HIGH",
					Status: "FAIL",
				},
			],
		});
		let args: ReadonlyArray<string> = [];
		let cwd: string | undefined;
		const report = await runWithExec(
			trivyFs,
			(bin) => `/usr/local/bin/${bin}`,
			async (cmd, opts) => {
				args = cmd;
				cwd = opts?.cwd;
				return {
					code: 0,
					stdout: JSON.stringify({
						Results: [
							misconfig("Dockerfile"),
							misconfig("node_modules/.bun/pkg/Dockerfile"),
						],
					}),
					stderr: "",
				};
			},
		);
		expect(args).toContain("**/node_modules");
		// Not from the target: trivy reads trivy.yaml from its working directory.
		expect(cwd).toBeDefined();
		expect(cwd).not.toBe(fixture("codebase", "external"));
		expect(cwd?.startsWith(fixture("codebase", "external"))).toBe(false);
		// Its Terraform scanner clones remote modules (target-chosen git URLs)
		// and has no switch to stop it; Checkov and TFLint cover Terraform.
		const scanners = args[args.indexOf("--misconfig-scanners") + 1] ?? "";
		expect(scanners.split(",")).toContain("dockerfile");
		expect(scanners.split(",")).not.toContain("terraform");
		expect(report.results[0]?.findings.map((f) => f.location?.file)).toEqual([
			"Dockerfile",
		]);
	});

	test("semgrep, osv-scanner and trivy parse stdout", async () => {
		const cases: Array<[Auditor, string, number]> = [
			[semgrep, "semgrep", 0],
			[osvScanner, "osv-scanner", 1],
			[trivyFs, "trivy", 0],
		];
		for (const [auditor, name, code] of cases) {
			const report = await runWithExec(
				auditor,
				(bin) => `/usr/local/bin/${bin}`,
				async () => ({ code, stdout: sampleText(name), stderr: "" }),
			);
			expect(report.results[0]?.status).toBe("failed");
			expect(report.results[0]?.findings.length).toBeGreaterThan(0);
		}
	});

	test("tool failures are reported as errors", async () => {
		const report = await runWithExec(
			trivyFs,
			(bin) => `/usr/local/bin/${bin}`,
			async () => ({
				code: 2,
				stdout: "",
				stderr: "fatal: db download failed",
			}),
		);
		expect(report.results[0]?.status).toBe("error");
		expect(report.results[0]?.message).toContain("db download failed");
	});

	test("osv-scanner with no lockfiles is skipped", async () => {
		const report = await runWithExec(
			osvScanner,
			(bin) => `/usr/local/bin/${bin}`,
			async () => ({
				code: 128,
				stdout: "",
				stderr: "No package sources found",
			}),
		);
		expect(report.results[0]?.status).toBe("skipped");
	});
});
