import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import {
	Exec,
	type ExecResult,
	Http,
	type Report,
	runAudit,
	Workspaces,
} from "@openaudit/core";
import { Effect, Layer } from "effect";

import {
	hasMobileSource,
	mobsfscan,
	parseMobsfscanReport,
} from "../src/codebase/mobsfscan";
import { fixture } from "./helpers";

// Recorded with mobsfscan 1.0.1 (`mobsfscan --json -o out.json <dir>`) on the
// source tree in fixtures/mobile-mobsfscan/src; the scan root was rewritten to
// /private/tmp/work/repo.
const recordedPath = fixture("mobile-mobsfscan", "mobsfscan.json");
const recorded = JSON.parse(readFileSync(recordedPath, "utf8")) as unknown;
const ROOT = "/private/tmp/work/repo";

describe("mobsfscan parser", () => {
	const findings = parseMobsfscanReport(recorded, ROOT);

	test("maps rules, severities and locations", () => {
		const weak = findings.find(
			(f) => f.ruleId === "code.mobsfscan/weak-cipher",
		);
		expect(weak?.severity).toBe("high");
		expect(weak?.location).toEqual({
			file: "app/src/main/java/com/example/demo/MainActivity.java",
			line: 19,
			column: 15,
		});
		expect(weak?.evidence).toContain("DES/ECB/PKCS5Padding");
		expect(weak?.category).toBe("security");
	});

	test("resolves the truncated relative paths mobsfscan emits for manifests", () => {
		const debug = findings.find(
			(f) => f.ruleId === "code.mobsfscan/android-manifest-debugging-enabled",
		);
		expect(debug?.location?.file).toBe("app/src/main/AndroidManifest.xml");
		expect(debug?.evidence).toBe("android:debuggable=true");
	});

	test("normalises CWE, OWASP Mobile and MASVS tags across both formats", () => {
		const weak = findings.find(
			(f) => f.ruleId === "code.mobsfscan/weak-cipher",
		);
		expect(weak?.tags).toEqual([
			"cwe-327",
			"owasp-mobile-m5",
			"masvs-mstg-crypto-4",
		]);
		expect(weak?.references).toContain(
			"https://cwe.mitre.org/data/definitions/327.html",
		);
		const debug = findings.find(
			(f) => f.ruleId === "code.mobsfscan/android-manifest-debugging-enabled",
		);
		expect(debug?.tags).toEqual([
			"cwe-489",
			"owasp-mobile-m10",
			"masvs-code-2",
		]);
	});

	test("INFO rules are advisory with low confidence", () => {
		const pinning = findings.find(
			(f) => f.ruleId === "code.mobsfscan/android-certificate-pinning",
		);
		expect(pinning?.severity).toBe("info");
		expect(pinning?.confidence).toBe("low");
	});

	test("every finding carries a remediation and rule ids are kebab-case", () => {
		expect(findings.length).toBeGreaterThan(10);
		for (const f of findings) {
			expect(f.remediation).toBeTruthy();
			expect(f.ruleId).toMatch(/^code\.mobsfscan\/[a-z0-9-]+$/);
		}
	});

	test("tolerates malformed output", () => {
		expect(parseMobsfscanReport(null, ROOT)).toEqual([]);
		expect(parseMobsfscanReport({ results: { x: 1 } }, ROOT)).toEqual([]);
	});
});

describe("mobile source detection", () => {
	test("matches Android and iOS markers only", () => {
		expect(hasMobileSource(["app/src/main/AndroidManifest.xml"])).toBe(true);
		expect(hasMobileSource(["ios/Podfile"])).toBe(true);
		expect(hasMobileSource(["Sources/App/main.swift"])).toBe(true);
		expect(hasMobileSource(["a/B.kt", "README.md"])).toBe(true);
		expect(hasMobileSource(["src/index.ts", "Cargo.toml", "main.mjs"])).toBe(
			false,
		);
	});
});

const runWithExec = (
	target: string,
	which: (bin: string) => string | undefined,
	run: (cmd: ReadonlyArray<string>) => Promise<ExecResult>,
): Promise<Report> =>
	Effect.runPromise(
		runAudit({
			target,
			auditors: [mobsfscan],
			selection: { only: [mobsfscan.id] },
		}).pipe(
			Effect.provide(
				Layer.mergeAll(
					Workspaces.layer,
					Http.layer,
					Layer.succeed(Exec, {
						which: (bin: string) => Effect.succeed(which(bin)),
						run: (cmd: ReadonlyArray<string>) => Effect.promise(() => run(cmd)),
					}),
				),
			),
		),
	);

describe("code.mobsfscan", () => {
	const sourceDir = fixture("mobile-mobsfscan", "src");

	test("is an external, default-enabled codebase auditor", () => {
		expect(mobsfscan.engine).toBe("external");
		expect(mobsfscan.tool).toBe("mobsfscan");
		expect(mobsfscan.targets).toEqual(["codebase"]);
		expect(mobsfscan.defaultEnabled).toBe(true);
	});

	test("skips with an install hint when the tool is missing", async () => {
		const report = await runWithExec(
			sourceDir,
			() => undefined,
			() => Promise.reject(new Error("unreachable")),
		);
		expect(report.results[0]?.status).toBe("skipped");
		expect(report.results[0]?.message).toContain("mobsfscan not found on PATH");
		expect(report.results[0]?.message).toContain("pipx install mobsfscan");
	});

	test("skips codebases without mobile source", async () => {
		const report = await runWithExec(
			fixture("codebase", "external"),
			(bin) => `/usr/local/bin/${bin}`,
			() => Promise.reject(new Error("unreachable")),
		);
		expect(report.results[0]?.status).toBe("skipped");
		expect(report.results[0]?.message).toContain("No Android or iOS source");
	});

	test("runs from a temp dir with hardening flags and reads the report file", async () => {
		let cwd = "";
		const report = await runWithExec(
			sourceDir,
			(bin) => `/usr/local/bin/${bin}`,
			async (cmd) => {
				expect(cmd).toContain("--json");
				expect(cmd).toContain("--no-fail");
				expect(cmd.at(-1)).toBe(sourceDir);
				const out = cmd[cmd.indexOf("-o") + 1] ?? "";
				cwd = out.slice(0, out.lastIndexOf("/"));
				await writeFile(
					out,
					readFileSync(recordedPath, "utf8")
						.replaceAll("/private/tmp/work/repo", sourceDir)
						.replaceAll("work/repo/", `${sourceDir.replace(/^\//, "")}/`),
				);
				return { code: 0, stdout: "", stderr: "" };
			},
		);
		expect(cwd).toContain("openaudit-mobsfscan-");
		expect(report.results[0]?.status).toBe("failed");
		const files = new Set(
			report.results[0]?.findings.map((f) => f.location?.file),
		);
		expect(files.has("app/src/main/AndroidManifest.xml")).toBe(true);
		expect(
			files.has("app/src/main/java/com/example/demo/MainActivity.java"),
		).toBe(true);
	});

	test("skips when mobsfscan cannot find semgrep", async () => {
		const report = await runWithExec(
			sourceDir,
			(bin) => `/usr/local/bin/${bin}`,
			async (cmd) => {
				const out = cmd[cmd.indexOf("-o") + 1] ?? "";
				await writeFile(
					out,
					JSON.stringify({
						errors: ["semgrep not found. Install with: pip install semgrep"],
						results: {},
					}),
				);
				return { code: 0, stdout: "", stderr: "" };
			},
		);
		expect(report.results[0]?.status).toBe("skipped");
		expect(report.results[0]?.message).toContain("semgrep");
	});

	test("tool failures are reported as errors", async () => {
		const report = await runWithExec(
			sourceDir,
			(bin) => `/usr/local/bin/${bin}`,
			async () => ({ code: 2, stdout: "", stderr: "boom" }),
		);
		expect(report.results[0]?.status).toBe("error");
		expect(report.results[0]?.message).toContain("boom");
	});
});
