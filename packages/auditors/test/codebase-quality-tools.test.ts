import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
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
	classifyLicense,
	jscpd,
	knip,
	parseJscpdReport,
	parseKnipReport,
	parseScancodeReport,
	scancode,
} from "../src/codebase/quality-tools";
import { fixture } from "./helpers";

const sampleText = (name: string) =>
	readFileSync(fixture("codebase", "external", `${name}.json`), "utf8");
const sample = (name: string): unknown => JSON.parse(sampleText(name));

const summary = (
	findings: ReadonlyArray<{
		ruleId: string;
		severity: string;
		location?: { file?: string; line?: number };
	}>,
) =>
	findings.map(
		(f) =>
			`${f.ruleId} ${f.severity} ${f.location?.file ?? "-"}:${f.location?.line ?? "-"}`,
	);

/** Runs an auditor against `target` with a fake Exec service. */
const runWithExec = (
	auditor: Auditor,
	target: string,
	which: (bin: string) => string | undefined,
	run: (cmd: ReadonlyArray<string>) => Promise<ExecResult>,
): Promise<Report> =>
	Effect.runPromise(
		runAudit({
			target,
			auditors: [auditor],
			selection: { only: [auditor.id] },
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

describe("jscpd parser", () => {
	test("one finding per clone pair plus a project-wide ratio", () => {
		const findings = parseJscpdReport(sample("jscpd"), "/repo");
		expect(summary(findings)).toEqual([
			"code.jscpd/duplicate-block info src/invoice.ts:1",
			"code.jscpd/duplication-ratio medium -:-",
		]);
		expect(findings[0]?.message).toContain("16 lines (141 tokens)");
		expect(findings[1]?.title).toBe("50.0% of scanned lines are duplicated");
	});

	test("evidence names both locations and never contains code", () => {
		const [pair] = parseJscpdReport(sample("jscpd"), "/repo");
		expect(pair?.evidence).toBe("src/invoice.ts:1-16 <-> src/order.ts:1-16");
		expect(pair?.evidence).not.toContain("summarizeInvoice");
		expect(pair?.message).not.toContain("summarizeInvoice");
	});

	test("blocks of 20 lines or more are low, and low ratios get no aggregate", () => {
		const report = {
			duplicates: [
				{
					firstFile: { name: "a.ts", start: 4, end: 30 },
					secondFile: { name: "b.ts", start: 9, end: 35 },
					lines: 27,
					tokens: 200,
				},
			],
			statistics: { total: { percentage: 2.5, lines: 400, sources: 2 } },
		};
		const findings = parseJscpdReport(report, "/repo");
		expect(summary(findings)).toEqual([
			"code.jscpd/duplicate-block low a.ts:4",
		]);
	});

	test("tolerates empty and unexpected shapes", () => {
		expect(parseJscpdReport({}, "/repo")).toEqual([]);
		expect(parseJscpdReport(null, "/repo")).toEqual([]);
		expect(parseJscpdReport({ duplicates: [42, null] }, "/repo")).toEqual([]);
	});
});

describe("knip parser", () => {
	test("maps every reported issue group to a rule", () => {
		const findings = parseKnipReport(sample("knip"), "/repo");
		expect(summary(findings)).toEqual([
			"code.knip/unused-file info src/orphan.js:-",
			"code.knip/unused-dependency low package.json:9",
			"code.knip/unlisted-dependency medium src/index.js:3",
			"code.knip/unused-export info src/util.js:3",
		]);
	});

	test("findings carry remediation, references and an accurate message", () => {
		const findings = parseKnipReport(sample("knip"), "/repo");
		const unlisted = findings.find(
			(f) => f.ruleId === "code.knip/unlisted-dependency",
		);
		expect(unlisted?.category).toBe("reliability");
		expect(unlisted?.message).toBe(
			"moment is imported but not declared in package.json.",
		);
		expect(unlisted?.remediation).toContain("Declare the package");
		expect(unlisted?.references).toEqual([
			"https://knip.dev/reference/issue-types",
		]);
		const dep = findings.find(
			(f) => f.ruleId === "code.knip/unused-dependency",
		);
		expect(dep?.message).toBe(
			"left-pad is listed in dependencies but never imported.",
		);
		expect(dep?.location?.column).toBe(4);
	});

	test("tolerates empty and unexpected shapes", () => {
		expect(parseKnipReport({ issues: [] }, "/repo")).toEqual([]);
		expect(parseKnipReport({}, "/repo")).toEqual([]);
		expect(
			parseKnipReport({ issues: [{ file: "a.js", exports: [{}] }] }, "/repo"),
		).toEqual([]);
	});
});

describe("code.jscpd auditor", () => {
	test("skip with an install hint when the tool is missing", async () => {
		const report = await runWithExec(
			jscpd,
			fixture("codebase", "dup"),
			() => undefined,
			() => Promise.reject(new Error("unreachable")),
		);
		expect(report.results[0]?.status).toBe("skipped");
		expect(report.results[0]?.message).toContain("jscpd not found on PATH");
		expect(report.results[0]?.message).toContain("Install");
		expect(jscpd.engine).toBe("external");
		expect(jscpd.defaultEnabled).toBe(true);
	});

	test("runs jscpd with a temp output dir and parses its report", async () => {
		let cmd: ReadonlyArray<string> = [];
		const report = await runWithExec(
			jscpd,
			fixture("codebase", "dup"),
			(bin) => `/usr/local/bin/${bin}`,
			async (argv) => {
				cmd = argv;
				const out = argv[argv.indexOf("--output") + 1] ?? "";
				await writeFile(join(out, "jscpd-report.json"), sampleText("jscpd"));
				return { code: 0, stdout: "", stderr: "" };
			},
		);
		expect(cmd).toContain("--silent");
		expect(cmd).toContain("--min-lines");
		expect(cmd[cmd.indexOf("--min-lines") + 1]).toBe("10");
		expect(report.results[0]?.status).toBe("failed");
		expect(report.results[0]?.findings.length).toBe(2);
	});

	test("no report file means no clones", async () => {
		const report = await runWithExec(
			jscpd,
			fixture("codebase", "dup"),
			(bin) => `/usr/local/bin/${bin}`,
			async () => ({ code: 0, stdout: "", stderr: "" }),
		);
		expect(report.results[0]?.status).toBe("passed");
	});

	test("tool failures are reported as errors", async () => {
		const report = await runWithExec(
			jscpd,
			fixture("codebase", "dup"),
			(bin) => `/usr/local/bin/${bin}`,
			async () => ({ code: 2, stdout: "", stderr: "bad option" }),
		);
		expect(report.results[0]?.status).toBe("error");
		expect(report.results[0]?.message).toContain("bad option");
	});
});

describe("code.knip auditor", () => {
	test("is opt-in because it executes project config files", () => {
		expect(knip.defaultEnabled).toBe(false);
		expect(knip.description).toContain("enable only for trusted code");
		expect(knip.engine).toBe("external");
	});

	test("skip without a package.json", async () => {
		const report = await runWithExec(
			knip,
			fixture("codebase", "external"),
			(bin) => `/usr/local/bin/${bin}`,
			() => Promise.reject(new Error("unreachable")),
		);
		expect(report.results[0]?.status).toBe("skipped");
		expect(report.results[0]?.message).toContain("No package.json");
	});

	test("skip when node_modules is missing", async () => {
		// The dup fixture has a package.json but no installed dependencies.
		const report = await runWithExec(
			knip,
			fixture("codebase", "dup"),
			(bin) => `/usr/local/bin/${bin}`,
			() => Promise.reject(new Error("unreachable")),
		);
		expect(report.results[0]?.status).toBe("skipped");
		expect(report.results[0]?.message).toContain("node_modules is missing");
	});

	test("skip with an install hint when the tool is missing", async () => {
		const dir = await mkdtemp(join(tmpdir(), "openaudit-knip-"));
		try {
			await writeFile(join(dir, "package.json"), '{"name":"x"}');
			await mkdir(join(dir, "node_modules"));
			const report = await runWithExec(
				knip,
				dir,
				() => undefined,
				() => Promise.reject(new Error("unreachable")),
			);
			expect(report.results[0]?.status).toBe("skipped");
			expect(report.results[0]?.message).toContain("knip not found on PATH");
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	test("parses the JSON reporter output", async () => {
		const dir = await mkdtemp(join(tmpdir(), "openaudit-knip-"));
		try {
			await writeFile(join(dir, "package.json"), '{"name":"x"}');
			await mkdir(join(dir, "node_modules"));
			let cmd: ReadonlyArray<string> = [];
			const report = await runWithExec(
				knip,
				dir,
				(bin) => `/usr/local/bin/${bin}`,
				async (argv) => {
					cmd = argv;
					return { code: 0, stdout: sampleText("knip"), stderr: "" };
				},
			);
			expect(cmd).toEqual([
				"/usr/local/bin/knip",
				"--reporter",
				"json",
				"--no-progress",
				"--no-exit-code",
			]);
			expect(report.results[0]?.status).toBe("failed");
			expect(report.results[0]?.findings.length).toBe(4);
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});
});

describe("scancode parser", () => {
	test("flags copyleft files and conflicts with the LICENSE file's licence", () => {
		const findings = parseScancodeReport(sample("scancode"), "/repo");
		expect(summary(findings)).toEqual([
			"code.scancode/strong-copyleft medium src/iproute.c:6",
			"code.scancode/license-conflict medium src/iproute.c:6",
			"code.scancode/weak-copyleft low src/lgpl-helper.c:1",
			"code.scancode/strong-copyleft medium src/server/agpl-app.js:1",
			"code.scancode/license-conflict medium src/server/agpl-app.js:1",
			"code.scancode/no-license-detected info -:-",
		]);
	});

	test("a declared GPL project does not conflict with GPL files", () => {
		const findings = parseScancodeReport(
			sample("scancode"),
			"/repo",
			"GPL-3.0-only",
		);
		expect(
			findings.some((f) => f.ruleId === "code.scancode/license-conflict"),
		).toBe(false);
		expect(
			findings.filter((f) => f.ruleId === "code.scancode/strong-copyleft"),
		).toHaveLength(2);
	});

	test("the declared project licence takes precedence over the LICENSE file", () => {
		const findings = parseScancodeReport(
			sample("scancode"),
			"/repo",
			"Apache-2.0",
		);
		expect(
			summary(findings).filter((s) => s.includes("license-conflict")),
		).toEqual([
			"code.scancode/license-conflict medium src/iproute.c:6",
			"code.scancode/license-conflict medium src/server/agpl-app.js:1",
		]);
		expect(findings[1]?.message).toContain("Apache-2.0");
	});

	test("evidence carries the SPDX expression and lines, never licence text", () => {
		const findings = parseScancodeReport(sample("scancode"), "/repo");
		expect(findings[0]?.evidence).toBe("GPL-2.0-or-later at lines 6-9");
		expect(findings[0]?.references).toContain(
			"https://spdx.org/licenses/GPL-2.0-or-later.html",
		);
		expect(findings[0]?.tags).toEqual(["license-gpl-2.0-or-later"]);
	});

	test("the no-detection finding counts files and lists a few paths", () => {
		const findings = parseScancodeReport(sample("scancode"), "/repo");
		const none = findings.find(
			(f) => f.ruleId === "code.scancode/no-license-detected",
		);
		expect(none?.title).toBe("2 files have no detected licence");
		expect(none?.evidence).toBe("src/nolicense.ts, src/nolicense2.ts");
	});

	test("tolerates empty and unexpected shapes", () => {
		expect(parseScancodeReport({}, "/repo")).toEqual([]);
		expect(parseScancodeReport({ files: [null, 1, "x"] }, "/repo")).toEqual([]);
	});
});

describe("scancode classification", () => {
	test("OR expressions are only copyleft when every alternative is", () => {
		expect(classifyLicense("GPL-2.0-only OR MIT")).toBe("none");
		expect(classifyLicense("GPL-2.0-only OR AGPL-3.0-only")).toBe("strong");
		expect(classifyLicense("(GPL-2.0-only OR GPL-3.0-or-later) AND MIT")).toBe(
			"strong",
		);
		expect(classifyLicense("GPL-2.0-only WITH Classpath-exception-2.0")).toBe(
			"strong",
		);
		expect(classifyLicense("LGPL-2.1-or-later")).toBe("weak");
		expect(classifyLicense("MPL-2.0")).toBe("weak");
		expect(classifyLicense("MIT")).toBe("none");
		expect(classifyLicense("LicenseRef-proprietary")).toBe("none");
	});
});

describe("code.scancode auditor", () => {
	test("is opt-in and runs no network", () => {
		expect(scancode.defaultEnabled).toBe(false);
		expect(scancode.network).toBeUndefined();
		expect(scancode.categories).toEqual(["compliance"]);
	});

	test("skip with an install hint when the tool is missing", async () => {
		const report = await runWithExec(
			scancode,
			fixture("codebase", "external"),
			() => undefined,
			() => Promise.reject(new Error("unreachable")),
		);
		expect(report.results[0]?.status).toBe("skipped");
		expect(report.results[0]?.message).toContain("scancode not found on PATH");
		expect(report.results[0]?.message).toContain("Install");
	});

	test("runs scancode with JSON output in a temp file and parses it", async () => {
		let cmd: ReadonlyArray<string> = [];
		const report = await runWithExec(
			scancode,
			fixture("codebase", "external"),
			(bin) => `/usr/local/bin/${bin}`,
			async (argv) => {
				cmd = argv;
				const out = argv[argv.indexOf("--json") + 1] ?? "";
				await writeFile(out, sampleText("scancode"));
				// Exit 1 = some files could not be scanned; the report is still usable.
				return { code: 1, stdout: "", stderr: "" };
			},
		);
		expect(cmd).toContain("--strip-root");
		expect(cmd).toContain("--license");
		expect(cmd).toContain("--copyright");
		expect(cmd[cmd.indexOf("--json") + 1]).not.toContain("codebase");
		expect(report.results[0]?.status).toBe("failed");
		expect(report.results[0]?.findings.length).toBe(6);
	});

	test("a missing report is an error", async () => {
		const report = await runWithExec(
			scancode,
			fixture("codebase", "external"),
			(bin) => `/usr/local/bin/${bin}`,
			async () => ({ code: 0, stdout: "", stderr: "" }),
		);
		expect(report.results[0]?.status).toBe("error");
		expect(report.results[0]?.message).toContain("did not write a report");
	});
});
