import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import {
	type AuditOptions,
	type Auditor,
	Exec,
	type ExecResult,
	Http,
	type Report,
	runAudit,
	Workspaces,
} from "@openaudit/core";
import { Effect, Layer } from "effect";

import { parseZapReport, ZAP_IMAGE } from "../src/web/zap";
import {
	isHostAllowed,
	readZapActiveSettings,
	zapActive,
} from "../src/web/zap-active";
import { fixture } from "./helpers";

// Reconstructed (no Docker pull possible): the baseline fixture's envelope
// with the alerts ZAP's active rules emit (SQLi 40018, reflected XSS 40012,
// path traversal 6, error disclosure 90022) plus a false positive.
const text = readFileSync(fixture("zap-active", "zap-full-scan.json"), "utf8");

const runWithExec = (
	auditor: Auditor,
	target: string,
	which: (bin: string) => string | undefined,
	run: (cmd: ReadonlyArray<string>) => Promise<ExecResult>,
	options: AuditOptions = {},
): Promise<Report> =>
	Effect.runPromise(
		runAudit({
			target,
			auditors: [auditor],
			options,
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

const docker = (bin: string) =>
	bin === "docker" ? "/usr/local/bin/docker" : undefined;
const allow = (...hosts: string[]): AuditOptions => ({
	settings: { "web.zap-active": { allowHosts: hosts } },
});
const never = () => Promise.reject(new Error("must not execute anything"));

describe("web.zap-active parsing", () => {
	test("reuses the ZAP parser under its own rule ids", () => {
		const findings = parseZapReport(
			JSON.parse(text),
			{ from: "host.docker.internal", to: "localhost" },
			"web.zap-active",
		);
		expect(findings.every((f) => f.ruleId.startsWith("web.zap-active/"))).toBe(
			true,
		);
		const sqli = findings.filter((f) => f.title === "SQL Injection");
		// The duplicate instance is collapsed.
		expect(sqli).toHaveLength(2);
		expect(sqli[0]?.ruleId).toBe("web.zap-active/40018-sql-injection");
		expect(sqli[0]?.severity).toBe("high");
		expect(sqli[0]?.tags).toEqual(["cwe-89", "wasc-19"]);
		expect(sqli[0]?.evidence).toContain("param: q");
		expect(findings.some((f) => f.title.includes("Persistent"))).toBe(false); // false positive
		expect(JSON.stringify(findings)).not.toContain("host.docker.internal");
		expect(
			findings.find((f) => f.title.startsWith("Path"))?.location?.url,
		).toBe(
			"http://localhost:8765/download?file=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
		);
	});

	test("baseline rule ids are unchanged", () => {
		const f = parseZapReport(JSON.parse(text));
		expect(f.every((x) => x.ruleId.startsWith("web.zap-baseline/"))).toBe(true);
	});
});

describe("web.zap-active allow-list", () => {
	test("is opt-in, exact host match only", () => {
		expect(zapActive.defaultEnabled).toBe(false);
		expect(isHostAllowed("Example.com", ["example.com"])).toBe(true);
		expect(isHostAllowed("sub.example.com", ["example.com"])).toBe(false);
		expect(isHostAllowed("example.com", ["*.example.com", "*"])).toBe(false);
		expect(isHostAllowed("example.com", [])).toBe(false);
	});

	test("skips with instructions, running nothing, when no host is allowed", async () => {
		const none = await runWithExec(
			zapActive,
			"https://example.com/",
			docker,
			never,
		);
		expect(none.results[0]?.status).toBe("skipped");
		expect(none.results[0]?.message).toContain("allowHosts");
		expect(none.results[0]?.message).toContain("--config");
		expect(none.results[0]?.message).toContain("example.com");

		const other = await runWithExec(
			zapActive,
			"https://example.com/",
			docker,
			never,
			allow("staging.example.com", "example.com.evil.test", 7 as never),
		);
		expect(other.results[0]?.status).toBe("skipped");

		const bad = await runWithExec(
			zapActive,
			"https://example.com/",
			docker,
			never,
			{ settings: { "web.zap-active": { allowHosts: "example.com" } } },
		);
		expect(bad.results[0]?.status).toBe("skipped"); // a string is not a list
	});

	test("settings validation", () => {
		const ctx = (s: Record<string, unknown>) =>
			({ options: { settings: { "web.zap-active": s } } }) as never;
		expect(readZapActiveSettings(ctx({})).maxMinutes).toBe(10);
		expect(readZapActiveSettings(ctx({ maxMinutes: 3 })).maxMinutes).toBe(3);
		for (const bad of [0, -1, 1.5, 9999, "5", null])
			expect(readZapActiveSettings(ctx({ maxMinutes: bad })).maxMinutes).toBe(
				10,
			);
	});
});

describe("web.zap-active run", () => {
	test("runs the pinned image with zap-full-scan.py and the host alias", async () => {
		let cmd: ReadonlyArray<string> = [];
		const report = await runWithExec(
			zapActive,
			"http://localhost:8765/",
			docker,
			async (c) => {
				if (c[1] === "info") return { code: 0, stdout: "", stderr: "" };
				cmd = c;
				const mount = c[c.indexOf("-v") + 1] ?? "";
				await writeFile(`${mount.split(":")[0]}/report.json`, text);
				return { code: 1, stdout: "", stderr: "" };
			},
			{
				settings: {
					"web.zap-active": { allowHosts: ["localhost"], maxMinutes: 4 },
				},
			},
		);
		expect(cmd).toContain(ZAP_IMAGE);
		expect(cmd).toContain("zap-full-scan.py");
		expect(cmd).not.toContain("zap-baseline.py");
		expect(cmd).toContain("--add-host=host.docker.internal:host-gateway");
		expect(cmd[cmd.indexOf("-t") + 1]).toBe(
			"http://host.docker.internal:8765/",
		);
		expect(cmd[cmd.indexOf("-m") + 1]).toBe("4");
		expect(cmd[cmd.indexOf("-z") + 1]).toBe(
			"-config scanner.maxScanDurationInMins=4",
		);
		expect(cmd).toContain("-J");
		expect(report.results[0]?.status).toBe("failed");
		const f = report.results[0]?.findings ?? [];
		expect(f.length).toBeGreaterThan(0);
		expect(f.every((x) => x.ruleId.startsWith("web.zap-active/"))).toBe(true);
		expect(
			f.every((x) => x.location?.url?.startsWith("http://localhost:8765")),
		).toBe(true);
	});

	test("errors when ZAP exits with a scan error and no report", async () => {
		const report = await runWithExec(
			zapActive,
			"https://example.com/",
			docker,
			async (c) =>
				c[1] === "info"
					? { code: 0, stdout: "", stderr: "" }
					: { code: 3, stdout: "", stderr: "boom" },
			allow("example.com"),
		);
		expect(report.results[0]?.status).toBe("error");
		expect(report.results[0]?.message).toContain("boom");
	});

	test("skips when Docker is unavailable even if the host is allowed", async () => {
		const report = await runWithExec(
			zapActive,
			"https://example.com/",
			() => undefined,
			never,
			allow("example.com"),
		);
		expect(report.results[0]?.status).toBe("skipped");
		expect(report.results[0]?.message).toContain("docker");
	});
});
