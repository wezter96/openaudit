import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { type JobDeps, runJob } from "../src/job";
import type { Job } from "../src/types";
import { type Call, type FakeRepo, fakeRunner, SHA } from "./fakes";

const JOB: Job = {
	id: "scan-1",
	projectId: "wezter96-openaudit",
	repo: "wezter96/openaudit",
	site: null,
	code: "oa-code-42",
};

let base = "";
beforeEach(() => {
	base = mkdtempSync(join(tmpdir(), "oa-scanner-job-"));
});
afterEach(() => rmSync(base, { recursive: true, force: true }));

const deps = (repo: FakeRepo, calls: Call[] = []): JobDeps => ({
	run: fakeRunner(repo, calls),
	openaudit: ["openaudit"],
	resolve: async () => ["93.184.215.14"],
	tmpBase: base,
	secrets: ["s3cret-token"],
});

describe("runJob", () => {
	test("scans a verified repo and reports both formats", async () => {
		const calls: Call[] = [];
		const result = await runJob(
			JOB,
			deps({ badgeFile: "oa-code-42\n" }, calls),
		);
		expect(result).toEqual({
			status: "ok",
			commit: SHA,
			openauditVersion: "9.8.7",
			codebase: {
				json: expect.stringContaining("/repo"),
				html: "<html></html>",
			},
		});
		const audit = calls.find((c) => c.cmd.includes("--format"));
		expect(audit?.cmd.slice(2)).toEqual([
			"--format",
			"json,html",
			"--out",
			audit?.cmd[5] as string,
		]);
		expect(audit?.cmd.join(" ")).not.toMatch(/--only|--agentic/);
		expect(audit?.options.cwd).not.toContain("/repo");
	});

	test("fails when the verification file is gone", async () => {
		expect(await runJob(JOB, deps({ badgeFile: "another code" }))).toEqual({
			status: "failed",
			error: "verification file missing",
		});
		expect(await runJob(JOB, deps({}))).toEqual({
			status: "failed",
			error: "verification file missing",
		});
	});

	test("fails with git's message when the clone fails", async () => {
		const result = await runJob(JOB, deps({ cloneFails: true }));
		expect(result).toEqual({
			status: "failed",
			error: "git clone failed: fatal: repository not found",
		});
	});

	test("fails when openaudit writes no report", async () => {
		const result = await runJob(
			JOB,
			deps({ badgeFile: "oa-code-42", auditCode: 2, brokenTarget: /repo$/ }),
		);
		expect(result.status).toBe("failed");
		expect(result.error).toStartWith("openaudit codebase scan failed (exit 2)");
	});

	test("scans a verified site too", async () => {
		const result = await runJob(
			{ ...JOB, site: "https://example.com" },
			deps({ badgeFile: "oa-code-42" }),
		);
		expect(result.status).toBe("ok");
		expect(result.site?.json).toContain("https://example.com/");
		expect(result.error).toBeUndefined();
	});

	test("a refused site keeps the codebase scan", async () => {
		const result = await runJob(
			{ ...JOB, site: "https://example.com" },
			{
				...deps({ badgeFile: "oa-code-42" }),
				resolve: async () => ["100.64.0.1"],
			},
		);
		expect(result.status).toBe("ok");
		expect(result.codebase).toBeDefined();
		expect(result.site).toBeUndefined();
		expect(result.error).toStartWith("site: refusing to scan example.com");
	});

	test("never reports a secret and caps the error", async () => {
		const result = await runJob(JOB, {
			...deps({}),
			run: async () => {
				throw new Error(`boom s3cret-token ${"x".repeat(900)}`);
			},
		});
		expect(result.status).toBe("failed");
		expect(result.error).not.toContain("s3cret-token");
		expect(result.error).toContain("[redacted]");
		expect(result.error?.length).toBe(500);
	});

	test("always removes its temp dir", async () => {
		await runJob(JOB, deps({ badgeFile: "oa-code-42" }));
		await runJob(JOB, deps({ cloneFails: true }));
		expect(readdirSync(base)).toEqual([]);
	});
});
