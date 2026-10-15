import { describe, expect, test } from "bun:test";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { auditArgs, parseCommand, parseVersion } from "../src/audit";
import { readConfig } from "../src/config";
import { publicError, ScanError } from "../src/errors";
import { bunRunner } from "../src/process";
import { sweepWorkdirs, WORKDIR_PREFIX, withWorkdir } from "../src/workdir";

describe("openaudit command", () => {
	test("OPENAUDIT_BIN may be a command with arguments", () => {
		expect(parseCommand(undefined)).toEqual(["openaudit"]);
		expect(parseCommand("  ")).toEqual(["openaudit"]);
		expect(parseCommand("bun apps/cli/src/bin.ts")).toEqual([
			"bun",
			"apps/cli/src/bin.ts",
		]);
	});

	test("audits with JSON and HTML into the out dir", () => {
		expect(auditArgs(["openaudit"], "/w/repo", "/w/out")).toEqual([
			"openaudit",
			"/w/repo",
			"--format",
			"json,html",
			"--out",
			"/w/out",
		]);
	});

	test("reads the version from --version", () => {
		expect(parseVersion("openaudit v0.2.1\n")).toBe("0.2.1");
		expect(parseVersion("1.0.0-beta.2")).toBe("1.0.0-beta.2");
		expect(parseVersion("unknown")).toBeUndefined();
	});
});

describe("config", () => {
	test("requires SCANNER_TOKEN and defaults the rest", () => {
		expect(() => readConfig({})).toThrow("SCANNER_TOKEN");
		expect(readConfig({ SCANNER_TOKEN: "t" })).toEqual({
			apiUrl: "https://openaudit.se",
			token: "t",
			openaudit: ["openaudit"],
		});
	});

	test("refuses a plain-http API outside localhost", () => {
		expect(() =>
			readConfig({ SCANNER_TOKEN: "t", API_URL: "http://example.com" }),
		).toThrow("https");
		expect(
			readConfig({ SCANNER_TOKEN: "t", API_URL: "http://localhost:8787/" })
				.apiUrl,
		).toBe("http://localhost:8787");
	});
});

describe("publicError", () => {
	test("redacts secrets and collapses whitespace", () => {
		expect(publicError(new ScanError("bad\n  tok here"), ["tok"])).toBe(
			"bad [redacted] here",
		);
		expect(publicError("", [])).toBe("scan failed");
	});
});

describe("workdir", () => {
	test("is removed even when the job throws", async () => {
		const base = mkdtempSync(join(tmpdir(), "oa-scanner-wd-"));
		let seen = "";
		await expect(
			withWorkdir(async (w) => {
				seen = w.root;
				expect(existsSync(w.codebaseOut)).toBe(true);
				throw new Error("x");
			}, base),
		).rejects.toThrow("x");
		expect(existsSync(seen)).toBe(false);
		rmSync(base, { recursive: true });
	});

	test("sweeps leftovers from a killed run", async () => {
		const base = mkdtempSync(join(tmpdir(), "oa-scanner-wd-"));
		mkdirSync(join(base, `${WORKDIR_PREFIX}old`));
		mkdirSync(join(base, "unrelated"));
		expect(await sweepWorkdirs(base)).toBe(1);
		expect(readdirSync(base)).toEqual(["unrelated"]);
		rmSync(base, { recursive: true });
	});
});

describe("bunRunner", () => {
	test("captures output and the exit code", async () => {
		const r = await bunRunner(["sh", "-c", "echo hi; echo err >&2; exit 3"], {
			timeoutMs: 5_000,
		});
		expect(r).toEqual({
			code: 3,
			stdout: "hi\n",
			stderr: "err\n",
			timedOut: false,
		});
	});

	test("kills the process group on timeout", async () => {
		const started = Date.now();
		const r = await bunRunner(["sh", "-c", "sleep 30 & sleep 30"], {
			timeoutMs: 200,
		});
		expect(r.timedOut).toBe(true);
		expect(Date.now() - started).toBeLessThan(5_000);
	});
});
