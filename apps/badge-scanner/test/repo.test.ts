import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { childEnv } from "../src/process";
import { cloneArgs, gitEnv, hasVerificationFile } from "../src/repo";

const dirs: string[] = [];
const tempDir = () => {
	const dir = mkdtempSync(join(tmpdir(), "oa-scanner-test-"));
	dirs.push(dir);
	return dir;
};
afterEach(() => {
	for (const dir of dirs.splice(0))
		rmSync(dir, { recursive: true, force: true });
});

describe("cloneArgs", () => {
	test("makes a hardened shallow https clone", () => {
		expect(cloneArgs("wezter96/openaudit", "/tmp/x/repo")).toEqual([
			"git",
			"-c",
			"core.hooksPath=/dev/null",
			"-c",
			"protocol.allow=never",
			"-c",
			"protocol.https.allow=always",
			"clone",
			"--depth",
			"1",
			"--no-tags",
			"--single-branch",
			"https://github.com/wezter96/openaudit.git",
			"/tmp/x/repo",
		]);
	});

	test.each([
		"-upload-pack=x/y",
		"owner",
		"owner/name/extra",
		"owner/..",
		"owner/name --config",
		"../etc/passwd",
	])("refuses %s", (repo) => {
		expect(() => cloneArgs(repo, "/tmp/x")).toThrow("invalid repository");
	});
});

describe("environment", () => {
	test("git and openaudit never see secrets", () => {
		const env = childEnv({
			PATH: "/usr/bin",
			HOME: "/home/bun",
			SCANNER_TOKEN: "s3cret",
			API_URL: "https://openaudit.se",
			ANTHROPIC_API_KEY: "sk-ant",
			GITHUB_TOKEN: "ghp",
		});
		expect(env).toEqual({ PATH: "/usr/bin", HOME: "/home/bun" });
	});

	test("git runs without system or global config and without prompts", () => {
		const env = gitEnv();
		expect(env.GIT_CONFIG_NOSYSTEM).toBe("1");
		expect(env.GIT_CONFIG_GLOBAL).toBe("/dev/null");
		expect(env.GIT_TERMINAL_PROMPT).toBe("0");
	});
});

describe("hasVerificationFile", () => {
	test("finds the code in the file", async () => {
		const dir = tempDir();
		writeFileSync(join(dir, ".openaudit-badge"), "openaudit-verify=abc123\n");
		expect(await hasVerificationFile(dir, "abc123")).toBe(true);
		expect(await hasVerificationFile(dir, "zzz999")).toBe(false);
		expect(await hasVerificationFile(dir, "")).toBe(false);
	});

	test("a missing file is not verified", async () => {
		expect(await hasVerificationFile(tempDir(), "abc123")).toBe(false);
	});

	test("a symlink never counts, even to a file with the code", async () => {
		const dir = tempDir();
		const outside = join(tempDir(), "code.txt");
		writeFileSync(outside, "abc123");
		symlinkSync(outside, join(dir, ".openaudit-badge"));
		expect(await hasVerificationFile(dir, "abc123")).toBe(false);
	});

	test("an oversized file never counts", async () => {
		const dir = tempDir();
		writeFileSync(
			join(dir, ".openaudit-badge"),
			`abc123${" ".repeat(70 * 1024)}`,
		);
		expect(await hasVerificationFile(dir, "abc123")).toBe(false);
	});
});
