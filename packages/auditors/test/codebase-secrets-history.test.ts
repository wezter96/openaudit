import { afterAll, describe, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
	cloneArgs,
	cloneEnv,
	gitHardeningEnv,
	parseSecretsHistory,
	secretsHistory,
} from "../src/codebase/secrets-history";
import { fixture, runAuditor } from "./helpers";

const recorded: unknown = JSON.parse(
	readFileSync(fixture("secrets-history", "gitleaks-git.json"), "utf8"),
);

const AWS = "AKIAZ3MSJV4WWLKNQ7XP";
const PAT = "ghp_aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jL5";

describe("parseSecretsHistory", () => {
	test("maps history hits, flags removed secrets and never leaks the secret", () => {
		const findings = parseSecretsHistory(
			recorded,
			new Map([
				[AWS, false],
				[PAT, true],
			]),
		);
		expect(findings.map((f) => `${f.ruleId} ${f.location?.file}`)).toEqual([
			"code.secrets-history/aws-access-token a.env",
			"code.secrets-history/github-pat b.py",
		]);
		const aws = findings[0];
		expect(aws?.message).toContain("commit d2d6f0a5");
		expect(aws?.message).toContain("on 2026-10-13");
		expect(aws?.message).toContain("by T");
		expect(aws?.message).toContain(
			"removed from the tree but is still in git history; rotate it",
		);
		expect(aws?.tags).toEqual(
			expect.arrayContaining(["secrets", "cwe-798", "removed-from-tree"]),
		);
		expect(findings[1]?.message).toContain("still present in the current tree");
		expect(findings[1]?.tags).not.toContain("removed-from-tree");
		const out = JSON.stringify(findings);
		expect(out).not.toContain(AWS);
		expect(out).not.toContain(PAT);
		expect(out).not.toContain("a@b.c"); // author email is not reported
		expect(aws?.evidence).toStartWith("AKIA");
	});

	test("says so when HEAD could not be checked, and groups repeat hits", () => {
		const hits = recorded as Array<Record<string, unknown>>;
		const dup = [
			{ ...hits[0], Commit: "ffffffffffffffffffffffffffffffffffffffff" },
			hits[0],
		];
		const findings = parseSecretsHistory(dup);
		expect(findings).toHaveLength(1);
		expect(findings[0]?.message).toContain("2 commits");
		// the oldest (last-listed) commit is reported as the introducing one
		expect(findings[0]?.message).toContain("commit d2d6f0a5");
		expect(findings[0]?.message).toContain("could not be determined");
		expect(parseSecretsHistory([])).toEqual([]);
		expect(parseSecretsHistory({})).toEqual([]);
	});
});

describe("hardening env", () => {
	test("neutralises every config source and only the clone may read local paths", () => {
		const env = gitHardeningEnv("/h");
		expect(env.GIT_CONFIG_NOSYSTEM).toBe("1");
		expect(env.GIT_CONFIG_GLOBAL).toBe("/dev/null");
		expect(env.HOME).toBe("/h");
		expect(env.GIT_TERMINAL_PROMPT).toBe("0");
		const pairs = (e: Record<string, string>) =>
			Object.fromEntries(
				Array.from({ length: Number(e.GIT_CONFIG_COUNT) }, (_, i) => [
					e[`GIT_CONFIG_KEY_${i}`],
					e[`GIT_CONFIG_VALUE_${i}`],
				]),
			);
		expect(pairs(env)).toEqual({
			"core.fsmonitor": "false",
			"core.hooksPath": "/dev/null",
			"core.attributesFile": "/dev/null",
		});
		expect(pairs(cloneEnv("/h"))["protocol.file.allow"]).toBe("always");
		expect(cloneArgs("git", "/src", "/dst")).toEqual(
			expect.arrayContaining(["--mirror", "--no-local", "--no-hardlinks"]),
		);
	});
});

/* -------------------------------------------------------------------------- */
/*                  Real git: a hostile repo must not run code                 */
/* -------------------------------------------------------------------------- */

const tmps: string[] = [];
afterAll(() => {
	for (const d of tmps) rmSync(d, { recursive: true, force: true });
});

const git = (cwd: string, args: string[], env: Record<string, string> = {}) =>
	execFileSync("git", args, {
		cwd,
		env: { ...process.env, ...env },
		stdio: ["ignore", "pipe", "pipe"],
	}).toString();

/** A repo with a removed secret whose .git/config tries to run commands. */
const hostileRepo = () => {
	const root = mkdtempSync(join(tmpdir(), "openaudit-hostile-"));
	tmps.push(root);
	const repo = join(root, "repo");
	const markers = join(root, "markers");
	mkdirSync(repo);
	mkdirSync(markers);
	const script = (name: string) => {
		const path = join(root, `${name}.sh`);
		writeFileSync(path, `#!/bin/sh\ntouch "${markers}/${name}"\ncat "$@"\n`);
		chmodSync(path, 0o755);
		return path;
	};
	git(repo, ["init", "-q"]);
	git(repo, ["config", "user.email", "t@example.com"]);
	git(repo, ["config", "user.name", "Tester"]);
	writeFileSync(join(repo, ".gitattributes"), "* diff=x\n");
	writeFileSync(join(repo, "a.env"), `key=${AWS}\n`);
	git(repo, ["add", "."]);
	git(repo, ["commit", "-qm", "add"]);
	writeFileSync(join(repo, "a.env"), "key=\n");
	git(repo, ["commit", "-qam", "remove"]);
	// Arm the traps only after committing, so setup itself cannot trip them.
	git(repo, ["config", "core.fsmonitor", script("fsmonitor")]);
	git(repo, ["config", "diff.x.textconv", script("textconv")]);
	git(repo, ["config", "diff.external", script("external")]);
	mkdirSync(join(repo, ".git", "hooks"), { recursive: true });
	const hook = join(repo, ".git", "hooks", "post-checkout");
	writeFileSync(hook, `#!/bin/sh\ntouch "${markers}/hook"\n`);
	chmodSync(hook, 0o755);
	return { repo, markers };
};

const gitleaksAvailable = Bun.which("gitleaks") !== null;

describe("git hardening (real git)", () => {
	test("the naive approach does execute the repository's commands", () => {
		const { repo, markers } = hostileRepo();
		git(repo, ["log", "-p"]);
		git(repo, ["status"]);
		expect(existsSync(join(markers, "textconv"))).toBe(true);
		expect(existsSync(join(markers, "fsmonitor"))).toBe(true);
	});

	test("clone and log -p with the hardened env run nothing", () => {
		const { repo, markers } = hostileRepo();
		const home = mkdtempSync(join(tmpdir(), "openaudit-home-"));
		tmps.push(home);
		const clone = join(home, "repo.git");
		const [, ...args] = cloneArgs("git", repo, clone);
		git(home, args, { ...cloneEnv(home) });
		// The mirror carries objects, not config, hooks or the traps.
		expect(readFileSync(join(clone, "config"), "utf8")).not.toContain(
			"textconv",
		);
		const log = git(
			clone,
			["log", "-p", "--all", "--full-history"],
			gitHardeningEnv(home),
		);
		expect(log).toContain(AWS);
		git(clone, ["grep", "-F", "-c", "key", "HEAD"], gitHardeningEnv(home));
		expect(existsSync(join(markers, "textconv"))).toBe(false);
		expect(existsSync(join(markers, "fsmonitor"))).toBe(false);
		expect(existsSync(join(markers, "external"))).toBe(false);
		expect(existsSync(join(markers, "hook"))).toBe(false);
	});

	test.skipIf(!gitleaksAvailable)(
		"the auditor finds the removed secret without running anything",
		async () => {
			const { repo, markers } = hostileRepo();
			const report = await runAuditor(secretsHistory, repo);
			const result = report.results[0];
			expect(result?.status).toBe("failed");
			expect(result?.findings.map((f) => f.ruleId)).toEqual([
				"code.secrets-history/aws-access-token",
			]);
			const f = result?.findings[0];
			expect(f?.message).toContain("removed from the tree");
			expect(f?.location?.file).toBe("a.env");
			expect(JSON.stringify(report)).not.toContain(AWS);
			for (const m of ["textconv", "fsmonitor", "external", "hook"])
				expect(existsSync(join(markers, m))).toBe(false);
			// Scratch space was cleaned up.
			expect(
				existsSync(join(repo, "repo.git")) ||
					existsSync(join(repo, ".git", "repo.git")),
			).toBe(false);
		},
	);

	test("is opt-in and skips non-git directories", async () => {
		expect(secretsHistory.defaultEnabled).toBe(false);
		const dir = mkdtempSync(join(tmpdir(), "openaudit-nogit-"));
		tmps.push(dir);
		writeFileSync(join(dir, "a.txt"), "x");
		const report = await runAuditor(secretsHistory, dir);
		expect(report.results[0]?.status).toBe("skipped");
	});
});
