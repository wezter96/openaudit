import { afterAll, describe, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	realpathSync,
	renameSync,
	rmSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
	cloneArgs,
	cloneEnv,
	confineGitDir,
	gitHardeningEnv,
	incompleteHistory,
	parseSecretsHistory,
	scanEnv,
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
		const [, ...args] = cloneArgs("git", join(repo, ".git"), clone);
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

/* -------------------------------------------------------------------------- */
/*        Real git: git must read nothing outside the target, see it all      */
/* -------------------------------------------------------------------------- */

const scratch = (prefix: string) => {
	const dir = mkdtempSync(join(tmpdir(), prefix));
	tmps.push(dir);
	return dir;
};

const initRepo = (repo: string) => {
	mkdirSync(repo, { recursive: true });
	git(repo, ["init", "-q", "-b", "main"]);
	git(repo, ["config", "user.email", "t@example.com"]);
	git(repo, ["config", "user.name", "Tester"]);
};

/** A repository with an AWS key that was committed and then removed. */
const removedSecretRepo = () => {
	const repo = join(scratch("openaudit-target-"), "repo");
	initRepo(repo);
	writeFileSync(join(repo, "a.env"), `key=${AWS}\n`);
	git(repo, ["add", "."]);
	git(repo, ["commit", "-qm", "add"]);
	writeFileSync(join(repo, "a.env"), "key=\n");
	git(repo, ["commit", "-qam", "remove"]);
	return repo;
};

/** Another repository on the auditor's machine, with a GitHub token in it. */
const victimRepo = () => {
	const repo = join(scratch("openaudit-victim-"), "repo");
	initRepo(repo);
	writeFileSync(join(repo, "b.py"), `token = "${PAT}"\n`);
	git(repo, ["add", "."]);
	git(repo, ["commit", "-qm", "victim"]);
	return { repo, head: git(repo, ["rev-parse", "HEAD"]).trim() };
};

const auditorResult = async (target: string, options = {}) =>
	(await runAuditor(secretsHistory, target, options)).results[0];

describe.skipIf(!gitleaksAvailable)(
	"confinement (real git): never scans another repository",
	() => {
		const expectRefused = async (target: string, reason: RegExp) => {
			const result = await auditorResult(target);
			expect(result?.findings.map((f) => f.ruleId)).toEqual([]);
			expect(result?.status).toBe("skipped");
			expect(result?.message).toMatch(reason);
		};

		test("refuses a .git gitfile that points outside the target", async () => {
			const victim = victimRepo();
			const target = scratch("openaudit-target-");
			writeFileSync(join(target, ".git"), `gitdir: ${victim.repo}/.git\n`);
			await expectRefused(target, /gitfile.*outside the target/);
		});

		test("refuses a .git symlink", async () => {
			const victim = victimRepo();
			const target = scratch("openaudit-target-");
			symlinkSync(join(victim.repo, ".git"), join(target, ".git"));
			await expectRefused(target, /symlink/);
		});

		test("refuses alternates that lend another repository's objects", async () => {
			const victim = victimRepo();
			const target = removedSecretRepo();
			writeFileSync(
				join(target, ".git", "objects", "info", "alternates"),
				`${victim.repo}/.git/objects\n`,
			);
			writeFileSync(
				join(target, ".git", "refs", "heads", "stolen"),
				`${victim.head}\n`,
			);
			await expectRefused(target, /alternates/);
		});

		test("refuses a commondir outside the target", async () => {
			const victim = victimRepo();
			const target = removedSecretRepo();
			writeFileSync(join(target, ".git", "commondir"), `${victim.repo}/.git\n`);
			await expectRefused(target, /commondir.*outside the target/);
		});

		test("refuses symlinks inside .git", async () => {
			const victim = victimRepo();
			const target = join(scratch("openaudit-target-"), "repo");
			initRepo(target);
			rmSync(join(target, ".git", "objects"), { recursive: true });
			symlinkSync(
				join(victim.repo, ".git", "objects"),
				join(target, ".git", "objects"),
			);
			writeFileSync(
				join(target, ".git", "refs", "heads", "main"),
				`${victim.head}\n`,
			);
			await expectRefused(target, /\.git\/objects is a symlink/);
		});

		test("a gitfile inside the target is followed", async () => {
			const repo = removedSecretRepo();
			renameSync(join(repo, ".git"), join(repo, "real.git"));
			writeFileSync(join(repo, ".git"), "gitdir: real.git\n");
			const result = await auditorResult(repo);
			expect(result?.findings.map((f) => f.ruleId)).toEqual([
				"code.secrets-history/aws-access-token",
			]);
		});
	},
);

describe.skipIf(!gitleaksAvailable)(
	"history integrity (real git): a repository cannot hide commits",
	() => {
		const expectFound = async (repo: string) => {
			const result = await auditorResult(repo);
			expect(result?.status).toBe("failed");
			expect(result?.findings.map((f) => f.ruleId)).toContain(
				"code.secrets-history/aws-access-token",
			);
		};

		test("replace refs cannot swap history out", async () => {
			const repo = removedSecretRepo();
			const tree = git(repo, ["rev-parse", "HEAD^{tree}"]).trim();
			const orphan = git(repo, ["commit-tree", "-m", "clean", tree]).trim();
			git(repo, ["replace", "HEAD", orphan]);
			await expectFound(repo);
		});

		test("grafts cannot cut history", async () => {
			const repo = removedSecretRepo();
			mkdirSync(join(repo, ".git", "info"), { recursive: true });
			writeFileSync(
				join(repo, ".git", "info", "grafts"),
				`${git(repo, ["rev-parse", "HEAD"]).trim()}\n`,
			);
			await expectFound(repo);
		});

		test("hidden refs are still scanned", async () => {
			const repo = join(scratch("openaudit-target-"), "repo");
			initRepo(repo);
			writeFileSync(join(repo, "README"), "hi\n");
			git(repo, ["add", "."]);
			git(repo, ["commit", "-qm", "init"]);
			git(repo, ["checkout", "-qb", "hidden"]);
			writeFileSync(join(repo, "a.env"), `key=${AWS}\n`);
			git(repo, ["add", "."]);
			git(repo, ["commit", "-qm", "secret"]);
			git(repo, ["checkout", "-q", "main"]);
			git(repo, ["config", "uploadpack.hideRefs", "refs/heads/hidden"]);
			git(repo, ["config", "transfer.hideRefs", "refs/heads"]);
			await expectFound(repo);
		});

		test("a shallow history is reported as incomplete", async () => {
			const repo = removedSecretRepo();
			writeFileSync(
				join(repo, ".git", "shallow"),
				`${git(repo, ["rev-parse", "HEAD"]).trim()}\n`,
			);
			const result = await auditorResult(repo);
			const incomplete = result?.findings.find(
				(f) => f.ruleId === "code.secrets-history/incomplete-history",
			);
			expect(incomplete?.severity).toBe("info");
			expect(incomplete?.message).toContain("shallow");
		});

		test("hitting the commit limit is reported as incomplete", async () => {
			const repo = removedSecretRepo();
			const result = await auditorResult(repo, {
				settings: { "code.secrets-history": { maxCommits: 1 } },
			});
			const incomplete = result?.findings.find(
				(f) => f.ruleId === "code.secrets-history/incomplete-history",
			);
			expect(incomplete?.message).toContain("newest 1 of 2 commits");
		});
	},
);

describe("confinement and the hardened clone (real git, no gitleaks)", () => {
	test("confineGitDir refuses layouts that let git read outside the target", async () => {
		const victim = victimRepo();
		const gitfile = scratch("openaudit-target-");
		writeFileSync(join(gitfile, ".git"), `gitdir: ${victim.repo}/.git\n`);
		const symlinked = scratch("openaudit-target-");
		symlinkSync(join(victim.repo, ".git"), join(symlinked, ".git"));
		const alternates = removedSecretRepo();
		writeFileSync(
			join(alternates, ".git", "objects", "info", "alternates"),
			`${victim.repo}/.git/objects\n`,
		);
		const commondir = removedSecretRepo();
		writeFileSync(join(commondir, ".git", "commondir"), `${victim.repo}/.git`);
		const inner = removedSecretRepo();
		symlinkSync(
			join(victim.repo, ".git", "refs", "heads", "main"),
			join(inner, ".git", "refs", "heads", "stolen"),
		);
		const cases: Array<[string, RegExp]> = [
			[gitfile, /gitfile that points outside/],
			[symlinked, /\.git is a symlink/],
			[alternates, /alternates/],
			[commondir, /commondir points outside/],
			[inner, /\.git\/refs\/heads\/stolen is a symlink/],
			[scratch("openaudit-nogit-"), /not the root of a git repository/],
		];
		for (const [dir, why] of cases)
			expect(await confineGitDir(dir)).toEqual({
				refused: expect.stringMatching(why),
			});
		const ok = removedSecretRepo();
		expect(await confineGitDir(ok)).toEqual({
			gitDir: realpathSync(join(ok, ".git")),
		});
	});

	test("the mirror holds replaced, grafted and hidden history, and ignores a planted gitfile", () => {
		const victim = victimRepo();
		const repo = removedSecretRepo();
		const head = git(repo, ["rev-parse", "HEAD"]).trim();
		const tree = git(repo, ["rev-parse", "HEAD^{tree}"]).trim();
		git(repo, ["checkout", "-qb", "hidden"]);
		writeFileSync(join(repo, "h.txt"), "HIDDEN-BRANCH\n");
		git(repo, ["add", "."]);
		git(repo, ["commit", "-qm", "hidden"]);
		git(repo, ["checkout", "-q", "main"]);
		git(repo, ["config", "uploadpack.hideRefs", "refs/heads/hidden"]);
		git(repo, [
			"replace",
			head,
			git(repo, ["commit-tree", "-m", "x", tree]).trim(),
		]);
		mkdirSync(join(repo, ".git", "info"), { recursive: true });
		writeFileSync(join(repo, ".git", "info", "grafts"), `${head}\n`);
		// upload-pack would look for this before the git dir itself.
		writeFileSync(join(repo, ".git", ".git"), `gitdir: ${victim.repo}/.git\n`);

		const home = scratch("openaudit-home-");
		const clone = join(home, "repo.git");
		const [bin = "git", ...args] = cloneArgs("git", join(repo, ".git"), clone);
		execFileSync(bin, args, {
			cwd: home,
			env: { ...process.env, ...cloneEnv(home) },
			stdio: "ignore",
		});
		const log = git(home, ["log", "-p", "--all"], scanEnv(home, clone));
		expect(log).toContain(AWS);
		expect(log).toContain("HIDDEN-BRANCH");
		expect(log).not.toContain(PAT);
	});

	test("reports shallow or truncated history as incomplete", () => {
		expect(incompleteHistory(false, 10, 10)).toEqual([]);
		const [shallow] = incompleteHistory(true, 3, 10);
		expect(shallow?.severity).toBe("info");
		expect(shallow?.message).toContain("shallow");
		expect(incompleteHistory(false, 11, 10)[0]?.message).toContain(
			"newest 10 of 11 commits",
		);
	});
});
