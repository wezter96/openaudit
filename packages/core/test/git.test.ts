import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { changedFilesSince, GitError } from "../src/git";

const git = (cwd: string, ...args: string[]) => {
	const r = Bun.spawnSync(["git", "-C", cwd, ...args], {
		env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", HOME: cwd },
	});
	if (r.exitCode !== 0) throw new Error(r.stderr.toString());
};

const repo = () => {
	const dir = mkdtempSync(join(tmpdir(), "oa-git-"));
	git(dir, "init", "-q", "-b", "main");
	git(dir, "config", "user.email", "t@t");
	git(dir, "config", "user.name", "t");
	writeFileSync(join(dir, "a.ts"), "a\n");
	writeFileSync(join(dir, "gone.ts"), "x\n");
	git(dir, "add", ".");
	git(dir, "commit", "-qm", "base");
	git(dir, "checkout", "-qb", "feature");
	writeFileSync(join(dir, "a.ts"), "a2\n");
	writeFileSync(join(dir, "b.ts"), "b\n");
	git(dir, "rm", "-q", "gone.ts");
	git(dir, "add", ".");
	git(dir, "commit", "-qm", "change");
	return dir;
};

describe("changedFilesSince", () => {
	test("lists added and modified files since the merge base, not deleted ones", async () => {
		const dir = repo();
		try {
			expect(await changedFilesSince(dir, "main")).toEqual(["a.ts", "b.ts"]);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	test("rejects refs that look like options or ranges", async () => {
		for (const ref of ["--output=/tmp/x", "main..HEAD", "a b", ""])
			await expect(changedFilesSince(".", ref)).rejects.toBeInstanceOf(
				GitError,
			);
	});

	test("hostile git config in the target never runs", async () => {
		const dir = repo();
		const marker = join(dir, "pwned");
		try {
			git(dir, "config", "core.fsmonitor", `touch ${marker}`);
			git(dir, "config", "filter.x.clean", `touch ${marker}; cat`);
			git(dir, "config", "diff.x.textconv", `touch ${marker}; cat`);
			writeFileSync(join(dir, ".gitattributes"), "* filter=x diff=x\n");
			writeFileSync(join(dir, "a.ts"), "dirty working tree\n");
			await changedFilesSince(dir, "main");
			expect(existsSync(marker)).toBe(false);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});
