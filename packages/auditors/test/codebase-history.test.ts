import { afterAll, describe, expect, test } from "bun:test";

import { execFileSync } from "node:child_process";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
	codeHistory,
	couplingsOf,
	ownershipOf,
	truckFactor,
} from "../src/codebase/history";
import {
	type Commit,
	hotspotsOf,
	parseGitLog,
	revisionsOf,
} from "../src/codebase/history/git-log";
import { runAuditor } from "./helpers";

const tmps: string[] = [];
afterAll(() => {
	for (const dir of tmps) rmSync(dir, { recursive: true, force: true });
});

const commit = (
	author: string,
	files: string[],
	time = 1_700_000_000,
): Commit => ({
	hash: `${author}-${files.join()}-${time}`,
	author,
	time,
	files,
});
const all = () => true;

describe("code.history parsing and analysis", () => {
	test("parses git log records and skips quoted names", () => {
		const out =
			'\u001eabc\u001fAda\u001f1700000000\n\nsrc/a.ts\n"we\\tird"\n\u001edef\u001fBo\u001f1700000100\n\nsrc/b.ts\n';
		expect(parseGitLog(out)).toEqual([
			{ hash: "abc", author: "Ada", time: 1_700_000_000, files: ["src/a.ts"] },
			{ hash: "def", author: "Bo", time: 1_700_000_100, files: ["src/b.ts"] },
		]);
	});

	test("files that change together, without tests and bulk commits", () => {
		const commits = [
			...Array.from({ length: 5 }, () =>
				commit("Ada", ["src/a.ts", "src/b.ts", "test/a.test.ts"]),
			),
			commit("Ada", ["src/a.ts"]),
			commit(
				"Ada",
				Array.from({ length: 40 }, (_, i) => `src/bulk${i}.ts`).concat(
					"src/b.ts",
				),
			),
		];
		expect(couplingsOf(commits, all)).toEqual([
			{ a: "src/a.ts", b: "src/b.ts", shared: 5, percent: 91 },
		]);
	});

	test("ownership, truck factor and hotspots", () => {
		const commits = [
			commit("Ada", ["a.ts", "b.ts"]),
			commit("Ada", ["a.ts"]),
			commit("Bo", ["b.ts"]),
			commit("Bo", ["b.ts"]),
			commit("Cy", ["c.ts"]),
		];
		const owners = ownershipOf(commits, all);
		expect(owners.find((o) => o.file === "a.ts")).toEqual({
			file: "a.ts",
			author: "Ada",
			share: 1,
		});
		expect(truckFactor(owners)).toBe(2);
		expect([
			...hotspotsOf(["a.ts", "b.ts", "c.ts"], revisionsOf(commits)),
		]).toEqual(["b.ts"]);
	});
});

const git = (cwd: string, args: string[], env: Record<string, string> = {}) =>
	execFileSync("git", args, {
		cwd,
		env: { ...process.env, ...env },
		stdio: ["ignore", "pipe", "pipe"],
	}).toString();

/** A repo with coupled files whose config tries to run commands. */
const hostileRepo = () => {
	const root = mkdtempSync(join(tmpdir(), "openaudit-history-"));
	tmps.push(root);
	const repo = join(root, "repo");
	const markers = join(root, "markers");
	mkdirSync(join(repo, "src"), { recursive: true });
	mkdirSync(markers);
	git(repo, ["init", "-q", "-b", "main"]);
	git(repo, ["config", "user.email", "t@example.com"]);
	git(repo, ["config", "user.name", "Ada"]);
	for (let i = 0; i < 5; i++) {
		writeFileSync(join(repo, "src/a.ts"), `export const a = ${i};\n`);
		writeFileSync(join(repo, "src/b.ts"), `export const b = ${i};\n`);
		git(repo, ["add", "."]);
		git(repo, ["commit", "-qm", `change ${i}`]);
	}
	const script = (name: string) => {
		const path = join(root, `${name}.sh`);
		writeFileSync(path, `#!/bin/sh\ntouch "${markers}/${name}"\ncat\n`);
		chmodSync(path, 0o755);
		return path;
	};
	git(repo, ["config", "core.fsmonitor", script("fsmonitor")]);
	git(repo, ["config", "diff.external", script("external")]);
	git(repo, ["config", "core.pager", script("pager")]);
	git(repo, ["config", "log.showSignature", "true"]);
	git(repo, ["config", "gpg.program", script("gpg")]);
	return { repo, markers };
};

describe("code.history auditor (real git)", () => {
	test("reports coupling and the truck factor, and runs nothing from the repo's config", async () => {
		const { repo, markers } = hostileRepo();
		const report = await runAuditor(codeHistory, repo);
		const findings = report.results.flatMap((r) => r.findings);
		expect(findings.map((f) => f.ruleId).sort()).toEqual([
			"code.history/change-coupling",
			"code.history/truck-factor",
		]);
		expect(findings[0]?.evidence).toBe("src/a.ts <-> src/b.ts");
		for (const name of ["fsmonitor", "external", "pager", "gpg"])
			expect(existsSync(join(markers, name))).toBe(false);
	});

	test("reports knowledge loss when the main author stopped committing", async () => {
		const root = mkdtempSync(join(tmpdir(), "openaudit-history-"));
		tmps.push(root);
		git(root, ["init", "-q", "-b", "main"]);
		git(root, ["config", "user.email", "t@example.com"]);
		writeFileSync(join(root, "old.ts"), "export const x = 1;\n");
		git(root, ["add", "."]);
		const recent = new Date(Date.now() - 300 * 86_400_000).toISOString();
		git(root, ["-c", "user.name=Ada", "commit", "-qm", "old"], {
			GIT_AUTHOR_DATE: recent,
			GIT_COMMITTER_DATE: recent,
		});
		writeFileSync(join(root, "new.ts"), "export const y = 1;\n");
		git(root, ["add", "."]);
		git(root, ["-c", "user.name=Bo", "commit", "-qm", "new"]);
		const report = await runAuditor(codeHistory, root);
		const loss = report.results
			.flatMap((r) => r.findings)
			.find((f) => f.ruleId === "code.history/knowledge-loss");
		expect(loss?.location?.file).toBe("old.ts");
		expect(loss?.message).toContain("Ada");
	});

	test("skips outside a git repository", async () => {
		const root = mkdtempSync(join(tmpdir(), "openaudit-history-"));
		tmps.push(root);
		writeFileSync(join(root, "a.ts"), "export const a = 1;\n");
		const report = await runAuditor(codeHistory, root);
		expect(report.results[0]?.status).toBe("skipped");
	});
});
