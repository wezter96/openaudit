import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { type AuditContext, AuditorError } from "@openaudit/core";
import { Effect } from "effect";

import { withTempDir } from "../../tool";
import { confineGitDir, gitHardeningEnv } from "../secrets-history";

/** One commit and the files it touched. */
export interface Commit {
	readonly hash: string;
	readonly author: string;
	/** Seconds since the epoch. */
	readonly time: number;
	readonly files: ReadonlyArray<string>;
}

export type History =
	| { readonly commits: ReadonlyArray<Commit> }
	| { readonly unavailable: string };

export const HISTORY_DAYS = 365;
const MAX_COMMITS = 10_000;

const RECORD = "\u001e";
const FIELD = "\u001f";

/** Parses `git log --format=%x1e%H%x1f%aN%x1f%at --name-only` output. */
export const parseGitLog = (stdout: string): Commit[] =>
	stdout
		.split(RECORD)
		.slice(1)
		.flatMap((record) => {
			const [head = "", ...names] = record.split("\n");
			const [hash, author, time] = head.split(FIELD);
			if (!hash || author === undefined) return [];
			const files = names.filter((n) => n && !n.startsWith('"'));
			return [{ hash, author, time: Number(time) || 0, files }];
		});

/**
 * Settings that could make `git log` run a program or read a file named by
 * the target's own config. The environment overrides the repository config.
 */
const LOG_HARDENING: ReadonlyArray<readonly [string, string]> = [
	["log.showSignature", "false"],
	["core.pager", "cat"],
	["core.quotePath", "true"],
	["log.mailmap", "false"],
];

const commonDirOf = async (gitDir: string) => {
	const common = await readFile(resolve(gitDir, "commondir"), "utf8").catch(
		() => undefined,
	);
	return common === undefined
		? gitDir
		: resolve(gitDir, common.replace(/[\r\n]+$/, ""));
};

const logArgs = (git: string, since: number) => [
	git,
	"log",
	"--no-merges",
	"--no-renames",
	"--no-show-signature",
	"--no-ext-diff",
	"--no-textconv",
	"--no-mailmap",
	`--since=${since}`,
	`--max-count=${MAX_COMMITS}`,
	`--format=${RECORD}%H${FIELD}%aN${FIELD}%at`,
	"--name-only",
	"HEAD",
	"--",
];

/**
 * The last year of non-merge commits on HEAD, read from the target's own git
 * directory after `confineGitDir` checked it stays inside the target. `git
 * log --name-only` compares commits, never the working tree, and runs with
 * the shared hardening plus the overrides above, so the target's config
 * cannot make it run anything.
 */
export const readHistory = (
	ctx: AuditContext,
	root: string,
): Effect.Effect<History, AuditorError> =>
	Effect.gen(function* () {
		const git = yield* ctx.exec.which("git");
		if (!git) return { unavailable: "git is not installed" };
		const confined = yield* Effect.tryPromise({
			try: () => confineGitDir(root),
			catch: (cause) =>
				new AuditorError({
					message: "Could not inspect the git directory",
					cause,
				}),
		});
		if ("refused" in confined) return { unavailable: confined.refused };
		const common = yield* Effect.promise(() => commonDirOf(confined.gitDir));
		const since = Math.floor(Date.now() / 1000) - HISTORY_DAYS * 86_400;
		const res = yield* withTempDir("openaudit-history-", (home) =>
			ctx.exec.run(logArgs(git, since), {
				cwd: home,
				timeoutMs: 120_000,
				env: {
					...gitHardeningEnv(home, LOG_HARDENING),
					GIT_DIR: confined.gitDir,
					GIT_COMMON_DIR: common,
					GIT_ALTERNATE_OBJECT_DIRECTORIES: "",
					GIT_PAGER: "cat",
				},
			}),
		);
		if (res.code !== 0)
			return {
				unavailable: `git log failed: ${res.stderr.trim().split("\n")[0] ?? ""}`,
			};
		return { commits: parseGitLog(res.stdout) };
	});

/** Commits per file. */
export const revisionsOf = (commits: ReadonlyArray<Commit>) => {
	const revs = new Map<string, number>();
	for (const c of commits)
		for (const f of c.files) revs.set(f, (revs.get(f) ?? 0) + 1);
	return revs;
};

/**
 * Hotspots: the files changed most often, the top 5% of `files` by commits
 * (at least one, and only files changed more than once).
 */
export const hotspotsOf = (
	files: ReadonlyArray<string>,
	revs: ReadonlyMap<string, number>,
): Set<string> => {
	const ranked = files
		.filter((f) => (revs.get(f) ?? 0) > 1)
		.sort((a, b) => (revs.get(b) ?? 0) - (revs.get(a) ?? 0));
	const count = Math.max(1, Math.ceil(files.length * 0.05));
	return new Set(ranked.slice(0, count));
};
