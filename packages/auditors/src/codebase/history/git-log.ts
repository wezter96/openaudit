import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
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
	const common = await readFile(join(gitDir, "commondir"), "utf8").catch(
		() => undefined,
	);
	return common === undefined
		? gitDir
		: resolve(gitDir, common.replace(/[\r\n]+$/, ""));
};

const OBJECT_ID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const REF = /^refs\/[\w./-]+$/;

const readTrimmed = (path: string) =>
	readFile(path, "utf8").then(
		(text) => text.trim(),
		() => undefined,
	);

/** A branch's commit, from its loose ref file or from `packed-refs`. */
const refCommit = async (common: string, ref: string) => {
	if (!REF.test(ref) || ref.includes("..")) return undefined;
	const loose = await readTrimmed(join(common, ref));
	if (loose !== undefined) return loose;
	const packed = (await readTrimmed(join(common, "packed-refs"))) ?? "";
	const line = packed.split("\n").find((l) => l.endsWith(` ${ref}`));
	return line?.split(" ")[0];
};

/**
 * The commit HEAD points to, read from the files rather than asked of git,
 * so git never loads the target's configuration.
 */
export const headCommit = async (
	gitDir: string,
	common: string,
): Promise<string | undefined> => {
	const head = (await readTrimmed(join(gitDir, "HEAD"))) ?? "";
	const ref = /^ref: (.+)$/.exec(head)?.[1];
	const id = ref === undefined ? head : await refCommit(common, ref);
	return id !== undefined && OBJECT_ID.test(id) ? id : undefined;
};

/**
 * A throwaway git directory that borrows only the target's objects: an empty
 * config, HEAD at the commit to read, and the target's shallow list.
 */
const scratchGitDir = async (dir: string, common: string, head: string) => {
	await mkdir(join(dir, "refs"), { recursive: true });
	const format =
		head.length === 64
			? "\trepositoryformatversion = 1\n[extensions]\n\tobjectFormat = sha256\n"
			: "\trepositoryformatversion = 0\n";
	await writeFile(join(dir, "config"), `[core]\n\tbare = true\n${format}`);
	await writeFile(join(dir, "HEAD"), `${head}\n`);
	const shallow = await readFile(join(common, "shallow")).catch(
		() => undefined,
	);
	if (shallow) await writeFile(join(dir, "shallow"), shallow);
};

const logArgs = (git: string, since: number, head: string) => [
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
	head,
	"--",
];

const runLog = (ctx: AuditContext, git: string, common: string, head: string) =>
	withTempDir("openaudit-history-", (tmp) =>
		Effect.gen(function* () {
			const dir = join(tmp, "git");
			yield* Effect.promise(() => scratchGitDir(dir, common, head));
			const since = Math.floor(Date.now() / 1000) - HISTORY_DAYS * 86_400;
			return yield* ctx.exec.run(logArgs(git, since, head), {
				cwd: tmp,
				timeoutMs: 120_000,
				env: {
					...gitHardeningEnv(tmp, LOG_HARDENING),
					GIT_DIR: dir,
					GIT_COMMON_DIR: dir,
					GIT_OBJECT_DIRECTORY: join(common, "objects"),
					GIT_ALTERNATE_OBJECT_DIRECTORIES: "",
					GIT_PAGER: "cat",
				},
			});
		}),
	);

/**
 * The last year of non-merge commits on HEAD. `confineGitDir` first checks
 * the target's git directory stays inside the target; git then runs on a
 * scratch git directory that borrows only the target's objects, so the
 * target's config, hooks and attributes are never read. `git log
 * --name-only` compares commits, never the working tree.
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
		const head = yield* Effect.promise(() =>
			headCommit(confined.gitDir, common),
		);
		if (!head) return { commits: [] };
		const res = yield* runLog(ctx, git, common, head);
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
