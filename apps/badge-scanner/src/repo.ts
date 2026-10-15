import { lstat, readFile } from "node:fs/promises";
import { join } from "node:path";
import { GIT_HARDENING_ENV } from "@openaudit/core/git";

import { lastLine, ScanError } from "./errors";
import type { ChildEnv, Exec } from "./types";

export const CLONE_TIMEOUT_MS = 5 * 60_000;
const GIT_TIMEOUT_MS = 30_000;
export const VERIFICATION_FILE = ".openaudit-badge";
/** A verification file is a code and maybe a comment; anything bigger is not one. */
const MAX_VERIFICATION_BYTES = 64 * 1024;

/** `owner/name` as GitHub allows it. The API validates too; this keeps argv safe. */
const REPO_PATTERN = /^[A-Za-z0-9][A-Za-z0-9-]*\/[A-Za-z0-9._-]+$/;

/**
 * git with no system or global config, no prompts, no hooks, no fsmonitor,
 * and https as the only transport (submodules and redirects included).
 */
export const gitEnv = (env: ChildEnv): ChildEnv => ({
	...env,
	...GIT_HARDENING_ENV,
	GIT_CONFIG_NOSYSTEM: "1",
	GIT_CONFIG_GLOBAL: "/dev/null",
	GIT_TERMINAL_PROMPT: "0",
	GIT_ASKPASS: "/bin/false",
	SSH_ASKPASS: "/bin/false",
});

const GIT_FLAGS = [
	"-c",
	"core.hooksPath=/dev/null",
	"-c",
	"protocol.allow=never",
	"-c",
	"protocol.https.allow=always",
];

export const cloneArgs = (repo: string, dir: string): string[] => {
	if (!REPO_PATTERN.test(repo) || repo.includes(".."))
		throw new ScanError(`invalid repository name "${repo}"`);
	return [
		"git",
		...GIT_FLAGS,
		"clone",
		"--depth",
		"1",
		"--no-tags",
		"--single-branch",
		`https://github.com/${repo}.git`,
		dir,
	];
};

/** Shallow-clones the default branch into `dir`, which must not exist yet. */
export const cloneRepo = async (
	exec: Exec,
	repo: string,
	dir: string,
): Promise<void> => {
	const result = await exec.run(cloneArgs(repo, dir), {
		env: gitEnv(exec.env),
		timeoutMs: CLONE_TIMEOUT_MS,
	});
	if (result.timedOut) throw new ScanError("git clone timed out");
	if (result.code !== 0)
		throw new ScanError(`git clone failed: ${lastLine(result.stderr)}`);
};

/** The commit the clone checked out. */
export const headCommit = async (exec: Exec, dir: string): Promise<string> => {
	const result = await exec.run(
		["git", ...GIT_FLAGS, "-C", dir, "rev-parse", "HEAD"],
		{ env: gitEnv(exec.env), timeoutMs: GIT_TIMEOUT_MS },
	);
	const sha = result.stdout.trim();
	if (result.code !== 0 || !/^[0-9a-f]{40,64}$/.test(sha))
		throw new ScanError("could not read the cloned commit");
	return sha;
};

/**
 * Whether the clone's verification file contains `code`. A symlink, a
 * directory or an oversized file never counts: the repository is untrusted.
 */
export const hasVerificationFile = async (
	dir: string,
	code: string,
): Promise<boolean> => {
	const path = join(dir, VERIFICATION_FILE);
	const stat = await lstat(path).catch(() => undefined);
	if (!stat?.isFile() || stat.size > MAX_VERIFICATION_BYTES) return false;
	return code.length > 0 && (await readFile(path, "utf8")).includes(code);
};
