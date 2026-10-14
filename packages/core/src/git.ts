import type { Report } from "./model";
import { filterFindings } from "./scoring";

/*
 * Git inside an audited target is hostile: `.git/config` can name an
 * fsmonitor, hooks, diff drivers and filters that run commands. Every git call
 * openaudit makes on a target uses this environment, and compares commits
 * (tree to tree) rather than the working tree, so clean filters and textconv
 * drivers never fire. Replace refs (`refs/replace/*`) and grafts
 * (`info/grafts`) are ignored, so a target cannot rewrite its own history to
 * hide commits or changes. The graft file is a path that cannot exist.
 */
export const GIT_HARDENING_ENV: Record<string, string> = {
	GIT_NO_REPLACE_OBJECTS: "1",
	GIT_GRAFT_FILE: "/dev/null/no-grafts",
	GIT_CONFIG_NOSYSTEM: "1",
	GIT_CONFIG_COUNT: "2",
	GIT_CONFIG_KEY_0: "core.fsmonitor",
	GIT_CONFIG_VALUE_0: "false",
	GIT_CONFIG_KEY_1: "core.hooksPath",
	GIT_CONFIG_VALUE_1: "/dev/null",
	GIT_TERMINAL_PROMPT: "0",
};

/** Refs a user may pass: branch, tag, sha, `origin/main`, `HEAD~3`. */
export const GIT_REF = /^[A-Za-z0-9][A-Za-z0-9._/@~^-]{0,99}$/;

export class GitError extends Error {}

/**
 * Files added or modified on HEAD since it diverged from `base` (`base...HEAD`),
 * relative to `root` and limited to it. Deleted files are left out.
 */
export const changedFilesSince = async (
	root: string,
	base: string,
): Promise<string[]> => {
	if (!GIT_REF.test(base) || base.includes(".."))
		throw new GitError(`Invalid git ref "${base}".`);
	const proc = Bun.spawn(
		[
			"git",
			"-C",
			root,
			"diff",
			"--name-only",
			"--relative",
			"--no-renames",
			"--diff-filter=d",
			"--no-ext-diff",
			"--no-textconv",
			"-z",
			`${base}...HEAD`,
			"--",
		],
		{
			env: { ...process.env, ...GIT_HARDENING_ENV },
			stdin: "ignore",
			stdout: "pipe",
			stderr: "pipe",
		},
	);
	const [stdout, stderr, code] = await Promise.all([
		new Response(proc.stdout).text(),
		new Response(proc.stderr).text(),
		proc.exited,
	]);
	if (code !== 0)
		throw new GitError(
			`git diff against "${base}" failed: ${stderr.trim().split("\n")[0] || `exit ${code}`}`,
		);
	return [...new Set(stdout.split("\0").filter(Boolean))].sort();
};

/**
 * Diff mode: keeps findings in `files` (paths relative to the target root)
 * and drops the rest, including findings with no file. The drop is disclosed
 * as a suppression, and statuses, correlation and the summary are recomputed.
 */
export const limitToChangedFiles = (
	report: Report,
	base: string,
	files: ReadonlyArray<string>,
): Report => {
	const keep = new Set(files);
	let dropped = 0;
	const { results, summary } = filterFindings(report.results, (f) => {
		const file = f.location?.file?.replace(/^\.\//, "");
		const inDiff = file !== undefined && keep.has(file);
		if (!inDiff) dropped++;
		return inDiff;
	});
	return {
		...report,
		results,
		summary,
		diff: { base, changedFiles: keep.size },
		...(dropped
			? {
					suppressed: [
						...(report.suppressed ?? []),
						{
							source: `--diff ${base}`,
							rules: 0,
							paths: dropped,
							fingerprints: 0,
						},
					],
				}
			: {}),
	};
};
