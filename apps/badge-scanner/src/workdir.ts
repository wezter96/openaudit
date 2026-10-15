import { mkdir, mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** Every job's temp dir starts with this, so a restart can sweep leftovers. */
export const WORKDIR_PREFIX = "oa-badge-";

/**
 * One job's scratch space: the clone, one report dir per audit (outside the
 * clone, so the repo cannot plant report files) and the children's TMPDIR.
 */
export interface Workdir {
	readonly root: string;
	readonly repo: string;
	readonly tmp: string;
	readonly codebaseOut: string;
	readonly siteOut: string;
}

export const createWorkdir = async (base = tmpdir()): Promise<Workdir> => {
	const root = await mkdtemp(join(base, WORKDIR_PREFIX));
	const workdir = {
		root,
		repo: join(root, "repo"),
		tmp: join(root, "tmp"),
		codebaseOut: join(root, "codebase-report"),
		siteOut: join(root, "site-report"),
	};
	await mkdir(workdir.codebaseOut, { mode: 0o700 });
	await mkdir(workdir.siteOut, { mode: 0o700 });
	await mkdir(workdir.tmp, { mode: 0o700 });
	return workdir;
};

export const removeDir = (dir: string): Promise<void> =>
	rm(dir, { recursive: true, force: true, maxRetries: 3 }).catch(() => {});

/** Runs `job` in a fresh workdir and always removes it afterwards. */
export const withWorkdir = async <A>(
	job: (workdir: Workdir) => Promise<A>,
	base = tmpdir(),
): Promise<A> => {
	const workdir = await createWorkdir(base);
	try {
		return await job(workdir);
	} finally {
		await removeDir(workdir.root);
	}
};

/** Removes workdirs a killed scanner left behind. Call before the first job. */
export const sweepWorkdirs = async (base = tmpdir()): Promise<number> => {
	const names = await readdir(base).catch(() => [] as string[]);
	const stale = names.filter((name) => name.startsWith(WORKDIR_PREFIX));
	await Promise.all(stale.map((name) => removeDir(join(base, name))));
	return stale.length;
};
