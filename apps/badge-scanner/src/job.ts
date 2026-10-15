import { MAX_REPORT_BYTES as MAX_UPLOAD_BYTES } from "@openaudit/badge/api";

import {
	CODEBASE_TIMEOUT_MS,
	type OpenauditCommand,
	openauditVersion,
	runAudit,
	SITE_TIMEOUT_MS,
} from "./audit";
import { publicError, ScanError } from "./errors";
import { cloneRepo, hasVerificationFile, headCommit } from "./repo";
import { assertPublicSite, dnsResolver, type Resolver } from "./site";
import type { Job, JobResult, ProcessRunner, ReportPair } from "./types";
import { type Workdir, withWorkdir } from "./workdir";

/** What the Worker accepts, less room for the JSON envelope and escaping. */
export const MAX_REPORT_BYTES = MAX_UPLOAD_BYTES - 2 * 1024 * 1024;

/** Everything a job touches outside its own logic. */
export interface JobDeps {
	readonly run: ProcessRunner;
	readonly openaudit: OpenauditCommand;
	readonly resolve?: Resolver;
	/** Parent of the per-job temp dirs; the OS temp dir by default. */
	readonly tmpBase?: string;
	/** Strings that must never appear in a reported error. */
	readonly secrets?: ReadonlyArray<string>;
}

type SiteOutcome = { site?: ReportPair; error?: string };

const reportBytes = (r: ReportPair | undefined) =>
	r ? Buffer.byteLength(r.json) + Buffer.byteLength(r.html) : 0;

/** Drops the site reports when both together would not fit in one upload. */
const fitSite = (codebase: ReportPair, outcome: SiteOutcome): SiteOutcome => {
	const codebaseBytes = reportBytes(codebase);
	if (codebaseBytes > MAX_REPORT_BYTES)
		throw new ScanError("the codebase report is too large to store");
	return codebaseBytes + reportBytes(outcome.site) > MAX_REPORT_BYTES
		? { error: "site: the report is too large to store" }
		: outcome;
};

/** Clones the repo, checks the verification file and records the commit. */
const checkout = async (job: Job, deps: JobDeps, workdir: Workdir) => {
	await cloneRepo(deps.run, job.repo, workdir.repo);
	if (!(await hasVerificationFile(workdir.repo, job.code)))
		throw new ScanError("verification file missing");
	return headCommit(deps.run, workdir.repo);
};

/**
 * The site audit. A failure here is reported next to a good codebase scan
 * rather than failing it: the repo badge does not depend on the site.
 */
const scanSite = async (
	site: string,
	deps: JobDeps,
	workdir: Workdir,
): Promise<SiteOutcome> => {
	try {
		const target = await assertPublicSite(site, deps.resolve ?? dnsResolver);
		const reports = await runAudit(deps.run, {
			command: deps.openaudit,
			target,
			out: workdir.siteOut,
			cwd: workdir.root,
			timeoutMs: SITE_TIMEOUT_MS,
			label: "site",
		});
		return { site: reports };
	} catch (cause) {
		return {
			error: `site: ${publicError(cause, deps.secrets ?? [])}`,
		};
	}
};

const scan = async (
	job: Job,
	deps: JobDeps,
	workdir: Workdir,
): Promise<JobResult> => {
	const commit = await checkout(job, deps, workdir);
	const openauditVersionText = await openauditVersion(deps.run, deps.openaudit);
	const codebase = await runAudit(deps.run, {
		command: deps.openaudit,
		target: workdir.repo,
		out: workdir.codebaseOut,
		cwd: workdir.root,
		timeoutMs: CODEBASE_TIMEOUT_MS,
		label: "codebase",
	});
	const site = fitSite(
		codebase,
		job.site ? await scanSite(job.site, deps, workdir) : {},
	);
	return {
		status: "ok",
		commit,
		codebase,
		...(openauditVersionText ? { openauditVersion: openauditVersionText } : {}),
		...site,
	};
};

/**
 * Runs one claimed job in a fresh temp dir, which is always removed. Never
 * rejects: any failure becomes a `failed` result with a short, scrubbed error.
 */
export const runJob = async (job: Job, deps: JobDeps): Promise<JobResult> => {
	try {
		return await withWorkdir(
			(workdir) => scan(job, deps, workdir),
			deps.tmpBase,
		);
	} catch (cause) {
		return { status: "failed", error: publicError(cause, deps.secrets ?? []) };
	}
};
