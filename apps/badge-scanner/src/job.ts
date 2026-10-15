import { MAX_REPORT_BYTES as MAX_UPLOAD_BYTES } from "@openaudit/badge/api";

import {
	CODEBASE_TIMEOUT_MS,
	type OpenauditCommand,
	openauditVersion,
	runAudit,
	SITE_TIMEOUT_MS,
} from "./audit";
import { publicError, ScanError } from "./errors";
import { childEnv } from "./process";
import { cloneRepo, hasVerificationFile, headCommit } from "./repo";
import { assertPublicSite, dnsResolver, type Resolver } from "./site";
import type { Exec, Job, JobResult, ProcessRunner, ReportPair } from "./types";
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

/** One job's deps plus its workdir and the minimal env its children get. */
interface JobRun extends JobDeps {
	readonly exec: Exec;
	readonly workdir: Workdir;
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
const checkout = async (job: Job, { exec, workdir }: JobRun) => {
	await cloneRepo(exec, job.repo, workdir.repo);
	if (!(await hasVerificationFile(workdir.repo, job.code)))
		throw new ScanError("verification file missing");
	return headCommit(exec, workdir.repo);
};

/**
 * The site audit. A failure here is reported next to a good codebase scan
 * rather than failing it: the repo badge does not depend on the site.
 */
const scanSite = async (site: string, ctx: JobRun): Promise<SiteOutcome> => {
	try {
		const target = await assertPublicSite(site, ctx.resolve ?? dnsResolver);
		const reports = await runAudit(ctx.exec, {
			command: ctx.openaudit,
			target,
			out: ctx.workdir.siteOut,
			cwd: ctx.workdir.root,
			timeoutMs: SITE_TIMEOUT_MS,
			label: "site",
		});
		return { site: reports };
	} catch (cause) {
		return {
			error: `site: ${publicError(cause, ctx.secrets ?? [])}`,
		};
	}
};

const scan = async (job: Job, ctx: JobRun): Promise<JobResult> => {
	const commit = await checkout(job, ctx);
	const openauditVersionText = await openauditVersion(ctx.exec, ctx.openaudit);
	const codebase = await runAudit(ctx.exec, {
		command: ctx.openaudit,
		target: ctx.workdir.repo,
		out: ctx.workdir.codebaseOut,
		cwd: ctx.workdir.root,
		timeoutMs: CODEBASE_TIMEOUT_MS,
		label: "codebase",
	});
	const site = fitSite(codebase, job.site ? await scanSite(job.site, ctx) : {});
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
			(workdir) =>
				scan(job, {
					...deps,
					workdir,
					exec: { run: deps.run, env: childEnv(workdir.tmp) },
				}),
			deps.tmpBase,
		);
	} catch (cause) {
		return { status: "failed", error: publicError(cause, deps.secrets ?? []) };
	}
};
