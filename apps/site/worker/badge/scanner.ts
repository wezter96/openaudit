/** The scanner's endpoints: claim the next due job, then report it. */
import {
	type ClaimResult,
	InvalidInput,
	type JobReport,
	MAX_ERROR_LENGTH,
	NotFound,
	type ReportFiles,
	type ScanId,
	summarize,
	type TargetSummary,
} from "@openaudit/badge";
import { Effect } from "effect";
import type { BadgeRequest, R2 } from "./env";
import {
	dueProject,
	expireLeases,
	findScan,
	finishScan,
	pruneScans,
	type ReportFile,
	reportKey,
	type ScanRow,
	startScan,
} from "./scans";

const promise = <A>(run: () => Promise<A>) => Effect.promise(run);

export const claim = (req: BadgeRequest) =>
	Effect.gen(function* () {
		const db = req.env.BADGES;
		yield* promise(() => expireLeases(db, req.now));
		const project = yield* promise(() => dueProject(db, req.now));
		if (!project) return { job: null } satisfies ClaimResult;
		const id = crypto.randomUUID();
		const started = yield* promise(() =>
			startScan(db, project.id, id, req.now),
		);
		if (!started) return { job: null } satisfies ClaimResult;
		const site = project.site_verified === 1 ? project.site : null;
		return {
			job: {
				id,
				projectId: project.id,
				repo: project.repo,
				site,
				code: project.code,
			},
		} satisfies ClaimResult;
	});

type Target = "codebase" | "site";

const invalid = (message: string) => new InvalidInput({ message });

/** The summary of an uploaded report, failing when it isn't one. */
const summaryOf = (target: Target, files: ReportFiles | undefined) =>
	Effect.gen(function* () {
		if (!files) return null;
		const summary = summarize(files.json);
		if (!summary)
			return yield* invalid(`The ${target} JSON isn't an openaudit report.`);
		return summary;
	});

const putReports = (
	reports: R2,
	scan: ScanRow,
	target: Target,
	files: ReportFiles,
) => {
	const key = (ext: "json" | "html") =>
		reportKey(scan.project_id, scan.id, `${target}.${ext}` as ReportFile);
	return Promise.all([
		reports.put(key("json"), files.json, {
			httpMetadata: { contentType: "application/json" },
		}),
		reports.put(key("html"), files.html, {
			httpMetadata: { contentType: "text/html; charset=utf-8" },
		}),
	]);
};

interface Summaries {
	readonly codebase: TargetSummary | null;
	readonly site: TargetSummary | null;
}

/** Validates and stores an ok scan's reports. */
const storeReports = (req: BadgeRequest, scan: ScanRow, report: JobReport) =>
	Effect.gen(function* () {
		const codebase = yield* summaryOf("codebase", report.codebase);
		const site = yield* summaryOf("site", report.site);
		if (!codebase && !site)
			return yield* invalid("An ok scan needs at least one report.");
		const put = (target: Target, files: ReportFiles | undefined) =>
			files
				? promise(() => putReports(req.env.BADGE_REPORTS, scan, target, files))
				: Effect.void;
		yield* put("codebase", report.codebase);
		yield* put("site", report.site);
		return { codebase, site } satisfies Summaries;
	});

const NO_REPORTS: Summaries = { codebase: null, site: null };

const runningScan = (req: BadgeRequest, id: ScanId) =>
	Effect.gen(function* () {
		const scan = yield* promise(() => findScan(req.env.BADGES, id));
		if (scan?.status !== "running")
			return yield* new NotFound({ message: "No running scan with this id." });
		return scan;
	});

export const report = (req: BadgeRequest, id: ScanId, body: JobReport) =>
	Effect.gen(function* () {
		const scan = yield* runningScan(req, id);
		const ok = body.status === "ok";
		const summaries = ok ? yield* storeReports(req, scan, body) : NO_REPORTS;
		// An ok scan may carry a note, such as why the site wasn't scanned.
		const error = body.error ?? (ok ? null : "scan failed");
		yield* promise(() =>
			finishScan(req.env.BADGES, {
				scan,
				status: body.status,
				commit: body.commit ?? null,
				openauditVersion: body.openauditVersion ?? null,
				...summaries,
				error: error?.slice(0, MAX_ERROR_LENGTH) ?? null,
				now: req.now,
			}),
		);
		yield* promise(() =>
			pruneScans(req.env.BADGES, req.env.BADGE_REPORTS, scan.project_id),
		);
	});
