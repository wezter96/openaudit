/** D1 queries for scans, and where their reports live in R2. */
import type {
	ProjectId,
	ScanId,
	ScanSummary,
	TargetSummary,
} from "@openaudit/badge";
import type { D1, R2, Seconds } from "./env";
import { DAY, type ProjectRow } from "./store";

export interface ScanRow {
	readonly id: ScanId;
	readonly project_id: ProjectId;
	readonly status: "running" | "ok" | "failed";
	readonly started_at: Seconds;
	readonly finished_at: Seconds | null;
	readonly lease_until: Seconds | null;
	readonly commit_sha: string | null;
	readonly openaudit_version: string | null;
	readonly codebase_summary: string | null;
	readonly site_summary: string | null;
	readonly error: string | null;
}

/** How long the scanner may hold a job. */
export const LEASE: Seconds = 30 * 60;
/** Time between scheduled scans. */
export const INTERVAL: Seconds = 7 * DAY;
/** Finished scans kept per project. */
export const KEEP = 5;

export type ReportFile =
	| "codebase.json"
	| "codebase.html"
	| "site.json"
	| "site.html";

const FILES: ReadonlyArray<ReportFile> = [
	"codebase.json",
	"codebase.html",
	"site.json",
	"site.html",
];

export const reportKey = (project: ProjectId, scan: ScanId, file: ReportFile) =>
	`${project}/${scan}/${file}`;

const parseSummary = (text: string | null): TargetSummary | null =>
	text ? (JSON.parse(text) as TargetSummary) : null;

export const toSummary = (row: ScanRow): ScanSummary => ({
	id: row.id,
	status: row.status === "ok" ? "ok" : "failed",
	startedAt: row.started_at,
	finishedAt: row.finished_at ?? row.started_at,
	commit: row.commit_sha,
	openauditVersion: row.openaudit_version,
	codebase: parseSummary(row.codebase_summary),
	site: parseSummary(row.site_summary),
	error: row.error,
});

/** The newest finished scans, newest first. */
export const finishedScans = async (db: D1, project: ProjectId) => {
	const { results } = await db
		.prepare(
			"SELECT * FROM scans WHERE project_id = ? AND status != 'running' ORDER BY started_at DESC LIMIT ?",
		)
		.bind(project, KEEP)
		.all<ScanRow>();
	return results.map(toSummary);
};

export const findScan = (db: D1, scan: ScanId) =>
	db.prepare("SELECT * FROM scans WHERE id = ?").bind(scan).first<ScanRow>();

/** Running scans past their lease fail, so their projects can be claimed. */
export const expireLeases = (db: D1, now: Seconds) =>
	db
		.prepare(
			"UPDATE scans SET status = 'failed', error = 'scan timed out', finished_at = ? WHERE status = 'running' AND lease_until < ?",
		)
		.bind(now, now)
		.run();

/** The active project that has waited longest, with no scan running. */
export const dueProject = (db: D1, now: Seconds) =>
	db
		.prepare(
			"SELECT * FROM projects p WHERE p.status = 'active' AND p.next_scan_at <= ? AND NOT EXISTS (SELECT 1 FROM scans s WHERE s.project_id = p.id AND s.status = 'running') ORDER BY p.next_scan_at LIMIT 1",
		)
		.bind(now)
		.first<ProjectRow>();

/** Starts a scan unless one is already running; true when it started. */
export const startScan = async (
	db: D1,
	project: ProjectId,
	scan: ScanId,
	now: Seconds,
) => {
	const result = await db
		.prepare(
			"INSERT INTO scans (id, project_id, status, started_at, lease_until) SELECT ?, ?, 'running', ?, ? WHERE NOT EXISTS (SELECT 1 FROM scans WHERE project_id = ? AND status = 'running')",
		)
		.bind(scan, project, now, now + LEASE, project)
		.run();
	return result.meta.changes === 1;
};

export interface FinishedScan {
	readonly scan: ScanRow;
	readonly status: "ok" | "failed";
	readonly commit: string | null;
	readonly openauditVersion: string | null;
	readonly codebase: TargetSummary | null;
	readonly site: TargetSummary | null;
	readonly error: string | null;
	readonly now: Seconds;
}

const json = (summary: TargetSummary | null) =>
	summary ? JSON.stringify(summary) : null;

/** Marks the scan done and schedules the next one. */
export const finishScan = (db: D1, f: FinishedScan) =>
	db.batch([
		db
			.prepare(
				"UPDATE scans SET status = ?, finished_at = ?, lease_until = NULL, commit_sha = ?, openaudit_version = ?, codebase_summary = ?, site_summary = ?, error = ? WHERE id = ?",
			)
			.bind(
				f.status,
				f.now,
				f.commit,
				f.openauditVersion,
				json(f.codebase),
				json(f.site),
				f.error,
				f.scan.id,
			),
		db
			.prepare("UPDATE projects SET next_scan_at = ? WHERE id = ?")
			.bind(f.now + INTERVAL, f.scan.project_id),
	]);

/** Every R2 key a scan may have written. */
const keysOf = (project: ProjectId, scans: ReadonlyArray<ScanId>) =>
	scans.flatMap((scan) => FILES.map((file) => reportKey(project, scan, file)));

const deleteRows = async (
	db: D1,
	reports: R2,
	project: ProjectId,
	ids: ReadonlyArray<ScanId>,
) => {
	if (ids.length === 0) return;
	await reports.delete(keysOf(project, ids));
	await db.batch(
		ids.map((id) => db.prepare("DELETE FROM scans WHERE id = ?").bind(id)),
	);
};

const scanIds = async (db: D1, sql: string, project: ProjectId) => {
	const { results } = await db.prepare(sql).bind(project).all<{ id: ScanId }>();
	return results.map((r) => r.id);
};

/** Keeps the newest finished scans and deletes the rest with their reports. */
export const pruneScans = async (db: D1, reports: R2, project: ProjectId) =>
	deleteRows(
		db,
		reports,
		project,
		await scanIds(
			db,
			`SELECT id FROM scans WHERE project_id = ? AND status != 'running' ORDER BY started_at DESC LIMIT -1 OFFSET ${KEEP}`,
			project,
		),
	);

/** Deletes every scan of the project and its reports. */
export const deleteAllScans = async (db: D1, reports: R2, project: ProjectId) =>
	deleteRows(
		db,
		reports,
		project,
		await scanIds(db, "SELECT id FROM scans WHERE project_id = ?", project),
	);
