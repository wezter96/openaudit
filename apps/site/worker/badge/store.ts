/** D1 queries for projects and registrations (schema.sql). */
import type {
	ProjectId,
	ProjectState,
	RepoSlug,
	ScanSummary,
	SiteUrl,
	VerificationCode,
} from "@openaudit/badge";
import type { D1, Seconds } from "./env";

export interface ProjectRow {
	readonly id: ProjectId;
	readonly repo: RepoSlug;
	readonly site: SiteUrl | null;
	readonly code: VerificationCode;
	readonly manage_hash: string;
	readonly status: "pending" | "active" | "removed";
	readonly repo_verified: number;
	readonly site_verified: number;
	readonly created_at: Seconds;
	readonly next_scan_at: Seconds | null;
	readonly last_rescan_at: Seconds | null;
	readonly checked_at: Seconds | null;
}

/** What registration writes; the rest starts empty. */
export interface NewProject {
	readonly id: ProjectId;
	readonly repo: RepoSlug;
	readonly site: SiteUrl | null;
	readonly code: VerificationCode;
	readonly manageHash: string;
	readonly ipDay: string;
	readonly now: Seconds;
}

/** A daily-salted IP hash. */
export type IpDay = string;

export const DAY: Seconds = 24 * 60 * 60;
/** At most this many pending or active projects during the beta. */
export const MAX_PROJECTS = 100;
/** Registrations per IP per day. */
export const MAX_REGISTRATIONS = 5;

export const findProject = (db: D1, id: ProjectId) =>
	db
		.prepare("SELECT * FROM projects WHERE id = ?")
		.bind(id)
		.first<ProjectRow>();

export const findByRepo = (db: D1, repo: RepoSlug) =>
	db
		.prepare("SELECT * FROM projects WHERE repo = ?")
		.bind(repo)
		.first<ProjectRow>();

const count = async (db: D1, sql: string, ...values: ReadonlyArray<unknown>) =>
	(
		await db
			.prepare(sql)
			.bind(...values)
			.first<{ n: number }>()
	)?.n ?? 0;

export const liveProjects = (db: D1) =>
	count(db, "SELECT count(*) AS n FROM projects WHERE status != 'removed'");

export const registrationsSince = (db: D1, ipDay: IpDay, since: Seconds) =>
	count(
		db,
		"SELECT count(*) AS n FROM registrations WHERE ip_day_hash = ? AND created_at > ?",
		ipDay,
		since,
	);

/** True when any row, live or removed, already has the id. */
export const idTaken = async (db: D1, id: ProjectId) =>
	(await findProject(db, id)) !== null;

/** Pending projects that never verified free their slot after a week. */
export const PENDING_FOR: Seconds = 7 * DAY;

export const expirePending = (db: D1, now: Seconds) =>
	db
		.prepare("DELETE FROM projects WHERE status = 'pending' AND created_at < ?")
		.bind(now - PENDING_FOR)
		.run();

/** Inserts the project and its registration; drops day-old registrations. */
export const insertProject = (db: D1, p: NewProject) =>
	db.batch([
		db
			.prepare(
				"INSERT INTO projects (id, repo, site, code, manage_hash, status, created_at, ip_day) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)",
			)
			.bind(p.id, p.repo, p.site, p.code, p.manageHash, p.now, p.ipDay),
		db
			.prepare(
				"INSERT INTO registrations (ip_day_hash, created_at) VALUES (?, ?)",
			)
			.bind(p.ipDay, p.now),
		db
			.prepare("DELETE FROM registrations WHERE created_at < ?")
			.bind(p.now - 2 * DAY),
	]);

/** Deletes a removed project's tombstone so its repo can register again. */
export const deleteTombstone = (db: D1, id: ProjectId) =>
	db
		.prepare("DELETE FROM projects WHERE id = ? AND status = 'removed'")
		.bind(id)
		.run();

export interface Verified {
	readonly repo: boolean;
	readonly site: boolean;
}

/** Records a check; the first verified repo makes the project due now. */
export const saveVerification = (
	db: D1,
	project: ProjectRow,
	verified: Verified,
	now: Seconds,
) => {
	const activates = verified.repo && project.status === "pending";
	return db
		.prepare(
			"UPDATE projects SET repo_verified = ?, site_verified = ?, checked_at = ?, status = ?, next_scan_at = ? WHERE id = ?",
		)
		.bind(
			verified.repo ? 1 : 0,
			verified.site ? 1 : 0,
			now,
			activates ? "active" : project.status,
			activates ? now : project.next_scan_at,
			project.id,
		)
		.run();
};

export const queueRescan = (db: D1, id: ProjectId, now: Seconds) =>
	db
		.prepare(
			"UPDATE projects SET next_scan_at = ?, last_rescan_at = ? WHERE id = ?",
		)
		.bind(now, now, id)
		.run();

/** Leaves a tombstone: no code, token, site or verification. */
export const markRemoved = (db: D1, id: ProjectId) =>
	db
		.prepare(
			"UPDATE projects SET status = 'removed', site = NULL, code = '', manage_hash = '', repo_verified = 0, site_verified = 0, next_scan_at = NULL, last_rescan_at = NULL, checked_at = NULL, ip_day = NULL WHERE id = ?",
		)
		.bind(id)
		.run();

/** The public state of a live project. */
export const stateOf = (
	row: ProjectRow,
	scans: ReadonlyArray<ScanSummary>,
): ProjectState => {
	const latest = scans.find((s) => s.status === "ok");
	const lastScan = scans[0];
	return {
		id: row.id,
		repo: row.repo,
		site: row.site,
		status: row.status === "active" ? "active" : "pending",
		repoVerified: row.repo_verified === 1,
		siteVerified: row.site_verified === 1,
		nextScanAt: row.next_scan_at,
		...(latest ? { latest } : {}),
		...(lastScan ? { lastScan } : {}),
	};
};
