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

/**
 * Records a sign-up attempt unless the address already made
 * MAX_REGISTRATIONS today, in one statement so parallel requests can't
 * slip past the count. True when it was recorded.
 */
export const claimRegistration = async (db: D1, ipDay: IpDay, now: Seconds) => {
	const result = await db
		.prepare(
			"INSERT INTO registrations (ip_day_hash, created_at) SELECT ?, ? WHERE (SELECT count(*) FROM registrations WHERE ip_day_hash = ? AND created_at > ?) < ?",
		)
		.bind(ipDay, now, ipDay, now - DAY, MAX_REGISTRATIONS)
		.run();
	return result.meta.changes === 1;
};

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

/**
 * Inserts the project, or replaces a removed or stale unverified one with
 * the same repo, in one statement: an active or fresh pending project is
 * never touched, and the beta cap holds even under parallel sign-ups. The
 * caller reads the row back to learn whether its write won.
 */
export const upsertProject = (db: D1, p: NewProject) =>
	db
		.prepare(
			`INSERT INTO projects (id, repo, site, code, manage_hash, status, repo_verified, site_verified, created_at, next_scan_at, last_rescan_at, ip_day, checked_at)
			SELECT ?, ?, ?, ?, ?, 'pending', 0, 0, ?, NULL, NULL, ?, NULL
			WHERE (SELECT count(*) FROM projects WHERE status != 'removed') < ?
			ON CONFLICT (repo) DO UPDATE SET repo = excluded.repo, site = excluded.site, code = excluded.code, manage_hash = excluded.manage_hash, status = 'pending', repo_verified = 0, site_verified = 0, created_at = excluded.created_at, next_scan_at = NULL, last_rescan_at = NULL, ip_day = excluded.ip_day, checked_at = NULL
			WHERE projects.status = 'removed' OR (projects.status = 'pending' AND projects.created_at < ?)`,
		)
		.bind(
			p.id,
			p.repo,
			p.site,
			p.code,
			p.manageHash,
			p.now,
			p.ipDay,
			MAX_PROJECTS,
			p.now - PENDING_FOR,
		)
		.run();

/** A removed project, or an unverified one older than PENDING_FOR. */
export const replaceable = (row: ProjectRow, now: Seconds) => {
	if (row.status === "removed") return true;
	return row.status === "pending" && row.created_at < now - PENDING_FOR;
};

export interface Verified {
	readonly repo: boolean;
	readonly site: boolean;
}

/**
 * Records a check, only while the row still has this manage hash; the first
 * verified repo makes the project due now. True when it was written.
 */
export const saveVerification = async (
	db: D1,
	project: ProjectRow,
	verified: Verified,
	now: Seconds,
) => {
	const activates = verified.repo && project.status === "pending";
	const result = await db
		.prepare(
			"UPDATE projects SET repo_verified = ?, site_verified = ?, checked_at = ?, status = ?, next_scan_at = ? WHERE id = ? AND manage_hash = ? AND status != 'removed'",
		)
		.bind(
			verified.repo ? 1 : 0,
			verified.site ? 1 : 0,
			now,
			activates ? "active" : project.status,
			activates ? now : project.next_scan_at,
			project.id,
			project.manage_hash,
		)
		.run();
	return result.meta.changes === 1;
};

/**
 * Queues a manual rescan of an active project, at most once a day, as one
 * conditional write so parallel requests can't both get through.
 */
export const queueRescan = async (
	db: D1,
	project: ProjectRow,
	now: Seconds,
) => {
	const result = await db
		.prepare(
			"UPDATE projects SET next_scan_at = ?, last_rescan_at = ? WHERE id = ? AND manage_hash = ? AND status = 'active' AND (last_rescan_at IS NULL OR last_rescan_at <= ?)",
		)
		.bind(now, now, project.id, project.manage_hash, now - DAY)
		.run();
	return result.meta.changes === 1;
};

/**
 * Leaves a tombstone with no code, token hash, site or verification, only
 * while the row still has this manage hash. True when it was written.
 */
export const markRemoved = async (db: D1, project: ProjectRow) => {
	const result = await db
		.prepare(
			"UPDATE projects SET status = 'removed', site = NULL, code = '', manage_hash = '', repo_verified = 0, site_verified = 0, next_scan_at = NULL, last_rescan_at = NULL, checked_at = NULL, ip_day = NULL WHERE id = ? AND manage_hash = ? AND status != 'removed'",
		)
		.bind(project.id, project.manage_hash)
		.run();
	return result.meta.changes === 1;
};

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
