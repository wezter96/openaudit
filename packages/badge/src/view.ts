/**
 * What a badge shows for a project: its state, plus the scans behind it.
 * Shared by the badge, the card and the verification page.
 */
import type { ProjectState, ScanSummary, TargetSummary } from "./api";

/** Unix seconds. */
export type UnixSeconds = number;

/** A scan older than this shows grey. */
export const STALE_AFTER: UnixSeconds = 14 * 24 * 60 * 60;

export type BadgeState =
	| "pending"
	| "ok"
	| "stale"
	| "failed"
	| "removed"
	| "notfound";

export interface BadgeView {
	readonly state: BadgeState;
	readonly project?: ProjectState;
	/** The newest successful scan, if any. */
	readonly scan?: ScanSummary;
}

const isStale = (scan: ScanSummary, now: UnixSeconds) =>
	now - scan.finishedAt > STALE_AFTER;

/** The newest finished scan failed after the newest good one. */
const lastFailed = (project: ProjectState) =>
	project.lastScan?.status === "failed";

const stateOf = (project: ProjectState, now: UnixSeconds): BadgeState => {
	if (lastFailed(project)) return "failed";
	const scan = project.latest;
	if (!scan) return "pending";
	return isStale(scan, now) ? "stale" : "ok";
};

/** The view of a project, or of a missing or removed one. */
export const viewOf = (
	project: ProjectState | "removed" | undefined,
	now: UnixSeconds,
): BadgeView => {
	if (project === undefined) return { state: "notfound" };
	if (project === "removed") return { state: "removed" };
	return {
		state: stateOf(project, now),
		project,
		...(project.latest ? { scan: project.latest } : {}),
	};
};

/** The score the badge leads with: the codebase's, else the site's. */
export const headline = (view: BadgeView): TargetSummary | undefined =>
	view.scan?.codebase ?? view.scan?.site ?? undefined;
