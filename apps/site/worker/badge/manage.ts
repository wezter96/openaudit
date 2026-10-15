/** The per-project endpoints: verify, get, rescan and remove. */
import {
	ManageToken,
	NotFound,
	type ProjectId,
	RateLimited,
	Unauthorized,
	type VerifyResult,
} from "@openaudit/badge";
import { Effect, Redacted } from "effect";
import { constantTimeEqual, sha256 } from "./crypto";
import type { BadgeRequest } from "./env";
import { deleteAllScans, finishedScans } from "./scans";
import {
	findProject,
	markRemoved,
	type ProjectRow,
	queueRescan,
	saveVerification,
	stateOf,
} from "./store";
import { repoHasCode, siteHasCode } from "./verify";

/** Ownership checks run at most this often per project. */
const CHECK_EVERY = 10;

const promise = <A>(run: () => Promise<A>) => Effect.promise(run);

const notFound = () => new NotFound({ message: "No badge with this id." });

/** A pending or active project. */
const liveProject = (req: BadgeRequest, id: ProjectId) =>
	Effect.gen(function* () {
		const row = yield* promise(() => findProject(req.env.BADGES, id));
		if (!row || row.status === "removed") return yield* notFound();
		return row;
	});

const resultOf = (row: ProjectRow): VerifyResult => ({
	status: row.status === "active" ? "active" : "pending",
	repoVerified: row.repo_verified === 1,
	siteVerified: row.site_verified === 1,
});

const recentlyChecked = (row: ProjectRow, now: number) =>
	row.checked_at !== null && now - row.checked_at < CHECK_EVERY;

const checkSite = async (row: ProjectRow) => {
	if (!row.site) return false;
	return row.site_verified === 1 || siteHasCode(row.site, row.code);
};

const check = async (row: ProjectRow) => ({
	repo: row.repo_verified === 1 || (await repoHasCode(row.repo, row.code)),
	site: await checkSite(row),
});

/** A SHA-256 in hex; a tombstone's empty hash never matches anything. */
const HASH = /^[0-9a-f]{64}$/;
/** Manage tokens are `oam_` plus 43 base64url characters. */
const TOKEN = /^oam_[A-Za-z0-9_-]{43}$/;

const wrongToken = () => new Unauthorized({ message: "Wrong manage token." });

/**
 * The live project, when the bearer token hashes to the row's current hash.
 * Removed rows are refused before any hashing, and every write that follows
 * repeats the hash in its WHERE, so a token from before a replace or removal
 * can't act even in a race.
 */
const authorised = (req: BadgeRequest, id: ProjectId) =>
	Effect.gen(function* () {
		const token = Redacted.value(yield* ManageToken);
		const row = yield* liveProject(req, id);
		if (!TOKEN.test(token)) return yield* wrongToken();
		if (!HASH.test(row.manage_hash ?? "")) return yield* wrongToken();
		const hash = yield* promise(() => sha256(token));
		if (!constantTimeEqual(hash, row.manage_hash)) return yield* wrongToken();
		return row;
	});

/** Only the registrant, with the manage token, can ask for a check. */
export const verify = (req: BadgeRequest, id: ProjectId) =>
	Effect.gen(function* () {
		const row = yield* authorised(req, id);
		if (recentlyChecked(row, req.now)) return resultOf(row);
		const verified = yield* promise(() => check(row));
		const saved = yield* promise(() =>
			saveVerification(req.env.BADGES, row, verified, req.now),
		);
		if (!saved) return yield* wrongToken();
		const activates = verified.repo && row.status === "pending";
		return {
			status: activates ? "active" : resultOf(row).status,
			repoVerified: verified.repo,
			siteVerified: verified.site,
		} satisfies VerifyResult;
	});

export const getState = (req: BadgeRequest, id: ProjectId) =>
	Effect.gen(function* () {
		const row = yield* liveProject(req, id);
		const scans = yield* promise(() => finishedScans(req.env.BADGES, id));
		return stateOf(row, scans);
	});

export const rescan = (req: BadgeRequest, id: ProjectId) =>
	Effect.gen(function* () {
		const row = yield* authorised(req, id);
		// A pending project has nothing to scan yet; it doesn't use up the day.
		if (row.status !== "active") return;
		if (!(yield* promise(() => queueRescan(req.env.BADGES, row, req.now))))
			return yield* new RateLimited({
				message: "One manual rescan a day. Try again tomorrow.",
			});
	});

/** Tombstones the row first, so the scans go only once removal has won. */
export const remove = (req: BadgeRequest, id: ProjectId) =>
	Effect.gen(function* () {
		const row = yield* authorised(req, id);
		if (!(yield* promise(() => markRemoved(req.env.BADGES, row))))
			return yield* wrongToken();
		yield* promise(() =>
			deleteAllScans(req.env.BADGES, req.env.BADGE_REPORTS, id),
		);
	});
