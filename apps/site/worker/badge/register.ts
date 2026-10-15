/** `POST /api/badges`: checks the repo and site, then stores a pending project. */
import {
	AlreadyRegistered,
	Full,
	InvalidInput,
	type ProjectId,
	RateLimited,
	type RegisterPayload,
	type Registration,
	RepoNotFound,
	type RepoSlug,
	RepoTooLarge,
	type SiteUrl,
	Unavailable,
} from "@openaudit/badge";
import { Effect } from "effect";
import { ipDayHash, newCode, newManageToken, sha256 } from "./crypto";
import type { BadgeRequest } from "./env";
import { parseRepo, parseSite, slugOf } from "./input";
import { deleteAllScans } from "./scans";
import {
	claimRegistration,
	expirePending,
	findByRepo,
	idTaken,
	liveProjects,
	MAX_PROJECTS,
	replaceable,
	upsertProject,
} from "./store";
import { dnsNameOf, lookupRepo, MAX_REPO_KB } from "./verify";

const promise = <A>(run: () => Promise<A>) => Effect.promise(run);

const parseInput = (payload: RegisterPayload) =>
	Effect.gen(function* () {
		const repo = parseRepo(payload.repo);
		if (!repo)
			return yield* new InvalidInput({
				message: "Give the repo as owner/name, like openaudit/openaudit.",
			});
		const site = payload.site?.trim() ? parseSite(payload.site) : null;
		if (site === undefined)
			return yield* new InvalidInput({
				message:
					"The site must be a public https:// address with no port or login.",
			});
		return { repo, site };
	});

const ipKey = (req: BadgeRequest) =>
	ipDayHash(
		req.ip,
		new Date(req.now * 1000).toISOString().slice(0, 10),
		req.env.SCANNER_TOKEN ?? "",
	);

/** One attempt per call, at most MAX_REGISTRATIONS a day per address. */
const checkLimits = (req: BadgeRequest) =>
	Effect.gen(function* () {
		if (req.ip === "")
			return yield* new InvalidInput({
				message: "We couldn't tell where your request came from.",
			});
		const db = req.env.BADGES;
		const ipDay = yield* promise(() => ipKey(req));
		if (!(yield* promise(() => claimRegistration(db, ipDay, req.now))))
			return yield* new RateLimited({
				message: "Too many sign-ups from your network today. Try tomorrow.",
			});
		yield* promise(() => expirePending(db, req.now));
		if ((yield* promise(() => liveProjects(db))) >= MAX_PROJECTS)
			return yield* full();
		return ipDay;
	});

const full = () =>
	new Full({ message: "The beta is full right now. Try again later." });

const taken = () =>
	new AlreadyRegistered({ message: "This repo already has a badge." });

/**
 * The id to write: the replaced row's own, or a free one. Refuses a live
 * duplicate early too, before GitHub is asked; the write itself re-checks.
 */
const targetId = (req: BadgeRequest, repo: RepoSlug) =>
	Effect.gen(function* () {
		const existing = yield* promise(() => findByRepo(req.env.BADGES, repo));
		if (!existing) return { id: yield* freeId(req, repo), replaces: false };
		if (!replaceable(existing, req.now)) return yield* taken();
		return { id: existing.id, replaces: true };
	});

const checkGitHub = (repo: RepoSlug) =>
	Effect.gen(function* () {
		const found = yield* promise(() => lookupRepo(repo));
		if (found.kind === "unavailable")
			return yield* new Unavailable({
				message: "GitHub didn't answer. Try again in a minute.",
			});
		if (found.kind === "missing")
			return yield* new RepoNotFound({
				message: "That repo doesn't exist or isn't public.",
			});
		if (found.sizeKb > MAX_REPO_KB)
			return yield* new RepoTooLarge({
				message: "Repos over 500 MB can't get a badge during the beta.",
			});
		return found.repo;
	});

/** The repo's slug, or the slug with `-2`, `-3`... when taken. */
const freeId = (req: BadgeRequest, repo: RepoSlug) =>
	Effect.gen(function* () {
		const base = slugOf(repo) || "project";
		for (let n = 1; n < 100; n++) {
			const id: ProjectId = n === 1 ? base : `${base}-${n}`;
			if (!(yield* promise(() => idTaken(req.env.BADGES, id)))) return id;
		}
		return yield* Effect.die("no free project id");
	});

interface Store {
	readonly req: BadgeRequest;
	readonly repo: RepoSlug;
	readonly site: SiteUrl | null;
	readonly ipDay: string;
}

/** Why the conditional write didn't land: a live duplicate, or the cap. */
const lost = (req: BadgeRequest, repo: RepoSlug) =>
	Effect.gen(function* () {
		const db = req.env.BADGES;
		if (yield* promise(() => findByRepo(db, repo))) return yield* taken();
		if ((yield* promise(() => liveProjects(db))) >= MAX_PROJECTS)
			return yield* full();
		return yield* new Unavailable({
			message: "Another sign-up got in the way. Try again.",
		});
	});

/**
 * Writes the project in one conditional statement, then reads it back: the
 * write won only if the row now holds this sign-up's token hash.
 */
const store = ({ req, repo, site, ipDay }: Store) =>
	Effect.gen(function* () {
		const db = req.env.BADGES;
		const { id, replaces } = yield* targetId(req, repo);
		const code = newCode();
		const manageToken = newManageToken();
		const manageHash = yield* promise(() => sha256(manageToken));
		const project = { id, repo, site, code, manageHash, ipDay, now: req.now };
		yield* Effect.tryPromise(() => upsertProject(db, project)).pipe(
			Effect.catch(() => Effect.void),
		);
		const row = yield* promise(() => findByRepo(db, repo));
		if (row?.manage_hash !== manageHash) return yield* lost(req, repo);
		if (replaces)
			yield* promise(() => deleteAllScans(db, req.env.BADGE_REPORTS, row.id));
		return { id: row.id, code, manageToken };
	});

export const register = (req: BadgeRequest, payload: RegisterPayload) =>
	Effect.gen(function* () {
		const input = yield* parseInput(payload);
		const ipDay = yield* checkLimits(req);
		yield* targetId(req, input.repo);
		const repo = yield* checkGitHub(input.repo);
		const saved = yield* store({ req, repo, site: input.site, ipDay });
		return {
			id: saved.id,
			repo,
			site: input.site,
			verification: {
				code: saved.code,
				repoFile: ".openaudit-badge",
				siteFile: "/.well-known/openaudit-badge.txt",
				dnsName: input.site ? dnsNameOf(input.site) : null,
			},
			manageToken: saved.manageToken,
		} satisfies Registration;
	});
