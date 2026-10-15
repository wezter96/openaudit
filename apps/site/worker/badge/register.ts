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
	DAY,
	deleteTombstone,
	expirePending,
	findByRepo,
	idTaken,
	insertProject,
	liveProjects,
	MAX_PROJECTS,
	MAX_REGISTRATIONS,
	registrationsSince,
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

const checkLimits = (req: BadgeRequest, ipDay: string) =>
	Effect.gen(function* () {
		const db = req.env.BADGES;
		const recent = yield* promise(() =>
			registrationsSince(db, ipDay, req.now - DAY),
		);
		if (recent >= MAX_REGISTRATIONS)
			return yield* new RateLimited({
				message: "Too many sign-ups from your network today. Try tomorrow.",
			});
		yield* promise(() => expirePending(db, req.now));
		if ((yield* promise(() => liveProjects(db))) >= MAX_PROJECTS)
			return yield* new Full({
				message: "The beta is full right now. Try again later.",
			});
	});

/** Refuses a live duplicate; clears a removed one so it can come back. */
const checkDuplicate = (req: BadgeRequest, repo: RepoSlug) =>
	Effect.gen(function* () {
		const existing = yield* promise(() => findByRepo(req.env.BADGES, repo));
		if (existing?.status !== "removed") {
			if (existing)
				return yield* new AlreadyRegistered({
					message: "This repo already has a badge.",
				});
			return;
		}
		yield* promise(() =>
			deleteAllScans(req.env.BADGES, req.env.BADGE_REPORTS, existing.id),
		);
		yield* promise(() => deleteTombstone(req.env.BADGES, existing.id));
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

const store = (req: BadgeRequest, repo: RepoSlug, site: SiteUrl | null) =>
	Effect.gen(function* () {
		const id = yield* freeId(req, repo);
		const code = newCode();
		const manageToken = newManageToken();
		const manageHash = yield* promise(() => sha256(manageToken));
		const ipDay = yield* promise(() => ipKey(req));
		const project = { id, repo, site, code, manageHash, ipDay, now: req.now };
		yield* Effect.tryPromise(() => insertProject(req.env.BADGES, project)).pipe(
			Effect.catch(() =>
				Effect.fail(
					new AlreadyRegistered({ message: "This repo already has a badge." }),
				),
			),
		);
		return { id, code, manageToken };
	});

export const register = (req: BadgeRequest, payload: RegisterPayload) =>
	Effect.gen(function* () {
		const input = yield* parseInput(payload);
		yield* checkLimits(req, yield* promise(() => ipKey(req)));
		yield* checkDuplicate(req, input.repo);
		const repo = yield* checkGitHub(input.repo);
		if (repo.toLowerCase() !== input.repo.toLowerCase())
			yield* checkDuplicate(req, repo);
		const saved = yield* store(req, repo, input.site);
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
