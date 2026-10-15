import { type AuditContext, AuditorError } from "@openaudit/core";
import { Effect } from "effect";

import { arr, str } from "../tool";
import type { Dependency, Ecosystem } from "./dependencies";
import { isRecord } from "./util";

/*
 * deps.dev (Google's Open Source Insights) for code.dependency-health: request
 * keys, response parsing, and batched lookups under a shared request budget.
 */

export const DEPS_DEV_API = "https://api.deps.dev";

/** deps.dev system per ecosystem. Packagist is not indexed by deps.dev. */
const SYSTEMS: Partial<Record<Ecosystem, string>> = {
	npm: "NPM",
	PyPI: "PYPI",
	Go: "GO",
	"crates.io": "CARGO",
	RubyGems: "RUBYGEMS",
};

/**
 * Systems where deps.dev's "deprecated" means the release was yanked: they
 * have no deprecation of their own.
 */
export const YANKING_SYSTEMS = new Set(["PYPI", "CARGO", "RUBYGEMS"]);

/** deps.dev pages batch answers at 100 entries, so larger chunks only resend bodies. */
const BATCH_SIZE = 100;
/** Guards against a server that keeps returning page tokens. */
const MAX_PAGES_PER_CHUNK = 20;

export const systemOf = (d: Dependency) => SYSTEMS[d.ecosystem];

/** deps.dev Go versions keep the `v` prefix that the go.mod parser drops. */
export const versionKeyOf = (d: Dependency) => ({
	system: systemOf(d) ?? "",
	name: d.name,
	version: d.ecosystem === "Go" ? `v${d.version}` : d.version,
});

export const keyOf = (k: { system: string; name: string; version: string }) =>
	`${k.system}|${k.name}|${k.version}`;

export const packageKeyOf = (d: Dependency) => `${systemOf(d)}|${d.name}`;

/* -------------------------------------------------------------------------- */
/*                                  Parsing                                   */
/* -------------------------------------------------------------------------- */

export interface VersionHealth {
	readonly publishedAt?: string;
	readonly isDefault: boolean;
	readonly isDeprecated: boolean;
	readonly deprecatedReason?: string;
	/** deps.dev project id of the source repository, e.g. `github.com/o/r`. */
	readonly sourceRepo?: string;
}

/** One page of a batch answer, keyed as the requests were. */
interface BatchPage<V> {
	readonly entries: Map<string, V>;
	/** Requests deps.dev answered, including ones it has no entry for. */
	readonly answered: Set<string>;
	readonly nextPageToken?: string;
}

type Response = Record<string, unknown>;

/** Reads the responses of a batch page with a key and a value reader per response. */
const parseBatch = <V>(
	json: unknown,
	keyOfResponse: (r: Response) => string | undefined,
	entryOf: (r: Response) => V | undefined,
): BatchPage<V> => {
	const entries = new Map<string, V>();
	const answered = new Set<string>();
	if (!isRecord(json)) return { entries, answered };
	for (const r of arr(json.responses)) {
		const key = isRecord(r) ? keyOfResponse(r) : undefined;
		if (!key) continue;
		answered.add(key);
		const value = entryOf(r as Response);
		if (value !== undefined) entries.set(key, value);
	}
	return {
		entries,
		answered,
		nextPageToken: str(json.nextPageToken) || undefined,
	};
};

/** The `SYSTEM|name|version` a `versionbatch` response answers. */
const requestedVersion = (r: Response): string | undefined => {
	const k = isRecord(r.request) ? r.request.versionKey : undefined;
	if (!isRecord(k)) return undefined;
	const parts = [str(k.system), str(k.name), str(k.version)];
	// The same key as `keyOf`, once every part is present.
	return parts.every(Boolean) ? parts.join("|") : undefined;
};

const isSourceRepo = (p: unknown) =>
	isRecord(p) &&
	p.relationType === "SOURCE_REPO" &&
	isRecord(p.projectKey) &&
	typeof p.projectKey.id === "string";

const sourceRepoOf = (v: Response): string | undefined => {
	const repo = arr(v.relatedProjects).find(isSourceRepo);
	return isRecord(repo) && isRecord(repo.projectKey)
		? str(repo.projectKey.id)
		: undefined;
};

const versionHealthOf = (r: Response): VersionHealth | undefined => {
	const v = r.version;
	if (!isRecord(v)) return undefined;
	return {
		publishedAt: str(v.publishedAt),
		isDefault: v.isDefault === true,
		isDeprecated: v.isDeprecated === true,
		deprecatedReason: str(v.deprecatedReason) || undefined,
		sourceRepo: sourceRepoOf(v),
	};
};

/** A `versionbatch` page: versions by `SYSTEM|name|version` as requested. */
export const parseVersionBatch = (
	json: unknown,
): {
	readonly versions: Map<string, VersionHealth>;
	/** Requests deps.dev answered, including packages it does not know. */
	readonly answered: Set<string>;
	readonly nextPageToken?: string;
} => {
	const { entries, ...page } = parseBatch(
		json,
		requestedVersion,
		versionHealthOf,
	);
	return { versions: entries, ...page };
};

export interface ProjectHealth {
	readonly archived: boolean;
	/** When Scorecard last looked at the repository. */
	readonly scorecardDate?: string;
}

const requestedProject = (r: Response): string | undefined =>
	isRecord(r.request) && isRecord(r.request.projectKey)
		? str(r.request.projectKey.id)
		: undefined;

const projectHealthOf = (r: Response): ProjectHealth | undefined => {
	if (!isRecord(r.project)) return undefined;
	const scorecard = isRecord(r.project.scorecard)
		? r.project.scorecard
		: undefined;
	const maintained = arr(scorecard?.checks).find(
		(c) => isRecord(c) && c.name === "Maintained",
	);
	const reason = isRecord(maintained) ? str(maintained.reason) : undefined;
	return {
		archived: reason !== undefined && /\bproject is archived\b/i.test(reason),
		scorecardDate: str(scorecard?.date),
	};
};

/**
 * A `projectbatch` page. deps.dev has no archived flag of its own; Scorecard's
 * Maintained check scores an archived repository 0 with this reason.
 */
export const parseProjectBatch = (
	json: unknown,
): {
	readonly projects: Map<string, ProjectHealth>;
	readonly answered: Set<string>;
	readonly nextPageToken?: string;
} => {
	const { entries, ...page } = parseBatch(
		json,
		requestedProject,
		projectHealthOf,
	);
	return { projects: entries, ...page };
};

export interface PackageHealth {
	/** The version the registry installs by default (npm `latest`). */
	readonly defaultVersion?: {
		readonly version: string;
		readonly isDeprecated: boolean;
	};
	/** The most recently published version, prereleases included. */
	readonly latest?: { readonly version: string; readonly publishedAt: string };
}

/** A version a `GetPackage` response lists, or nothing without a version. */
const listedVersion = (v: unknown) => {
	if (!isRecord(v) || !isRecord(v.versionKey)) return [];
	const version = str(v.versionKey.version);
	if (!version) return [];
	return [
		{
			version,
			isDefault: v.isDefault === true,
			isDeprecated: v.isDeprecated === true,
			publishedAt: str(v.publishedAt),
		},
	];
};

/** A valid publish date later than the newest one seen so far. */
const isNewer = (
	publishedAt: string | undefined,
	latest: PackageHealth["latest"],
): publishedAt is string => {
	if (!publishedAt || Number.isNaN(Date.parse(publishedAt))) return false;
	return !latest || Date.parse(publishedAt) > Date.parse(latest.publishedAt);
};

/** A `GetPackage` response, or undefined when it lists no versions. */
export const parsePackage = (json: unknown): PackageHealth | undefined => {
	if (!isRecord(json)) return undefined;
	const listed = arr(json.versions).flatMap(listedVersion);
	if (listed.length === 0) return undefined;
	let defaultVersion: PackageHealth["defaultVersion"];
	let latest: PackageHealth["latest"];
	for (const v of listed) {
		if (v.isDefault)
			defaultVersion = { version: v.version, isDeprecated: v.isDeprecated };
		if (isNewer(v.publishedAt, latest))
			latest = { version: v.version, publishedAt: v.publishedAt };
	}
	return { defaultVersion, latest };
};

/* -------------------------------------------------------------------------- */
/*                                  Lookups                                   */
/* -------------------------------------------------------------------------- */

type Http = AuditContext["http"];

export type Stage = "versions" | "projects" | "packages";

/** Request budget and failures shared by every lookup of one run. */
export interface Lookup {
	readonly http: Http;
	remaining: number;
	readonly skipped: Record<Stage, number>;
	readonly failures: string[];
}

const chunks = <A>(xs: ReadonlyArray<A>, size: number): A[][] => {
	const out: A[][] = [];
	for (let i = 0; i < xs.length; i += size) out.push(xs.slice(i, i + size));
	return out;
};

/** Takes one request from the budget, or returns false when it is spent. */
const spend = (lookup: Lookup): boolean => {
	if (lookup.remaining <= 0) return false;
	lookup.remaining--;
	return true;
};

const GET = { timeoutMs: 30_000, maxBytes: 20 * 1024 * 1024 };

const post = (body: unknown) => ({
	method: "POST",
	headers: { "content-type": "application/json" },
	body: JSON.stringify(body),
	timeoutMs: 60_000,
	maxBytes: 50 * 1024 * 1024,
});

/**
 * One deps.dev request. Resolves to the parsed JSON, or to undefined when the
 * request fails (recorded), so one bad response never fails the run.
 */
const call = (
	lookup: Lookup,
	url: string,
	body?: unknown,
): Effect.Effect<unknown> => {
	const path = url.replace(DEPS_DEV_API, "");
	return lookup.http(url, body === undefined ? GET : post(body)).pipe(
		Effect.flatMap((res) =>
			res.status === 200
				? Effect.try({
						try: () => JSON.parse(res.body) as unknown,
						catch: () =>
							new AuditorError({
								message: `deps.dev ${path} returned invalid JSON`,
							}),
					})
				: Effect.fail(
						new AuditorError({
							message: `deps.dev ${path} failed with HTTP ${res.status}`,
						}),
					),
		),
		Effect.match({
			onFailure: (e) => {
				lookup.failures.push(e.message);
				return undefined;
			},
			onSuccess: (json) => json,
		}),
	);
};

type Paged = {
	readonly answered: ReadonlySet<string>;
	readonly nextPageToken?: string;
};

/** A batch endpoint, what its requests are counted as, and its page parser. */
export interface BatchEndpoint<Page extends Paged> {
	readonly stage: Stage;
	readonly path: string;
	readonly parse: (json: unknown) => Page;
}

/** All pages of one chunk of requests, until the budget or the pages run out. */
const fetchChunk = <Page extends Paged>(
	lookup: Lookup,
	endpoint: BatchEndpoint<Page>,
	chunk: ReadonlyArray<unknown>,
): Effect.Effect<Page[]> =>
	Effect.gen(function* () {
		const pages: Page[] = [];
		let answered = 0;
		let pageToken: string | undefined;
		for (let i = 0; i < MAX_PAGES_PER_CHUNK; i++) {
			if (!spend(lookup)) {
				lookup.skipped[endpoint.stage] += chunk.length - answered;
				break;
			}
			const json = yield* call(
				lookup,
				`${DEPS_DEV_API}${endpoint.path}`,
				pageToken ? { requests: chunk, pageToken } : { requests: chunk },
			);
			if (json === undefined) break;
			const page = endpoint.parse(json);
			pages.push(page);
			answered += page.answered.size;
			if (!page.nextPageToken || page.nextPageToken === pageToken) break;
			pageToken = page.nextPageToken;
		}
		return pages;
	});

/** POSTs `requests` to a deps.dev batch endpoint in chunks, following page tokens. */
export const batch = <Page extends Paged>(
	lookup: Lookup,
	endpoint: BatchEndpoint<Page>,
	requests: ReadonlyArray<unknown>,
): Effect.Effect<Page[]> =>
	Effect.map(
		Effect.forEach(
			chunks(requests, BATCH_SIZE),
			(chunk) => fetchChunk(lookup, endpoint, chunk),
			{ concurrency: 4 },
		),
		(perChunk) => perChunk.flat(),
	);

export const fetchPackage = (
	lookup: Lookup,
	d: Dependency,
): Effect.Effect<PackageHealth | undefined> => {
	if (!spend(lookup)) {
		lookup.skipped.packages++;
		return Effect.succeed(undefined);
	}
	return Effect.map(
		call(
			lookup,
			`${DEPS_DEV_API}/v3/systems/${(systemOf(d) ?? "").toLowerCase()}/packages/${encodeURIComponent(d.name)}`,
		),
		(json) => (json === undefined ? undefined : parsePackage(json)),
	);
};
