import {
	type AuditContext,
	AuditorError,
	defineAuditor,
	type FindingInput,
	requireWorkspace,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, str } from "../tool";
import {
	DEP_FIELDS,
	type Dependency,
	dependencyLineFinder,
	type Ecosystem,
	isManifest,
	parseDependencies,
	uniqueDependencies,
} from "./dependencies";
import {
	baseName,
	cweUrl,
	isFixturePath,
	isRecord,
	owaspUrl,
	parseJsonc,
	readTextFiles,
	type SourceFile,
	truncate,
} from "./util";

/*
 * Deprecated, yanked, archived and stale dependencies, from deps.dev (Google's
 * Open Source Insights). One `versionbatch` call per 100 dependencies answers
 * deprecation and yanking for npm, PyPI, Go, Cargo and RubyGems (deps.dev
 * reports a yanked PyPI or Cargo release as deprecated, with the registry's
 * reason; RubyGems has no deprecation either, so it is read the same way), and one `projectbatch` call per 100 source repositories answers
 * whether a repository is archived (OpenSSF Scorecard's Maintained check).
 * Per-package `GetPackage` calls are made only where they change a finding:
 * the newest non-deprecated version for a deprecated or yanked release, and
 * the newest release date of an old direct dependency.
 */

export const DEPENDENCY_HEALTH_ID = "code.dependency-health";
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
const YANKING_SYSTEMS = new Set(["PYPI", "CARGO", "RUBYGEMS"]);

/** deps.dev pages batch answers at 100 entries, so larger chunks only resend bodies. */
const BATCH_SIZE = 100;
/** Guards against a server that keeps returning page tokens. */
const MAX_PAGES_PER_CHUNK = 20;
const YEAR_MS = 365.25 * 24 * 60 * 60 * 1000;

const systemOf = (d: Dependency) => SYSTEMS[d.ecosystem];

/** deps.dev Go versions keep the `v` prefix that the go.mod parser drops. */
const versionKeyOf = (d: Dependency) => ({
	system: systemOf(d) ?? "",
	name: d.name,
	version: d.ecosystem === "Go" ? `v${d.version}` : d.version,
});

const keyOf = (k: { system: string; name: string; version: string }) =>
	`${k.system}|${k.name}|${k.version}`;

const packageKeyOf = (d: Dependency) => `${systemOf(d)}|${d.name}`;

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

/** A `versionbatch` page: versions by `SYSTEM|name|version` as requested. */
export const parseVersionBatch = (
	json: unknown,
): {
	readonly versions: Map<string, VersionHealth>;
	/** Requests deps.dev answered, including packages it does not know. */
	readonly answered: Set<string>;
	readonly nextPageToken?: string;
} => {
	const versions = new Map<string, VersionHealth>();
	const answered = new Set<string>();
	if (!isRecord(json)) return { versions, answered };
	for (const r of arr(json.responses)) {
		if (!isRecord(r) || !isRecord(r.request)) continue;
		const k = r.request.versionKey;
		if (!isRecord(k)) continue;
		const system = str(k.system);
		const name = str(k.name);
		const version = str(k.version);
		if (!system || !name || !version) continue;
		const key = keyOf({ system, name, version });
		answered.add(key);
		const v = r.version;
		if (!isRecord(v)) continue;
		const repo = arr(v.relatedProjects).find(
			(p) =>
				isRecord(p) &&
				p.relationType === "SOURCE_REPO" &&
				isRecord(p.projectKey) &&
				typeof p.projectKey.id === "string",
		);
		versions.set(key, {
			publishedAt: str(v.publishedAt),
			isDefault: v.isDefault === true,
			isDeprecated: v.isDeprecated === true,
			deprecatedReason: str(v.deprecatedReason) || undefined,
			sourceRepo:
				isRecord(repo) && isRecord(repo.projectKey)
					? str(repo.projectKey.id)
					: undefined,
		});
	}
	return {
		versions,
		answered,
		nextPageToken: str(json.nextPageToken) || undefined,
	};
};

export interface ProjectHealth {
	readonly archived: boolean;
	/** When Scorecard last looked at the repository. */
	readonly scorecardDate?: string;
}

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
	const projects = new Map<string, ProjectHealth>();
	const answered = new Set<string>();
	if (!isRecord(json)) return { projects, answered };
	for (const r of arr(json.responses)) {
		if (!isRecord(r) || !isRecord(r.request)) continue;
		const id = isRecord(r.request.projectKey)
			? str(r.request.projectKey.id)
			: undefined;
		if (!id) continue;
		answered.add(id);
		if (!isRecord(r.project)) continue;
		const scorecard = isRecord(r.project.scorecard)
			? r.project.scorecard
			: undefined;
		const maintained = arr(scorecard?.checks).find(
			(c) => isRecord(c) && c.name === "Maintained",
		);
		const reason = isRecord(maintained) ? str(maintained.reason) : undefined;
		projects.set(id, {
			archived: reason !== undefined && /\bproject is archived\b/i.test(reason),
			scorecardDate: str(scorecard?.date),
		});
	}
	return {
		projects,
		answered,
		nextPageToken: str(json.nextPageToken) || undefined,
	};
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

/** A `GetPackage` response, or undefined when it lists no versions. */
export const parsePackage = (json: unknown): PackageHealth | undefined => {
	if (!isRecord(json)) return undefined;
	let defaultVersion: PackageHealth["defaultVersion"];
	let latest: PackageHealth["latest"];
	let any = false;
	for (const v of arr(json.versions)) {
		if (!isRecord(v) || !isRecord(v.versionKey)) continue;
		const version = str(v.versionKey.version);
		if (!version) continue;
		any = true;
		if (v.isDefault === true)
			defaultVersion = { version, isDeprecated: v.isDeprecated === true };
		const publishedAt = str(v.publishedAt);
		if (
			publishedAt &&
			!Number.isNaN(Date.parse(publishedAt)) &&
			(!latest || Date.parse(publishedAt) > Date.parse(latest.publishedAt))
		)
			latest = { version, publishedAt };
	}
	return any ? { defaultVersion, latest } : undefined;
};

/* -------------------------------------------------------------------------- */
/*                           Direct (declared) dependencies                   */
/* -------------------------------------------------------------------------- */

/** Name as the registry compares it (PEP 503 for PyPI, `-`/`_` for crates). */
const normalizeName = (ecosystem: Ecosystem, name: string): string =>
	ecosystem === "PyPI"
		? name.toLowerCase().replace(/[-_.]+/g, "-")
		: ecosystem === "crates.io"
			? name.toLowerCase().replace(/_/g, "-")
			: name;

const directKey = (ecosystem: Ecosystem, name: string) =>
	`${ecosystem}|${normalizeName(ecosystem, name)}`;

const REQUIREMENT_NAME = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)/;

const packageJsonNames = (text: string): string[] => {
	const json = parseJsonc(text);
	if (!isRecord(json)) return [];
	return DEP_FIELDS.flatMap((field) => {
		const deps = json[field];
		return isRecord(deps) ? Object.keys(deps) : [];
	});
};

const goModNames = (text: string): string[] => {
	const names: string[] = [];
	let inBlock = false;
	for (const raw of text.split("\n")) {
		const line = raw.trim();
		if (/^require\s*\($/.test(line)) inBlock = true;
		else if (inBlock && line === ")") inBlock = false;
		else if (inBlock || /^require\s+/.test(line)) {
			if (/\/\/\s*indirect\b/.test(line)) continue;
			const m = /^(?:require\s+)?(\S+)\s+v\S+/.exec(line);
			if (m?.[1] && !m[1].startsWith("//")) names.push(m[1]);
		}
	}
	return names;
};

/** `[dependencies]`-like tables of a Cargo.toml, including target and workspace ones. */
const cargoTomlNames = (text: string): string[] => {
	const names: string[] = [];
	let inDeps = false;
	for (const raw of text.split("\n")) {
		const line = raw.replace(/#.*$/, "").trim();
		const header = /^\[([^[\]]+)\]$/.exec(line)?.[1]?.trim();
		if (header !== undefined) {
			const table = /(?:^|\.)(?:dev-|build-)?dependencies\.([\w-]+)$/.exec(
				header,
			);
			if (table?.[1]) names.push(table[1]);
			inDeps = !table && /(?:^|\.)(?:dev-|build-)?dependencies$/.test(header);
			continue;
		}
		const m = inDeps ? /^([\w-]+)\s*=/.exec(line) : null;
		if (m?.[1]) names.push(m[1]);
	}
	return names;
};

/** PEP 621/735 dependency arrays and Poetry dependency tables. */
const pyprojectNames = (text: string): string[] => {
	const names: string[] = [];
	let section = "";
	let inArray = false;
	const addQuoted = (line: string) => {
		for (const m of line.matchAll(/["']([^"']+)["']/g)) {
			const name = m[1] ? REQUIREMENT_NAME.exec(m[1])?.[1] : undefined;
			if (name) names.push(name);
		}
	};
	for (const raw of text.split("\n")) {
		const line = raw.replace(/\s#.*$/, "").trim();
		if (inArray) {
			addQuoted(line.replace(/\].*$/, ""));
			if (line.includes("]")) inArray = false;
			continue;
		}
		const header = /^\[([^[\]]+)\]$/.exec(line)?.[1]?.trim();
		if (header !== undefined) {
			section = header;
			continue;
		}
		const poetry =
			/^tool\.poetry\.(?:(?:dev-)?dependencies|group\.[\w-]+\.dependencies)$/.test(
				section,
			);
		if (poetry) {
			const key = /^([A-Za-z0-9][\w.-]*)\s*=/.exec(line)?.[1];
			if (key && key.toLowerCase() !== "python") names.push(key);
			continue;
		}
		const isArray =
			(section === "project" && /^dependencies\s*=\s*\[/.test(line)) ||
			((section === "project.optional-dependencies" ||
				section === "dependency-groups") &&
				/^[\w.-]+\s*=\s*\[/.test(line));
		if (!isArray) continue;
		const rest = line.slice(line.indexOf("[") + 1);
		addQuoted(rest.replace(/\].*$/, ""));
		inArray = !rest.includes("]");
	}
	return names;
};

const gemfileNames = (text: string): string[] =>
	[...text.matchAll(/^\s*gem\s+["']([^"']+)["']/gm)].flatMap((m) =>
		m[1] ? [m[1]] : [],
	);

const requirementsNames = (text: string): string[] =>
	text
		.split("\n")
		.filter((line) => !/^\s*(#|-)/.test(line))
		.flatMap((line) => {
			const name = REQUIREMENT_NAME.exec(line)?.[1];
			return name ? [name] : [];
		});

const DECLARATIONS: ReadonlyArray<
	readonly [RegExp, Ecosystem, (text: string) => string[]]
> = [
	[/(^|\/)package\.json$/, "npm", packageJsonNames],
	[/(^|\/)go\.mod$/, "Go", goModNames],
	[/(^|\/)Cargo\.toml$/, "crates.io", cargoTomlNames],
	[/(^|\/)pyproject\.toml$/, "PyPI", pyprojectNames],
	[/(^|\/)requirements[\w.-]*\.txt$/, "PyPI", requirementsNames],
	[/(^|\/)Gemfile$/, "RubyGems", gemfileNames],
];

/**
 * Dependencies the project declares itself (`ecosystem|normalized name`), as
 * opposed to transitive ones that only appear in a lockfile.
 */
export const declaredDependencies = (
	files: ReadonlyArray<SourceFile>,
): Set<string> => {
	const out = new Set<string>();
	for (const file of files)
		for (const [re, ecosystem, names] of DECLARATIONS)
			if (re.test(file.path))
				for (const name of names(file.text))
					out.add(directKey(ecosystem, name));
	return out;
};

const isHealthManifest = (path: string) =>
	isManifest(path) ||
	(!isFixturePath(path) &&
		/(^|\/)(Cargo\.toml|pyproject\.toml|Gemfile)$/.test(path));

/* -------------------------------------------------------------------------- */
/*                                  Settings                                  */
/* -------------------------------------------------------------------------- */

export interface HealthSettings {
	/** A direct dependency whose newest release is older than this is stale; 0 disables. */
	readonly staleYears: number;
	/** Upper bound on deps.dev requests per run. */
	readonly maxRequests: number;
}

export const DEFAULT_HEALTH_SETTINGS: HealthSettings = {
	staleYears: 3,
	maxRequests: 200,
};

/** Validates `settings["code.dependency-health"]`; throws with a readable message. */
export const readHealthSettings = (raw: unknown): HealthSettings => {
	if (raw === undefined) return DEFAULT_HEALTH_SETTINGS;
	if (!isRecord(raw))
		throw new Error(`settings["${DEPENDENCY_HEALTH_ID}"] must be an object`);
	const { staleYears = 3, maxRequests = 200 } = raw;
	if (
		typeof staleYears !== "number" ||
		!Number.isFinite(staleYears) ||
		staleYears < 0 ||
		staleYears > 100
	)
		throw new Error(
			`settings["${DEPENDENCY_HEALTH_ID}"].staleYears must be a number of years from 0 (off) to 100`,
		);
	if (
		typeof maxRequests !== "number" ||
		!Number.isInteger(maxRequests) ||
		maxRequests < 1 ||
		maxRequests > 5000
	)
		throw new Error(
			`settings["${DEPENDENCY_HEALTH_ID}"].maxRequests must be an integer from 1 to 5000`,
		);
	return { staleYears, maxRequests };
};

/* -------------------------------------------------------------------------- */
/*                                  Findings                                  */
/* -------------------------------------------------------------------------- */

const depsDevUrl = (d: Dependency) => {
	const k = versionKeyOf(d);
	return `https://deps.dev/${k.system.toLowerCase()}/${encodeURIComponent(k.name)}/${encodeURIComponent(k.version)}`;
};

const DEPRECATION_DOCS: Partial<Record<Ecosystem, string>> = {
	npm: "https://docs.npmjs.com/deprecating-and-undeprecating-packages-or-package-versions",
	Go: "https://go.dev/ref/mod#go-mod-file-module-deprecation",
};

const YANK_DOCS: Partial<Record<Ecosystem, string>> = {
	PyPI: "https://peps.python.org/pep-0592/",
	"crates.io": "https://doc.rust-lang.org/cargo/commands/cargo-yank.html",
	RubyGems: "https://guides.rubygems.org/command-reference/#gem-yank",
};

const UNMAINTAINED_TAGS = ["cwe-1104", "owasp-a06"];

export interface Assessment {
	readonly version: VersionHealth | undefined;
	readonly project?: ProjectHealth;
	readonly pkg?: PackageHealth;
	/** Declared by the project rather than pulled in transitively. */
	readonly direct: boolean;
	readonly now: number;
	readonly staleYears: number;
	readonly line?: number;
}

/** Deprecated as a whole: the default (latest) release is deprecated too. */
const deprecatedOutright = (
	d: Dependency,
	v: VersionHealth,
	pkg: PackageHealth | undefined,
): boolean =>
	v.isDeprecated &&
	!YANKING_SYSTEMS.has(systemOf(d) ?? "") &&
	(v.isDefault || pkg?.defaultVersion?.isDeprecated === true);

/** A stale candidate: a direct dependency whose pinned release is already old. */
const oldRelease = (
	v: VersionHealth,
	a: Pick<Assessment, "direct" | "now" | "staleYears">,
) =>
	a.direct &&
	a.staleYears > 0 &&
	v.publishedAt !== undefined &&
	Date.parse(v.publishedAt) < a.now - a.staleYears * YEAR_MS;

const day = (iso: string) => iso.slice(0, 10);

/**
 * Findings for one dependency. A package deprecated outright is reported once:
 * replacing it also answers an archived repository or a stale release line.
 */
export const assessDependency = (
	d: Dependency,
	a: Assessment,
): FindingInput[] => {
	const v = a.version;
	if (!v) return [];
	const system = systemOf(d) ?? "";
	const location = { file: d.file, line: a.line };
	const id = `${d.name}@${d.version}`;
	const findings: FindingInput[] = [];
	const replacement =
		a.pkg?.defaultVersion &&
		!a.pkg.defaultVersion.isDeprecated &&
		a.pkg.defaultVersion.version !== versionKeyOf(d).version
			? a.pkg.defaultVersion.version
			: undefined;
	const reason = v.deprecatedReason?.trim();

	if (v.isDeprecated && YANKING_SYSTEMS.has(system)) {
		// Cargo and RubyGems have no yank message; deps.dev says "yanked".
		const why =
			reason && reason.toLowerCase() !== "yanked" ? reason : undefined;
		findings.push({
			ruleId: `${DEPENDENCY_HEALTH_ID}/yanked-release`,
			title: `${id} was yanked`,
			severity: "medium",
			category: "supply-chain",
			message: `${d.name} ${d.version} (${d.ecosystem}) was yanked from the registry${why ? `: "${truncate(why, 300)}"` : ""}. Maintainers yank a release that is broken or unsafe; installers skip it unless it is pinned exactly, as here.`,
			location,
			evidence: `${id} yanked${why ? `: ${truncate(why, 120)}` : ""}`,
			remediation: replacement
				? `Pin ${d.name} to ${replacement} (or another release that is not yanked), then regenerate the lockfile.`
				: `Pin ${d.name} to a release that is not yanked, then regenerate the lockfile.`,
			references: [YANK_DOCS[d.ecosystem], depsDevUrl(d)].filter(
				(r): r is string => r !== undefined,
			),
			confidence: "high",
			tags: ["owasp-a06"],
		});
	} else if (v.isDeprecated) {
		const outright = deprecatedOutright(d, v, a.pkg);
		const quoted = reason ? `: "${truncate(reason, 300)}"` : ".";
		findings.push({
			ruleId: `${DEPENDENCY_HEALTH_ID}/deprecated-package`,
			title: outright ? `${d.name} is deprecated` : `${id} is deprecated`,
			severity: outright ? "medium" : "low",
			category: "supply-chain",
			message: outright
				? `${d.name} (${d.ecosystem}) is deprecated by its maintainers, including its latest release${quoted} It will not get fixes, security fixes included.`
				: `${d.name} ${d.version} (${d.ecosystem}) is a deprecated release${quoted}${replacement ? ` ${replacement} is not deprecated.` : ""}`,
			location,
			evidence: `${id} deprecated${reason ? `: ${truncate(reason, 120)}` : ""}`,
			remediation: outright
				? `Replace ${d.name} with the alternative the deprecation message suggests or another maintained package, or remove it if it is unused. If it is a transitive dependency, upgrade or replace the package that pulls it in.`
				: replacement
					? `Upgrade ${d.name} to ${replacement} (or the newest release of your major line that is not deprecated), then regenerate the lockfile. If it is a transitive dependency, upgrade the package that pulls it in.`
					: `Upgrade ${d.name} to a release that is not deprecated, then regenerate the lockfile. If it is a transitive dependency, upgrade the package that pulls it in.`,
			references: [DEPRECATION_DOCS[d.ecosystem], depsDevUrl(d)].filter(
				(r): r is string => r !== undefined,
			),
			confidence: "high",
			tags: UNMAINTAINED_TAGS,
		});
		if (outright) return findings;
	}

	if (a.project?.archived && v.sourceRepo) {
		// Newer releases than the pinned one usually mean the package moved
		// (into a monorepo, to a new owner) rather than that it was abandoned.
		const moved = !v.isDefault;
		findings.push({
			ruleId: `${DEPENDENCY_HEALTH_ID}/archived-repository`,
			title: `${d.name}'s source repository is archived`,
			severity: moved ? "low" : "medium",
			category: "supply-chain",
			message: `${d.name} ${d.version} (${d.ecosystem}) names ${v.sourceRepo} as its source repository, and that repository is archived (read-only)${a.project.scorecardDate ? ` according to OpenSSF Scorecard on ${day(a.project.scorecardDate)}` : ""}. Bugs and vulnerabilities reported against it will not be fixed there.${moved ? " Newer releases exist, so the package may have moved to another repository." : ""}`,
			location,
			evidence: `${id} ${v.sourceRepo} archived`,
			remediation: moved
				? `Upgrade ${d.name} to its latest release and check which repository that release comes from. If it is still the archived one, move to a maintained alternative or fork.`
				: `Move to a maintained alternative or an actively maintained fork of ${d.name}, or vendor the code and own its fixes. If the project moved, check that the package metadata points at the new repository.`,
			references: [
				`https://deps.dev/project/${v.sourceRepo.split("/")[0]?.replace(/\.(com|org)$/, "")}/${encodeURIComponent(v.sourceRepo.split("/").slice(1).join("/"))}`,
				"https://github.com/ossf/scorecard/blob/main/docs/checks.md#maintained",
				cweUrl(1104),
			],
			// The package-to-repository link is unverified package metadata.
			confidence: moved ? "low" : "medium",
			tags: UNMAINTAINED_TAGS,
		});
		return findings;
	}

	const latest = a.pkg?.latest;
	if (
		oldRelease(v, a) &&
		latest &&
		Date.parse(latest.publishedAt) < a.now - a.staleYears * YEAR_MS
	)
		findings.push({
			ruleId: `${DEPENDENCY_HEALTH_ID}/stale-package`,
			title: `${d.name} has had no release in over ${a.staleYears} years`,
			severity: "low",
			category: "supply-chain",
			message: `The newest ${d.name} release (${latest.version}) was published on ${day(latest.publishedAt)}, more than ${a.staleYears} years ago. It may be finished rather than abandoned, but if it is unmaintained, bugs and vulnerabilities will not be fixed.`,
			location,
			evidence: `${id} newest release ${latest.version} on ${day(latest.publishedAt)}`,
			remediation: `Check whether ${d.name} is still maintained (recent commits, answered issues). For anything security-relevant, prefer a maintained alternative. Tune the threshold with settings["${DEPENDENCY_HEALTH_ID}"].staleYears.`,
			references: [depsDevUrl(d), cweUrl(1104), owaspUrl("a06")],
			confidence: "low",
			tags: UNMAINTAINED_TAGS,
		});
	return findings;
};

/* -------------------------------------------------------------------------- */
/*                                  Lookups                                   */
/* -------------------------------------------------------------------------- */

type Http = AuditContext["http"];

type Stage = "versions" | "projects" | "packages";

/** Request budget and failures shared by every lookup of one run. */
interface Lookup {
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
	return lookup
		.http(
			url,
			body === undefined
				? { timeoutMs: 30_000, maxBytes: 20 * 1024 * 1024 }
				: {
						method: "POST",
						headers: { "content-type": "application/json" },
						body: JSON.stringify(body),
						timeoutMs: 60_000,
						maxBytes: 50 * 1024 * 1024,
					},
		)
		.pipe(
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

/** POSTs `requests` to a deps.dev batch endpoint in chunks, following page tokens. */
const batch = <
	Page extends {
		readonly answered: ReadonlySet<string>;
		readonly nextPageToken?: string;
	},
>(
	lookup: Lookup,
	stage: Stage,
	path: string,
	requests: ReadonlyArray<unknown>,
	parse: (json: unknown) => Page,
): Effect.Effect<Page[]> =>
	Effect.map(
		Effect.forEach(
			chunks(requests, BATCH_SIZE),
			(chunk) =>
				Effect.gen(function* () {
					const pages: Page[] = [];
					let answered = 0;
					let pageToken: string | undefined;
					for (let i = 0; i < MAX_PAGES_PER_CHUNK; i++) {
						if (!spend(lookup)) {
							lookup.skipped[stage] += chunk.length - answered;
							break;
						}
						const json = yield* call(
							lookup,
							`${DEPS_DEV_API}${path}`,
							pageToken ? { requests: chunk, pageToken } : { requests: chunk },
						);
						if (json === undefined) break;
						const page = parse(json);
						pages.push(page);
						answered += page.answered.size;
						if (!page.nextPageToken || page.nextPageToken === pageToken) break;
						pageToken = page.nextPageToken;
					}
					return pages;
				}),
			{ concurrency: 4 },
		),
		(perChunk) => perChunk.flat(),
	);

const fetchPackage = (
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

const truncatedFinding = (
	lookup: Lookup,
	settings: HealthSettings,
): FindingInput => {
	const { versions, projects, packages } = lookup.skipped;
	const parts = [
		versions > 0 ? `${versions} dependencies` : "",
		projects > 0 ? `${projects} source repositories` : "",
		packages > 0 ? `${packages} package histories` : "",
	].filter(Boolean);
	return {
		ruleId: `${DEPENDENCY_HEALTH_ID}/truncated`,
		title: "Dependency health lookups stopped at the request limit",
		severity: "info",
		category: "supply-chain",
		message: `The run used its budget of ${settings.maxRequests} deps.dev requests, so ${parts.join(", ")} were not looked up. Findings that need them (deprecation and yanking, archived repositories, replacement versions and stale releases) may be missing.`,
		evidence: `${parts.join(", ")} not looked up (maxRequests ${settings.maxRequests})`,
		remediation: `Raise settings["${DEPENDENCY_HEALTH_ID}"].maxRequests (up to 5000) in a config passed with --config, or audit the packages of a large monorepo separately.`,
		references: ["https://docs.deps.dev/api/v3alpha/"],
		confidence: "high",
	};
};

const failedFinding = (lookup: Lookup, unchecked: number): FindingInput => ({
	ruleId: `${DEPENDENCY_HEALTH_ID}/lookup-failed`,
	title: "Some dependency health lookups failed",
	severity: "info",
	category: "supply-chain",
	message: `${lookup.failures.length} deps.dev requests failed (${[...new Set(lookup.failures)].slice(0, 3).join("; ")})${unchecked > 0 ? `, so ${unchecked} dependencies were not checked` : ""}. Findings that depend on them may be missing.`,
	evidence: `${lookup.failures.length} failed requests`,
	remediation:
		"Re-run the audit. If it keeps failing, check that api.deps.dev is reachable from this machine.",
	references: ["https://docs.deps.dev/api/v3alpha/"],
	confidence: "high",
});

/* -------------------------------------------------------------------------- */
/*                                  Auditor                                   */
/* -------------------------------------------------------------------------- */

export const dependencyHealth = defineAuditor({
	id: DEPENDENCY_HEALTH_ID,
	title: "Dependency health",
	description: `Flags deprecated packages and releases (npm, Go), yanked releases (PyPI, Cargo, RubyGems), dependencies whose source repository is archived (OpenSSF Scorecard), and direct dependencies with no release in settings["${DEPENDENCY_HEALTH_ID}"].staleYears years (default 3, 0 turns it off). Pinned versions from the lockfiles code.dependencies reads are looked up on deps.dev (Google's Open Source Insights) with one batch request per 100 dependencies and per 100 repositories, plus a package history only where it changes a finding, capped at settings["${DEPENDENCY_HEALTH_ID}"].maxRequests (default 200). Opt-in, because it sends every pinned package name and version to another third party and relies on deps.dev's v3alpha batch API, which has no stability guarantee. Packagist is not covered.`,
	categories: ["supply-chain"],
	targets: ["codebase"],
	engine: "builtin",
	network: true,
	defaultEnabled: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const settings = yield* Effect.try({
				try: () =>
					readHealthSettings(ctx.options.settings?.[DEPENDENCY_HEALTH_ID]),
				catch: (e) =>
					new AuditorError({
						message: e instanceof Error ? e.message : String(e),
					}),
			});
			const ws = yield* requireWorkspace(ctx);
			const files = yield* readTextFiles(ws, isHealthManifest, {
				maxBytes: 20 * 1024 * 1024,
				allowMinified: true,
			});
			// Sorted so the file a shared dependency is attributed to is stable.
			const sorted = [...files].sort((a, b) => a.path.localeCompare(b.path));
			const deps = uniqueDependencies(sorted.flatMap(parseDependencies)).filter(
				(d) => systemOf(d) !== undefined,
			);
			if (deps.length === 0)
				return yield* skip(
					files.some((f) => baseName(f.path) !== "package.json")
						? "No pinned npm, PyPI, Go, Cargo or RubyGems dependencies in the lockfiles"
						: "No dependency lockfiles found",
				);
			yield* ctx.log(
				`${DEPENDENCY_HEALTH_ID}: looking up ${deps.length} packages on deps.dev`,
			);

			const lookup: Lookup = {
				http: ctx.http,
				remaining: settings.maxRequests,
				skipped: { versions: 0, projects: 0, packages: 0 },
				failures: [],
			};

			const versionPages = yield* batch(
				lookup,
				"versions",
				"/v3alpha/versionbatch",
				deps.map((d) => ({ versionKey: versionKeyOf(d) })),
				parseVersionBatch,
			);
			const versions = new Map(versionPages.flatMap((p) => [...p.versions]));
			const answered = new Set(versionPages.flatMap((p) => [...p.answered]));
			if (answered.size === 0 && lookup.failures.length > 0)
				return yield* Effect.fail(
					new AuditorError({
						message: `deps.dev lookup failed: ${lookup.failures[0]}`,
					}),
				);
			const versionOf = (d: Dependency) => versions.get(keyOf(versionKeyOf(d)));

			const direct = declaredDependencies(files);
			const now = Date.now();
			const isDirect = (d: Dependency) =>
				direct.has(directKey(d.ecosystem, d.name));

			// Repositories matter unless the package is deprecated outright.
			const repos = [
				...new Set(
					deps.flatMap((d) => {
						const v = versionOf(d);
						return v?.sourceRepo && !deprecatedOutright(d, v, undefined)
							? [v.sourceRepo]
							: [];
					}),
				),
			].sort();
			const projectPages = yield* batch(
				lookup,
				"projects",
				"/v3alpha/projectbatch",
				repos.map((id) => ({ projectKey: { id } })),
				parseProjectBatch,
			);
			const projects = new Map(projectPages.flatMap((p) => [...p.projects]));

			// Package histories: replacements for deprecated or yanked releases
			// first, then the newest release of old direct dependencies.
			const wanted = new Map<string, Dependency>();
			const want = (d: Dependency) => {
				if (!wanted.has(packageKeyOf(d))) wanted.set(packageKeyOf(d), d);
			};
			for (const d of deps) {
				const v = versionOf(d);
				if (v?.isDeprecated && !v.isDefault) want(d);
			}
			for (const d of deps) {
				const v = versionOf(d);
				const archived =
					v?.sourceRepo !== undefined && projects.get(v.sourceRepo)?.archived;
				if (
					v &&
					!archived &&
					!deprecatedOutright(d, v, undefined) &&
					oldRelease(v, {
						direct: isDirect(d),
						now,
						staleYears: settings.staleYears,
					})
				)
					want(d);
			}
			const histories = yield* Effect.forEach(
				[...wanted],
				([key, d]) =>
					Effect.map(fetchPackage(lookup, d), (pkg) => [key, pkg] as const),
				{ concurrency: 4 },
			);
			const packages = new Map(histories);

			const lineFor = dependencyLineFinder(files);
			const findings = deps.flatMap((d) => {
				const v = versionOf(d);
				return assessDependency(d, {
					version: v,
					project: v?.sourceRepo ? projects.get(v.sourceRepo) : undefined,
					pkg: packages.get(packageKeyOf(d)),
					direct: isDirect(d),
					now,
					staleYears: settings.staleYears,
					line: v ? lineFor(d) : undefined,
				});
			});

			const { skipped } = lookup;
			if (skipped.versions + skipped.projects + skipped.packages > 0)
				findings.push(truncatedFinding(lookup, settings));
			if (lookup.failures.length > 0)
				findings.push(
					failedFinding(lookup, deps.length - answered.size - skipped.versions),
				);
			return findings;
		}),
});
