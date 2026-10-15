import {
	type AuditContext,
	AuditorError,
	defineAuditor,
	type FindingInput,
	requireWorkspace,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import {
	type Dependency,
	dependencyLineFinder,
	parseDependencies,
	uniqueDependencies,
} from "./dependencies";
import {
	batch,
	fetchPackage,
	keyOf,
	type Lookup,
	type PackageHealth,
	type ProjectHealth,
	packageKeyOf,
	parseProjectBatch,
	parseVersionBatch,
	systemOf,
	type VersionHealth,
	versionKeyOf,
} from "./dependency-health-deps-dev";
import {
	assessDependency,
	DEPENDENCY_HEALTH_ID,
	deprecatedOutright,
	oldRelease,
} from "./dependency-health-findings";
import {
	declaredDependencies,
	directKey,
	isHealthManifest,
} from "./dependency-health-manifests";
import { baseName, isRecord, readTextFiles, type SourceFile } from "./util";

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

export {
	DEPS_DEV_API,
	type PackageHealth,
	type ProjectHealth,
	parsePackage,
	parseProjectBatch,
	parseVersionBatch,
	type VersionHealth,
} from "./dependency-health-deps-dev";
export {
	type Assessment,
	assessDependency,
	DEPENDENCY_HEALTH_ID,
} from "./dependency-health-findings";
export { declaredDependencies } from "./dependency-health-manifests";

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

/** A number of years from 0 (off) to 100. */
const isStaleYears = (x: unknown): x is number =>
	typeof x === "number" && Number.isFinite(x) && x >= 0 && x <= 100;

/** An integer from 1 to 5000. */
const isMaxRequests = (x: unknown): x is number =>
	typeof x === "number" && Number.isInteger(x) && x >= 1 && x <= 5000;

/** Validates `settings["code.dependency-health"]`; throws with a readable message. */
export const readHealthSettings = (raw: unknown): HealthSettings => {
	if (raw === undefined) return DEFAULT_HEALTH_SETTINGS;
	if (!isRecord(raw))
		throw new Error(`settings["${DEPENDENCY_HEALTH_ID}"] must be an object`);
	const { staleYears = 3, maxRequests = 200 } = raw;
	if (!isStaleYears(staleYears))
		throw new Error(
			`settings["${DEPENDENCY_HEALTH_ID}"].staleYears must be a number of years from 0 (off) to 100`,
		);
	if (!isMaxRequests(maxRequests))
		throw new Error(
			`settings["${DEPENDENCY_HEALTH_ID}"].maxRequests must be an integer from 1 to 5000`,
		);
	return { staleYears, maxRequests };
};

const loadSettings = (ctx: AuditContext) =>
	Effect.try({
		try: () => readHealthSettings(ctx.options.settings?.[DEPENDENCY_HEALTH_ID]),
		catch: (e) =>
			new AuditorError({
				message: e instanceof Error ? e.message : String(e),
			}),
	});

/* -------------------------------------------------------------------------- */
/*                               Run findings                                 */
/* -------------------------------------------------------------------------- */

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

/** Findings about the run itself: an exhausted request budget, failed requests. */
const runFindings = (
	lookup: Lookup,
	settings: HealthSettings,
	unchecked: number,
): FindingInput[] => {
	const { skipped } = lookup;
	const findings: FindingInput[] = [];
	if (skipped.versions + skipped.projects + skipped.packages > 0)
		findings.push(truncatedFinding(lookup, settings));
	if (lookup.failures.length > 0)
		findings.push(failedFinding(lookup, unchecked));
	return findings;
};

/* -------------------------------------------------------------------------- */
/*                                  Lookups                                   */
/* -------------------------------------------------------------------------- */

/** What one run knows about its dependencies once their versions are looked up. */
interface HealthRun {
	readonly deps: ReadonlyArray<Dependency>;
	readonly versionOf: (d: Dependency) => VersionHealth | undefined;
	readonly isDirect: (d: Dependency) => boolean;
	readonly now: number;
	readonly staleYears: number;
}

/** Pinned dependencies of an ecosystem deps.dev indexes, or a skip without any. */
const pinnedDependencies = (files: ReadonlyArray<SourceFile>) =>
	Effect.gen(function* () {
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
		return deps;
	});

/** Versions of every dependency; fails when deps.dev answered none of them. */
const lookupVersions = (lookup: Lookup, deps: ReadonlyArray<Dependency>) =>
	Effect.gen(function* () {
		const pages = yield* batch(
			lookup,
			{
				stage: "versions",
				path: "/v3alpha/versionbatch",
				parse: parseVersionBatch,
			},
			deps.map((d) => ({ versionKey: versionKeyOf(d) })),
		);
		const versions = new Map(pages.flatMap((p) => [...p.versions]));
		const answered = new Set(pages.flatMap((p) => [...p.answered]));
		if (answered.size === 0 && lookup.failures.length > 0)
			return yield* Effect.fail(
				new AuditorError({
					message: `deps.dev lookup failed: ${lookup.failures[0]}`,
				}),
			);
		const versionOf = (d: Dependency) => versions.get(keyOf(versionKeyOf(d)));
		return { versionOf, answered };
	});

/** Source repositories, which matter unless the package is deprecated outright. */
const lookupProjects = (lookup: Lookup, run: HealthRun) => {
	const repos = [
		...new Set(
			run.deps.flatMap((d) => {
				const v = run.versionOf(d);
				return v?.sourceRepo && !deprecatedOutright(d, v, undefined)
					? [v.sourceRepo]
					: [];
			}),
		),
	].sort();
	return Effect.map(
		batch(
			lookup,
			{
				stage: "projects",
				path: "/v3alpha/projectbatch",
				parse: parseProjectBatch,
			},
			repos.map((id) => ({ projectKey: { id } })),
		),
		(pages) => new Map(pages.flatMap((p) => [...p.projects])),
	);
};

/** A deprecated or yanked release that a newer one may replace. */
const needsReplacement = (v: VersionHealth | undefined) =>
	v?.isDeprecated === true && !v.isDefault;

const isArchived = (v: VersionHealth, projects: Map<string, ProjectHealth>) =>
	v.sourceRepo !== undefined && projects.get(v.sourceRepo)?.archived === true;

/** An old direct release that no other finding about the package supersedes. */
const mayBeStale = (
	run: HealthRun,
	projects: Map<string, ProjectHealth>,
	d: Dependency,
): boolean => {
	const v = run.versionOf(d);
	if (!v) return false;
	if (isArchived(v, projects) || deprecatedOutright(d, v, undefined))
		return false;
	return oldRelease(v, {
		direct: run.isDirect(d),
		now: run.now,
		staleYears: run.staleYears,
	});
};

/**
 * Package histories to fetch: replacements for deprecated or yanked releases
 * first, then the newest release of old direct dependencies.
 */
const wantedPackages = (
	run: HealthRun,
	projects: Map<string, ProjectHealth>,
): Map<string, Dependency> => {
	const wanted = new Map<string, Dependency>();
	const candidates = [
		...run.deps.filter((d) => needsReplacement(run.versionOf(d))),
		...run.deps.filter((d) => mayBeStale(run, projects, d)),
	];
	for (const d of candidates)
		if (!wanted.has(packageKeyOf(d))) wanted.set(packageKeyOf(d), d);
	return wanted;
};

const lookupPackages = (lookup: Lookup, wanted: Map<string, Dependency>) =>
	Effect.map(
		Effect.forEach(
			[...wanted],
			([key, d]) =>
				Effect.map(fetchPackage(lookup, d), (pkg) => [key, pkg] as const),
			{ concurrency: 4 },
		),
		(histories) => new Map(histories),
	);

/** Everything the lookups found about the run's dependencies. */
interface Found {
	readonly projects: Map<string, ProjectHealth>;
	readonly packages: Map<string, PackageHealth | undefined>;
	readonly lineFor: (d: Dependency) => number | undefined;
}

const assessAll = (run: HealthRun, found: Found): FindingInput[] =>
	run.deps.flatMap((d) => {
		const v = run.versionOf(d);
		return assessDependency(d, {
			version: v,
			project: v?.sourceRepo ? found.projects.get(v.sourceRepo) : undefined,
			pkg: found.packages.get(packageKeyOf(d)),
			direct: run.isDirect(d),
			now: run.now,
			staleYears: run.staleYears,
			line: v ? found.lineFor(d) : undefined,
		});
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
			const settings = yield* loadSettings(ctx);
			const ws = yield* requireWorkspace(ctx);
			const files = yield* readTextFiles(ws, isHealthManifest, {
				maxBytes: 20 * 1024 * 1024,
				allowMinified: true,
			});
			const deps = yield* pinnedDependencies(files);
			yield* ctx.log(
				`${DEPENDENCY_HEALTH_ID}: looking up ${deps.length} packages on deps.dev`,
			);

			const lookup: Lookup = {
				http: ctx.http,
				remaining: settings.maxRequests,
				skipped: { versions: 0, projects: 0, packages: 0 },
				failures: [],
			};
			const { versionOf, answered } = yield* lookupVersions(lookup, deps);
			const direct = declaredDependencies(files);
			const run: HealthRun = {
				deps,
				versionOf,
				isDirect: (d) => direct.has(directKey(d.ecosystem, d.name)),
				now: Date.now(),
				staleYears: settings.staleYears,
			};
			const projects = yield* lookupProjects(lookup, run);
			const packages = yield* lookupPackages(
				lookup,
				wantedPackages(run, projects),
			);

			const findings = assessAll(run, {
				projects,
				packages,
				lineFor: dependencyLineFinder(files),
			});
			const unchecked = deps.length - answered.size - lookup.skipped.versions;
			return [...findings, ...runFindings(lookup, settings, unchecked)];
		}),
});
