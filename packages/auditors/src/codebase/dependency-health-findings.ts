import type { FindingInput } from "@openaudit/core";

import type { Dependency, Ecosystem } from "./dependencies";
import {
	type PackageHealth,
	type ProjectHealth,
	systemOf,
	type VersionHealth,
	versionKeyOf,
	YANKING_SYSTEMS,
} from "./dependency-health-deps-dev";
import { cweUrl, owaspUrl, truncate } from "./util";

/* Findings of code.dependency-health about one dependency. */

export const DEPENDENCY_HEALTH_ID = "code.dependency-health";

const YEAR_MS = 365.25 * 24 * 60 * 60 * 1000;

const depsDevUrl = (d: Dependency) => {
	const k = versionKeyOf(d);
	return `https://deps.dev/${k.system.toLowerCase()}/${encodeURIComponent(k.name)}/${encodeURIComponent(k.version)}`;
};

/** deps.dev's page for a source repository such as `github.com/o/r`. */
const depsDevProjectUrl = (repo: string) => {
	const [host = "", ...path] = repo.split("/");
	return `https://deps.dev/project/${host.replace(/\.(com|org)$/, "")}/${encodeURIComponent(path.join("/"))}`;
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
export const deprecatedOutright = (
	d: Dependency,
	v: VersionHealth,
	pkg: PackageHealth | undefined,
): boolean =>
	v.isDeprecated &&
	!YANKING_SYSTEMS.has(systemOf(d) ?? "") &&
	(v.isDefault || pkg?.defaultVersion?.isDeprecated === true);

const staleCutoff = (a: Pick<Assessment, "now" | "staleYears">) =>
	a.now - a.staleYears * YEAR_MS;

/** A stale candidate: a direct dependency whose pinned release is already old. */
export const oldRelease = (
	v: VersionHealth,
	a: Pick<Assessment, "direct" | "now" | "staleYears">,
) =>
	a.direct &&
	a.staleYears > 0 &&
	v.publishedAt !== undefined &&
	Date.parse(v.publishedAt) < staleCutoff(a);

const day = (iso: string) => iso.slice(0, 10);

/** One dependency with a deps.dev answer, and what every finding about it shares. */
interface Subject {
	readonly d: Dependency;
	readonly v: VersionHealth;
	readonly a: Assessment;
	readonly location: { readonly file: string; readonly line?: number };
	/** `name@version`. */
	readonly id: string;
	/** A newer default release that is not deprecated, to move to. */
	readonly replacement?: string;
	readonly reason?: string;
}

const replacementOf = (d: Dependency, pkg: PackageHealth | undefined) => {
	const target = pkg?.defaultVersion;
	if (!target || target.isDeprecated) return undefined;
	return target.version !== versionKeyOf(d).version
		? target.version
		: undefined;
};

const subjectOf = (
	d: Dependency,
	a: Assessment,
	v: VersionHealth,
): Subject => ({
	d,
	v,
	a,
	location: { file: d.file, line: a.line },
	id: `${d.name}@${d.version}`,
	replacement: replacementOf(d, a.pkg),
	reason: v.deprecatedReason?.trim(),
});

const yankedFinding = ({
	d,
	location,
	id,
	replacement,
	reason,
}: Subject): FindingInput => {
	// Cargo and RubyGems have no yank message; deps.dev says "yanked".
	const why = reason && reason.toLowerCase() !== "yanked" ? reason : undefined;
	return {
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
	};
};

const deprecatedRemediation = (
	{ d, replacement }: Subject,
	outright: boolean,
): string => {
	if (outright)
		return `Replace ${d.name} with the alternative the deprecation message suggests or another maintained package, or remove it if it is unused. If it is a transitive dependency, upgrade or replace the package that pulls it in.`;
	return replacement
		? `Upgrade ${d.name} to ${replacement} (or the newest release of your major line that is not deprecated), then regenerate the lockfile. If it is a transitive dependency, upgrade the package that pulls it in.`
		: `Upgrade ${d.name} to a release that is not deprecated, then regenerate the lockfile. If it is a transitive dependency, upgrade the package that pulls it in.`;
};

const deprecatedFinding = (s: Subject): FindingInput => {
	const { d, id, replacement, reason } = s;
	const outright = deprecatedOutright(d, s.v, s.a.pkg);
	const quoted = reason ? `: "${truncate(reason, 300)}"` : ".";
	return {
		ruleId: `${DEPENDENCY_HEALTH_ID}/deprecated-package`,
		title: outright ? `${d.name} is deprecated` : `${id} is deprecated`,
		severity: outright ? "medium" : "low",
		category: "supply-chain",
		message: outright
			? `${d.name} (${d.ecosystem}) is deprecated by its maintainers, including its latest release${quoted} It will not get fixes, security fixes included.`
			: `${d.name} ${d.version} (${d.ecosystem}) is a deprecated release${quoted}${replacement ? ` ${replacement} is not deprecated.` : ""}`,
		location: s.location,
		evidence: `${id} deprecated${reason ? `: ${truncate(reason, 120)}` : ""}`,
		remediation: deprecatedRemediation(s, outright),
		references: [DEPRECATION_DOCS[d.ecosystem], depsDevUrl(d)].filter(
			(r): r is string => r !== undefined,
		),
		confidence: "high",
		tags: UNMAINTAINED_TAGS,
	};
};

/** A yanked release where the registry yanks, a deprecated one elsewhere. */
const deprecationFinding = (s: Subject): FindingInput =>
	YANKING_SYSTEMS.has(systemOf(s.d) ?? "")
		? yankedFinding(s)
		: deprecatedFinding(s);

/**
 * Newer releases than the pinned one usually mean the package moved (into a
 * monorepo, to a new owner) rather than that it was abandoned.
 */
const archivedAdvice = (d: Dependency, moved: boolean) => {
	if (moved)
		return {
			severity: "low",
			remediation: `Upgrade ${d.name} to its latest release and check which repository that release comes from. If it is still the archived one, move to a maintained alternative or fork.`,
			confidence: "low",
		} as const;
	return {
		severity: "medium",
		remediation: `Move to a maintained alternative or an actively maintained fork of ${d.name}, or vendor the code and own its fixes. If the project moved, check that the package metadata points at the new repository.`,
		confidence: "medium",
	} as const;
};

const archivedFinding = ({
	d,
	v,
	a,
	location,
	id,
}: Subject): FindingInput | undefined => {
	const repo = v.sourceRepo;
	if (!a.project?.archived || !repo) return undefined;
	const moved = !v.isDefault;
	const advice = archivedAdvice(d, moved);
	return {
		ruleId: `${DEPENDENCY_HEALTH_ID}/archived-repository`,
		title: `${d.name}'s source repository is archived`,
		severity: advice.severity,
		category: "supply-chain",
		message: `${d.name} ${d.version} (${d.ecosystem}) names ${repo} as its source repository, and that repository is archived (read-only)${a.project.scorecardDate ? ` according to OpenSSF Scorecard on ${day(a.project.scorecardDate)}` : ""}. Bugs and vulnerabilities reported against it will not be fixed there.${moved ? " Newer releases exist, so the package may have moved to another repository." : ""}`,
		location,
		evidence: `${id} ${repo} archived`,
		remediation: advice.remediation,
		references: [
			depsDevProjectUrl(repo),
			"https://github.com/ossf/scorecard/blob/main/docs/checks.md#maintained",
			cweUrl(1104),
		],
		// The package-to-repository link is unverified package metadata.
		confidence: advice.confidence,
		tags: UNMAINTAINED_TAGS,
	};
};

const staleFinding = ({
	d,
	v,
	a,
	location,
	id,
}: Subject): FindingInput | undefined => {
	const latest = a.pkg?.latest;
	if (!latest || !oldRelease(v, a)) return undefined;
	if (!(Date.parse(latest.publishedAt) < staleCutoff(a))) return undefined;
	return {
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
	};
};

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
	const s = subjectOf(d, a, v);
	const findings = v.isDeprecated ? [deprecationFinding(s)] : [];
	if (deprecatedOutright(d, v, a.pkg)) return findings;
	// An archived repository says more than a stale release line.
	const maintenance = archivedFinding(s) ?? staleFinding(s);
	return maintenance ? [...findings, maintenance] : findings;
};
