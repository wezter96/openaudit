import type { FindingInput } from "@openaudit/core";

import {
	baseName,
	cweUrl,
	isRecord,
	owaspUrl,
	type SourceFile,
	truncate,
} from "../util";
import {
	type FileConfig,
	type Registry,
	registryFor,
	scopeOfPackage,
} from "./config";
import {
	base,
	capPerRule,
	type FindingSite,
	gitFinding,
	insecureFinding,
	LOCKFILE_LINT,
	label,
	listNames,
	NPM_LOCKFILE,
	NPM_REGISTRY,
	partlyCheckedFinding,
	pathFinding,
	rule,
	tlsFinding,
	unique,
} from "./findings";
import { installScriptFindings } from "./scripts";
import { scrubText } from "./scrub";
import {
	declaredSpecs,
	dirOf,
	type Importer,
	joinDir,
	type LockedPackage,
	type Lockfile,
	lineFinder,
	parseJson,
} from "./shared";
import {
	classifySource,
	DEFAULT_REGISTRY_HOSTS,
	displayHost,
	displaySpec,
	displayUrl,
	escapesRoot,
	hostOf,
	integrityStrength,
	isOfficialRuntime,
	type Source,
} from "./sources";
import type { FilePath, Host, PackageName } from "./types";

/** Packages served by a registry that a config in the target declares. */
interface CustomSource {
	readonly registry: Registry;
	readonly host: Host;
	readonly packages: LockedPackage[];
}

/** One lockfile entry being checked, and what its findings need. */
interface EntryContext {
	readonly lock: Lockfile;
	readonly p: LockedPackage;
	readonly configs: ReadonlyArray<FileConfig>;
	/** Packages from registries the target configures, reported together. */
	readonly custom: Map<Host, CustomSource>;
}

/** A source host the lockfile points at, as shown to users. */
interface UnexpectedHost {
	readonly host: Host;
	readonly shown: Text;
	readonly why: Text;
}

/** Text shown to users. */
type Text = string;

const unexpectedHostFinding = (
	{ lock, p }: EntryContext,
	{ host, shown, why }: UnexpectedHost,
): FindingInput => ({
	...base,
	ruleId: rule("unexpected-host"),
	title: truncate(
		`${p.name} is downloaded from ${host || "an unrecognised source"}`,
		120,
	),
	severity: "medium",
	message: truncate(
		`${label(p)} resolves to ${shown}, ${why}. A lockfile that points a package at another host is a known way to slip in a modified package${integrityStrength(p.integrity) === "none" ? ", and this entry has no integrity hash either" : ""}.`,
		600,
	),
	location: { file: lock.path, line: p.line },
	evidence: `${label(p)}: ${shown}`,
	remediation:
		"If the host is your private registry, configure it for the package's scope in .npmrc, .yarnrc.yml or bunfig.toml next to the lockfile. Otherwise reinstall the package from the registry and regenerate the lockfile.",
	references: [LOCKFILE_LINT, NPM_REGISTRY, cweUrl(829), owaspUrl("a08")],
	tags: ["cwe-829", "owasp-a08"],
});

const siteOf = ({ lock, p }: EntryContext): FindingSite => ({
	file: lock.path,
	line: p.line,
});

const entryEvidence = ({ p }: EntryContext, shown: Text) =>
	`${label(p)}: ${shown}`;

/** Collects the entry under the configured registry that serves it. */
const fromRegistry = (ctx: EntryContext, host: Host, registry: Registry) => {
	const entry = ctx.custom.get(host) ?? { registry, host, packages: [] };
	entry.packages.push(ctx.p);
	ctx.custom.set(host, entry);
};

/** A configured registry other than the public one, over https. */
const isCustomHttpsRegistry = (host: Host, registry: Registry) =>
	!DEFAULT_REGISTRY_HOSTS.has(host) &&
	!registry.url.toLowerCase().startsWith("http:");

/** No URL recorded: the package comes from the configured registry. */
const registrySourceFinding = (ctx: EntryContext): undefined => {
	const registry = registryFor(ctx.configs, ctx.p.name);
	if (!registry) return undefined;
	const host = hostOf(registry.url);
	if (host && isCustomHttpsRegistry(host, registry))
		fromRegistry(ctx, host, registry);
	return undefined;
};

const unknownSourceFinding = (ctx: EntryContext): FindingInput =>
	unexpectedHostFinding(ctx, {
		host: "",
		shown: displayUrl(ctx.p.source ?? ""),
		why: "a source that is not a registry, a URL, git or a local path",
	});

const pathSourceFinding = (
	ctx: EntryContext,
	source: SourceOf<"path">,
): FindingInput | undefined => {
	const from = joinDir(dirOf(ctx.lock.path), ctx.p.base ?? "");
	return escapesRoot(from, source.path)
		? pathFinding(
				siteOf(ctx),
				ctx.p.name,
				entryEvidence(ctx, truncate(source.path, 120)),
			)
		: undefined;
};

const gitSourceFinding = (
	ctx: EntryContext,
	source: SourceOf<"git">,
): FindingInput => {
	const { p } = ctx;
	const evidence = entryEvidence(ctx, displayUrl(p.source ?? ""));
	if (source.insecure) return insecureFinding(siteOf(ctx), p.name, evidence);
	return gitFinding(siteOf(ctx), p.name, evidence, {
		pinned: source.pinned || integrityStrength(p.integrity) !== "none",
		how: source.ref
			? `${displayUrl(source.url)} at "${truncate(scrubText(source.ref), 60)}"`
			: displayUrl(source.url),
		host: displayHost(p.source ?? "", source.host),
	});
};

/** A registry configured next to the lockfile that serves `host` for `name`; a scoped registry only serves its own scope. */
const configuredRegistry = (
	configs: ReadonlyArray<FileConfig>,
	host: Host,
	name: PackageName,
): Registry | undefined => {
	const scope = scopeOfPackage(name);
	const servesScope = (r: Registry) =>
		r.scope === undefined || r.scope === scope;
	return configs
		.flatMap((c) => c.registries)
		.find((r) => hostOf(r.url) === host && servesScope(r));
};

const tarballSourceFinding = (
	ctx: EntryContext,
	source: SourceOf<"tarball">,
): FindingInput | undefined => {
	const { p } = ctx;
	const shown = displayUrl(source.url);
	if (source.insecure)
		return insecureFinding(siteOf(ctx), p.name, entryEvidence(ctx, shown));
	if (DEFAULT_REGISTRY_HOSTS.has(source.host)) return undefined;
	if (p.runtime && isOfficialRuntime(p.name, source.url)) return undefined;
	const registry = configuredRegistry(ctx.configs, source.host, p.name);
	if (registry) {
		fromRegistry(ctx, source.host, registry);
		return undefined;
	}
	return unexpectedHostFinding(ctx, {
		host: displayHost(source.url, source.host),
		shown,
		why: "which is neither the public npm registry nor a registry configured for this package next to the lockfile",
	});
};

type SourceOf<K extends Source["kind"]> = Extract<Source, { kind: K }>;

const SOURCE_FINDINGS: {
	readonly [K in Source["kind"]]: (
		ctx: EntryContext,
		source: SourceOf<K>,
	) => FindingInput | undefined;
} = {
	ignored: () => undefined,
	registry: registrySourceFinding,
	unknown: unknownSourceFinding,
	path: pathSourceFinding,
	git: gitSourceFinding,
	tarball: tarballSourceFinding,
};

/**
 * One finding for an entry's source, or none. Packages from a registry the
 * target configures are collected in `ctx.custom` and reported together.
 */
const sourceFinding = (ctx: EntryContext): FindingInput | undefined => {
	const source = classifySource(ctx.p.source);
	const find = SOURCE_FINDINGS[source.kind] as (
		ctx: EntryContext,
		source: Source,
	) => FindingInput | undefined;
	return find(ctx, source);
};

const customSourceFinding = (
	lock: Lockfile,
	{ registry, host: rawHost, packages }: CustomSource,
): FindingInput => {
	const host = displayHost(registry.url, rawHost);
	const names = unique(packages.map(label));
	const declared = `${registry.file}:${registry.line ?? "?"}`;
	return {
		...base,
		ruleId: rule("custom-registry-source"),
		title: truncate(
			`${names.length} ${names.length === 1 ? "package" : "packages"} in ${baseName(lock.path)} ${names.length === 1 ? "comes" : "come"} from ${host}`,
			120,
		),
		severity: "low",
		message: truncate(
			`${listNames(names)} ${names.length === 1 ? "is" : "are"} downloaded from ${host}, which ${declared} configures as ${registry.scope ? `the registry for ${registry.scope}` : "the default registry"} instead of the public npm registry. The lockfile's integrity hashes for them come from that registry too, so it decides what gets installed. The setting is part of the repository, so check that ${host} is your organisation's registry.`,
			800,
		),
		location: { file: lock.path, line: packages[0]?.line },
		evidence: truncate(`${host}: ${names.join(", ")}`),
		remediation:
			"If this is your private registry, suppress the finding by fingerprint. Otherwise remove the registry setting, reinstall from the public registry and regenerate the lockfile.",
		references: [NPM_REGISTRY, LOCKFILE_LINT, cweUrl(829), owaspUrl("a08")],
		tags: ["cwe-829", "owasp-a08"],
	};
};

/** Entries with a missing or weak integrity hash, and the line of the first. */
interface IntegrityGap {
	readonly names: string[];
	line: number | undefined;
}

const DOWNLOADED_KINDS = new Set<Source["kind"]>(["registry", "tarball"]);

/** npm workspaces and the root are not downloaded. */
const isNpmLocalEntry = (lock: Lockfile, p: LockedPackage) => {
	if (lock.manager !== "npm") return false;
	return !p.version && !p.source;
};

const needsIntegrity = (lock: Lockfile, p: LockedPackage) => {
	if (p.bundled) return false;
	if (!DOWNLOADED_KINDS.has(classifySource(p.source).kind)) return false;
	return !isNpmLocalEntry(lock, p);
};

const integrityGaps = (
	lock: Lockfile,
	packages: ReadonlyArray<LockedPackage>,
): Record<"none" | "weak", IntegrityGap> => {
	const gaps: Record<"none" | "weak", IntegrityGap> = {
		none: { names: [], line: undefined },
		weak: { names: [], line: undefined },
	};
	for (const p of packages.filter((p) => needsIntegrity(lock, p))) {
		const strength = integrityStrength(p.integrity);
		if (strength === "strong") continue;
		const gap = gaps[strength];
		gap.names.push(label(p));
		gap.line ??= p.line;
	}
	return gaps;
};

const missingIntegrityFinding = (
	lock: Lockfile,
	m: ReadonlyArray<string>,
	line: number | undefined,
): FindingInput => ({
	...base,
	ruleId: rule("missing-integrity"),
	title: `${m.length} ${m.length === 1 ? "entry" : "entries"} in ${baseName(lock.path)} ${m.length === 1 ? "has" : "have"} no integrity hash`,
	severity: "low",
	message: truncate(
		`The lockfile records no valid integrity hash for ${listNames(m)}. The package manager cannot detect a tarball that was changed on the server or in transit.`,
		600,
	),
	location: { file: lock.path, line },
	evidence: truncate(m.join(", ")),
	remediation:
		"Delete the affected entries (or the lockfile) and reinstall with a current package manager so it records integrity hashes; then commit the lockfile.",
	references: [LOCKFILE_LINT, NPM_LOCKFILE, cweUrl(494), owaspUrl("a08")],
	tags: ["cwe-494", "owasp-a08"],
});

const weakIntegrityFinding = (
	lock: Lockfile,
	w: ReadonlyArray<string>,
	line: number | undefined,
): FindingInput => ({
	...base,
	ruleId: rule("weak-integrity"),
	title: `${w.length} ${w.length === 1 ? "entry" : "entries"} in ${baseName(lock.path)} ${w.length === 1 ? "is" : "are"} only checked with SHA-1`,
	severity: "low",
	message: truncate(
		`The only integrity hash recorded for ${listNames(w)} is SHA-1, which is no longer collision resistant.`,
		600,
	),
	location: { file: lock.path, line },
	evidence: truncate(w.join(", ")),
	remediation:
		"Regenerate the lockfile with a current package manager so it records sha512 integrity hashes.",
	references: [LOCKFILE_LINT, NPM_LOCKFILE, cweUrl(328)],
	tags: ["cwe-328"],
});

const integrityFindings = (
	lock: Lockfile,
	packages: ReadonlyArray<LockedPackage>,
): FindingInput[] => {
	const { none, weak } = integrityGaps(lock, packages);
	const m = unique(none.names);
	const w = unique(weak.names);
	return [
		...(m.length ? [missingIntegrityFinding(lock, m, none.line)] : []),
		...(w.length ? [weakIntegrityFinding(lock, w, weak.line)] : []),
	];
};

/** A declared dependency the lockfile does not match. */
interface Drift {
	readonly name: PackageName;
	readonly text: Text;
	readonly evidence: Text;
}

const driftOf = (
	importer: Importer,
	name: PackageName,
	specs: ReadonlyArray<string> | undefined,
): Drift | undefined => {
	const spec = specs?.[0] ?? "";
	// Specs can carry credentials (git+https://user:token@…).
	const shown = displaySpec(spec);
	if (!importer.has(name))
		return {
			name,
			text: `${name} is missing`,
			evidence: `${name}: ${shown} (not locked)`,
		};
	const locked = importer.get(name);
	if (!locked || locked.includes(spec)) return undefined;
	const lockedShown = displaySpec(locked[0] ?? "");
	return {
		name,
		text: `${name} is "${shown}" but locked as "${lockedShown}"`,
		evidence: `${name}: ${shown} (locked ${lockedShown})`,
	};
};

/** package.json dependencies the lockfile does not record (or records differently). */
const driftFinding = (
	lock: Lockfile,
	manifest: SourceFile,
	importer: Importer,
): FindingInput | undefined => {
	const json = parseJson(manifest.text);
	if (!isRecord(json)) return undefined;
	const drifted = [...declaredSpecs(json)]
		.map(([name, specs]) => driftOf(importer, name, specs))
		.filter((d) => d !== undefined);
	const first = drifted[0];
	if (!first) return undefined;
	const lineOf = lineFinder(manifest.text);
	return {
		...base,
		ruleId: rule("lockfile-drift"),
		title: `${baseName(lock.path)} is out of date with ${manifest.path}`,
		severity: "low",
		message: truncate(
			`${manifest.path} declares ${drifted.length} ${drifted.length === 1 ? "dependency" : "dependencies"} that ${lock.path} does not match: ${drifted
				.slice(0, 10)
				.map((d) => d.text)
				.join(
					"; ",
				)}${drifted.length > 10 ? "; …" : ""}. A frozen install (npm ci, --frozen-lockfile) fails, and a plain install resolves the versions anew instead of using reviewed ones.`,
			1000,
		),
		location: { file: manifest.path, line: lineOf(`"${first.name}"`) },
		evidence: truncate(drifted.map((d) => d.evidence).join("; ")),
		remediation:
			"Run the package manager's install to update the lockfile, review the diff, and commit both files together. Use frozen installs in CI.",
		references: [NPM_LOCKFILE, LOCKFILE_LINT],
		confidence: lock.manager === "yarn" ? "medium" : "high",
		tags: ["lockfile-drift"],
	};
};

/** Source findings per entry, capped per rule, plus one per configured registry. */
const sourceFindings = (
	lock: Lockfile,
	configs: ReadonlyArray<FileConfig>,
): { perEntry: FindingInput[]; custom: Map<Host, CustomSource> } => {
	const custom = new Map<Host, CustomSource>();
	const perEntry = lock.packages
		.map((p) => sourceFinding({ lock, p, configs, custom }))
		.filter((f) => f !== undefined);
	return { perEntry, custom };
};

/** Drift between each workspace's package.json and the lockfile. */
const driftFindings = (
	lock: Lockfile,
	manifests: ReadonlyMap<FilePath, SourceFile>,
): FindingInput[] => {
	const lockDir = dirOf(lock.path);
	return [...lock.importers]
		.filter(([dir]) => !escapesRoot(lockDir, dir))
		.map(([dir, importer]) => {
			const manifest = manifests.get(
				joinDir(joinDir(lockDir, dir), "package.json"),
			);
			return manifest && driftFinding(lock, manifest, importer);
		})
		.filter((f) => f !== undefined);
};

/** All findings for one parsed lockfile. */
export const lockfileFindings = (
	lock: Lockfile,
	configs: ReadonlyArray<FileConfig>,
	manifests: ReadonlyMap<string, SourceFile>,
): FindingInput[] => {
	const { perEntry, custom } = sourceFindings(lock, configs);
	return [
		...capPerRule(perEntry),
		...(lock.problems ?? []).map((problem) =>
			partlyCheckedFinding(lock.path, problem),
		),
		...[...custom.values()].map((c) => customSourceFinding(lock, c)),
		...integrityFindings(lock, lock.packages),
		...installScriptFindings(lock, lock.packages, configs),
		...driftFindings(lock, manifests),
	];
};

/** Registries (custom or insecure) and disabled TLS checks in a config file. */
export const configFindings = (config: FileConfig): FindingInput[] => {
	const out: FindingInput[] = [];
	for (const r of config.registries) {
		const host = hostOf(r.url);
		if (r.url.toLowerCase().startsWith("http:"))
			out.push(
				insecureFinding(
					{ file: r.file, line: r.line },
					`The registry ${displayUrl(r.url)}`,
					r.evidence,
				),
			);
		else if (!host || !DEFAULT_REGISTRY_HOSTS.has(host))
			out.push({
				...base,
				ruleId: rule("custom-registry"),
				title: truncate(
					`${baseName(r.file)} installs ${r.scope ? `${r.scope} packages` : "packages"} from ${host ? displayHost(r.url, host) : "a registry set outside the repository"}`,
					120,
				),
				severity: "info",
				message: truncate(
					`${r.file} sets ${displayUrl(r.url)} as ${r.scope ? `the registry for ${r.scope} packages` : "the default registry"}.${host ? "" : " The value comes from an environment variable or is not a URL, so openaudit cannot tell which registry is used."} Whoever runs that registry decides what gets installed, and the setting lives in the repository, so a change to it deserves the same review as a change to the code.`,
					600,
				),
				location: { file: r.file, line: r.line },
				evidence: truncate(r.evidence),
				remediation:
					"Confirm the host is your organisation's registry. Keep registry settings in CI or user configuration where possible, and review changes to them.",
				references: [NPM_REGISTRY, LOCKFILE_LINT],
				tags: ["registry"],
			});
	}
	if (config.strictSslOff)
		out.push(tlsFinding(config.strictSslOff, "the package manager"));
	return out;
};
