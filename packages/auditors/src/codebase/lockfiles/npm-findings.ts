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
	maskTokens,
} from "./sources";

const unexpectedHostFinding = (
	lock: Lockfile,
	p: LockedPackage,
	host: string,
	shown: string,
	why: string,
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

/** Packages served by a registry that a config in the target declares. */
interface CustomSource {
	readonly registry: Registry;
	readonly host: string;
	readonly packages: LockedPackage[];
}

/**
 * One finding for an entry's source, or none. Packages from a registry the
 * target configures are collected in `custom` and reported together.
 */
const sourceFinding = (
	lock: Lockfile,
	p: LockedPackage,
	configs: ReadonlyArray<FileConfig>,
	custom: Map<string, CustomSource>,
): FindingInput | undefined => {
	const source = classifySource(p.source);
	const file = lock.path;
	const evidence = (s: string) => `${label(p)}: ${s}`;
	const fromRegistry = (host: string, registry: Registry) => {
		const entry = custom.get(host) ?? { registry, host, packages: [] };
		entry.packages.push(p);
		custom.set(host, entry);
	};
	switch (source.kind) {
		case "ignored":
			return undefined;
		case "registry": {
			// No URL recorded: the package comes from the configured registry.
			const registry = registryFor(configs, p.name);
			const host = registry && hostOf(registry.url);
			if (
				registry &&
				host &&
				!DEFAULT_REGISTRY_HOSTS.has(host) &&
				!registry.url.toLowerCase().startsWith("http:")
			)
				fromRegistry(host, registry);
			return undefined;
		}
		case "unknown":
			return unexpectedHostFinding(
				lock,
				p,
				"",
				displayUrl(p.source ?? ""),
				"a source that is not a registry, a URL, git or a local path",
			);
		case "path": {
			const from = joinDir(dirOf(lock.path), p.base ?? "");
			return escapesRoot(from, source.path)
				? pathFinding(
						file,
						p.line,
						p.name,
						evidence(truncate(source.path, 120)),
					)
				: undefined;
		}
		case "git": {
			const shown = displayUrl(p.source ?? "");
			if (source.insecure)
				return insecureFinding(file, p.line, p.name, evidence(shown));
			const pinned = source.pinned || integrityStrength(p.integrity) !== "none";
			return gitFinding(
				file,
				p.line,
				p.name,
				evidence(shown),
				pinned,
				source.ref
					? `${displayUrl(source.url)} at "${truncate(maskTokens(source.ref), 60)}"`
					: displayUrl(source.url),
				displayHost(p.source ?? "", source.host),
			);
		}
		case "tarball": {
			const shown = displayUrl(source.url);
			if (source.insecure)
				return insecureFinding(file, p.line, p.name, evidence(shown));
			if (DEFAULT_REGISTRY_HOSTS.has(source.host)) return undefined;
			if (p.runtime && isOfficialRuntime(p.name, source.url)) return undefined;
			// A scoped registry only serves its own scope.
			const scope = scopeOfPackage(p.name);
			const registry = configs
				.flatMap((c) => c.registries)
				.find(
					(r) =>
						hostOf(r.url) === source.host &&
						(r.scope === undefined || r.scope === scope),
				);
			if (registry) {
				fromRegistry(source.host, registry);
				return undefined;
			}
			return unexpectedHostFinding(
				lock,
				p,
				displayHost(source.url, source.host),
				shown,
				"which is neither the public npm registry nor a registry configured for this package next to the lockfile",
			);
		}
	}
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

const integrityFindings = (
	lock: Lockfile,
	packages: ReadonlyArray<LockedPackage>,
): FindingInput[] => {
	const missing: string[] = [];
	const weak: string[] = [];
	let missingLine: number | undefined;
	let weakLine: number | undefined;
	for (const p of packages) {
		if (p.bundled) continue;
		const kind = classifySource(p.source).kind;
		if (kind !== "registry" && kind !== "tarball") continue;
		// npm workspaces and the root are not downloaded.
		if (lock.manager === "npm" && !p.version && !p.source) continue;
		const strength = integrityStrength(p.integrity);
		if (strength === "none") {
			missing.push(label(p));
			missingLine ??= p.line;
		} else if (strength === "weak") {
			weak.push(label(p));
			weakLine ??= p.line;
		}
	}
	const out: FindingInput[] = [];
	const m = unique(missing);
	const w = unique(weak);
	if (m.length)
		out.push({
			...base,
			ruleId: rule("missing-integrity"),
			title: `${m.length} ${m.length === 1 ? "entry" : "entries"} in ${baseName(lock.path)} ${m.length === 1 ? "has" : "have"} no integrity hash`,
			severity: "low",
			message: truncate(
				`The lockfile records no valid integrity hash for ${listNames(m)}. The package manager cannot detect a tarball that was changed on the server or in transit.`,
				600,
			),
			location: { file: lock.path, line: missingLine },
			evidence: truncate(m.join(", ")),
			remediation:
				"Delete the affected entries (or the lockfile) and reinstall with a current package manager so it records integrity hashes; then commit the lockfile.",
			references: [LOCKFILE_LINT, NPM_LOCKFILE, cweUrl(494), owaspUrl("a08")],
			tags: ["cwe-494", "owasp-a08"],
		});
	if (w.length)
		out.push({
			...base,
			ruleId: rule("weak-integrity"),
			title: `${w.length} ${w.length === 1 ? "entry" : "entries"} in ${baseName(lock.path)} ${w.length === 1 ? "is" : "are"} only checked with SHA-1`,
			severity: "low",
			message: truncate(
				`The only integrity hash recorded for ${listNames(w)} is SHA-1, which is no longer collision resistant.`,
				600,
			),
			location: { file: lock.path, line: weakLine },
			evidence: truncate(w.join(", ")),
			remediation:
				"Regenerate the lockfile with a current package manager so it records sha512 integrity hashes.",
			references: [LOCKFILE_LINT, NPM_LOCKFILE, cweUrl(328)],
			tags: ["cwe-328"],
		});
	return out;
};

/** package.json dependencies the lockfile does not record (or records differently). */
const driftFinding = (
	lock: Lockfile,
	manifest: SourceFile,
	importer: Importer,
): FindingInput | undefined => {
	const json = parseJson(manifest.text);
	if (!isRecord(json)) return undefined;
	const drifted: Array<{ name: string; text: string; evidence: string }> = [];
	for (const [name, specs] of declaredSpecs(json)) {
		const spec = specs?.[0] ?? "";
		// Specs can carry credentials (git+https://user:token@…).
		const shown = displaySpec(spec);
		if (!importer.has(name))
			drifted.push({
				name,
				text: `${name} is missing`,
				evidence: `${name}: ${shown} (not locked)`,
			});
		else {
			const locked = importer.get(name);
			if (locked && !locked.includes(spec)) {
				const lockedShown = displaySpec(locked[0] ?? "");
				drifted.push({
					name,
					text: `${name} is "${shown}" but locked as "${lockedShown}"`,
					evidence: `${name}: ${shown} (locked ${lockedShown})`,
				});
			}
		}
	}
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

/** All findings for one parsed lockfile. */
export const lockfileFindings = (
	lock: Lockfile,
	configs: ReadonlyArray<FileConfig>,
	manifests: ReadonlyMap<string, SourceFile>,
): FindingInput[] => {
	const perEntry: FindingInput[] = [];
	const custom = new Map<string, CustomSource>();
	for (const p of lock.packages) {
		const f = sourceFinding(lock, p, configs, custom);
		if (f) perEntry.push(f);
	}
	const findings = capPerRule(perEntry);
	for (const problem of lock.problems ?? [])
		findings.push(partlyCheckedFinding(lock.path, problem));
	for (const c of custom.values()) findings.push(customSourceFinding(lock, c));
	findings.push(...integrityFindings(lock, lock.packages));
	findings.push(...installScriptFindings(lock, lock.packages, configs));
	const lockDir = dirOf(lock.path);
	for (const [dir, importer] of lock.importers) {
		if (escapesRoot(lockDir, dir)) continue;
		const manifest = manifests.get(
			joinDir(joinDir(lockDir, dir), "package.json"),
		);
		const drift = manifest && driftFinding(lock, manifest, importer);
		if (drift) findings.push(drift);
	}
	return findings;
};

/** Registries (custom or insecure) and disabled TLS checks in a config file. */
export const configFindings = (config: FileConfig): FindingInput[] => {
	const out: FindingInput[] = [];
	for (const r of config.registries) {
		const host = hostOf(r.url);
		if (r.url.toLowerCase().startsWith("http:"))
			out.push(
				insecureFinding(
					r.file,
					r.line,
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
