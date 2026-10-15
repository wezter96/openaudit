import {
	AuditorError,
	type Confidence,
	defineAuditor,
	type FindingInput,
	requireWorkspace,
	Severity,
	skip,
	type Workspace,
} from "@openaudit/core";
import { Effect, Schema } from "effect";

import {
	type Dependency,
	dependencyLineFinder,
	isManifest,
	parseDependencies,
	uniqueDependencies,
} from "./dependencies";
import {
	compileLicensePolicy,
	evaluateLicense,
	formatLicenseExpression,
	globMatcher,
	type LicensePolicy,
	type LicenseText,
	type LicenseVerdict,
	parseLicense,
} from "./spdx";
import {
	baseName,
	isRecord,
	parseJsonc,
	readTextFiles,
	type SourceFile,
	truncate,
} from "./util";

export const LICENSES_ID = "code.licenses";

/** `options.settings["code.licenses"]`. */
export const LicenseSettings = Schema.Struct({
	/** Licence ids or globs (`GPL-*`) that fail the policy. */
	deny: Schema.optional(Schema.Array(Schema.String)),
	/** When set, any licence not listed fails the policy. */
	allow: Schema.optional(Schema.Array(Schema.String)),
	/** Severity for missing or unreadable licences, or `off` (default `low`). */
	unknown: Schema.optional(Schema.Union([Severity, Schema.Literal("off")])),
	/** Package names or globs (`@acme/*`) exempt from the policy. */
	ignorePackages: Schema.optional(Schema.Array(Schema.String)),
});
export type LicenseSettings = typeof LicenseSettings.Type;

/* -------------------------------------------------------------------------- */
/*                              Licence metadata                              */
/* -------------------------------------------------------------------------- */

/** A dependency's declared licence and the file it was read from. */
export interface DeclaredLicense {
	/** `undefined`: the metadata was found but declares no licence. */
	readonly license?: string;
	readonly source: string;
}

/** A workspace-relative path, or a directory prefix ending in `/`. */
type FilePath = string;

const keyOf = (ecosystem: string, name: string, version: string) =>
	`${ecosystem}|${ecosystem === "PyPI" ? name.toLowerCase() : name}|${version}`;

const dirOf = (path: FilePath) => path.slice(0, path.lastIndexOf("/") + 1);

const stringOrType = (v: unknown): string | undefined =>
	typeof v === "string"
		? v
		: isRecord(v) && typeof v.type === "string"
			? v.type
			: undefined;

/**
 * Joins licences that are alternatives (npm's legacy `licenses`, Composer's
 * `license` array, Python classifiers) into one SPDX expression. Values that
 * do not parse are kept as written, so the result reads as unknown.
 */
export const anyOf = (values: ReadonlyArray<string>): string | undefined => {
	const trimmed = values.map((v) => v.trim()).filter(Boolean);
	if (trimmed.length <= 1) return trimmed[0];
	const parsed = trimmed.map(parseLicense);
	return parsed.every((p) => p !== undefined)
		? parsed
				.map((p) =>
					p.type === "and"
						? `(${formatLicenseExpression(p)})`
						: formatLicenseExpression(p),
				)
				.join(" OR ")
		: trimmed.join(", ");
};

/** `license` (string or legacy `{type}`) or legacy `licenses` (alternatives). */
export const npmLicense = (
	pkg: Record<string, unknown>,
): string | undefined => {
	const single = stringOrType(pkg.license)?.trim();
	if (single) return single;
	return Array.isArray(pkg.licenses)
		? anyOf(pkg.licenses.flatMap((l) => stringOrType(l) ?? []))
		: undefined;
};

/** A lockfile's record of a package: its licence and npm install path. */
interface LockEntry {
	readonly source: string;
	readonly license?: string;
	readonly installDir?: string;
}

const NODE_MODULES = "node_modules/";

type LockPackage = Record<string, unknown> & { readonly version: string };

/** An installed (not linked) package of a package-lock `packages` map. */
const isInstalledPackage = (
	key: FilePath,
	value: unknown,
): value is LockPackage => {
	if (!key.includes(NODE_MODULES) || !isRecord(value)) return false;
	return !value.link && typeof value.version === "string";
};

const packageLockEntry = (
	file: SourceFile,
	key: FilePath,
	value: LockPackage,
): [string, LockEntry] => {
	const name =
		typeof value.name === "string"
			? value.name
			: key.slice(key.lastIndexOf(NODE_MODULES) + NODE_MODULES.length);
	const license = npmLicense(value);
	return [
		keyOf("npm", name, value.version),
		{
			source: file.path,
			installDir: `${dirOf(file.path)}${key}`,
			...(license ? { license } : {}),
		},
	];
};

const packageLockEntries = (file: SourceFile): Array<[string, LockEntry]> => {
	const json = parseJsonc(file.text);
	if (!isRecord(json) || !isRecord(json.packages)) return [];
	return Object.entries(json.packages).flatMap(([key, value]) =>
		isInstalledPackage(key, value) ? [packageLockEntry(file, key, value)] : [],
	);
};

const arrayOrEmpty = (v: unknown): ReadonlyArray<unknown> =>
	Array.isArray(v) ? v : [];

type ComposerPackage = Record<string, unknown> & {
	readonly name: string;
	readonly version: string;
};

const isComposerPackage = (p: unknown): p is ComposerPackage => {
	if (!isRecord(p)) return false;
	return typeof p.name === "string" && typeof p.version === "string";
};

const composerLockEntry = (
	file: SourceFile,
	p: ComposerPackage,
): [string, LockEntry] => {
	const license = Array.isArray(p.license)
		? anyOf(p.license.filter((l): l is string => typeof l === "string"))
		: undefined;
	return [
		keyOf("Packagist", p.name, p.version.replace(/^v/, "")),
		{ source: file.path, ...(license ? { license } : {}) },
	];
};

const composerLockEntries = (file: SourceFile): Array<[string, LockEntry]> => {
	const json = parseJsonc(file.text);
	if (!isRecord(json)) return [];
	return [...arrayOrEmpty(json.packages), ...arrayOrEmpty(json["packages-dev"])]
		.filter(isComposerPackage)
		.map((p) => composerLockEntry(file, p));
};

const LOCKFILE_READERS = new Map<
	string,
	(file: SourceFile) => Array<[string, LockEntry]>
>([
	["package-lock.json", packageLockEntries],
	["npm-shrinkwrap.json", packageLockEntries],
	["composer.lock", composerLockEntries],
]);

/**
 * Licences recorded in lockfiles: npm lockfile v2/v3 `packages[].license` and
 * composer.lock `license` arrays. The first file to list a package wins.
 */
export const lockfileLicenses = (
	files: ReadonlyArray<SourceFile>,
): Map<string, LockEntry> => {
	const out = new Map<string, LockEntry>();
	for (const file of files) {
		const entries = LOCKFILE_READERS.get(baseName(file.path))?.(file) ?? [];
		for (const [key, entry] of entries) if (!out.has(key)) out.set(key, entry);
	}
	return out;
};

const NPM_NAME = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i;

const readJson = (ws: Workspace, path: FilePath) =>
	ws.readText(path).pipe(
		Effect.map((text) => parseJsonc(text)),
		Effect.orElseSucceed(() => undefined),
	);

/** The lockfile directory and the root, where metadata may be installed. */
const searchDirs = (d: Dependency) => [...new Set([dirOf(d.file), ""])];

const declaredAt = (
	source: FilePath,
	license: LicenseText | undefined,
): DeclaredLicense => (license ? { license, source } : { source });

/**
 * Installed npm metadata, next to the lockfile and at the root: the
 * package-lock install path, the hoisted `node_modules/<name>`, then the
 * pnpm and bun (isolated linker) stores and their hoisted links. Store
 * entries with a peer-dependency suffix are not found.
 */
const npmCandidates = (d: Dependency, installDir: FilePath | undefined) => [
	...(installDir ? [installDir] : []),
	...searchDirs(d).flatMap((dir) => [
		`${dir}node_modules/${d.name}`,
		...[".pnpm", ".bun"].flatMap((store) => [
			`${dir}node_modules/${store}/${d.name.replace("/", "+")}@${d.version}/node_modules/${d.name}`,
			`${dir}node_modules/${store}/node_modules/${d.name}`,
		]),
	]),
];

const isInstalledVersion = (
	pkg: unknown,
	d: Dependency,
): pkg is Record<string, unknown> => isRecord(pkg) && pkg.version === d.version;

/**
 * The first installed npm package.json matching the dependency's version.
 * Reads go through the Workspace, so they stay inside the target.
 */
const installedNpm = (
	ws: Workspace,
	d: Dependency,
	installDir: FilePath | undefined,
): Effect.Effect<DeclaredLicense | undefined> =>
	Effect.gen(function* () {
		if (!NPM_NAME.test(d.name)) return undefined;
		for (const dir of new Set(npmCandidates(d, installDir))) {
			const path = `${dir}/package.json`;
			const pkg = yield* readJson(ws, path);
			if (isInstalledVersion(pkg, d)) return declaredAt(path, npmLicense(pkg));
		}
		return undefined;
	});

const PYTHON_MINORS = Array.from({ length: 10 }, (_, i) => i + 6);

/** `site-packages` of a `.venv` or `venv` next to `dir`. */
const sitePackages = (ws: Workspace, dir: FilePath) =>
	Effect.filter(
		[".venv", "venv"].flatMap((venv) => [
			...PYTHON_MINORS.map(
				(m) => `${dir}${venv}/lib/python3.${m}/site-packages`,
			),
			`${dir}${venv}/Lib/site-packages`,
		]),
		(path) => ws.exists(path),
		{ concurrency: 8 },
	);

/** A METADATA header field: lowercased name and raw value. */
type MetadataField = readonly [string, string];

const metadataFields = (metadata: string): MetadataField[] => {
	const header = metadata.split(/\r?\n\r?\n/)[0] ?? "";
	return header
		.split(/\r?\n(?![ \t])/)
		.map((line) => /^([\w-]+):[ \t]*([\s\S]*)$/.exec(line))
		.flatMap((m) =>
			m?.[1] ? [[m[1].toLowerCase(), m[2] ?? ""] as const] : [],
		);
};

const fieldValue = (fields: ReadonlyArray<MetadataField>, name: string) =>
	fields.find(([k]) => k === name)?.[1].trim() || undefined;

/** A one-line `License` field, as opposed to a full licence text. */
const isShortLicense = (license: LicenseText) => {
	if (/[\r\n]/.test(license) || license.length > 100) return false;
	return !/^unknown$/i.test(license);
};

const isLicenseClassifier = ([k, v]: MetadataField) =>
	k === "classifier" && v.startsWith("License ::");

const classifierLicenses = (fields: ReadonlyArray<MetadataField>) =>
	fields
		.filter(isLicenseClassifier)
		.map(([, v]) => v.split("::").pop()?.trim() ?? "")
		.filter((v) => v && v !== "OSI Approved");

/**
 * Licence from a wheel's METADATA: `License-Expression` (PEP 639), else a
 * short `License` field that parses, else the licence classifiers.
 */
export const pythonLicense = (metadata: string): string | undefined => {
	const fields = metadataFields(metadata);
	const expression = fieldValue(fields, "license-expression");
	if (expression) return expression;
	const license = fieldValue(fields, "license");
	const short = license && isShortLicense(license) ? license : undefined;
	if (short && parseLicense(short)) return short;
	return anyOf(classifierLicenses(fields)) ?? short;
};

const installedPython = (
	ws: Workspace,
	d: Dependency,
	sites: ReadonlyArray<string>,
): Effect.Effect<DeclaredLicense | undefined> =>
	Effect.gen(function* () {
		if (!/^[A-Za-z0-9][\w.-]*$/.test(d.name)) return undefined;
		const escaped = d.name.replace(/[-_.]+/g, "_");
		const names = [...new Set([d.name, escaped, escaped.toLowerCase()])];
		for (const site of sites)
			for (const name of names) {
				const path = `${site}/${name}-${d.version}.dist-info/METADATA`;
				const text = yield* ws
					.readText(path)
					.pipe(Effect.orElseSucceed(() => undefined));
				if (text !== undefined) return declaredAt(path, pythonLicense(text));
			}
		return undefined;
	});

/* -------------------------------------------------------------------------- */
/*                                  Findings                                  */
/* -------------------------------------------------------------------------- */

const REFERENCES = [
	"https://spdx.org/licenses/",
	"https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/",
];

const EXEMPT = `add the package to ignorePackages in settings["${LICENSES_ID}"]`;

/** One dependency's declared licence, checked against the policy. */
export interface LicenseCheck {
	readonly dependency: Dependency;
	readonly declared: DeclaredLicense;
	readonly policy: LicensePolicy;
	readonly unknownSeverity: Severity | "off";
	readonly line: number | undefined;
}

/** What every licence finding for one dependency says the same way. */
interface FindingContext {
	readonly d: Dependency;
	readonly at: string;
	readonly license: string;
	readonly from: string;
	readonly culprits: string;
	readonly base: Pick<
		FindingInput,
		"category" | "location" | "evidence" | "references"
	>;
}

const POLICY_TAGS = ["licence", "licence-policy"];

/** A policy finding; a broken policy is certain unless `confidence` says so. */
const policyFinding = (
	c: FindingContext,
	f: {
		readonly rule: string;
		readonly title: string;
		readonly severity: Severity;
		readonly message: string;
		readonly remediation: string;
		readonly confidence?: Confidence;
		readonly tags?: ReadonlyArray<string>;
	},
): FindingInput => ({
	...c.base,
	ruleId: `${LICENSES_ID}/${f.rule}`,
	title: truncate(f.title, 120),
	severity: f.severity,
	message: truncate(f.message, 500),
	remediation: f.remediation,
	confidence: f.confidence ?? "high",
	tags: [...(f.tags ?? POLICY_TAGS)],
});

const deniedFinding = (c: FindingContext): FindingInput =>
	policyFinding(c, {
		rule: "denied-license",
		title: `${c.at} uses denied licence ${c.culprits}`,
		severity: "high",
		message: `${c.d.name} ${c.d.version} (${c.d.ecosystem}) is licensed under ${c.license}${c.from}. The licence policy denies ${c.culprits}, and the expression offers no allowed alternative.`,
		remediation: `Replace ${c.d.name} with a package under an accepted licence or obtain a different licence from its authors. If legal review accepts this use, ${EXEMPT}.`,
	});

const notAllowedFinding = (c: FindingContext): FindingInput =>
	policyFinding(c, {
		rule: "license-not-allowed",
		title: `${c.at} uses ${c.culprits}, not on the allow list`,
		severity: "medium",
		message: `${c.d.name} ${c.d.version} (${c.d.ecosystem}) is licensed under ${c.license}${c.from}. The licence policy has an allow list, and ${c.culprits} is not on it.`,
		remediation: `Review ${c.culprits}. Add it to the allow list if it is acceptable, replace ${c.d.name}, or ${EXEMPT}.`,
	});

const unknownFinding = (c: FindingContext, severity: Severity): FindingInput =>
	policyFinding(c, {
		rule: "unknown-license",
		title: c.license
			? `${c.at} has an unrecognised licence: ${c.culprits}`
			: `${c.at} declares no licence`,
		severity,
		message: c.license
			? `${c.d.name} ${c.d.version} (${c.d.ecosystem}) declares "${c.license}"${c.from}, which is not an SPDX licence the policy can evaluate (${c.culprits}).`
			: `${c.d.name} ${c.d.version} (${c.d.ecosystem}) has metadata${c.from} but declares no licence. Without one, no one is granted rights to use it.`,
		remediation: `Check ${c.d.name}'s repository for its actual licence. If it is acceptable, name it in the allow list (a LicenseRef-* id or the exact value) or ${EXEMPT}.`,
		confidence: "medium",
		tags: [...POLICY_TAGS, "unknown-license"],
	});

const findingContext = (
	{ dependency: d, declared, line }: LicenseCheck,
	license: LicenseText,
	verdict: LicenseVerdict,
): FindingContext => {
	const at = `${d.name}@${d.version}`;
	return {
		d,
		at,
		license,
		from: declared.source === d.file ? "" : ` (from ${declared.source})`,
		culprits: verdict.culprits.join(", "),
		base: {
			category: "compliance",
			location: { file: d.file, line },
			evidence: truncate(`${at}: ${license || "(no licence)"}`, 160),
			references: REFERENCES,
		},
	};
};

export const licenseFinding = (
	check: LicenseCheck,
): FindingInput | undefined => {
	const license = check.declared.license ?? "";
	const verdict = evaluateLicense(license, check.policy);
	if (verdict.status === "ok") return undefined;
	const c = findingContext(check, license, verdict);
	if (verdict.status === "denied") return deniedFinding(c);
	if (verdict.status === "not-allowed") return notAllowedFinding(c);
	return check.unknownSeverity === "off"
		? undefined
		: unknownFinding(c, check.unknownSeverity);
};

/** One info finding listing packages whose licence could not be read offline. */
const noDataFinding = (
	missing: ReadonlyArray<Dependency>,
	total: number,
): FindingInput => {
	const shown = missing
		.slice(0, 10)
		.map((d) => `${d.name}@${d.version}`)
		.join(", ");
	const ecosystems = [...new Set(missing.map((d) => d.ecosystem))].join(", ");
	return {
		ruleId: `${LICENSES_ID}/no-license-data`,
		title: `${missing.length} of ${total} dependencies have no licence data to check`,
		severity: "info",
		category: "compliance",
		message: `No licence was found offline for ${missing.length} of ${total} dependencies (${ecosystems}): ${shown}${missing.length > 10 ? ", ..." : ""}. They were not checked against the policy.`,
		evidence: `${missing.length}/${total} dependencies without licence data`,
		remediation:
			"Licences are read from package-lock.json, composer.lock, node_modules and a .venv/venv. Install dependencies before auditing (openaudit itself never installs them), or run the opt-in code.syft-licenses auditor for other ecosystems.",
		references: REFERENCES,
		confidence: "high",
		tags: ["licence", "licence-policy"],
	};
};

/**
 * Dependencies checked per run. Each one can cost a dozen metadata reads, and
 * a lockfile is target input, so a hostile one must not make that unbounded.
 */
export const MAX_LICENSE_DEPENDENCIES = 5000;

const truncatedFinding = (total: number): FindingInput => ({
	ruleId: `${LICENSES_ID}/truncated`,
	title: `Only ${MAX_LICENSE_DEPENDENCIES} of ${total} dependencies were checked`,
	severity: "info",
	category: "compliance",
	message: `The lockfiles list ${total} dependencies; the licence policy was checked for the first ${MAX_LICENSE_DEPENDENCIES} (sorted by lockfile path) and the rest were skipped.`,
	evidence: `${total} dependencies, ${MAX_LICENSE_DEPENDENCIES} checked`,
	remediation:
		"Audit each package of a large monorepo separately, or exempt build tooling with ignorePackages.",
	references: REFERENCES,
	confidence: "high",
	tags: ["licence", "licence-policy"],
});

/* -------------------------------------------------------------------------- */
/*                                  Auditor                                   */
/* -------------------------------------------------------------------------- */

const decodeSettings = Schema.decodeUnknownSync(LicenseSettings);

const invalidSettings = (cause: unknown) =>
	new AuditorError({
		message: `Invalid settings["${LICENSES_ID}"]: ${cause instanceof Error ? cause.message : String(cause)}`,
		cause,
	});

/** Validated settings, or `undefined` when no policy is configured. */
export const readLicenseSettings = (
	raw: unknown,
): Effect.Effect<LicenseSettings | undefined, AuditorError> =>
	raw === undefined
		? Effect.succeed(undefined)
		: Effect.try({
				try: () => decodeSettings(raw, { onExcessProperty: "error" }),
				catch: invalidSettings,
			});

const NO_POLICY = `No licence policy configured. Set options.settings["${LICENSES_ID}"] in openaudit.config.json, for example {"deny": ["AGPL-*", "GPL-*"]} or {"allow": ["MIT", "Apache-2.0", "BSD-*", "ISC"]}.`;

const NOTHING_TO_CHECK = `The licence policy in settings["${LICENSES_ID}"] has no deny or allow list and unknown is off, so there is nothing to check.`;

/** No deny or allow list, and unknown licences are not reported either. */
const checksNothing = (settings: LicenseSettings) => {
	if (settings.deny?.length || settings.allow) return false;
	return (settings.unknown ?? "low") === "off";
};

/**
 * Pinned dependencies outside ignorePackages. Files are sorted so the file a
 * shared dependency is attributed to is stable.
 */
const policyDependencies = (
	sorted: ReadonlyArray<SourceFile>,
	settings: LicenseSettings,
) => {
	const exempt = (settings.ignorePackages ?? []).map(globMatcher);
	return uniqueDependencies(sorted.flatMap(parseDependencies)).filter(
		(d) => !exempt.some((re) => re.test(d.name)),
	);
};

/** Where licences are looked up: lockfiles, then installed metadata. */
interface LicenseSources {
	readonly ws: Workspace;
	readonly locked: Map<string, LockEntry>;
	/** `site-packages` directories found per search directory. */
	readonly sites: Map<string, ReadonlyArray<string>>;
}

/** Virtualenvs next to each Python lockfile and at the root. */
const pythonSiteMap = (ws: Workspace, deps: ReadonlyArray<Dependency>) =>
	Effect.map(
		Effect.forEach(
			[
				...new Set(
					deps.filter((d) => d.ecosystem === "PyPI").flatMap(searchDirs),
				),
			],
			(dir) =>
				Effect.map(sitePackages(ws, dir), (found) => [dir, found] as const),
		),
		(entries) => new Map<string, ReadonlyArray<string>>(entries),
	);

const pythonSites = (src: LicenseSources, d: Dependency) =>
	searchDirs(d).flatMap((dir) => src.sites.get(dir) ?? []);

const declaredLicense = (
	src: LicenseSources,
	d: Dependency,
): Effect.Effect<DeclaredLicense | undefined> =>
	Effect.gen(function* () {
		const lock = src.locked.get(keyOf(d.ecosystem, d.name, d.version));
		if (lock?.license) return { license: lock.license, source: lock.source };
		if (d.ecosystem === "npm")
			return yield* installedNpm(src.ws, d, lock?.installDir);
		if (d.ecosystem === "PyPI")
			return yield* installedPython(src.ws, d, pythonSites(src, d));
		// composer.lock lists every package, with or without a licence.
		return lock ? { source: lock.source } : undefined;
	});

/** The policy checks of one run, over the dependencies within the cap. */
interface LicenseRun {
	readonly deps: ReadonlyArray<Dependency>;
	readonly declared: ReadonlyArray<DeclaredLicense | undefined>;
	readonly policy: LicensePolicy;
	readonly unknownSeverity: Severity | "off";
	readonly lineFor: (d: Dependency) => number | undefined;
	/** Dependencies before the cap. */
	readonly total: number;
}

const runFindings = (run: LicenseRun): FindingInput[] => {
	const findings: FindingInput[] = [];
	const missing: Dependency[] = [];
	run.deps.forEach((d, i) => {
		const found = run.declared[i];
		if (!found) {
			missing.push(d);
			return;
		}
		const finding = licenseFinding({
			dependency: d,
			declared: found,
			policy: run.policy,
			unknownSeverity: run.unknownSeverity,
			line: run.lineFor(d),
		});
		if (finding) findings.push(finding);
	});
	if (missing.length) findings.push(noDataFinding(missing, run.deps.length));
	if (run.total > run.deps.length) findings.push(truncatedFinding(run.total));
	return findings;
};

export const licenses = defineAuditor({
	id: LICENSES_ID,
	title: "Dependency licence policy",
	description: `Checks dependency licences against a policy in settings["${LICENSES_ID}"]: deny and allow lists of SPDX ids or globs, evaluated over SPDX expressions (OR, AND, WITH). Reads licences offline from package-lock.json, composer.lock, installed node_modules and Python virtualenvs. Skipped until a policy is configured.`,
	categories: ["compliance"],
	targets: ["codebase"],
	engine: "builtin",
	network: false,
	// Installed packages in node_modules and virtualenvs are gitignored.
	keepIgnored: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const settings = yield* readLicenseSettings(
				ctx.options.settings?.[LICENSES_ID],
			);
			if (!settings) return yield* skip(NO_POLICY);
			if (checksNothing(settings)) return yield* skip(NOTHING_TO_CHECK);
			const policy = yield* Effect.try({
				try: () => compileLicensePolicy(settings),
				catch: invalidSettings,
			});

			const ws = yield* requireWorkspace(ctx);
			const files = yield* readTextFiles(ws, isManifest, {
				maxBytes: 20 * 1024 * 1024,
				allowMinified: true,
			});
			const sorted = [...files].sort((a, b) => a.path.localeCompare(b.path));
			const all = policyDependencies(sorted, settings);
			const deps = all.slice(0, MAX_LICENSE_DEPENDENCIES);
			if (deps.length === 0)
				return yield* skip("No pinned dependencies found in lockfiles");

			const src: LicenseSources = {
				ws,
				locked: lockfileLicenses(sorted),
				sites: yield* pythonSiteMap(ws, deps),
			};
			const declared = yield* Effect.forEach(
				deps,
				(d) => declaredLicense(src, d),
				{ concurrency: 16 },
			);
			return runFindings({
				deps,
				declared,
				policy,
				unknownSeverity: settings.unknown ?? "low",
				lineFor: dependencyLineFinder(files),
				total: all.length,
			});
		}),
});
