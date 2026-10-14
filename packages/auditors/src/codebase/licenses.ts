import {
	AuditorError,
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
	globRegExp,
	type LicensePolicy,
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

const keyOf = (ecosystem: string, name: string, version: string) =>
	`${ecosystem}|${ecosystem === "PyPI" ? name.toLowerCase() : name}|${version}`;

const dirOf = (path: string) => path.slice(0, path.lastIndexOf("/") + 1);

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

const packageLockEntries = (file: SourceFile): Array<[string, LockEntry]> => {
	const json = parseJsonc(file.text);
	if (!isRecord(json) || !isRecord(json.packages)) return [];
	return Object.entries(json.packages).flatMap(([key, value]) => {
		if (
			!key.includes("node_modules/") ||
			!isRecord(value) ||
			value.link ||
			typeof value.version !== "string"
		)
			return [];
		const name =
			typeof value.name === "string"
				? value.name
				: key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);
		const license = npmLicense(value);
		return [
			[
				keyOf("npm", name, value.version),
				{
					source: file.path,
					installDir: `${dirOf(file.path)}${key}`,
					...(license ? { license } : {}),
				},
			],
		];
	});
};

const composerLockEntries = (file: SourceFile): Array<[string, LockEntry]> => {
	const json = parseJsonc(file.text);
	if (!isRecord(json)) return [];
	return [
		...(Array.isArray(json.packages) ? json.packages : []),
		...(Array.isArray(json["packages-dev"]) ? json["packages-dev"] : []),
	].flatMap((p) => {
		if (
			!isRecord(p) ||
			typeof p.name !== "string" ||
			typeof p.version !== "string"
		)
			return [];
		const license = Array.isArray(p.license)
			? anyOf(p.license.filter((l): l is string => typeof l === "string"))
			: undefined;
		return [
			[
				keyOf("Packagist", p.name, p.version.replace(/^v/, "")),
				{ source: file.path, ...(license ? { license } : {}) },
			],
		];
	});
};

/**
 * Licences recorded in lockfiles: npm lockfile v2/v3 `packages[].license` and
 * composer.lock `license` arrays. The first file to list a package wins.
 */
export const lockfileLicenses = (
	files: ReadonlyArray<SourceFile>,
): Map<string, LockEntry> => {
	const out = new Map<string, LockEntry>();
	for (const file of files) {
		const name = baseName(file.path);
		const entries =
			name === "package-lock.json" || name === "npm-shrinkwrap.json"
				? packageLockEntries(file)
				: name === "composer.lock"
					? composerLockEntries(file)
					: [];
		for (const [key, entry] of entries) if (!out.has(key)) out.set(key, entry);
	}
	return out;
};

const NPM_NAME = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i;

const readJson = (ws: Workspace, path: string) =>
	ws.readText(path).pipe(
		Effect.map((text) => parseJsonc(text)),
		Effect.orElseSucceed(() => undefined),
	);

/**
 * Installed npm metadata, next to the lockfile and at the root: the
 * package-lock install path, the hoisted `node_modules/<name>`, then the
 * pnpm and bun (isolated linker) stores and their hoisted links. Store
 * entries with a peer-dependency suffix are not found. Reads go through the
 * Workspace, so they stay inside the target.
 */
const installedNpm = (
	ws: Workspace,
	d: Dependency,
	installDir: string | undefined,
): Effect.Effect<DeclaredLicense | undefined> =>
	Effect.gen(function* () {
		if (!NPM_NAME.test(d.name)) return undefined;
		const dirs = [...new Set([dirOf(d.file), ""])];
		const candidates = [
			...(installDir ? [installDir] : []),
			...dirs.flatMap((dir) => [
				`${dir}node_modules/${d.name}`,
				...[".pnpm", ".bun"].flatMap((store) => [
					`${dir}node_modules/${store}/${d.name.replace("/", "+")}@${d.version}/node_modules/${d.name}`,
					`${dir}node_modules/${store}/node_modules/${d.name}`,
				]),
			]),
		];
		for (const dir of new Set(candidates)) {
			const path = `${dir}/package.json`;
			const pkg = yield* readJson(ws, path);
			if (!isRecord(pkg) || pkg.version !== d.version) continue;
			const license = npmLicense(pkg);
			return license ? { license, source: path } : { source: path };
		}
		return undefined;
	});

const PYTHON_MINORS = Array.from({ length: 10 }, (_, i) => i + 6);

/** `site-packages` of a `.venv` or `venv` next to `dir`. */
const sitePackages = (ws: Workspace, dir: string) =>
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

/**
 * Licence from a wheel's METADATA: `License-Expression` (PEP 639), else a
 * short `License` field that parses, else the licence classifiers.
 */
export const pythonLicense = (metadata: string): string | undefined => {
	const header = metadata.split(/\r?\n\r?\n/)[0] ?? "";
	const fields = header
		.split(/\r?\n(?![ \t])/)
		.map((line) => /^([\w-]+):[ \t]*([\s\S]*)$/.exec(line))
		.flatMap((m) =>
			m?.[1] ? [[m[1].toLowerCase(), m[2] ?? ""] as const] : [],
		);
	const field = (name: string) =>
		fields.find(([k]) => k === name)?.[1].trim() || undefined;
	const expression = field("license-expression");
	if (expression) return expression;
	const license = field("license");
	const short =
		license &&
		!/[\r\n]/.test(license) &&
		license.length <= 100 &&
		!/^unknown$/i.test(license)
			? license
			: undefined;
	if (short && parseLicense(short)) return short;
	const classifiers = fields
		.filter(([k, v]) => k === "classifier" && v.startsWith("License ::"))
		.map(([, v]) => v.split("::").pop()?.trim() ?? "")
		.filter((v) => v && v !== "OSI Approved");
	return anyOf(classifiers) ?? short;
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
				if (text === undefined) continue;
				const license = pythonLicense(text);
				return license ? { license, source: path } : { source: path };
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

export const licenseFinding = (
	d: Dependency,
	declared: DeclaredLicense,
	policy: LicensePolicy,
	unknownSeverity: Severity | "off",
	line: number | undefined,
): FindingInput | undefined => {
	const at = `${d.name}@${d.version}`;
	const license = declared.license ?? "";
	const verdict = evaluateLicense(license, policy);
	const from = declared.source === d.file ? "" : ` (from ${declared.source})`;
	const culprits = verdict.culprits.join(", ");
	const base = {
		category: "compliance",
		location: { file: d.file, line },
		evidence: truncate(`${at}: ${license || "(no licence)"}`, 160),
		references: REFERENCES,
	} as const;
	switch (verdict.status) {
		case "ok":
			return undefined;
		case "denied":
			return {
				...base,
				ruleId: `${LICENSES_ID}/denied-license`,
				title: truncate(`${at} uses denied licence ${culprits}`, 120),
				severity: "high",
				message: truncate(
					`${d.name} ${d.version} (${d.ecosystem}) is licensed under ${license}${from}. The licence policy denies ${culprits}, and the expression offers no allowed alternative.`,
					500,
				),
				remediation: `Replace ${d.name} with a package under an accepted licence or obtain a different licence from its authors. If legal review accepts this use, ${EXEMPT}.`,
				confidence: "high",
				tags: ["licence", "licence-policy"],
			};
		case "not-allowed":
			return {
				...base,
				ruleId: `${LICENSES_ID}/license-not-allowed`,
				title: truncate(`${at} uses ${culprits}, not on the allow list`, 120),
				severity: "medium",
				message: truncate(
					`${d.name} ${d.version} (${d.ecosystem}) is licensed under ${license}${from}. The licence policy has an allow list, and ${culprits} is not on it.`,
					500,
				),
				remediation: `Review ${culprits}. Add it to the allow list if it is acceptable, replace ${d.name}, or ${EXEMPT}.`,
				confidence: "high",
				tags: ["licence", "licence-policy"],
			};
		case "unknown":
			if (unknownSeverity === "off") return undefined;
			return {
				...base,
				ruleId: `${LICENSES_ID}/unknown-license`,
				title: truncate(
					license
						? `${at} has an unrecognised licence: ${culprits}`
						: `${at} declares no licence`,
					120,
				),
				severity: unknownSeverity,
				message: truncate(
					license
						? `${d.name} ${d.version} (${d.ecosystem}) declares "${license}"${from}, which is not an SPDX licence the policy can evaluate (${culprits}).`
						: `${d.name} ${d.version} (${d.ecosystem}) has metadata${from} but declares no licence. Without one, no one is granted rights to use it.`,
					500,
				),
				remediation: `Check ${d.name}'s repository for its actual licence. If it is acceptable, name it in the allow list (a LicenseRef-* id or the exact value) or ${EXEMPT}.`,
				confidence: "medium",
				tags: ["licence", "licence-policy", "unknown-license"],
			};
	}
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

/* -------------------------------------------------------------------------- */
/*                                  Auditor                                   */
/* -------------------------------------------------------------------------- */

const decodeSettings = Schema.decodeUnknownSync(LicenseSettings);

/** Validated settings, or `undefined` when no policy is configured. */
export const readLicenseSettings = (
	raw: unknown,
): Effect.Effect<LicenseSettings | undefined, AuditorError> =>
	raw === undefined
		? Effect.succeed(undefined)
		: Effect.try({
				try: () => decodeSettings(raw, { onExcessProperty: "error" }),
				catch: (cause) =>
					new AuditorError({
						message: `Invalid settings["${LICENSES_ID}"]: ${cause instanceof Error ? cause.message : String(cause)}`,
						cause,
					}),
			});

export const licenses = defineAuditor({
	id: LICENSES_ID,
	title: "Dependency licence policy",
	description: `Checks dependency licences against a policy in settings["${LICENSES_ID}"]: deny and allow lists of SPDX ids or globs, evaluated over SPDX expressions (OR, AND, WITH). Reads licences offline from package-lock.json, composer.lock, installed node_modules and Python virtualenvs. Skipped until a policy is configured.`,
	categories: ["compliance"],
	targets: ["codebase"],
	engine: "builtin",
	network: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const settings = yield* readLicenseSettings(
				ctx.options.settings?.[LICENSES_ID],
			);
			if (!settings)
				return yield* skip(
					`No licence policy configured. Set options.settings["${LICENSES_ID}"] in openaudit.config.json, for example {"deny": ["AGPL-*", "GPL-*"]} or {"allow": ["MIT", "Apache-2.0", "BSD-*", "ISC"]}.`,
				);
			const unknownSeverity = settings.unknown ?? "low";
			if (
				!settings.deny?.length &&
				!settings.allow &&
				unknownSeverity === "off"
			)
				return yield* skip(
					`The licence policy in settings["${LICENSES_ID}"] has no deny or allow list and unknown is off, so there is nothing to check.`,
				);
			const policy = yield* Effect.try({
				try: () => compileLicensePolicy(settings),
				catch: (cause) =>
					new AuditorError({
						message: `Invalid settings["${LICENSES_ID}"]: ${cause instanceof Error ? cause.message : String(cause)}`,
						cause,
					}),
			});
			const exempt = (settings.ignorePackages ?? []).map(globRegExp);

			const ws = yield* requireWorkspace(ctx);
			const files = yield* readTextFiles(ws, isManifest, {
				maxBytes: 20 * 1024 * 1024,
				allowMinified: true,
			});
			// Sorted so the file a shared dependency is attributed to is stable.
			const sorted = [...files].sort((a, b) => a.path.localeCompare(b.path));
			const deps = uniqueDependencies(sorted.flatMap(parseDependencies)).filter(
				(d) => !exempt.some((re) => re.test(d.name)),
			);
			if (deps.length === 0)
				return yield* skip("No pinned dependencies found in lockfiles");

			const locked = lockfileLicenses(sorted);
			// Virtualenvs next to each Python lockfile and at the root.
			const pythonDirs = [
				...new Set(
					deps
						.filter((d) => d.ecosystem === "PyPI")
						.flatMap((d) => [dirOf(d.file), ""]),
				),
			];
			const sites = new Map(
				yield* Effect.forEach(pythonDirs, (dir) =>
					Effect.map(sitePackages(ws, dir), (found) => [dir, found] as const),
				),
			);
			const pythonSites = (d: Dependency) =>
				[...new Set([dirOf(d.file), ""])].flatMap(
					(dir) => sites.get(dir) ?? [],
				);

			const declared = yield* Effect.forEach(
				deps,
				(d) =>
					Effect.gen(function* () {
						const lock = locked.get(keyOf(d.ecosystem, d.name, d.version));
						if (lock?.license)
							return { license: lock.license, source: lock.source };
						if (d.ecosystem === "npm")
							return yield* installedNpm(ws, d, lock?.installDir);
						if (d.ecosystem === "PyPI")
							return yield* installedPython(ws, d, pythonSites(d));
						// composer.lock lists every package, with or without a licence.
						return lock ? { source: lock.source } : undefined;
					}),
				{ concurrency: 16 },
			);

			const lineFor = dependencyLineFinder(files);
			const findings: FindingInput[] = [];
			const missing: Dependency[] = [];
			deps.forEach((d, i) => {
				const found = declared[i];
				if (!found) {
					missing.push(d);
					return;
				}
				const finding = licenseFinding(
					d,
					found,
					policy,
					unknownSeverity,
					lineFor(d),
				);
				if (finding) findings.push(finding);
			});
			if (missing.length) findings.push(noDataFinding(missing, deps.length));
			return findings;
		}),
});
