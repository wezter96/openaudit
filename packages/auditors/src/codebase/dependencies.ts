import {
	type AuditContext,
	AuditorError,
	defineAuditor,
	type FindingInput,
	requireWorkspace,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";
import { parse as parseYaml } from "yaml";

import {
	baseName,
	cweUrl,
	fullLineAt,
	isFixturePath,
	isRecord,
	lineLocator,
	owaspUrl,
	parseJsonc,
	readTextFiles,
	type SourceFile,
} from "./util";

/* -------------------------------------------------------------------------- */
/*                                  Parsing                                   */
/* -------------------------------------------------------------------------- */

/** OSV ecosystem names. */
export type Ecosystem =
	| "npm"
	| "PyPI"
	| "Go"
	| "crates.io"
	| "RubyGems"
	| "Packagist";

type FilePath = string;
type FileText = string;
type PackageName = string;
type Version = string;
/** A `name@version` specifier. */
type PackageSpec = string;

export interface Dependency {
	readonly name: string;
	readonly version: string;
	readonly ecosystem: Ecosystem;
	/** Manifest or lockfile the version was read from. */
	readonly file: string;
}

type LockfileParser = (text: FileText, file: FilePath) => Dependency[];

const EXACT_VERSION = /^v?\d+(?:\.\d+){0,3}(?:[-+.][\w.+-]*)?$/;

const dep = (
	name: PackageName,
	version: Version,
	ecosystem: Ecosystem,
	file: FilePath,
): Dependency | undefined => {
	const v = version.trim();
	if (!name || !EXACT_VERSION.test(v)) return undefined;
	return { name, version: v, ecosystem, file };
};

const compact = <A>(xs: ReadonlyArray<A | undefined>): A[] =>
	xs.filter((x): x is A => x !== undefined);

/** Splits `name@version` (scoped names keep their leading `@`). */
const splitAt = (spec: PackageSpec): [string, string] | undefined => {
	const at = spec.lastIndexOf("@");
	return at > 0 ? [spec.slice(0, at), spec.slice(at + 1)] : undefined;
};

const NODE_MODULES = "node_modules/";

/** A lockfile v2+ `packages` entry installed under node_modules (not a link). */
const isInstalledPackage = (
	key: FilePath,
	value: unknown,
): value is Record<string, unknown> =>
	key.includes(NODE_MODULES) && isRecord(value) && !value.link;

const installedName = (key: FilePath, value: Record<string, unknown>) =>
	typeof value.name === "string"
		? value.name
		: key.slice(key.lastIndexOf(NODE_MODULES) + NODE_MODULES.length);

/** Lockfile v2+: a flat `packages` map keyed by install path. */
const packageLockPackages = (
	packages: Record<string, unknown>,
	file: FilePath,
): Array<Dependency | undefined> =>
	Object.entries(packages).map(([key, value]) =>
		isInstalledPackage(key, value)
			? dep(installedName(key, value), String(value.version ?? ""), "npm", file)
			: undefined,
	);

/** Lockfile v1: a nested `dependencies` tree, flattened depth-first. */
const packageLockTree = (
	deps: Record<string, unknown>,
	file: FilePath,
): Array<Dependency | undefined> =>
	Object.entries(deps).flatMap(([name, value]) => {
		if (!isRecord(value)) return [];
		const nested = isRecord(value.dependencies)
			? packageLockTree(value.dependencies, file)
			: [];
		return [dep(name, String(value.version ?? ""), "npm", file), ...nested];
	});

export const parsePackageLock: LockfileParser = (text, file) => {
	const json = parseJsonc(text);
	if (!isRecord(json)) return [];
	if (isRecord(json.packages))
		return compact(packageLockPackages(json.packages, file));
	if (isRecord(json.dependencies))
		return compact(packageLockTree(json.dependencies, file));
	return [];
};

const bunLockDependency = (value: unknown, file: FilePath) => {
	if (!Array.isArray(value) || typeof value[0] !== "string") return undefined;
	const parts = splitAt(value[0]);
	return parts ? dep(parts[0], parts[1], "npm", file) : undefined;
};

/** bun.lock (text, JSONC): `"key": ["name@version", registry, {...}, integrity]`. */
export const parseBunLock: LockfileParser = (text, file) => {
	const json = parseJsonc(text);
	if (!isRecord(json) || !isRecord(json.packages)) return [];
	return compact(
		Object.values(json.packages).map((value) => bunLockDependency(value, file)),
	);
};

/** v9: `name@1.0.0(peer@2)`; v6: `/name@1.0.0`; v5: `/name/1.0.0_peer@2`. */
const pnpmKeyDependency = (rawKey: PackageSpec, file: FilePath) => {
	const key = rawKey
		.replace(/^\//, "")
		.replace(/\(.*$/, "")
		.replace(/_.*$/, "");
	const parts = splitAt(key);
	if (parts && /^\d/.test(parts[1]))
		return dep(parts[0], parts[1], "npm", file);
	const slash = key.lastIndexOf("/");
	return slash > 0
		? dep(key.slice(0, slash), key.slice(slash + 1), "npm", file)
		: undefined;
};

export const parsePnpmLock: LockfileParser = (text, file) => {
	let doc: unknown;
	try {
		doc = parseYaml(text, { maxAliasCount: -1 });
	} catch {
		return [];
	}
	if (!isRecord(doc) || !isRecord(doc.packages)) return [];
	return compact(
		Object.keys(doc.packages).map((rawKey) => pnpmKeyDependency(rawKey, file)),
	);
};

const isBlankOrComment = (line: string) => !line.trim() || line.startsWith("#");

/** Package names from a yarn.lock entry header such as `"a@^1", a@~1.2:`. */
const yarnEntryNames = (header: string): PackageName[] =>
	header
		.replace(/:\s*$/, "")
		.split(",")
		.map((s) => s.trim().replace(/^"|"$/g, ""))
		.map((spec) => {
			const at = spec.indexOf("@", 1);
			return at > 0 ? spec.slice(0, at) : "";
		})
		.filter(Boolean);

/** yarn.lock v1 and Berry (best-effort). */
export const parseYarnLock: LockfileParser = (text, file) => {
	const out: Array<Dependency | undefined> = [];
	let names: PackageName[] = [];
	for (const line of text.split("\n")) {
		if (isBlankOrComment(line)) continue;
		if (!/^\s/.test(line)) {
			names = yarnEntryNames(line);
			continue;
		}
		const version = /^\s+version:?\s+"?([^"\s]+)"?/.exec(line)?.[1];
		if (version && names[0]) {
			out.push(dep(names[0], version, "npm", file));
			names = [];
		}
	}
	return compact(out);
};

export const parseRequirements: LockfileParser = (text, file) =>
	compact(
		text.split("\n").map((raw) => {
			const line = raw.replace(/\s+#.*$/, "").trim();
			const m =
				/^([A-Za-z0-9][\w.-]*)(?:\[[^\]]*\])?\s*===?\s*([\w.!+-]+)/.exec(line);
			return m?.[1] && m[2]
				? dep(m[1].toLowerCase(), m[2], "PyPI", file)
				: undefined;
		}),
	);

/** How a `[[package]]` TOML lockfile is read. */
interface TomlLockFormat {
	readonly ecosystem: Ecosystem;
	/** Skip packages without a `source` key. */
	readonly requireSource: boolean;
}

const tomlPackage = (block: string, file: FilePath, format: TomlLockFormat) => {
	const body = block.split(/^\[/m)[0] ?? "";
	const name = /^name\s*=\s*"([^"]+)"/m.exec(body)?.[1];
	const version = /^version\s*=\s*"([^"]+)"/m.exec(body)?.[1];
	if (format.requireSource && !/^source\s*=/m.test(body)) return undefined;
	return name && version
		? dep(name, version, format.ecosystem, file)
		: undefined;
};

/** `[[package]]` tables with `name`/`version` keys (poetry.lock, Cargo.lock). */
const parseTomlPackages = (
	text: FileText,
	file: FilePath,
	format: TomlLockFormat,
): Dependency[] =>
	compact(
		text
			.split(/^\[\[package\]\]\s*$/m)
			.slice(1)
			.map((block) => tomlPackage(block, file, format)),
	);

export const parsePoetryLock = (text: FileText, file: FilePath) =>
	parseTomlPackages(text, file, { ecosystem: "PyPI", requireSource: false });

/** Workspace-local crates have no `source` and are skipped. */
export const parseCargoLock = (text: FileText, file: FilePath) =>
	parseTomlPackages(text, file, {
		ecosystem: "crates.io",
		requireSource: true,
	});

/** One `module version` requirement line of a go.mod. */
const goRequirement = (line: string, file: FilePath) => {
	const m = /^\s*([^\s/]+\/\S+|\S+\.\S+)\s+(v[^\s]+)/.exec(
		line.replace(/\/\/.*$/, ""),
	);
	if (!m?.[1] || !m[2]) return undefined;
	return dep(
		m[1],
		m[2].replace(/^v/, "").replace(/\+incompatible$/, ""),
		"Go",
		file,
	);
};

export const parseGoMod: LockfileParser = (text, file) => {
	const out: Array<Dependency | undefined> = [];
	let inBlock = false;
	for (const line of text.split("\n")) {
		if (/^require\s*\($/.test(line.trim())) inBlock = true;
		else if (inBlock && line.trim() === ")") inBlock = false;
		else if (inBlock) out.push(goRequirement(line, file));
		else if (/^require\s+/.test(line))
			out.push(goRequirement(line.replace(/^require\s+/, ""), file));
	}
	return compact(out);
};

export const parseGemfileLock: LockfileParser = (text, file) => {
	const out: Array<Dependency | undefined> = [];
	let inGem = false;
	for (const line of text.split("\n")) {
		if (/^\S/.test(line)) inGem = line.trim() === "GEM";
		if (!inGem) continue;
		const m = /^ {4}([\w.-]+) \(([^)]+)\)$/.exec(line);
		if (m?.[1] && m[2])
			out.push(
				dep(
					m[1],
					m[2].replace(/-(?:x86|arm|aarch|java|universal|x64).*$/, ""),
					"RubyGems",
					file,
				),
			);
	}
	return compact(out);
};

const arrayField = (json: Record<string, unknown>, key: string): unknown[] => {
	const value = json[key];
	return Array.isArray(value) ? value : [];
};

const isComposerPackage = (
	p: unknown,
): p is { readonly name: string; readonly version: string } =>
	isRecord(p) && typeof p.name === "string" && typeof p.version === "string";

export const parseComposerLock: LockfileParser = (text, file) => {
	const json = parseJsonc(text);
	if (!isRecord(json)) return [];
	const list = [
		...arrayField(json, "packages"),
		...arrayField(json, "packages-dev"),
	];
	return compact(
		list.map((p) =>
			isComposerPackage(p)
				? dep(p.name, p.version.replace(/^v/, ""), "Packagist", file)
				: undefined,
		),
	);
};

const PARSERS: ReadonlyArray<readonly [RegExp, LockfileParser]> = [
	[/(^|\/)(package-lock|npm-shrinkwrap)\.json$/, parsePackageLock],
	[/(^|\/)bun\.lock$/, parseBunLock],
	[/(^|\/)pnpm-lock\.yaml$/, parsePnpmLock],
	[/(^|\/)yarn\.lock$/, parseYarnLock],
	[/(^|\/)requirements[\w.-]*\.txt$/, parseRequirements],
	[/(^|\/)poetry\.lock$/, parsePoetryLock],
	[/(^|\/)go\.mod$/, parseGoMod],
	[/(^|\/)Cargo\.lock$/, parseCargoLock],
	[/(^|\/)Gemfile\.lock$/, parseGemfileLock],
	[/(^|\/)composer\.lock$/, parseComposerLock],
];

/** Parses any supported lockfile/manifest; `[]` for unknown files. */
export const parseDependencies = (file: SourceFile): Dependency[] => {
	const parser = PARSERS.find(([re]) => re.test(file.path))?.[1];
	return parser ? parser(file.text, file.path) : [];
};

export const isManifest = (path: FilePath) =>
	!isFixturePath(path) &&
	(PARSERS.some(([re]) => re.test(path)) || baseName(path) === "package.json");

/* -------------------------------------------------------------------------- */
/*                           package.json declarations                        */
/* -------------------------------------------------------------------------- */

export const DEP_FIELDS = [
	"dependencies",
	"devDependencies",
	"optionalDependencies",
	"peerDependencies",
] as const;

/** One string-valued entry of a package.json dependency field. */
interface DeclaredSpec {
	readonly field: (typeof DEP_FIELDS)[number];
	readonly name: PackageName;
	readonly spec: string;
}

type Locate = (name: PackageName) => FindingInput["location"];

const UNBOUNDED_SPEC = /^(\*|latest|x|)$/i;
const URL_SPEC =
	/^(git(\+[a-z]+)?:|git@|https?:|github:|gitlab:|bitbucket:|gist:)/i;
const REPO_SHORTHAND = /^[\w.-]+\/[\w.-]+(#.*)?$/;

const declaredSpecs = (json: Record<string, unknown>): DeclaredSpec[] =>
	DEP_FIELDS.flatMap((field) => {
		const deps = json[field];
		if (!isRecord(deps)) return [];
		return Object.entries(deps).flatMap(([name, raw]) =>
			typeof raw === "string" ? [{ field, name, spec: raw.trim() }] : [],
		);
	});

const isUnbounded = (s: DeclaredSpec) =>
	s.field !== "peerDependencies" && UNBOUNDED_SPEC.test(s.spec);

const isUrlSpec = (s: DeclaredSpec) =>
	URL_SPEC.test(s.spec) || REPO_SHORTHAND.test(s.spec);

const unpinnedFinding = (
	{ field, name, spec }: DeclaredSpec,
	locate: Locate,
): FindingInput => ({
	ruleId: "code.dependencies/unpinned-version",
	title: `Unbounded version for ${name}`,
	severity: "medium",
	category: "supply-chain",
	message: `${field}.${name} is "${spec || "(empty)"}", so any future release (including a malicious or breaking one) is installed automatically.`,
	location: locate(name),
	evidence: `"${name}": "${spec}"`,
	remediation: "Pin a semver range such as ^1.2.3 and commit the lockfile.",
	references: [owaspUrl("a06"), cweUrl(1357)],
	confidence: "high",
	tags: ["cwe-1357", "owasp-a06"],
});

const urlFinding = (
	{ field, name, spec }: DeclaredSpec,
	locate: Locate,
): FindingInput => {
	const pinned = /#[0-9a-f]{40}$/i.test(spec);
	return {
		ruleId: "code.dependencies/url-dependency",
		title: `${name} is installed from a URL`,
		severity: pinned ? "low" : "medium",
		category: "supply-chain",
		message: `${field}.${name} points at "${spec}" instead of a registry version. It bypasses registry integrity checks and audits${pinned ? "" : ", and can change under you because it is not pinned to a commit"}.`,
		location: locate(name),
		evidence: `"${name}": "${spec}"`,
		remediation:
			"Publish the package to a registry (public or private) and depend on a version; if you must use git, pin a full commit SHA.",
		references: [owaspUrl("a08"), cweUrl(829)],
		confidence: "high",
		tags: ["cwe-829", "owasp-a08"],
	};
};

const specFindings = (s: DeclaredSpec, locate: Locate): FindingInput[] => {
	if (isUnbounded(s)) return [unpinnedFinding(s, locate)];
	if (isUrlSpec(s)) return [urlFinding(s, locate)];
	return [];
};

/** Locates a dependency by the first occurrence of its quoted name. */
const packageJsonLocator = (file: SourceFile): Locate => {
	const lineOf = lineLocator(file.text);
	return (name) => {
		const i = file.text.indexOf(`"${name}"`);
		return { file: file.path, line: i === -1 ? undefined : lineOf(i) };
	};
};

/** Wildcard and URL dependency specs in a package.json. */
export const checkPackageJson = (file: SourceFile): FindingInput[] => {
	const json = parseJsonc(file.text);
	if (!isRecord(json)) return [];
	const locate = packageJsonLocator(file);
	return declaredSpecs(json).flatMap((s) => specFindings(s, locate));
};

/* -------------------------------------------------------------------------- */
/*                                    OSV                                     */
/* -------------------------------------------------------------------------- */

export const OSV_API = "https://api.osv.dev/v1";
const BATCH_SIZE = 1000;
const MAX_DETAILS = 100;

/** An OSV advisory id such as `GHSA-...`, `CVE-...` or `PYSEC-...`. */
type AdvisoryId = string;
/** A CVSS vector such as `CVSS:3.1/AV:N/AC:L/...`. */
type CvssVector = string;
type CvssScore = number;

export interface OsvVuln {
	readonly id: string;
	readonly summary?: string;
	readonly details?: string;
	readonly aliases?: ReadonlyArray<string>;
	readonly severity?: ReadonlyArray<OsvSeverityEntry>;
	readonly affected?: ReadonlyArray<OsvAffected>;
	readonly references?: ReadonlyArray<{
		readonly type?: string;
		readonly url: string;
	}>;
	readonly database_specific?: Record<string, unknown>;
}

interface OsvSeverityEntry {
	readonly type: string;
	readonly score: string;
}

interface OsvAffected {
	readonly package?: { readonly name?: string; readonly ecosystem?: string };
	readonly ranges?: ReadonlyArray<{
		readonly events?: ReadonlyArray<Record<string, string>>;
	}>;
	readonly database_specific?: Record<string, unknown>;
	readonly ecosystem_specific?: Record<string, unknown>;
}

type WeightTable = Record<string, Record<string, number>>;
type BaseWeights = readonly [number, number, number, number, number, number];

const CVSS3_WEIGHTS: WeightTable = {
	AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
	AC: { L: 0.77, H: 0.44 },
	UI: { N: 0.85, R: 0.62 },
	C: { H: 0.56, L: 0.22, N: 0 },
	I: { H: 0.56, L: 0.22, N: 0 },
	A: { H: 0.56, L: 0.22, N: 0 },
};

type Cvss3Scope = "U" | "C";

/** Privileges Required weights per scope (unchanged / changed). */
const CVSS3_PRIVILEGES: Record<string, Record<Cvss3Scope, number>> = {
	N: { U: 0.85, C: 0.85 },
	L: { U: 0.62, C: 0.68 },
	H: { U: 0.27, C: 0.5 },
};

const roundUp = (x: CvssScore) => {
	const i = Math.round(x * 100_000);
	return i % 10_000 === 0 ? i / 100_000 : (Math.floor(i / 10_000) + 1) / 10;
};

/** `K:V` metrics of a CVSS vector, keyed by metric. */
const vectorMetrics = (vector: CvssVector): Record<string, string> => {
	const m: Record<string, string> = {};
	for (const part of vector.split("/")) {
		const [k, v] = part.split(":");
		if (k && v) m[k] = v;
	}
	return m;
};

/** Weights for six metrics, or undefined when any is missing or unknown. */
const baseWeights = (
	m: Record<string, string>,
	table: WeightTable,
	keys: ReadonlyArray<string>,
): BaseWeights | undefined => {
	const weights = keys.map((k) => (m[k] ? table[k]?.[m[k]] : undefined));
	return weights.some((w) => w === undefined)
		? undefined
		: (weights as unknown as BaseWeights);
};

const isCvss3Scope = (scope: string | undefined): scope is Cvss3Scope =>
	scope === "U" || scope === "C";

const cvss3Score = (
	scope: Cvss3Scope,
	[av, ac, ui, c, i, a]: BaseWeights,
	pr: number,
): CvssScore => {
	const iss = 1 - (1 - c) * (1 - i) * (1 - a);
	const impact =
		scope === "U"
			? 6.42 * iss
			: 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
	const exploitability = 8.22 * av * ac * pr * ui;
	if (impact <= 0) return 0;
	return scope === "U"
		? roundUp(Math.min(impact + exploitability, 10))
		: roundUp(Math.min(1.08 * (impact + exploitability), 10));
};

/** CVSS v3.x base score from a vector like `CVSS:3.1/AV:N/AC:L/...`. */
export const cvss3BaseScore = (vector: CvssVector): CvssScore | undefined => {
	const m = vectorMetrics(vector);
	const scope = m.S;
	if (!isCvss3Scope(scope)) return undefined;
	const weights = baseWeights(m, CVSS3_WEIGHTS, [
		"AV",
		"AC",
		"UI",
		"C",
		"I",
		"A",
	]);
	const pr = CVSS3_PRIVILEGES[m.PR ?? ""]?.[scope];
	if (!weights || pr === undefined) return undefined;
	return cvss3Score(scope, weights, pr);
};

export const severityFromScore = (score: CvssScore): Severity =>
	score >= 9
		? "critical"
		: score >= 7
			? "high"
			: score >= 4
				? "medium"
				: score > 0
					? "low"
					: "info";

const LABELS: Record<string, Severity> = {
	CRITICAL: "critical",
	HIGH: "high",
	MODERATE: "medium",
	MEDIUM: "medium",
	LOW: "low",
};

const CVSS2_WEIGHTS: WeightTable = {
	AV: { L: 0.395, A: 0.646, N: 1 },
	AC: { H: 0.35, M: 0.61, L: 0.71 },
	Au: { M: 0.45, S: 0.56, N: 0.704 },
	C: { N: 0, P: 0.275, C: 0.66 },
	I: { N: 0, P: 0.275, C: 0.66 },
	A: { N: 0, P: 0.275, C: 0.66 },
};

/** CVSS v2 base score from a vector like `AV:N/AC:L/Au:N/C:P/I:P/A:P`. */
export const cvss2BaseScore = (vector: CvssVector): CvssScore | undefined => {
	const weights = baseWeights(
		vectorMetrics(vector.replace(/[()]/g, "")),
		CVSS2_WEIGHTS,
		["AV", "AC", "Au", "C", "I", "A"],
	);
	if (!weights) return undefined;
	const [av, ac, au, c, i, a] = weights;
	const impact = 10.41 * (1 - (1 - c) * (1 - i) * (1 - a));
	const exploitability = 20 * av * ac * au;
	const f = impact === 0 ? 0 : 1.176;
	return Math.round((0.6 * impact + 0.4 * exploitability - 1.5) * f * 10) / 10;
};

/** Severity of one entry: a scorable CVSS v3 vector, else a numeric score. */
const entrySeverity = (s: OsvSeverityEntry): Severity | undefined => {
	const cvss3 = s.type.startsWith("CVSS_V3")
		? cvss3BaseScore(s.score)
		: undefined;
	if (cvss3 !== undefined) return severityFromScore(cvss3);
	const n = Number(s.score);
	return Number.isFinite(n) && n > 0 ? severityFromScore(n) : undefined;
};

const scoredSeverity = (vuln: OsvVuln): Severity | undefined => {
	for (const s of vuln.severity ?? []) {
		const sev = entrySeverity(s);
		if (sev) return sev;
	}
	return undefined;
};

const labelSeverity = (vuln: OsvVuln): Severity | undefined => {
	const labels = [
		vuln.database_specific?.severity,
		...(vuln.affected ?? []).flatMap((a) => [
			a.database_specific?.severity,
			a.ecosystem_specific?.severity,
		]),
	];
	return labels
		.map((label) =>
			typeof label === "string" ? LABELS[label.toUpperCase()] : undefined,
		)
		.find((sev): sev is Severity => Boolean(sev));
};

const cvss2Severity = (vuln: OsvVuln): Severity | undefined => {
	for (const s of vuln.severity ?? []) {
		if (s.type !== "CVSS_V2") continue;
		const score = cvss2BaseScore(s.score);
		if (score !== undefined) return severityFromScore(score);
	}
	return undefined;
};

/**
 * Severity from a CVSS v3 vector, a numeric score, the database's own label
 * (GitHub's label already reflects CVSS v4), then a CVSS v2 vector. CVSS v4
 * vectors are not scored here: their score needs MacroVector lookup tables.
 */
export const osvSeverity = (vuln: OsvVuln): Severity =>
	scoredSeverity(vuln) ??
	labelSeverity(vuln) ??
	cvss2Severity(vuln) ??
	"medium";

/** An `affected` entry for `d`, or one that names no package. */
const affectsPackage = (a: OsvAffected, d: Dependency) =>
	!a.package?.name || a.package.name.toLowerCase() === d.name.toLowerCase();

const fixedEvents = (a: OsvAffected): Version[] =>
	(a.ranges ?? []).flatMap((r) =>
		(r.events ?? []).flatMap((e) => (e.fixed ? [e.fixed] : [])),
	);

/** Earliest `fixed` versions published for this package. */
export const fixedVersions = (vuln: OsvVuln, d: Dependency): string[] => [
	...new Set(
		(vuln.affected ?? [])
			.filter((a) => affectsPackage(a, d))
			.flatMap(fixedEvents),
	),
];

type Http = AuditContext["http"];

const postJson = (http: Http, url: string, body: unknown) =>
	Effect.flatMap(
		http(url, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(body),
			timeoutMs: 60_000,
			maxBytes: 50 * 1024 * 1024,
		}),
		(res) =>
			res.status === 200
				? Effect.try({
						try: () => JSON.parse(res.body) as unknown,
						catch: (cause) =>
							new AuditorError({ message: "OSV returned invalid JSON", cause }),
					})
				: Effect.fail(
						new AuditorError({
							message: `OSV query failed with HTTP ${res.status}`,
						}),
					),
	);

const batchResults = (json: unknown): unknown[] =>
	isRecord(json) && Array.isArray(json.results) ? json.results : [];

const resultIds = (result: unknown): AdvisoryId[] => {
	const vulns =
		isRecord(result) && Array.isArray(result.vulns) ? result.vulns : [];
	return vulns.flatMap((v) =>
		isRecord(v) && typeof v.id === "string" ? [v.id] : [],
	);
};

/** Vulnerability ids per dependency (same order as `deps`), via `/v1/querybatch`. */
export const queryOsvBatch = (
	http: Http,
	deps: ReadonlyArray<Dependency>,
): Effect.Effect<string[][], AuditorError> =>
	Effect.gen(function* () {
		const ids: string[][] = [];
		for (let start = 0; start < deps.length; start += BATCH_SIZE) {
			const chunk = deps.slice(start, start + BATCH_SIZE);
			const json = yield* postJson(http, `${OSV_API}/querybatch`, {
				queries: chunk.map((d) => ({
					package: { name: d.name, ecosystem: d.ecosystem },
					version: d.version,
				})),
			});
			const results = batchResults(json);
			chunk.forEach((_, i) => {
				ids.push(resultIds(results[i]));
			});
		}
		return ids;
	});

const parseOsvRecord = (status: number, body: string): OsvVuln | undefined => {
	const v: unknown = status === 200 ? JSON.parse(body) : undefined;
	return isRecord(v) && typeof v.id === "string"
		? (v as unknown as OsvVuln)
		: undefined;
};

/** Fetches full records for up to `MAX_DETAILS` ids; failures yield no entry. */
export const fetchOsvVulns = (
	http: Http,
	ids: ReadonlyArray<string>,
): Effect.Effect<Map<string, OsvVuln>> =>
	Effect.map(
		Effect.forEach(
			ids.slice(0, MAX_DETAILS),
			(id) =>
				http(`${OSV_API}/vulns/${encodeURIComponent(id)}`, {
					timeoutMs: 30_000,
				}).pipe(
					Effect.flatMap((res) =>
						Effect.try({
							try: () => parseOsvRecord(res.status, res.body),
							catch: (cause) =>
								new AuditorError({
									message: `Invalid OSV record for ${id}`,
									cause,
								}),
						}),
					),
					Effect.orElseSucceed(() => undefined),
				),
			{ concurrency: 8 },
		),
		(vulns) => new Map(vulns.flatMap((v) => (v ? [[v.id, v] as const] : []))),
	);

/** How a vulnerable-dependency finding words its message and advice. */
export interface VulnWording {
	readonly ruleId: string;
	/** Verb phrase between the package and the advisory id. */
	readonly affected: string;
	/** Appended to the upgrade advice after "(or a newer major)". */
	readonly upgrade: string;
	/** Tags added after `owasp-a06`. */
	readonly tags?: ReadonlyArray<string>;
}

const cweIdsOf = (vuln: OsvVuln | undefined): string[] => {
	const ids = vuln?.database_specific?.cwe_ids;
	return Array.isArray(ids)
		? ids.filter((c): c is string => typeof c === "string")
		: [];
};

const summaryOf = (vuln: OsvVuln | undefined) =>
	vuln?.summary ?? vuln?.details?.split("\n")[0]?.slice(0, 200);

const upgradeAdvice = (
	d: Dependency,
	fixed: ReadonlyArray<Version>,
	wording: VulnWording,
) =>
	fixed.length
		? `Upgrade ${d.name} to ${fixed.join(" or ")} or later (or a newer major)${wording.upgrade}`
		: `No fixed version is published for ${d.name}; consider replacing it or mitigating per the advisory.`;

const advisoryReferences = (id: AdvisoryId, vuln: OsvVuln | undefined) => [
	`https://osv.dev/vulnerability/${id}`,
	...(vuln?.references ?? [])
		.filter((r) => r.type === "ADVISORY" || r.type === "FIX")
		.slice(0, 3)
		.map((r) => r.url),
];

const advisoryTags = (
	wording: VulnWording,
	ids: ReadonlyArray<AdvisoryId>,
	cwes: ReadonlyArray<string>,
) => [
	"owasp-a06",
	...(wording.tags ?? []),
	...cwes.map((c) => c.toLowerCase()),
	...ids.filter((a) => /^(CVE|GHSA)-/.test(a)).map((a) => a.toLowerCase()),
];

/**
 * One finding for an OSV advisory affecting `d`, located at the start of its
 * manifest (callers that know the line set `location` themselves).
 */
export const vulnFinding = (
	wording: VulnWording,
	d: Dependency,
	id: AdvisoryId,
	vuln: OsvVuln | undefined,
): FindingInput => {
	const aliases = (vuln?.aliases ?? []).filter((a) => a !== id);
	const fixed = vuln ? fixedVersions(vuln, d) : [];
	const summary = summaryOf(vuln);
	return {
		ruleId: wording.ruleId,
		title: `${d.name}@${d.version}: ${summary ?? id}`,
		severity: vuln ? osvSeverity(vuln) : "medium",
		category: "supply-chain",
		message: `${d.name} ${d.version} (${d.ecosystem}) ${wording.affected} ${id}${aliases.length ? ` (${aliases.slice(0, 3).join(", ")})` : ""}${summary ? `: ${summary}` : "."}${vuln ? "" : " Advisory details were not fetched (detail limit reached), so the severity is estimated."}`,
		location: { file: d.file, line: undefined },
		evidence: `${d.name}@${d.version} ${id}`,
		remediation: upgradeAdvice(d, fixed, wording),
		references: advisoryReferences(id, vuln),
		confidence: vuln ? "high" : "medium",
		tags: advisoryTags(wording, [id, ...aliases], cweIdsOf(vuln)),
	};
};

const isCovered = (
	covered: ReadonlySet<AdvisoryId>,
	id: AdvisoryId,
	vuln: OsvVuln | undefined,
) => covered.has(id) || Boolean(vuln?.aliases?.some((a) => covered.has(a)));

/** Advisory ids with their records, skipping aliases of an earlier one. */
const distinctAdvisories = (
	ids: ReadonlyArray<AdvisoryId>,
	details: ReadonlyMap<AdvisoryId, OsvVuln>,
) => {
	const covered = new Set<AdvisoryId>();
	const out: Array<readonly [AdvisoryId, OsvVuln | undefined]> = [];
	for (const id of ids) {
		const vuln = details.get(id);
		if (isCovered(covered, id, vuln)) continue;
		covered.add(id);
		for (const alias of vuln?.aliases ?? []) covered.add(alias);
		out.push([id, vuln]);
	}
	return out;
};

/**
 * Looks `deps` up on OSV and returns one finding per distinct advisory: OSV
 * can return the same advisory under several ids (PYSEC + GHSA, GHSA + CVE).
 */
export const osvFindings = (
	http: Http,
	deps: ReadonlyArray<Dependency>,
	toFinding: (
		d: Dependency,
		id: string,
		vuln: OsvVuln | undefined,
	) => FindingInput,
) =>
	Effect.gen(function* () {
		const idsPerDep = yield* queryOsvBatch(http, deps);
		const details = yield* fetchOsvVulns(http, roundRobin(idsPerDep));
		return deps.flatMap((d, i) =>
			distinctAdvisories(idsPerDep[i] ?? [], details).map(([id, vuln]) =>
				toFinding(d, id, vuln),
			),
		);
	});

const CODE_VULN: VulnWording = {
	ruleId: "code.dependencies/vulnerable-dependency",
	affected: "is affected by",
	upgrade: ", then regenerate the lockfile.",
};

/**
 * Unique ids interleaved across packages, so the detail-fetch cap covers the
 * first advisories of every package before the long tail of any single one.
 */
export const roundRobin = (
	idsPerDep: ReadonlyArray<ReadonlyArray<string>>,
): string[] => {
	const out = new Set<string>();
	const longest = Math.max(0, ...idsPerDep.map((ids) => ids.length));
	for (let round = 0; round < longest; round++)
		for (const ids of idsPerDep) {
			const id = ids[round];
			if (id) out.add(id);
		}
	return [...out];
};

/** Deduplicates by ecosystem/name/version, keeping the first file seen. */
export const uniqueDependencies = (
	deps: ReadonlyArray<Dependency>,
): Dependency[] => {
	const seen = new Map<string, Dependency>();
	for (const d of deps) {
		const key = `${d.ecosystem}|${d.ecosystem === "PyPI" ? d.name.toLowerCase() : d.name}|${d.version}`;
		if (!seen.has(key)) seen.set(key, d);
	}
	return [...seen.values()];
};

/**
 * Index of the dependency's name in a lowercased file, preferring a line that
 * also mentions the resolved version; -1 when the name is absent.
 */
const dependencyIndex = (text: FileText, d: Dependency) => {
	// The version is escaped, so it only matches itself.
	// nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
	const exact = new RegExp(
		`(?<![\\w.^~<>=*-])${d.version.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\w.-])`,
	);
	const name = d.name.toLowerCase();
	let i = text.indexOf(name);
	const first = i;
	while (i !== -1 && !exact.test(fullLineAt(text, i)))
		i = text.indexOf(name, i + 1);
	return i === -1 ? first : i;
};

/**
 * The 1-based line declaring a dependency in its lockfile or manifest,
 * preferring a line that mentions both the name and the resolved version.
 */
export const dependencyLineFinder = (
	files: ReadonlyArray<SourceFile>,
): ((d: Dependency) => number | undefined) => {
	const texts = new Map(files.map((f) => [f.path, f.text.toLowerCase()]));
	const locators = new Map<string, (i: number) => number>();
	const locatorFor = (file: FilePath, text: FileText) => {
		const cached = locators.get(file);
		if (cached) return cached;
		const locate = lineLocator(text);
		locators.set(file, locate);
		return locate;
	};
	return (d) => {
		const text = texts.get(d.file);
		if (!text) return undefined;
		const i = dependencyIndex(text, d);
		return i === -1 ? undefined : locatorFor(d.file, text)(i);
	};
};

export const dependencies = defineAuditor({
	id: "code.dependencies",
	title: "Vulnerable dependencies",
	description:
		"Parses lockfiles and manifests (npm, bun, pnpm, yarn, pip, poetry, Go, Cargo, Bundler, Composer), checks every pinned version against OSV.dev, and flags wildcard and URL dependencies.",
	categories: ["supply-chain", "security"],
	targets: ["codebase"],
	engine: "builtin",
	network: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const files = yield* readTextFiles(ws, isManifest, {
				maxBytes: 20 * 1024 * 1024,
				allowMinified: true,
			});
			if (files.length === 0)
				return yield* skip("No dependency manifests or lockfiles found");

			const findings: FindingInput[] = files
				.filter((f) => baseName(f.path) === "package.json")
				.flatMap(checkPackageJson);

			// Sorted so the file a shared dependency is attributed to is stable.
			const sorted = [...files].sort((a, b) => a.path.localeCompare(b.path));
			const deps = uniqueDependencies(sorted.flatMap(parseDependencies));
			if (deps.length === 0) return findings;
			yield* ctx.log(
				`code.dependencies: querying OSV for ${deps.length} packages`,
			);

			const lineFor = dependencyLineFinder(files);
			findings.push(
				...(yield* osvFindings(ctx.http, deps, (d, id, vuln) => ({
					...vulnFinding(CODE_VULN, d, id, vuln),
					location: { file: d.file, line: lineFor(d) },
				}))),
			);
			return findings;
		}),
});
