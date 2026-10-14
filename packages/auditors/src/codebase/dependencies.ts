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

export interface Dependency {
	readonly name: string;
	readonly version: string;
	readonly ecosystem: Ecosystem;
	/** Manifest or lockfile the version was read from. */
	readonly file: string;
}

const EXACT_VERSION = /^v?\d+(?:\.\d+){0,3}(?:[-+.][\w.+-]*)?$/;

const dep = (
	name: string,
	version: string,
	ecosystem: Ecosystem,
	file: string,
): Dependency | undefined => {
	const v = version.trim();
	if (!name || !EXACT_VERSION.test(v)) return undefined;
	return { name, version: v, ecosystem, file };
};

const compact = <A>(xs: ReadonlyArray<A | undefined>): A[] =>
	xs.filter((x): x is A => x !== undefined);

/** Splits `name@version` (scoped names keep their leading `@`). */
const splitAt = (spec: string): [string, string] | undefined => {
	const at = spec.lastIndexOf("@");
	return at > 0 ? [spec.slice(0, at), spec.slice(at + 1)] : undefined;
};

export const parsePackageLock = (text: string, file: string): Dependency[] => {
	const json = parseJsonc(text);
	if (!isRecord(json)) return [];
	const out: Array<Dependency | undefined> = [];
	if (isRecord(json.packages)) {
		for (const [key, value] of Object.entries(json.packages)) {
			if (!key || !isRecord(value) || value.link) continue;
			const name =
				typeof value.name === "string"
					? value.name
					: key.slice(
							key.lastIndexOf("node_modules/") + "node_modules/".length,
						);
			if (!key.includes("node_modules/")) continue;
			out.push(dep(name, String(value.version ?? ""), "npm", file));
		}
	} else if (isRecord(json.dependencies)) {
		const visit = (deps: Record<string, unknown>) => {
			for (const [name, value] of Object.entries(deps)) {
				if (!isRecord(value)) continue;
				out.push(dep(name, String(value.version ?? ""), "npm", file));
				if (isRecord(value.dependencies)) visit(value.dependencies);
			}
		};
		visit(json.dependencies);
	}
	return compact(out);
};

/** bun.lock (text, JSONC): `"key": ["name@version", registry, {...}, integrity]`. */
export const parseBunLock = (text: string, file: string): Dependency[] => {
	const json = parseJsonc(text);
	if (!isRecord(json) || !isRecord(json.packages)) return [];
	return compact(
		Object.values(json.packages).map((value) => {
			if (!Array.isArray(value) || typeof value[0] !== "string")
				return undefined;
			const parts = splitAt(value[0]);
			return parts ? dep(parts[0], parts[1], "npm", file) : undefined;
		}),
	);
};

export const parsePnpmLock = (text: string, file: string): Dependency[] => {
	let doc: unknown;
	try {
		doc = parseYaml(text, { maxAliasCount: -1 });
	} catch {
		return [];
	}
	if (!isRecord(doc) || !isRecord(doc.packages)) return [];
	return compact(
		Object.keys(doc.packages).map((rawKey) => {
			// v9: `name@1.0.0(peer@2)`; v6: `/name@1.0.0`; v5: `/name/1.0.0_peer@2`.
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
		}),
	);
};

/** yarn.lock v1 and Berry (best-effort). */
export const parseYarnLock = (text: string, file: string): Dependency[] => {
	const out: Array<Dependency | undefined> = [];
	let names: string[] = [];
	for (const line of text.split("\n")) {
		if (!line.trim() || line.startsWith("#")) continue;
		if (!/^\s/.test(line)) {
			names = line
				.replace(/:\s*$/, "")
				.split(",")
				.map((s) => s.trim().replace(/^"|"$/g, ""))
				.map((spec) => {
					const at = spec.indexOf("@", 1);
					return at > 0 ? spec.slice(0, at) : "";
				})
				.filter(Boolean);
			continue;
		}
		const m = /^\s+version:?\s+"?([^"\s]+)"?/.exec(line);
		if (m?.[1] && names[0]) {
			out.push(dep(names[0], m[1], "npm", file));
			names = [];
		}
	}
	return compact(out);
};

export const parseRequirements = (text: string, file: string): Dependency[] =>
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

/** `[[package]]` tables with `name`/`version` keys (poetry.lock, Cargo.lock). */
const parseTomlPackages = (
	text: string,
	file: string,
	ecosystem: Ecosystem,
	requireSource: boolean,
): Dependency[] =>
	compact(
		text
			.split(/^\[\[package\]\]\s*$/m)
			.slice(1)
			.map((block) => {
				const body = block.split(/^\[/m)[0] ?? "";
				const name = /^name\s*=\s*"([^"]+)"/m.exec(body)?.[1];
				const version = /^version\s*=\s*"([^"]+)"/m.exec(body)?.[1];
				if (requireSource && !/^source\s*=/m.test(body)) return undefined;
				return name && version
					? dep(name, version, ecosystem, file)
					: undefined;
			}),
	);

export const parsePoetryLock = (text: string, file: string) =>
	parseTomlPackages(text, file, "PyPI", false);

/** Workspace-local crates have no `source` and are skipped. */
export const parseCargoLock = (text: string, file: string) =>
	parseTomlPackages(text, file, "crates.io", true);

export const parseGoMod = (text: string, file: string): Dependency[] => {
	const out: Array<Dependency | undefined> = [];
	const add = (line: string) => {
		const m = /^\s*([^\s/]+\/\S+|\S+\.\S+)\s+(v[^\s]+)/.exec(
			line.replace(/\/\/.*$/, ""),
		);
		if (m?.[1] && m[2])
			out.push(
				dep(
					m[1],
					m[2].replace(/^v/, "").replace(/\+incompatible$/, ""),
					"Go",
					file,
				),
			);
	};
	let inBlock = false;
	for (const line of text.split("\n")) {
		if (/^require\s*\($/.test(line.trim())) inBlock = true;
		else if (inBlock && line.trim() === ")") inBlock = false;
		else if (inBlock) add(line);
		else if (/^require\s+/.test(line)) add(line.replace(/^require\s+/, ""));
	}
	return compact(out);
};

export const parseGemfileLock = (text: string, file: string): Dependency[] => {
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

export const parseComposerLock = (text: string, file: string): Dependency[] => {
	const json = parseJsonc(text);
	if (!isRecord(json)) return [];
	const list = [
		...(Array.isArray(json.packages) ? json.packages : []),
		...(Array.isArray(json["packages-dev"]) ? json["packages-dev"] : []),
	];
	return compact(
		list.map((p) =>
			isRecord(p) && typeof p.name === "string" && typeof p.version === "string"
				? dep(p.name, p.version.replace(/^v/, ""), "Packagist", file)
				: undefined,
		),
	);
};

const PARSERS: ReadonlyArray<
	readonly [RegExp, (text: string, file: string) => Dependency[]]
> = [
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

const isManifest = (path: string) =>
	!isFixturePath(path) &&
	(PARSERS.some(([re]) => re.test(path)) || baseName(path) === "package.json");

/* -------------------------------------------------------------------------- */
/*                           package.json declarations                        */
/* -------------------------------------------------------------------------- */

const DEP_FIELDS = [
	"dependencies",
	"devDependencies",
	"optionalDependencies",
	"peerDependencies",
] as const;

/** Wildcard and URL dependency specs in a package.json. */
export const checkPackageJson = (file: SourceFile): FindingInput[] => {
	const json = parseJsonc(file.text);
	if (!isRecord(json)) return [];
	const lineOf = lineLocator(file.text);
	const findings: FindingInput[] = [];
	const lineFor = (name: string) => {
		const i = file.text.indexOf(`"${name}"`);
		return i === -1 ? undefined : lineOf(i);
	};
	for (const field of DEP_FIELDS) {
		const deps = json[field];
		if (!isRecord(deps)) continue;
		for (const [name, raw] of Object.entries(deps)) {
			if (typeof raw !== "string") continue;
			const spec = raw.trim();
			if (field !== "peerDependencies" && /^(\*|latest|x|)$/i.test(spec)) {
				findings.push({
					ruleId: "code.dependencies/unpinned-version",
					title: `Unbounded version for ${name}`,
					severity: "medium",
					category: "supply-chain",
					message: `${field}.${name} is "${spec || "(empty)"}", so any future release (including a malicious or breaking one) is installed automatically.`,
					location: { file: file.path, line: lineFor(name) },
					evidence: `"${name}": "${spec}"`,
					remediation:
						"Pin a semver range such as ^1.2.3 and commit the lockfile.",
					references: [owaspUrl("a06"), cweUrl(1357)],
					confidence: "high",
					tags: ["cwe-1357", "owasp-a06"],
				});
			} else if (
				/^(git(\+[a-z]+)?:|git@|https?:|github:|gitlab:|bitbucket:|gist:)/i.test(
					spec,
				) ||
				/^[\w.-]+\/[\w.-]+(#.*)?$/.test(spec)
			) {
				const pinned = /#[0-9a-f]{40}$/i.test(spec);
				findings.push({
					ruleId: "code.dependencies/url-dependency",
					title: `${name} is installed from a URL`,
					severity: pinned ? "low" : "medium",
					category: "supply-chain",
					message: `${field}.${name} points at "${spec}" instead of a registry version. It bypasses registry integrity checks and audits${pinned ? "" : ", and can change under you because it is not pinned to a commit"}.`,
					location: { file: file.path, line: lineFor(name) },
					evidence: `"${name}": "${spec}"`,
					remediation:
						"Publish the package to a registry (public or private) and depend on a version; if you must use git, pin a full commit SHA.",
					references: [owaspUrl("a08"), cweUrl(829)],
					confidence: "high",
					tags: ["cwe-829", "owasp-a08"],
				});
			}
		}
	}
	return findings;
};

/* -------------------------------------------------------------------------- */
/*                                    OSV                                     */
/* -------------------------------------------------------------------------- */

export const OSV_API = "https://api.osv.dev/v1";
const BATCH_SIZE = 1000;
const MAX_DETAILS = 100;

export interface OsvVuln {
	readonly id: string;
	readonly summary?: string;
	readonly details?: string;
	readonly aliases?: ReadonlyArray<string>;
	readonly severity?: ReadonlyArray<{
		readonly type: string;
		readonly score: string;
	}>;
	readonly affected?: ReadonlyArray<{
		readonly package?: { readonly name?: string; readonly ecosystem?: string };
		readonly ranges?: ReadonlyArray<{
			readonly events?: ReadonlyArray<Record<string, string>>;
		}>;
		readonly database_specific?: Record<string, unknown>;
		readonly ecosystem_specific?: Record<string, unknown>;
	}>;
	readonly references?: ReadonlyArray<{
		readonly type?: string;
		readonly url: string;
	}>;
	readonly database_specific?: Record<string, unknown>;
}

const CVSS3_WEIGHTS: Record<string, Record<string, number>> = {
	AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
	AC: { L: 0.77, H: 0.44 },
	UI: { N: 0.85, R: 0.62 },
	C: { H: 0.56, L: 0.22, N: 0 },
	I: { H: 0.56, L: 0.22, N: 0 },
	A: { H: 0.56, L: 0.22, N: 0 },
};

const roundUp = (x: number) => {
	const i = Math.round(x * 100_000);
	return i % 10_000 === 0 ? i / 100_000 : (Math.floor(i / 10_000) + 1) / 10;
};

/** CVSS v3.x base score from a vector like `CVSS:3.1/AV:N/AC:L/...`. */
export const cvss3BaseScore = (vector: string): number | undefined => {
	const m: Record<string, string> = {};
	for (const part of vector.split("/")) {
		const [k, v] = part.split(":");
		if (k && v) m[k] = v;
	}
	const scope = m.S;
	const w = (k: string) => (m[k] ? CVSS3_WEIGHTS[k]?.[m[k]] : undefined);
	const [av, ac, ui, c, i, a] = ["AV", "AC", "UI", "C", "I", "A"].map(w);
	const pr =
		m.PR === "N"
			? 0.85
			: m.PR === "L"
				? scope === "C"
					? 0.68
					: 0.62
				: m.PR === "H"
					? scope === "C"
						? 0.5
						: 0.27
					: undefined;
	if (
		av === undefined ||
		ac === undefined ||
		ui === undefined ||
		pr === undefined ||
		c === undefined ||
		i === undefined ||
		a === undefined ||
		(scope !== "U" && scope !== "C")
	)
		return undefined;
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

export const severityFromScore = (score: number): Severity =>
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

const CVSS2_WEIGHTS: Record<string, Record<string, number>> = {
	AV: { L: 0.395, A: 0.646, N: 1 },
	AC: { H: 0.35, M: 0.61, L: 0.71 },
	Au: { M: 0.45, S: 0.56, N: 0.704 },
	C: { N: 0, P: 0.275, C: 0.66 },
	I: { N: 0, P: 0.275, C: 0.66 },
	A: { N: 0, P: 0.275, C: 0.66 },
};

/** CVSS v2 base score from a vector like `AV:N/AC:L/Au:N/C:P/I:P/A:P`. */
export const cvss2BaseScore = (vector: string): number | undefined => {
	const m: Record<string, string> = {};
	for (const part of vector.replace(/[()]/g, "").split("/")) {
		const [k, v] = part.split(":");
		if (k && v) m[k] = v;
	}
	const w = (k: string) => (m[k] ? CVSS2_WEIGHTS[k]?.[m[k]] : undefined);
	const [av, ac, au, c, i, a] = ["AV", "AC", "Au", "C", "I", "A"].map(w);
	if ([av, ac, au, c, i, a].some((x) => x === undefined)) return undefined;
	const impact =
		10.41 *
		(1 - (1 - (c as number)) * (1 - (i as number)) * (1 - (a as number)));
	const exploitability = 20 * (av as number) * (ac as number) * (au as number);
	const f = impact === 0 ? 0 : 1.176;
	return Math.round((0.6 * impact + 0.4 * exploitability - 1.5) * f * 10) / 10;
};

/**
 * Severity from a CVSS v3 vector, a numeric score, the database's own label
 * (GitHub's label already reflects CVSS v4), then a CVSS v2 vector. CVSS v4
 * vectors are not scored here: their score needs MacroVector lookup tables.
 */
export const osvSeverity = (vuln: OsvVuln): Severity => {
	for (const s of vuln.severity ?? []) {
		if (s.type.startsWith("CVSS_V3")) {
			const score = cvss3BaseScore(s.score);
			if (score !== undefined) return severityFromScore(score);
		}
		const n = Number(s.score);
		if (Number.isFinite(n) && n > 0) return severityFromScore(n);
	}
	const labels = [
		vuln.database_specific?.severity,
		...(vuln.affected ?? []).flatMap((a) => [
			a.database_specific?.severity,
			a.ecosystem_specific?.severity,
		]),
	];
	for (const label of labels) {
		const sev =
			typeof label === "string" ? LABELS[label.toUpperCase()] : undefined;
		if (sev) return sev;
	}
	for (const s of vuln.severity ?? []) {
		if (s.type !== "CVSS_V2") continue;
		const score = cvss2BaseScore(s.score);
		if (score !== undefined) return severityFromScore(score);
	}
	return "medium";
};

/** Earliest `fixed` versions published for this package. */
export const fixedVersions = (vuln: OsvVuln, d: Dependency): string[] => {
	const fixed = new Set<string>();
	for (const a of vuln.affected ?? []) {
		if (
			a.package?.name &&
			a.package.name.toLowerCase() !== d.name.toLowerCase()
		)
			continue;
		for (const r of a.ranges ?? [])
			for (const e of r.events ?? []) if (e.fixed) fixed.add(e.fixed);
	}
	return [...fixed];
};

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
			const results =
				isRecord(json) && Array.isArray(json.results) ? json.results : [];
			chunk.forEach((_, i) => {
				const r = results[i];
				const vulns = isRecord(r) && Array.isArray(r.vulns) ? r.vulns : [];
				ids.push(
					vulns.flatMap((v) =>
						isRecord(v) && typeof v.id === "string" ? [v.id] : [],
					),
				);
			});
		}
		return ids;
	});

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
							try: () => {
								const v: unknown =
									res.status === 200 ? JSON.parse(res.body) : undefined;
								return isRecord(v) && typeof v.id === "string"
									? (v as unknown as OsvVuln)
									: undefined;
							},
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

const vulnFinding = (
	d: Dependency,
	id: string,
	vuln: OsvVuln | undefined,
	line: number | undefined,
): FindingInput => {
	const aliases = (vuln?.aliases ?? []).filter((a) => a !== id);
	const fixed = vuln ? fixedVersions(vuln, d) : [];
	const cwes = Array.isArray(vuln?.database_specific?.cwe_ids)
		? (vuln.database_specific.cwe_ids as unknown[]).filter(
				(c): c is string => typeof c === "string",
			)
		: [];
	const summary = vuln?.summary ?? vuln?.details?.split("\n")[0]?.slice(0, 200);
	return {
		ruleId: "code.dependencies/vulnerable-dependency",
		title: `${d.name}@${d.version}: ${summary ?? id}`,
		severity: vuln ? osvSeverity(vuln) : "medium",
		category: "supply-chain",
		message: `${d.name} ${d.version} (${d.ecosystem}) is affected by ${id}${aliases.length ? ` (${aliases.slice(0, 3).join(", ")})` : ""}${summary ? `: ${summary}` : "."}${vuln ? "" : " Advisory details were not fetched (detail limit reached), so the severity is estimated."}`,
		location: { file: d.file, line },
		evidence: `${d.name}@${d.version} ${id}`,
		remediation: fixed.length
			? `Upgrade ${d.name} to ${fixed.join(" or ")} or later (or a newer major), then regenerate the lockfile.`
			: `No fixed version is published for ${d.name}; consider replacing it or mitigating per the advisory.`,
		references: [
			`https://osv.dev/vulnerability/${id}`,
			...(vuln?.references ?? [])
				.filter((r) => r.type === "ADVISORY" || r.type === "FIX")
				.slice(0, 3)
				.map((r) => r.url),
		],
		confidence: vuln ? "high" : "medium",
		tags: [
			"owasp-a06",
			...cwes.map((c) => c.toLowerCase()),
			...[id, ...aliases]
				.filter((a) => /^(CVE|GHSA)-/.test(a))
				.map((a) => a.toLowerCase()),
		],
	};
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

			const idsPerDep = yield* queryOsvBatch(ctx.http, deps);
			const details = yield* fetchOsvVulns(ctx.http, roundRobin(idsPerDep));

			const texts = new Map(files.map((f) => [f.path, f.text.toLowerCase()]));
			const locators = new Map<string, (i: number) => number>();
			const lineFor = (d: Dependency) => {
				const text = texts.get(d.file);
				if (!text) return undefined;
				// Prefer the line that mentions both the name and the resolved version.
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
				if (i === -1) i = first;
				if (i === -1) return undefined;
				let locate = locators.get(d.file);
				if (!locate) {
					locate = lineLocator(text);
					locators.set(d.file, locate);
				}
				return locate(i);
			};

			deps.forEach((d, i) => {
				// OSV can return the same advisory under several ids (PYSEC + GHSA).
				const covered = new Set<string>();
				for (const id of idsPerDep[i] ?? []) {
					const vuln = details.get(id);
					if (covered.has(id) || vuln?.aliases?.some((a) => covered.has(a)))
						continue;
					covered.add(id);
					for (const alias of vuln?.aliases ?? []) covered.add(alias);
					findings.push(vulnFinding(d, id, vuln, lineFor(d)));
				}
			});
			return findings;
		}),
});
