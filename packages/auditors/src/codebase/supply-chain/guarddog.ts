import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
	type AuditContext,
	AuditorError,
	defineAuditor,
	type FindingInput,
	requireTool,
	requireWorkspace,
	type Severity,
	skip,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, num, parseJson, str } from "../../tool";
import { isRecord, kebab, scrubLine, truncate } from "../util";
import { isPyRequirements } from "./python";
import type {
	FilePath,
	FileText,
	Json,
	PackageName,
	ToolBin,
	Url,
} from "./report";
import { baseOf, findFiles, lower, run, withTempDir } from "./shared";

/* -------------------------------------------------------------------------- */
/*                                  guarddog                                  */
/* -------------------------------------------------------------------------- */

export type GuarddogEcosystem = "npm" | "pypi";

export interface GuarddogManifest {
	/** The sanitised manifest handed to guarddog: registry dependencies only. */
	readonly content: string;
	/** Normalised package name → line declaring it in the original manifest. */
	readonly lines: ReadonlyMap<string, number>;
}

const GUARDDOG_URL = "https://github.com/DataDog/guarddog";

const NPM_NAME = /^(?:@[a-z0-9~][\w.~-]*\/)?[a-z0-9~][\w.~-]*$/i;
// Specs that do not name a registry release; guarddog would scan the latest
// registry version under that name instead, which is not what gets installed.
const NPM_LOCAL_SPEC =
	/^(?:workspace|file|link|portal|patch|catalog|git|git\+\w+|github|gitlab|bitbucket|gist|https?):|^[./~]|^[\w.-]+\/[\w.-]+(?:#.*)?$/i;
const NPM_ALIAS = /^npm:((?:@[^/@\s]+\/)?[^@\s]+)(?:@.*)?$/;

const normName = (eco: GuarddogEcosystem, name: PackageName) =>
	eco === "pypi" ? name.toLowerCase().replace(/[-_.]+/g, "-") : name;

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

type DependencyGroup = "dependencies" | "devDependencies";

const NPM_GROUPS = [
	["dependencies", "dependencies"],
	["optionalDependencies", "dependencies"],
	["devDependencies", "devDependencies"],
] as const;

/** The registry package a dependency installs, or undefined for local, git or URL specs. */
const npmRegistryName = (
	name: PackageName,
	spec: string,
): PackageName | undefined => {
	if (!NPM_NAME.test(name)) return undefined;
	const alias = NPM_ALIAS.exec(spec)?.[1];
	if (alias) return NPM_NAME.test(alias) ? alias : undefined;
	return NPM_LOCAL_SPEC.test(spec.trim()) ? undefined : name;
};

/** 1-based line declaring `"name":` in the manifest, or 1 when not found. */
const declarationLine = (rows: ReadonlyArray<string>, name: PackageName) => {
	// The package name is escaped with escapeRe.
	// nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
	const key = new RegExp(`(?:^|[{,\\s])"${escapeRe(name)}"\\s*:`);
	return rows.findIndex((row) => key.test(row)) + 1 || 1;
};

interface NpmManifestBuilder {
	readonly rows: ReadonlyArray<string>;
	readonly lines: Map<string, number>;
	readonly out: Record<DependencyGroup, Record<string, string>>;
}

const addNpmDependencies = (
	b: NpmManifestBuilder,
	deps: unknown,
	into: DependencyGroup,
): void => {
	if (!isRecord(deps)) return;
	for (const [name, spec] of Object.entries(deps)) {
		if (typeof spec !== "string") continue;
		const pkg = npmRegistryName(name, spec);
		if (!pkg) continue;
		b.out[into][name] = spec;
		b.lines.set(pkg, declarationLine(b.rows, name));
	}
};

/**
 * Registry dependencies of a package.json (`dependencies` and
 * `optionalDependencies` → dependencies, plus `devDependencies`), or undefined
 * when there are none. Aliases map to the real package, as guarddog reports it.
 */
export const guarddogNpmManifest = (
	text: FileText,
): GuarddogManifest | undefined => {
	let json: unknown;
	try {
		json = JSON.parse(text);
	} catch {
		return undefined;
	}
	if (!isRecord(json)) return undefined;
	const b: NpmManifestBuilder = {
		rows: text.split(/\r?\n/),
		lines: new Map(),
		out: { dependencies: {}, devDependencies: {} },
	};
	for (const [field, into] of NPM_GROUPS)
		addNpmDependencies(b, json[field], into);
	return b.lines.size
		? { content: `${JSON.stringify(b.out, null, 2)}\n`, lines: b.lines }
		: undefined;
};

// Matched against the requirement with whitespace removed. Version tokens
// share no character with the operators, so the match cannot backtrack.
const REQUIREMENT =
	/^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(?:\[[^\]]*\])?((?:(?:===?|[<>!~]=?)[\w.*+-]+,?)*)$/;

/** Name and specifier of a plain requirement line, or undefined for anything else. */
const plainRequirement = (raw: string) => {
	const line = raw
		.replace(/(^|\s)#.*$/, "")
		.replace(/\\$/, "")
		.trim();
	if (!line || line.startsWith("-")) return undefined;
	const req = line
		.replace(/\s+--[\w-]+(=\S+|\s+\S+)?/g, "")
		.split(";")[0]
		?.replace(/\s+/g, "");
	const m = req ? REQUIREMENT.exec(req) : null;
	return m?.[1]
		? { name: m[1], spec: (m[2] ?? "").replace(/,$/, "") }
		: undefined;
};

/**
 * Plain `name[extras]<specifier>` lines of a requirements file, or undefined
 * when there are none. Options, includes, editable installs, direct URLs and
 * environment markers are dropped.
 */
export const guarddogRequirements = (
	text: FileText,
): GuarddogManifest | undefined => {
	const reqs: string[] = [];
	const lines = new Map<string, number>();
	text.split(/\r?\n/).forEach((raw, i) => {
		const req = plainRequirement(raw);
		if (!req) return;
		const key = normName("pypi", req.name);
		if (lines.has(key)) return;
		lines.set(key, i + 1);
		reqs.push(`${req.name}${req.spec}`);
	});
	return reqs.length ? { content: `${reqs.join("\n")}\n`, lines } : undefined;
};

const LEVELS: ReadonlyArray<string> = ["low", "medium", "high"];
const levelOf = (risk: Record<string, unknown>) =>
	LEVELS.indexOf(str(risk.severity) ?? "");
const LABELS: Record<
	string,
	{ readonly text: string; readonly severity: Severity }
> = {
	high_risk: { text: "high risk", severity: "high" },
	suspicious: { text: "suspicious", severity: "medium" },
};

const ruleWords = (rule: string) =>
	rule
		.replace(/^threat-/, "")
		.replace(/[-_]+/g, " ")
		.trim();

const registryUrl = (
	eco: GuarddogEcosystem,
	name: PackageName,
	version: string,
) =>
	eco === "npm"
		? `https://www.npmjs.com/package/${name}/v/${encodeURIComponent(version)}`
		: `https://pypi.org/project/${name}/${encodeURIComponent(version)}/`;

interface GuarddogTarget {
	readonly ecosystem: GuarddogEcosystem;
	/** Workspace-relative manifest path the findings point at. */
	readonly file: string;
	readonly lines: ReadonlyMap<string, number>;
}

/** A dependency GuardDog labelled, with what its findings share. */
interface FlaggedPackage {
	readonly name: string;
	/** `name@version`. */
	readonly at: string;
	readonly label: (typeof LABELS)[string];
	/** GuardDog's verdict, the first sentence of every message. */
	readonly rated: string;
	readonly location: { readonly file: string; readonly line?: number };
	readonly references: string[];
	/** Risks with a threat rule, most severe first. */
	readonly risks: ReadonlyArray<Json>;
}

const guarddogReferences = (packageUrl: Url, result: Json) => {
	const inspector = str(result.pypi_inspector_url);
	return [GUARDDOG_URL, packageUrl, ...(inspector ? [inspector] : [])];
};

const threats = (result: Json) =>
	arr(result.risks)
		.filter(isRecord)
		.filter((r) => !!str(r.threat_rule))
		.sort((a, b) => levelOf(b) - levelOf(a));

const flaggedPackage = (
	entry: unknown,
	target: GuarddogTarget,
): FlaggedPackage | undefined => {
	if (!isRecord(entry) || !isRecord(entry.result)) return undefined;
	const name = str(entry.dependency);
	const result = entry.result;
	const score = isRecord(result.risk_score) ? result.risk_score : {};
	const label = LABELS[str(score.label) ?? ""];
	if (!name || !label) return undefined;
	const version = str(entry.version) ?? str(result.package_version) ?? "latest";
	const at = `${name}@${version}`;
	const points = num(score.score);
	return {
		name,
		at,
		label,
		rated: `GuardDog rates ${at} ${label.text}${points !== undefined ? ` (risk score ${points}/10)` : ""}.`,
		location: {
			file: target.file,
			line: target.lines.get(normName(target.ecosystem, name)),
		},
		references: guarddogReferences(
			registryUrl(target.ecosystem, name, version),
			result,
		),
		risks: threats(result),
	};
};

const metadataFinding = (
	pkg: FlaggedPackage,
	risk: Json,
	rule: string,
): FindingInput => {
	const description = str(risk.threat_description) || ruleWords(rule);
	const level = LEVELS[levelOf(risk)] as Severity | undefined;
	return {
		ruleId: `code.guarddog/${kebab(rule)}`,
		title: `${pkg.at}: ${ruleWords(rule)} (GuardDog)`,
		severity: lower(level ?? "medium"),
		category: "supply-chain",
		message: `${pkg.rated} ${description}`,
		location: pkg.location,
		evidence: truncate(`${pkg.at}: ${description}`),
		remediation: `Check that ${pkg.name} is the package you meant to depend on and that its registry page and maintainers look legitimate; if not, replace it with the intended package and treat machines that installed it as exposed.`,
		references: pkg.references,
		confidence: "low",
		tags: ["owasp-a08"],
	};
};

/** One finding per registry-metadata rule. */
const metadataFindings = (
	pkg: FlaggedPackage,
	risks: ReadonlyArray<Json>,
): FindingInput[] => {
	const seen = new Set<string>();
	const findings: FindingInput[] = [];
	for (const risk of risks) {
		const rule = str(risk.threat_rule) as string;
		if (seen.has(rule)) continue;
		seen.add(rule);
		findings.push(metadataFinding(pkg, risk, rule));
	}
	return findings;
};

/** Distinct locations per source-code rule, in report order. */
const locationsByRule = (code: ReadonlyArray<Json>) => {
	const byRule = new Map<string, string[]>();
	for (const risk of code) {
		const rule = str(risk.threat_rule) as string;
		const where = str(risk.threat_location);
		const list = byRule.get(rule) ?? [];
		if (where && !list.includes(where)) list.push(where);
		byRule.set(rule, list);
	}
	return byRule;
};

const ruleSummary = ([rule, where]: [string, string[]]) =>
	`${ruleWords(rule)}${where[0] ? ` (${where[0]}${where.length > 1 ? `, +${where.length - 1}` : ""})` : ""}`;

const codeSnippet = (risk: Json) =>
	(str(risk.threat_match) || str(risk.threat_code) || "")
		.replace(/\s+/g, " ")
		.trim();

/** All source-code risks of a package folded into one finding. */
const suspiciousCodeFinding = (
	pkg: FlaggedPackage,
	code: ReadonlyArray<Json>,
): FindingInput => {
	const byRule = locationsByRule(code);
	const listed = [...byRule].slice(0, 5).map(ruleSummary);
	const top = code[0] ?? {};
	const topWhere = str(top.threat_location);
	return {
		ruleId: "code.guarddog/suspicious-code",
		title: `${pkg.at}: ${pkg.label.text} code (GuardDog)`,
		severity: pkg.label.severity,
		category: "supply-chain",
		message: `${pkg.rated} Source-code heuristics: ${listed.join("; ")}${byRule.size > 5 ? `; +${byRule.size - 5} more` : ""}.`,
		location: pkg.location,
		evidence: truncate(
			`${topWhere ? `${topWhere}: ` : ""}${scrubLine(codeSnippet(top)) || (str(top.threat_description) ?? "")}`,
		),
		remediation: `Inspect ${pkg.at}${topWhere ? ` (${topWhere})` : ""} before installing it. Large bundled packages often trip these heuristics; if the behaviour is not expected for this package, remove it or pin a known-good version, report it to the registry, and rotate credentials on machines and CI runners that installed it.`,
		references: pkg.references,
		confidence: "low",
		tags: ["owasp-a08", "cwe-506"],
	};
};

const packageFindings = (pkg: FlaggedPackage): FindingInput[] => {
	const metadata = pkg.risks.filter((r) => str(r.category) === "metadata");
	const code = pkg.risks.filter((r) => str(r.category) !== "metadata");
	return [
		...metadataFindings(pkg, metadata),
		...(code.length ? [suspiciousCodeFinding(pkg, code)] : []),
	];
};

const byLineThenRule = (a: FindingInput, b: FindingInput) =>
	(a.location?.line ?? 0) - (b.location?.line ?? 0) ||
	a.ruleId.localeCompare(b.ruleId);

/**
 * Parses `guarddog <npm|pypi> verify --output-format json`: one entry per
 * dependency, each with GuardDog's risks (threats, optionally backed by a
 * matching capability) and an overall label. Only packages labelled
 * `suspicious` or `high_risk` (score 5+, GuardDog's own bar for flagging a
 * dependency) are reported, on the manifest line declaring them:
 * - each registry-metadata risk (typosquatting, maintainer email, ...) as its
 *   own rule, one step below GuardDog's severity;
 * - all source-code risks together as one `suspicious-code` finding, high for
 *   `high_risk` and medium for `suspicious`. Large bundled packages often
 *   trip several YARA rules at once, so one finding per rule would bury the
 *   verdict.
 * Capabilities on their own are normal package behaviour and are ignored.
 */
export const parseGuarddogReport = (
	json: unknown,
	target: GuarddogTarget,
): FindingInput[] =>
	arr(json)
		.flatMap((entry) => {
			const pkg = flaggedPackage(entry, target);
			return pkg ? packageFindings(pkg) : [];
		})
		.sort(byLineThenRule);

const MANIFESTS: Record<
	GuarddogEcosystem,
	{
		readonly file: string;
		readonly parse: (text: string) => GuarddogManifest | undefined;
	}
> = {
	npm: { file: "package.json", parse: guarddogNpmManifest },
	pypi: { file: "requirements.txt", parse: guarddogRequirements },
};

interface ManifestCopy {
	/** Workspace-relative path of the original manifest. */
	readonly file: FilePath;
	readonly ecosystem: GuarddogEcosystem;
	readonly manifest: GuarddogManifest;
}

const isGuarddogManifest = (p: FilePath) =>
	baseOf(p) === "package.json" || isPyRequirements(p);

const ecosystemOf = (file: FilePath): GuarddogEcosystem =>
	baseOf(file) === "package.json" ? "npm" : "pypi";

/** Manifests that declare at least one registry dependency. */
const readManifests = (ws: Workspace, files: ReadonlyArray<FilePath>) =>
	Effect.gen(function* () {
		const manifests: ManifestCopy[] = [];
		for (const file of files) {
			const ecosystem = ecosystemOf(file);
			const manifest = MANIFESTS[ecosystem].parse(yield* ws.readText(file));
			if (manifest) manifests.push({ file, ecosystem, manifest });
		}
		return manifests;
	});

const writeManifestCopy = (path: string, content: FileText) =>
	Effect.tryPromise({
		try: () => writeFile(path, content),
		catch: (cause) =>
			new AuditorError({
				message: "Could not write the manifest copy",
				cause,
			}),
	});

const verifyArgs = (
	bin: ToolBin,
	ecosystem: GuarddogEcosystem,
	path: string,
) => [
	bin,
	"--log-level",
	"error",
	ecosystem,
	"verify",
	path,
	"--output-format",
	"json",
	...(ecosystem === "npm" ? ["--include-dev-dependencies"] : []),
];

/**
 * Runs `guarddog verify` on a sanitised copy of the manifest. From a scratch
 * dir: guarddog re-runs itself with `python -m`, which imports from the cwd.
 */
const verifyManifest = (
	ctx: AuditContext,
	bin: ToolBin,
	{ ecosystem, manifest }: ManifestCopy,
) =>
	withTempDir((dir) =>
		Effect.gen(function* () {
			const path = join(dir, MANIFESTS[ecosystem].file);
			yield* writeManifestCopy(path, manifest.content);
			return yield* run(ctx, verifyArgs(bin, ecosystem, path), {
				cwd: dir,
				okCodes: [0],
			});
		}),
	);

export const guarddog = defineAuditor({
	id: "code.guarddog",
	title: "GuardDog (malicious packages)",
	description:
		"Checks the npm and PyPI dependencies declared in package.json and requirements*.txt for malicious packages with DataDog GuardDog. guarddog downloads each dependency (the highest version matching its range) from the public registry and analyses it statically with YARA rules and registry-metadata heuristics such as typosquatting; nothing is installed or run. Only a sanitised copy of each manifest, holding registry dependencies, is passed to it from a scratch directory. Opt-in because it downloads every dependency and sends their names to the registries.",
	categories: ["supply-chain", "security"],
	targets: ["codebase"],
	engine: "external",
	tool: "guarddog",
	network: true,
	defaultEnabled: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const files = yield* findFiles(ctx, isGuarddogManifest);
			if (!files.length)
				return yield* skip("No package.json or requirements*.txt found");
			const manifests = yield* readManifests(ws, files);
			if (!manifests.length)
				return yield* skip(
					`No registry dependencies to verify in ${files.join(", ")}`,
				);
			const bin = yield* requireTool(
				ctx,
				"guarddog",
				"Install: pipx install guarddog (or uv tool install guarddog).",
			);
			const findings: FindingInput[] = [];
			for (const copy of manifests) {
				const out = yield* verifyManifest(ctx, bin, copy);
				findings.push(
					...parseGuarddogReport(yield* parseJson(out.stdout, "guarddog"), {
						ecosystem: copy.ecosystem,
						file: copy.file,
						lines: copy.manifest.lines,
					}),
				);
			}
			return findings;
		}),
});
