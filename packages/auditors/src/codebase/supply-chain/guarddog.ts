import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
	AuditorError,
	defineAuditor,
	type FindingInput,
	requireTool,
	requireWorkspace,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, num, parseJson, str } from "../../tool";
import { isRecord, kebab, scrubLine, truncate } from "../util";
import { isPyRequirements } from "./python";
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

const normName = (eco: GuarddogEcosystem, name: string) =>
	eco === "pypi" ? name.toLowerCase().replace(/[-_.]+/g, "-") : name;

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Registry dependencies of a package.json (`dependencies` and
 * `optionalDependencies` → dependencies, plus `devDependencies`), or undefined
 * when there are none. Aliases map to the real package, as guarddog reports it.
 */
export const guarddogNpmManifest = (
	text: string,
): GuarddogManifest | undefined => {
	let json: unknown;
	try {
		json = JSON.parse(text);
	} catch {
		return undefined;
	}
	if (!isRecord(json)) return undefined;
	const rows = text.split(/\r?\n/);
	const lines = new Map<string, number>();
	const out: Record<
		"dependencies" | "devDependencies",
		Record<string, string>
	> = { dependencies: {}, devDependencies: {} };
	const groups = [
		["dependencies", "dependencies"],
		["optionalDependencies", "dependencies"],
		["devDependencies", "devDependencies"],
	] as const;
	for (const [field, into] of groups) {
		const deps = json[field];
		if (!isRecord(deps)) continue;
		for (const [name, spec] of Object.entries(deps)) {
			if (typeof spec !== "string" || !NPM_NAME.test(name)) continue;
			const alias = NPM_ALIAS.exec(spec)?.[1];
			if (alias ? !NPM_NAME.test(alias) : NPM_LOCAL_SPEC.test(spec.trim()))
				continue;
			out[into][name] = spec;
			const key = new RegExp(`(?:^|[{,\\s])"${escapeRe(name)}"\\s*:`);
			const line = rows.findIndex((row) => key.test(row));
			lines.set(alias ?? name, line + 1 || 1);
		}
	}
	return lines.size
		? { content: `${JSON.stringify(out, null, 2)}\n`, lines }
		: undefined;
};

// Matched against the requirement with whitespace removed. Version tokens
// share no character with the operators, so the match cannot backtrack.
const REQUIREMENT =
	/^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(?:\[[^\]]*\])?((?:(?:===?|[<>!~]=?)[\w.*+-]+,?)*)$/;

/**
 * Plain `name[extras]<specifier>` lines of a requirements file, or undefined
 * when there are none. Options, includes, editable installs, direct URLs and
 * environment markers are dropped.
 */
export const guarddogRequirements = (
	text: string,
): GuarddogManifest | undefined => {
	const reqs: string[] = [];
	const lines = new Map<string, number>();
	text.split(/\r?\n/).forEach((raw, i) => {
		const line = raw
			.replace(/(^|\s)#.*$/, "")
			.replace(/\\$/, "")
			.trim();
		if (!line || line.startsWith("-")) return;
		const req = line
			.replace(/\s+--[\w-]+(=\S+|\s+\S+)?/g, "")
			.split(";")[0]
			?.replace(/\s+/g, "");
		const m = req ? REQUIREMENT.exec(req) : null;
		if (!m?.[1]) return;
		const key = normName("pypi", m[1]);
		if (lines.has(key)) return;
		lines.set(key, i + 1);
		reqs.push(`${m[1]}${(m[2] ?? "").replace(/,$/, "")}`);
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

const registryUrl = (eco: GuarddogEcosystem, name: string, version: string) =>
	eco === "npm"
		? `https://www.npmjs.com/package/${name}/v/${encodeURIComponent(version)}`
		: `https://pypi.org/project/${name}/${encodeURIComponent(version)}/`;

interface GuarddogTarget {
	readonly ecosystem: GuarddogEcosystem;
	/** Workspace-relative manifest path the findings point at. */
	readonly file: string;
	readonly lines: ReadonlyMap<string, number>;
}

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
): FindingInput[] => {
	const findings: FindingInput[] = [];
	for (const entry of arr(json)) {
		if (!isRecord(entry) || !isRecord(entry.result)) continue;
		const name = str(entry.dependency);
		const result = entry.result;
		const score = isRecord(result.risk_score) ? result.risk_score : {};
		const label = LABELS[str(score.label) ?? ""];
		if (!name || !label) continue;
		const version =
			str(entry.version) ?? str(result.package_version) ?? "latest";
		const at = `${name}@${version}`;
		const points = num(score.score);
		const rated = `GuardDog rates ${at} ${label.text}${points !== undefined ? ` (risk score ${points}/10)` : ""}.`;
		const location = {
			file: target.file,
			line: target.lines.get(normName(target.ecosystem, name)),
		};
		const references = [
			GUARDDOG_URL,
			registryUrl(target.ecosystem, name, version),
			...(str(result.pypi_inspector_url)
				? [str(result.pypi_inspector_url) as string]
				: []),
		];
		const risks = arr(result.risks)
			.filter(isRecord)
			.filter((r) => !!str(r.threat_rule))
			.sort((a, b) => levelOf(b) - levelOf(a));
		const metadata = risks.filter((r) => str(r.category) === "metadata");
		const code = risks.filter((r) => str(r.category) !== "metadata");

		const seen = new Set<string>();
		for (const risk of metadata) {
			const rule = str(risk.threat_rule) as string;
			if (seen.has(rule)) continue;
			seen.add(rule);
			const description = str(risk.threat_description) || ruleWords(rule);
			const level = LEVELS[levelOf(risk)] as Severity | undefined;
			findings.push({
				ruleId: `code.guarddog/${kebab(rule)}`,
				title: `${at}: ${ruleWords(rule)} (GuardDog)`,
				severity: lower(level ?? "medium"),
				category: "supply-chain",
				message: `${rated} ${description}`,
				location,
				evidence: truncate(`${at}: ${description}`),
				remediation: `Check that ${name} is the package you meant to depend on and that its registry page and maintainers look legitimate; if not, replace it with the intended package and treat machines that installed it as exposed.`,
				references,
				confidence: "low",
				tags: ["owasp-a08"],
			});
		}

		if (code.length) {
			const byRule = new Map<string, string[]>();
			for (const risk of code) {
				const rule = str(risk.threat_rule) as string;
				const where = str(risk.threat_location);
				const list = byRule.get(rule) ?? [];
				if (where && !list.includes(where)) list.push(where);
				byRule.set(rule, list);
			}
			const listed = [...byRule]
				.slice(0, 5)
				.map(
					([rule, where]) =>
						`${ruleWords(rule)}${where[0] ? ` (${where[0]}${where.length > 1 ? `, +${where.length - 1}` : ""})` : ""}`,
				);
			const top = code[0] ?? {};
			const topWhere = str(top.threat_location);
			const snippet = (str(top.threat_match) || str(top.threat_code) || "")
				.replace(/\s+/g, " ")
				.trim();
			findings.push({
				ruleId: "code.guarddog/suspicious-code",
				title: `${at}: ${label.text} code (GuardDog)`,
				severity: label.severity,
				category: "supply-chain",
				message: `${rated} Source-code heuristics: ${listed.join("; ")}${byRule.size > 5 ? `; +${byRule.size - 5} more` : ""}.`,
				location,
				evidence: truncate(
					`${topWhere ? `${topWhere}: ` : ""}${scrubLine(snippet) || (str(top.threat_description) ?? "")}`,
				),
				remediation: `Inspect ${at}${topWhere ? ` (${topWhere})` : ""} before installing it. Large bundled packages often trip these heuristics; if the behaviour is not expected for this package, remove it or pin a known-good version, report it to the registry, and rotate credentials on machines and CI runners that installed it.`,
				references,
				confidence: "low",
				tags: ["owasp-a08", "cwe-506"],
			});
		}
	}
	return findings.sort(
		(a, b) =>
			(a.location?.line ?? 0) - (b.location?.line ?? 0) ||
			a.ruleId.localeCompare(b.ruleId),
	);
};

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
			const files = yield* findFiles(
				ctx,
				(p) => baseOf(p) === "package.json" || isPyRequirements(p),
			);
			if (!files.length)
				return yield* skip("No package.json or requirements*.txt found");
			const manifests: Array<{
				file: string;
				ecosystem: GuarddogEcosystem;
				manifest: GuarddogManifest;
			}> = [];
			for (const file of files) {
				const ecosystem: GuarddogEcosystem =
					baseOf(file) === "package.json" ? "npm" : "pypi";
				const manifest = MANIFESTS[ecosystem].parse(yield* ws.readText(file));
				if (manifest) manifests.push({ file, ecosystem, manifest });
			}
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
			for (const { file, ecosystem, manifest } of manifests) {
				// From a scratch dir: guarddog re-runs itself with `python -m`,
				// which imports from the cwd.
				const out = yield* withTempDir((dir) =>
					Effect.gen(function* () {
						const path = join(dir, MANIFESTS[ecosystem].file);
						yield* Effect.tryPromise({
							try: () => writeFile(path, manifest.content),
							catch: (cause) =>
								new AuditorError({
									message: "Could not write the manifest copy",
									cause,
								}),
						});
						return yield* run(
							ctx,
							[
								bin,
								"--log-level",
								"error",
								ecosystem,
								"verify",
								path,
								"--output-format",
								"json",
								...(ecosystem === "npm" ? ["--include-dev-dependencies"] : []),
							],
							{ cwd: dir, okCodes: [0] },
						);
					}),
				);
				findings.push(
					...parseGuarddogReport(yield* parseJson(out.stdout, "guarddog"), {
						ecosystem,
						file,
						lines: manifest.lines,
					}),
				);
			}
			return findings;
		}),
});
