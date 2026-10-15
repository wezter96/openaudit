import { resolve } from "node:path";
import {
	AuditorError,
	defineAuditor,
	type FindingInput,
	requireTool,
	requireWorkspace,
	type Severity,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import {
	arr,
	cweTags,
	gitignoredPaths,
	num,
	parseJson,
	severityOf,
	str,
} from "../../tool";
import { severityFromScore } from "../dependencies";
import { isRecord, truncate } from "../util";
import type { FilePath, Json, PackageName, RootPath } from "./report";
import { run, scanPath, vulnFinding, withTempDir } from "./shared";

/* -------------------------------------------------------------------------- */
/*                                    grype                                   */
/* -------------------------------------------------------------------------- */

const strings = (value: unknown): string[] =>
	arr(value).filter((v): v is string => typeof v === "string");

const baseScores = (cvss: unknown): number[] => {
	if (!isRecord(cvss) || !isRecord(cvss.metrics)) return [];
	const score = num(cvss.metrics.baseScore);
	return score !== undefined ? [score] : [];
};

const grypeSeverity = (vuln: Record<string, unknown>): Severity => {
	const label = str(vuln.severity)?.toLowerCase();
	if (label === "negligible") return "info";
	if (label && label !== "unknown") return severityOf(label);
	const scores = arr(vuln.cvss).flatMap(baseScores);
	return scores.length ? severityFromScore(Math.max(...scores)) : "medium";
};

/** grype and syft `--exclude` globs, relative to the scanned directory, for what .gitignore excludes. */
const anchoreExcludes = (ws: Workspace) =>
	Effect.map(gitignoredPaths(ws), (paths) =>
		paths.flatMap((p) => [
			"--exclude",
			p.endsWith("/") ? `./${p}**` : `./${p}`,
		]),
	);

interface GrypeMatch extends Json {
	readonly vulnerability: Json;
	readonly artifact: Json;
}

const isGrypeMatch = (m: unknown): m is GrypeMatch =>
	isRecord(m) && isRecord(m.vulnerability) && isRecord(m.artifact);

const grypeFix = (vuln: Json, name: PackageName) => {
	const fix = isRecord(vuln.fix) ? vuln.fix : {};
	return {
		fixed: strings(fix.versions),
		fixHint:
			str(fix.state) === "wont-fix"
				? `The vendor will not fix this in ${name}; consider replacing it.`
				: undefined,
	};
};

/** CPE matches can be false positives. */
const grypeConfidence = (m: GrypeMatch) => {
	const details = arr(m.matchDetails).find(isRecord);
	return (str(details?.type) ?? "").includes("cpe")
		? {
				confidence: "low" as const,
				note: "Matched by CPE, which can produce false positives.",
			}
		: { confidence: "high" as const, note: undefined };
};

const grypeReferences = (vuln: Json) => {
	const source = str(vuln.dataSource);
	return [...(source ? [source] : []), ...strings(vuln.urls).slice(0, 2)];
};

/** One match as a finding, with the key grype's duplicate matches share. */
const grypeFinding = (m: GrypeMatch, root: RootPath) => {
	const vuln = m.vulnerability;
	const art = m.artifact;
	const id = str(vuln.id) ?? "unknown";
	const name = str(art.name) ?? "unknown";
	const version = str(art.version);
	const loc = arr(art.locations).find(isRecord);
	const file = scanPath(root, loc ? str(loc.path) : undefined);
	const description = str(vuln.description);
	const finding = vulnFinding({
		auditor: "code.grype",
		name,
		version,
		ecosystem: str(art.type),
		id,
		aliases: arr(m.relatedVulnerabilities)
			.filter(isRecord)
			.map((r) => str(r.id))
			.filter((r): r is string => !!r),
		summary: truncate((description ?? id).split("\n")[0] ?? id, 140),
		severity: grypeSeverity(vuln),
		...grypeFix(vuln, name),
		file,
		references: grypeReferences(vuln),
		...grypeConfidence(m),
		tags: cweTags(
			arr(vuln.cwes)
				.filter(isRecord)
				.map((c) => str(c.cwe) ?? ""),
		),
	});
	return { key: `${id}|${name}|${version}|${file}`, finding };
};

/** Parses `grype -o json`. */
export const parseGrypeReport = (
	json: unknown,
	root: RootPath,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	const findings: FindingInput[] = [];
	const seen = new Set<string>();
	for (const m of arr(json.matches)) {
		if (!isGrypeMatch(m)) continue;
		const { key, finding } = grypeFinding(m, root);
		if (seen.has(key)) continue;
		seen.add(key);
		findings.push(finding);
	}
	return findings;
};

export const grype = defineAuditor({
	id: "code.grype",
	title: "grype vulnerability scan",
	description:
		"Scans the directory with Anchore grype (builds an SBOM with syft, matches against the grype database). Overlaps osv-scanner and trivy, so it is opt-in. Runs from a scratch directory so project-level grype config is ignored; the vulnerability database is downloaded on first use.",
	categories: ["supply-chain", "security"],
	targets: ["codebase"],
	engine: "external",
	tool: "grype",
	network: true,
	defaultEnabled: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const bin = yield* requireTool(
				ctx,
				"grype",
				"Install: brew install grype or curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh.",
			);
			const exclude = yield* anchoreExcludes(ws);
			const res = yield* withTempDir((dir) =>
				run(ctx, [bin, `dir:${ws.root}`, ...exclude, "-o", "json", "-q"], {
					cwd: dir,
					okCodes: [0],
					env: { GRYPE_CHECK_FOR_APP_UPDATE: "false" },
				}),
			);
			return parseGrypeReport(yield* parseJson(res.stdout, "grype"), ws.root);
		}),
});

/* -------------------------------------------------------------------------- */
/*                               syft (licences)                              */
/* -------------------------------------------------------------------------- */

type LicenseClass = "strong" | "weak" | "permissive";
/** An SPDX licence id or expression, or a registry's free-form licence name. */
type SpdxExpression = string;
const RANK: Record<LicenseClass, number> = {
	permissive: 0,
	weak: 1,
	strong: 2,
};

const classifyLicense = (id: SpdxExpression): LicenseClass => {
	const s = id.trim();
	if (/^(A?GPL|SSPL|EUPL|OSL)\b/i.test(s)) return "strong";
	if (/^(LGPL|MPL|EPL|CDDL)\b/i.test(s)) return "weak";
	// Free-form names used by registries that do not use SPDX ids.
	if (/lesser general public|library general public/i.test(s)) return "weak";
	if (/(affero|general public license)/i.test(s)) return "strong";
	if (/mozilla public license|eclipse public license/i.test(s)) return "weak";
	return "permissive";
};

/** Free-form text ("GNU General Public License v3") does not tokenise usefully. */
const isFreeForm = (expr: SpdxExpression, tokens: ReadonlyArray<string>) =>
	tokens.length > 1 && !/\b(AND|OR)\b/i.test(expr);

/**
 * Worst-case class of an SPDX expression: `OR` lets the consumer pick the
 * least restrictive alternative, `AND` takes the most restrictive, and `WITH`
 * exceptions are ignored.
 */
export const classifyLicenseExpression = (
	expr: SpdxExpression,
): LicenseClass => {
	const tokens = expr.match(/\(|\)|[^\s()]+/g) ?? [];
	let i = 0;
	const atom = (): LicenseClass => {
		if (tokens[i] === "(") {
			i++;
			const v = or();
			if (tokens[i] === ")") i++;
			return v;
		}
		const id = tokens[i++] ?? "";
		if (tokens[i]?.toUpperCase() === "WITH") i += 2;
		return classifyLicense(id);
	};
	const and = (): LicenseClass => {
		let v = atom();
		while (tokens[i]?.toUpperCase() === "AND") {
			i++;
			const next = atom();
			if (RANK[next] > RANK[v]) v = next;
		}
		return v;
	};
	const or = (): LicenseClass => {
		let v = and();
		while (tokens[i]?.toUpperCase() === "OR") {
			i++;
			const next = and();
			if (RANK[next] < RANK[v]) v = next;
		}
		return v;
	};
	const result = tokens.length ? or() : "permissive";
	return result === "permissive" && isFreeForm(expr, tokens)
		? classifyLicense(expr)
		: result;
};

const licenseValues = (art: Record<string, unknown>): string[] =>
	arr(art.licenses).flatMap((l) => {
		if (typeof l === "string") return [l];
		if (!isRecord(l)) return [];
		const v = str(l.spdxExpression) || str(l.value);
		return v ? [v] : [];
	});

/** The project's own lockfile entry (no source, no integrity) is not a dependency. */
const isOwnLockEntry = (art: Json): boolean => {
	if (str(art.metadataType) !== "javascript-npm-package-lock-entry")
		return false;
	const meta = isRecord(art.metadata) ? art.metadata : {};
	return !str(meta.resolved) && !str(meta.integrity);
};

interface SyftPackage {
	readonly name: PackageName;
	/** `name@version`, or the name alone. */
	readonly at: string;
	readonly file?: FilePath;
	/** Packages with the same key are cataloged once. */
	readonly key: string;
}

const syftPackage = (art: Json, root: RootPath): SyftPackage => {
	const name = str(art.name) ?? "unknown";
	const version = str(art.version);
	const at = version ? `${name}@${version}` : name;
	const loc = arr(art.locations).find(isRecord);
	return {
		name,
		at,
		file: scanPath(root, loc ? str(loc.path) : undefined),
		key: `${str(art.type)}|${at}`,
	};
};

const copyleftFinding = (
	{ name, at, file }: SyftPackage,
	license: SpdxExpression,
	strong: boolean,
): FindingInput => ({
	ruleId: `code.syft-licenses/${strong ? "strong-copyleft" : "weak-copyleft"}`,
	title: `${at}: ${license} (${strong ? "strong" : "weak"} copyleft)`,
	severity: strong ? "medium" : "low",
	category: "compliance",
	message: `${at} is licensed under ${license}, a ${strong ? "strong" : "weak"} copyleft licence${strong ? " whose terms can extend to software that links or distributes it" : " that applies to modifications of the component itself"}.`,
	location: { file },
	evidence: `${at} ${license}`,
	remediation: `Whether this is a problem depends on how the project is distributed (SaaS, shipped binary, internal tool, library). Review ${license} with legal counsel, and replace ${name} or seek a commercial licence if it conflicts with your distribution model.`,
	references: [
		"https://spdx.org/licenses/",
		"https://choosealicense.com/licenses/",
	],
	confidence: "high",
	tags: ["licence", strong ? "strong-copyleft" : "weak-copyleft"],
});

const copyleftFindings = (
	pkg: SyftPackage,
	licenses: ReadonlyArray<SpdxExpression>,
): FindingInput[] =>
	licenses.flatMap((license) => {
		const cls = classifyLicenseExpression(license);
		return cls === "permissive"
			? []
			: [copyleftFinding(pkg, license, cls === "strong")];
	});

const missingLicenseFinding = (
	unlicensed: ReadonlyArray<string>,
	total: number,
): FindingInput => {
	const shown = unlicensed.slice(0, 10).join(", ");
	return {
		ruleId: "code.syft-licenses/missing-license",
		title: `${unlicensed.length} of ${total} packages have no licence information`,
		severity: "info",
		category: "compliance",
		message: `syft found no licence for ${unlicensed.length} of ${total} cataloged packages: ${shown}${unlicensed.length > 10 ? ", ..." : ""}.`,
		evidence: `${unlicensed.length}/${total} packages without licence`,
		remediation:
			"Check these packages' repositories for a licence before redistributing them. Lockfiles often omit licence metadata, so a clean result needs the installed packages or an SBOM from a build; what is acceptable depends on how the project is distributed.",
		references: ["https://spdx.org/licenses/"],
		confidence: "medium",
		tags: ["licence", "unknown-license"],
	};
};

/** Turns `syft -o syft-json` into licence-policy findings. */
export const parseSyftLicenses = (
	json: unknown,
	root: RootPath,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	const findings: FindingInput[] = [];
	const seen = new Set<string>();
	const unlicensed: string[] = [];
	for (const art of arr(json.artifacts)) {
		if (!isRecord(art) || isOwnLockEntry(art)) continue;
		const pkg = syftPackage(art, root);
		if (seen.has(pkg.key)) continue;
		seen.add(pkg.key);
		const licenses = licenseValues(art);
		if (licenses.length) findings.push(...copyleftFindings(pkg, licenses));
		else unlicensed.push(pkg.at);
	}
	if (unlicensed.length)
		findings.push(missingLicenseFinding(unlicensed, seen.size));
	return findings;
};

// biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting control characters is the point
const CONTROL_CHARACTERS = /[\u0000-\u001f]/;

const isPlainPath = (value: string) =>
	value.length > 0 &&
	value.length <= 1024 &&
	!CONTROL_CHARACTERS.test(value) &&
	!value.includes(",") &&
	!value.startsWith("-");

/** `sbomOut` must be a plain, non-empty path string. */
export const validSbomPath = (value: unknown): string | undefined =>
	typeof value === "string" && isPlainPath(value) ? value : undefined;

export const syftLicenses = defineAuditor({
	id: "code.syft-licenses",
	title: "syft licence policy",
	description:
		'Builds an SBOM with syft and flags copyleft licences: strong (AGPL, GPL, SSPL, EUPL, OSL) as medium, weak (LGPL, MPL, EPL, CDDL) as low, and one aggregated info finding for packages with no licence. Set settings["code.syft-licenses"].sbomOut to also write the CycloneDX SBOM to that path. Policy relevance depends on how the project is distributed, so it is opt-in.',
	categories: ["supply-chain", "compliance"],
	targets: ["codebase"],
	engine: "external",
	tool: "syft",
	network: false,
	defaultEnabled: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const bin = yield* requireTool(
				ctx,
				"syft",
				"Install: brew install syft or curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh.",
			);
			const rawOut = ctx.options.settings?.["code.syft-licenses"]?.sbomOut;
			let sbomOut: string | undefined;
			if (rawOut !== undefined) {
				sbomOut = validSbomPath(rawOut);
				if (!sbomOut)
					return yield* Effect.fail(
						new AuditorError({
							message:
								"code.syft-licenses sbomOut must be a plain path string (no control characters or commas, not starting with '-')",
						}),
					);
			}
			const args = [
				bin,
				"scan",
				`dir:${ws.root}`,
				...(yield* anchoreExcludes(ws)),
				"-o",
				"syft-json",
				"-q",
			];
			if (sbomOut)
				args.push("-o", `cyclonedx-json=${resolve(ws.root, sbomOut)}`);
			const res = yield* withTempDir((dir) =>
				run(ctx, args, {
					cwd: dir,
					okCodes: [0],
					env: { SYFT_CHECK_FOR_APP_UPDATE: "false" },
				}),
			);
			return parseSyftLicenses(yield* parseJson(res.stdout, "syft"), ws.root);
		}),
});
