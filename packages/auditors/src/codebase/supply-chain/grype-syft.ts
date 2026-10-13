import { resolve } from "node:path";
import {
	AuditorError,
	defineAuditor,
	type FindingInput,
	requireTool,
	requireWorkspace,
	type Severity,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, cweTags, num, parseJson, severityOf, str } from "../../tool";
import { severityFromScore } from "../dependencies";
import { isRecord, truncate } from "../util";
import { run, scanPath, vulnFinding, withTempDir } from "./shared";

/* -------------------------------------------------------------------------- */
/*                                    grype                                   */
/* -------------------------------------------------------------------------- */

const grypeSeverity = (vuln: Record<string, unknown>): Severity => {
	const label = str(vuln.severity)?.toLowerCase();
	if (label === "negligible") return "info";
	if (label && label !== "unknown") return severityOf(label);
	const scores = arr(vuln.cvss).flatMap((c) =>
		isRecord(c) && isRecord(c.metrics) && num(c.metrics.baseScore) !== undefined
			? [num(c.metrics.baseScore) as number]
			: [],
	);
	return scores.length ? severityFromScore(Math.max(...scores)) : "medium";
};

/** Parses `grype -o json`. */
export const parseGrypeReport = (
	json: unknown,
	root: string,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	const findings: FindingInput[] = [];
	const seen = new Set<string>();
	for (const m of arr(json.matches)) {
		if (!isRecord(m) || !isRecord(m.vulnerability) || !isRecord(m.artifact))
			continue;
		const vuln = m.vulnerability;
		const art = m.artifact;
		const id = str(vuln.id) ?? "unknown";
		const name = str(art.name) ?? "unknown";
		const version = str(art.version);
		const loc = arr(art.locations).find(isRecord);
		const file = scanPath(root, loc ? str(loc.path) : undefined);
		const key = `${id}|${name}|${version}|${file}`;
		if (seen.has(key)) continue;
		seen.add(key);
		const related = arr(m.relatedVulnerabilities)
			.filter(isRecord)
			.map((r) => str(r.id))
			.filter((r): r is string => !!r);
		const fix = isRecord(vuln.fix) ? vuln.fix : {};
		const state = str(fix.state);
		const details = arr(m.matchDetails).find(isRecord);
		const fuzzy = (str(details?.type) ?? "").includes("cpe");
		const urls = arr(vuln.urls).filter(
			(u): u is string => typeof u === "string",
		);
		const description = str(vuln.description);
		findings.push(
			vulnFinding({
				auditor: "code.grype",
				name,
				version,
				ecosystem: str(art.type),
				id,
				aliases: related,
				summary: truncate((description ?? id).split("\n")[0] ?? id, 140),
				severity: grypeSeverity(vuln),
				fixed: arr(fix.versions).filter(
					(v): v is string => typeof v === "string",
				),
				fixHint:
					state === "wont-fix"
						? `The vendor will not fix this in ${name}; consider replacing it.`
						: undefined,
				file,
				references: [
					...(str(vuln.dataSource) ? [str(vuln.dataSource) as string] : []),
					...urls.slice(0, 2),
				],
				confidence: fuzzy ? "low" : "high",
				note: fuzzy
					? "Matched by CPE, which can produce false positives."
					: undefined,
				tags: cweTags(
					arr(vuln.cwes)
						.filter(isRecord)
						.map((c) => str(c.cwe) ?? ""),
				),
			}),
		);
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
			const res = yield* withTempDir((dir) =>
				run(ctx, [bin, `dir:${ws.root}`, "-o", "json", "-q"], {
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
const RANK: Record<LicenseClass, number> = {
	permissive: 0,
	weak: 1,
	strong: 2,
};

const classifyLicense = (id: string): LicenseClass => {
	const s = id.trim();
	if (/^(A?GPL|SSPL|EUPL|OSL)\b/i.test(s)) return "strong";
	if (/^(LGPL|MPL|EPL|CDDL)\b/i.test(s)) return "weak";
	// Free-form names used by registries that do not use SPDX ids.
	if (/lesser general public|library general public/i.test(s)) return "weak";
	if (/(affero|general public license)/i.test(s)) return "strong";
	if (/mozilla public license|eclipse public license/i.test(s)) return "weak";
	return "permissive";
};

/**
 * Worst-case class of an SPDX expression: `OR` lets the consumer pick the
 * least restrictive alternative, `AND` takes the most restrictive, and `WITH`
 * exceptions are ignored.
 */
export const classifyLicenseExpression = (expr: string): LicenseClass => {
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
	// Free-form text ("GNU General Public License v3") does not tokenise usefully.
	return result === "permissive" &&
		tokens.length > 1 &&
		!/\b(AND|OR)\b/i.test(expr)
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

/** Turns `syft -o syft-json` into licence-policy findings. */
export const parseSyftLicenses = (
	json: unknown,
	root: string,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	const findings: FindingInput[] = [];
	const seen = new Set<string>();
	const unlicensed: string[] = [];
	let total = 0;
	for (const art of arr(json.artifacts)) {
		if (!isRecord(art)) continue;
		// The project's own lockfile entry (no source, no integrity) is not a dependency.
		const meta = isRecord(art.metadata) ? art.metadata : {};
		if (
			str(art.metadataType) === "javascript-npm-package-lock-entry" &&
			!str(meta.resolved) &&
			!str(meta.integrity)
		)
			continue;
		const name = str(art.name) ?? "unknown";
		const version = str(art.version);
		const at = version ? `${name}@${version}` : name;
		const loc = arr(art.locations).find(isRecord);
		const file = scanPath(root, loc ? str(loc.path) : undefined);
		const key = `${str(art.type)}|${at}`;
		if (seen.has(key)) continue;
		seen.add(key);
		total++;
		const licenses = licenseValues(art);
		if (!licenses.length) {
			unlicensed.push(at);
			continue;
		}
		for (const license of licenses) {
			const cls = classifyLicenseExpression(license);
			if (cls === "permissive") continue;
			const strong = cls === "strong";
			findings.push({
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
		}
	}
	if (unlicensed.length) {
		const shown = unlicensed.slice(0, 10).join(", ");
		findings.push({
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
		});
	}
	return findings;
};

/** `sbomOut` must be a plain, non-empty path string. */
export const validSbomPath = (value: unknown): string | undefined =>
	typeof value === "string" &&
	value.length > 0 &&
	value.length <= 1024 &&
	// biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting control characters is the point
	!/[\u0000-\u001f]/.test(value) &&
	!value.includes(",") &&
	!value.startsWith("-")
		? value
		: undefined;

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
			const args = [bin, "scan", `dir:${ws.root}`, "-o", "syft-json", "-q"];
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
