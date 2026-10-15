import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	AuditorError,
	type Category,
	type Confidence,
	DEFAULT_IGNORES,
	defineAuditor,
	type FindingInput,
	redact,
	requireTool,
	requireWorkspace,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import {
	arr,
	cweTags,
	gitignoredPaths,
	inIgnoredDir,
	num,
	owaspTags,
	parseJson,
	relPath,
	runTool,
	severityOf,
	str,
	withTempDir,
} from "../tool";
import { type OsvVuln, osvSeverity, severityFromScore } from "./dependencies";
import { listOf, oneOrMany, recordOf, stringsOf } from "./report-fields";
import { cweUrl, isRecord, kebab, scrubLine, truncate } from "./util";

/* -------------------------------------------------------------------------- */
/*                                   Shared                                   */
/* -------------------------------------------------------------------------- */

/** Parses `gitleaks detect --report-format json` output. */
export const parseGitleaksReport = (
	json: unknown,
	root: string,
): FindingInput[] =>
	arr(json).flatMap((item) => {
		if (!isRecord(item)) return [];
		const rule = str(item.RuleID) ?? "secret";
		const secret = str(item.Secret) ?? "";
		const match = str(item.Match) ?? "";
		const hasSecret = secret !== "" && secret !== "REDACTED";
		const evidence = hasSecret
			? match.split(secret).join(redact(secret))
			: match;
		return [
			{
				ruleId: `code.gitleaks/${kebab(rule)}`,
				title: str(item.Description) ?? `Secret detected (${rule})`,
				severity: "high",
				category: "security",
				message: `gitleaks rule \`${rule}\` matched a likely secret${item.Entropy ? ` (entropy ${Number(item.Entropy).toFixed(2)})` : ""}.`,
				location: {
					file: relPath(root, str(item.File)),
					line: num(item.StartLine),
					column: num(item.StartColumn),
				},
				evidence: truncate(scrubLine(evidence, hasSecret ? [secret] : [])),
				remediation:
					"Revoke and rotate the credential, purge it from git history, and load it from a secret manager or environment variable.",
				references: [cweUrl(798), "https://github.com/gitleaks/gitleaks"],
				confidence: "medium",
				tags: ["cwe-798", "owasp-a07", "secrets", ...stringsOf(item.Tags)],
			},
		];
	});

export const gitleaks = defineAuditor({
	id: "code.gitleaks",
	title: "gitleaks secret scan",
	description:
		"Runs gitleaks over the working tree (no git history) to detect hardcoded secrets, skipping dependencies and build output like the built-in auditors.",
	categories: ["security"],
	targets: ["codebase"],
	engine: "external",
	tool: "gitleaks",
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const bin = yield* requireTool(
				ctx,
				"gitleaks",
				"Install: brew install gitleaks (https://github.com/gitleaks/gitleaks#installing).",
			);
			const report = join(
				tmpdir(),
				`openaudit-gitleaks-${crypto.randomUUID()}.json`,
			);
			const text = yield* runTool(
				ctx,
				[
					bin,
					"detect",
					"--no-git",
					"--source",
					ws.root,
					"--report-format",
					"json",
					"--report-path",
					report,
					"--redact",
					"--exit-code",
					"0",
					"--no-banner",
				],
				ws.root,
				[0, 1],
			).pipe(
				Effect.andThen(
					Effect.tryPromise({
						try: () => Bun.file(report).text(),
						catch: (cause) =>
							new AuditorError({
								message: "gitleaks did not write a report",
								cause,
							}),
					}),
				),
				Effect.ensuring(Effect.promise(() => rm(report, { force: true }))),
			);
			// gitleaks has no exclude flag, so drop what the built-ins skip
			// (gitignored build output in dist/ would otherwise be reported).
			return parseGitleaksReport(
				yield* parseJson(text || "[]", "gitleaks"),
				ws.root,
			).filter((f) => !inIgnoredDir(f.location?.file));
		}),
});

/* -------------------------------------------------------------------------- */
/*                                   semgrep                                  */
/* -------------------------------------------------------------------------- */

/** Semgrep `metadata.category` values that are not security findings. */
const SEMGREP_CATEGORIES = new Map<string, Category>([
	["performance", "performance"],
	["best-practice", "best-practices"],
]);

/** Secret rules are always security, whatever category their metadata gives. */
const semgrepCategory = (checkId: string, category: unknown): Category =>
	/secret/i.test(checkId)
		? "security"
		: (SEMGREP_CATEGORIES.get(str(category) ?? "") ?? "security");

const semgrepConfidence = (value: unknown): Confidence => {
	const level = str(value)?.toLowerCase();
	return level === "high" || level === "low" ? level : "medium";
};

/** The matched lines, unless semgrep withheld them behind a login. */
const semgrepEvidence = (lines: string | undefined): string | undefined =>
	lines && lines !== "requires login" ? truncate(scrubLine(lines)) : undefined;

const semgrepFinding = (r: unknown, root: string): FindingInput[] => {
	if (!isRecord(r)) return [];
	const extra = recordOf(r.extra);
	const meta = recordOf(extra.metadata);
	const start = recordOf(r.start);
	const checkId = str(r.check_id) ?? "unknown";
	const fix = str(extra.fix);
	return [
		{
			ruleId: `code.semgrep/${checkId}`,
			title: truncate(
				checkId.split(".").pop()?.replace(/[-_]/g, " ") ?? checkId,
				100,
			),
			severity: severityOf(meta.impact ?? extra.severity),
			category: semgrepCategory(checkId, meta.category),
			message: str(extra.message) ?? checkId,
			location: {
				file: relPath(root, str(r.path)),
				line: num(start.line),
				column: num(start.col),
			},
			evidence: semgrepEvidence(str(extra.lines)),
			remediation: fix
				? `Suggested fix: ${fix}`
				: "See the rule documentation for the recommended fix.",
			references: [
				...stringsOf(meta.references).slice(0, 3),
				...listOf(meta.source),
			],
			confidence: semgrepConfidence(meta.confidence),
			tags: [
				...cweTags(oneOrMany(meta.cwe)),
				...owaspTags(oneOrMany(meta.owasp)),
			],
		},
	];
};

/** Parses `semgrep scan --json` output. */
export const parseSemgrepReport = (
	json: unknown,
	root: string,
): FindingInput[] =>
	isRecord(json)
		? arr(json.results).flatMap((r) => semgrepFinding(r, root))
		: [];

export const semgrep = defineAuditor({
	id: "code.semgrep",
	title: "Semgrep SAST",
	description:
		"Runs Semgrep with the community `auto` ruleset (downloads rules from the Semgrep registry).",
	categories: ["security", "best-practices"],
	targets: ["codebase"],
	engine: "external",
	tool: "semgrep",
	network: true,
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const bin = yield* requireTool(
				ctx,
				"semgrep",
				"Install: pipx install semgrep or brew install semgrep (https://semgrep.dev/docs/getting-started/).",
			);
			const res = yield* runTool(
				ctx,
				[bin, "scan", "--config", "auto", "--json", "--quiet", ws.root],
				ws.root,
				[0, 1],
			);
			return parseSemgrepReport(
				yield* parseJson(res.stdout, "semgrep"),
				ws.root,
			);
		}),
});

/* -------------------------------------------------------------------------- */
/*                                 osv-scanner                                */
/* -------------------------------------------------------------------------- */

/** One reported vulnerability: a group of alias ids, or a single id. */
interface OsvUnit {
	readonly ids: string[];
	readonly max: string | undefined;
}

interface OsvPackage {
	readonly name: string;
	readonly version: string;
	readonly ecosystem: string;
	readonly file: string | undefined;
	readonly vulns: ReadonlyMap<string, OsvVuln>;
}

const osvVulnsById = (vulnerabilities: unknown): Map<string, OsvVuln> =>
	new Map(
		arr(vulnerabilities).flatMap((v) =>
			isRecord(v) && typeof v.id === "string"
				? [[v.id, v as unknown as OsvVuln] as const]
				: [],
		),
	);

/** v2 groups aliases with a max severity; v1 lists each vulnerability alone. */
const osvUnits = (
	groups: unknown,
	vulns: ReadonlyMap<string, OsvVuln>,
): OsvUnit[] => {
	const records = arr(groups).filter(isRecord);
	return records.length
		? records.map((g) => ({ ids: stringsOf(g.ids), max: str(g.max_severity) }))
		: [...vulns.keys()].map((id) => ({ ids: [id], max: undefined }));
};

const osvUnitSeverity = (
	max: string | undefined,
	vuln: OsvVuln | undefined,
): Severity => {
	const score = max ? Number(max) : Number.NaN;
	if (Number.isFinite(score) && score > 0) return severityFromScore(score);
	return vuln ? osvSeverity(vuln) : "medium";
};

const osvFixedVersions = (vuln: OsvVuln | undefined): Set<string> =>
	new Set(
		(vuln?.affected ?? []).flatMap((a) =>
			(a.ranges ?? []).flatMap((r) =>
				(r.events ?? []).flatMap((e) => (e.fixed ? [e.fixed] : [])),
			),
		),
	);

const osvFinding = (pkg: OsvPackage, unit: OsvUnit): FindingInput[] => {
	const { name, version, ecosystem, vulns } = pkg;
	const id = unit.ids.find((i) => i.startsWith("GHSA-")) ?? unit.ids[0];
	if (!id) return [];
	const vuln = vulns.get(id) ?? unit.ids.map((i) => vulns.get(i)).find(Boolean);
	const fixed = osvFixedVersions(vuln);
	const aliases = [...new Set([...unit.ids, ...(vuln?.aliases ?? [])])].filter(
		(a) => a !== id,
	);
	return [
		{
			ruleId: "code.osv-scanner/vulnerable-dependency",
			title: `${name}@${version}: ${vuln?.summary ?? id}`,
			severity: osvUnitSeverity(unit.max, vuln),
			category: "supply-chain",
			message: `${name} ${version}${ecosystem ? ` (${ecosystem})` : ""} is affected by ${id}${aliases.length ? ` (${aliases.slice(0, 3).join(", ")})` : ""}.`,
			location: { file: pkg.file },
			evidence: `${name}@${version} ${id}`,
			remediation: fixed.size
				? `Upgrade ${name} to ${[...fixed].join(" or ")} or later.`
				: `No fixed version is published for ${name}; consider replacing it or mitigating per the advisory.`,
			references: [`https://osv.dev/vulnerability/${id}`],
			confidence: "high",
			tags: [
				"owasp-a06",
				...[id, ...aliases]
					.filter((a) => /^(CVE|GHSA)-/.test(a))
					.map((a) => a.toLowerCase()),
			],
		},
	];
};

const osvPackageFindings = (
	p: unknown,
	file: string | undefined,
): FindingInput[] => {
	if (!isRecord(p) || !isRecord(p.package)) return [];
	const vulns = osvVulnsById(p.vulnerabilities);
	const pkg: OsvPackage = {
		name: str(p.package.name) ?? "unknown",
		version: str(p.package.version) ?? "",
		ecosystem: str(p.package.ecosystem) ?? "",
		file,
		vulns,
	};
	return osvUnits(p.groups, vulns).flatMap((unit) => osvFinding(pkg, unit));
};

const osvResultFindings = (result: unknown, root: string): FindingInput[] => {
	if (!isRecord(result)) return [];
	const file = relPath(root, str(recordOf(result.source).path));
	return arr(result.packages).flatMap((p) => osvPackageFindings(p, file));
};

/** Parses `osv-scanner --format json` output (v1 and v2). */
export const parseOsvScannerReport = (
	json: unknown,
	root: string,
): FindingInput[] =>
	isRecord(json)
		? arr(json.results).flatMap((result) => osvResultFindings(result, root))
		: [];

export const osvScanner = defineAuditor({
	id: "code.osv-scanner",
	title: "osv-scanner dependency scan",
	description:
		"Runs Google's osv-scanner recursively over lockfiles and SBOMs to find known-vulnerable dependencies.",
	categories: ["supply-chain", "security"],
	targets: ["codebase"],
	engine: "external",
	tool: "osv-scanner",
	network: true,
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const bin = yield* requireTool(
				ctx,
				"osv-scanner",
				"Install: brew install osv-scanner or go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest.",
			);
			// Exit 1 = vulnerabilities found; 128 = no packages found.
			const res = yield* runTool(
				ctx,
				[bin, "--format", "json", "-r", ws.root],
				ws.root,
				[0, 1, 128],
			);
			if (res.code === 128 || !res.stdout.trim())
				return yield* skip("osv-scanner found no supported lockfiles");
			return parseOsvScannerReport(
				yield* parseJson(res.stdout, "osv-scanner"),
				ws.root,
			);
		}),
});

/* -------------------------------------------------------------------------- */
/*                                  trivy fs                                  */
/* -------------------------------------------------------------------------- */

const trivyVulnFinding = (
	v: unknown,
	file: string | undefined,
): FindingInput[] => {
	if (!isRecord(v)) return [];
	const id = str(v.VulnerabilityID) ?? "unknown";
	const pkg = str(v.PkgName) ?? "unknown";
	const installed = str(v.InstalledVersion) ?? "";
	const fixed = str(v.FixedVersion);
	return [
		{
			ruleId: "code.trivy-fs/vulnerable-dependency",
			title: `${pkg}@${installed}: ${str(v.Title) ?? id}`,
			severity: severityOf(v.Severity),
			category: "supply-chain",
			message: `${pkg} ${installed} is affected by ${id}${str(v.Title) ? `: ${str(v.Title)}` : "."}`,
			location: { file },
			evidence: `${pkg}@${installed} ${id}`,
			remediation: fixed
				? `Upgrade ${pkg} to ${fixed}.`
				: `No fixed version is available for ${pkg}; consider replacing it.`,
			references: listOf(v.PrimaryURL),
			confidence: "high",
			tags: ["owasp-a06", ...cweTags(stringsOf(v.CweIDs)), id.toLowerCase()],
		},
	];
};

const trivySecretFinding = (
	s: unknown,
	file: string | undefined,
): FindingInput[] => {
	if (!isRecord(s)) return [];
	const rule = str(s.RuleID) ?? "secret";
	const match = str(s.Match);
	return [
		{
			ruleId: `code.trivy-fs/secret-${kebab(rule)}`,
			title: str(s.Title) ?? `Secret detected (${rule})`,
			severity: severityOf(s.Severity, "high"),
			category: "security",
			message: `trivy secret rule \`${rule}\` matched in ${file ?? "a file"}.`,
			location: { file, line: num(s.StartLine) },
			// Trivy masks secrets with `*`; scrub defensively anyway.
			evidence: match ? truncate(scrubLine(match), 120) : undefined,
			remediation:
				"Revoke and rotate the credential, remove it from the repository and history, and load it from a secret manager.",
			references: [cweUrl(798)],
			confidence: "medium",
			tags: ["cwe-798", "owasp-a07", "secrets"],
		},
	];
};

const trivyMisconfigFinding = (
	m: unknown,
	file: string | undefined,
): FindingInput[] => {
	if (!isRecord(m)) return [];
	const id = str(m.AVDID) ?? str(m.ID) ?? "misconfig";
	return [
		{
			ruleId: `code.trivy-fs/misconfig-${kebab(id)}`,
			title: str(m.Title) ?? id,
			severity: severityOf(m.Severity),
			category: "security",
			message: str(m.Message) ?? str(m.Description) ?? id,
			location: { file, line: num(recordOf(m.CauseMetadata).StartLine) },
			remediation: str(m.Resolution) ?? "See the referenced documentation.",
			references: [
				...listOf(m.PrimaryURL),
				...stringsOf(m.References).slice(0, 2),
			],
			confidence: "high",
			tags: ["owasp-a05"],
		},
	];
};

const trivyResultFindings = (result: unknown, root: string): FindingInput[] => {
	if (!isRecord(result)) return [];
	const file = relPath(root, str(result.Target));
	return [
		...arr(result.Vulnerabilities).flatMap((v) => trivyVulnFinding(v, file)),
		...arr(result.Secrets).flatMap((s) => trivySecretFinding(s, file)),
		...arr(result.Misconfigurations).flatMap((m) =>
			trivyMisconfigFinding(m, file),
		),
	];
};

/** Parses `trivy fs --format json` output (vulnerabilities, secrets, misconfigurations). */
export const parseTrivyReport = (
	json: unknown,
	root: string,
): FindingInput[] =>
	isRecord(json)
		? arr(json.Results).flatMap((result) => trivyResultFindings(result, root))
		: [];

/**
 * trivy's misconfig scanners minus `terraform`, which clones remote modules
 * (git URLs chosen by the target) with no switch to stop it. Checkov, TFLint
 * and iac.terraform cover Terraform without fetching anything.
 */
const TRIVY_MISCONFIG_SCANNERS = [
	"azure-arm",
	"cloudformation",
	"dockerfile",
	"helm",
	"kubernetes",
	"terraformplan-json",
	"terraformplan-snapshot",
	"ansible",
];

export const trivyFs = defineAuditor({
	id: "code.trivy-fs",
	title: "Trivy filesystem scan",
	description:
		"Runs `trivy fs` for vulnerable dependencies, secrets and IaC misconfigurations.",
	categories: ["security", "supply-chain"],
	targets: ["codebase"],
	engine: "external",
	tool: "trivy",
	network: true,
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const bin = yield* requireTool(
				ctx,
				"trivy",
				"Install: brew install trivy (https://trivy.dev/latest/getting-started/installation/).",
			);
			const skip = (yield* gitignoredPaths(ws)).flatMap((p) =>
				p.endsWith("/") ? ["--skip-dirs", p.slice(0, -1)] : ["--skip-files", p],
			);
			// From a scratch dir: trivy reads trivy.yaml from its cwd.
			const res = yield* withTempDir("openaudit-trivy-", (cwd) =>
				runTool(
					ctx,
					[
						bin,
						"fs",
						"--format",
						"json",
						"--scanners",
						"vuln,secret,misconfig",
						"--misconfig-scanners",
						TRIVY_MISCONFIG_SCANNERS.join(","),
						...DEFAULT_IGNORES.flatMap((d) => ["--skip-dirs", `**/${d}`]),
						...skip,
						"--quiet",
						ws.root,
					],
					cwd,
					[0],
				),
			);
			return parseTrivyReport(
				yield* parseJson(res.stdout, "trivy"),
				ws.root,
			).filter((f) => !inIgnoredDir(f.location?.file));
		}),
});
