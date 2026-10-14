import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	AuditorError,
	DEFAULT_IGNORES,
	defineAuditor,
	type FindingInput,
	redact,
	requireTool,
	requireWorkspace,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import {
	arr,
	cweTags,
	inIgnoredDir,
	num,
	owaspTags,
	parseJson,
	relPath,
	runTool,
	severityOf,
	str,
} from "../tool";
import { type OsvVuln, osvSeverity, severityFromScore } from "./dependencies";
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
		const evidence =
			secret && secret !== "REDACTED"
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
				evidence: truncate(
					scrubLine(evidence, secret && secret !== "REDACTED" ? [secret] : []),
				),
				remediation:
					"Revoke and rotate the credential, purge it from git history, and load it from a secret manager or environment variable.",
				references: [cweUrl(798), "https://github.com/gitleaks/gitleaks"],
				confidence: "medium",
				tags: [
					"cwe-798",
					"owasp-a07",
					"secrets",
					...arr(item.Tags).filter((t): t is string => typeof t === "string"),
				],
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

/** Parses `semgrep scan --json` output. */
export const parseSemgrepReport = (
	json: unknown,
	root: string,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	return arr(json.results).flatMap((r) => {
		if (!isRecord(r)) return [];
		const extra = isRecord(r.extra) ? r.extra : {};
		const meta = isRecord(extra.metadata) ? extra.metadata : {};
		const start = isRecord(r.start) ? r.start : {};
		const checkId = str(r.check_id) ?? "unknown";
		const cwe = arr(meta.cwe)
			.concat(str(meta.cwe) ?? [])
			.filter((c): c is string => typeof c === "string");
		const owasp = arr(meta.owasp)
			.concat(str(meta.owasp) ?? [])
			.filter((c): c is string => typeof c === "string");
		const refs = arr(meta.references).filter(
			(u): u is string => typeof u === "string",
		);
		const lines = str(extra.lines);
		const message = str(extra.message) ?? checkId;
		const category = /secret/i.test(checkId)
			? "security"
			: str(meta.category) === "performance"
				? "performance"
				: str(meta.category) === "best-practice"
					? "best-practices"
					: "security";
		return [
			{
				ruleId: `code.semgrep/${checkId}`,
				title: truncate(
					checkId.split(".").pop()?.replace(/[-_]/g, " ") ?? checkId,
					100,
				),
				severity: severityOf(meta.impact ?? extra.severity),
				category,
				message,
				location: {
					file: relPath(root, str(r.path)),
					line: num(start.line),
					column: num(start.col),
				},
				evidence:
					lines && lines !== "requires login"
						? truncate(scrubLine(lines))
						: undefined,
				remediation: str(extra.fix)
					? `Suggested fix: ${str(extra.fix)}`
					: "See the rule documentation for the recommended fix.",
				references: [
					...refs.slice(0, 3),
					...(str(meta.source) ? [str(meta.source) as string] : []),
				],
				confidence:
					str(meta.confidence)?.toLowerCase() === "high"
						? "high"
						: str(meta.confidence)?.toLowerCase() === "low"
							? "low"
							: "medium",
				tags: [...cweTags(cwe), ...owaspTags(owasp)],
			},
		];
	});
};

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

/** Parses `osv-scanner --format json` output (v1 and v2). */
export const parseOsvScannerReport = (
	json: unknown,
	root: string,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	const findings: FindingInput[] = [];
	for (const result of arr(json.results)) {
		if (!isRecord(result)) continue;
		const source = isRecord(result.source) ? result.source : {};
		const file = relPath(root, str(source.path));
		for (const p of arr(result.packages)) {
			if (!isRecord(p) || !isRecord(p.package)) continue;
			const name = str(p.package.name) ?? "unknown";
			const version = str(p.package.version) ?? "";
			const ecosystem = str(p.package.ecosystem) ?? "";
			const vulns = new Map(
				arr(p.vulnerabilities).flatMap((v) =>
					isRecord(v) && typeof v.id === "string"
						? [[v.id, v as unknown as OsvVuln] as const]
						: [],
				),
			);
			const groups = arr(p.groups).filter(isRecord);
			const units = groups.length
				? groups.map((g) => ({
						ids: arr(g.ids).filter((i): i is string => typeof i === "string"),
						max: str(g.max_severity),
					}))
				: [...vulns.keys()].map((id) => ({ ids: [id], max: undefined }));
			for (const unit of units) {
				const id = unit.ids.find((i) => i.startsWith("GHSA-")) ?? unit.ids[0];
				if (!id) continue;
				const vuln =
					vulns.get(id) ?? unit.ids.map((i) => vulns.get(i)).find(Boolean);
				const score = unit.max ? Number(unit.max) : Number.NaN;
				const severity =
					Number.isFinite(score) && score > 0
						? severityFromScore(score)
						: vuln
							? osvSeverity(vuln)
							: "medium";
				const fixed = new Set<string>();
				for (const a of vuln?.affected ?? [])
					for (const r of a.ranges ?? [])
						for (const e of r.events ?? []) if (e.fixed) fixed.add(e.fixed);
				const aliases = [
					...new Set([...unit.ids, ...(vuln?.aliases ?? [])]),
				].filter((a) => a !== id);
				findings.push({
					ruleId: "code.osv-scanner/vulnerable-dependency",
					title: `${name}@${version}: ${vuln?.summary ?? id}`,
					severity,
					category: "supply-chain",
					message: `${name} ${version}${ecosystem ? ` (${ecosystem})` : ""} is affected by ${id}${aliases.length ? ` (${aliases.slice(0, 3).join(", ")})` : ""}.`,
					location: { file },
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
				});
			}
		}
	}
	return findings;
};

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

/** Parses `trivy fs --format json` output (vulnerabilities, secrets, misconfigurations). */
export const parseTrivyReport = (
	json: unknown,
	root: string,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	const findings: FindingInput[] = [];
	for (const result of arr(json.Results)) {
		if (!isRecord(result)) continue;
		const file = relPath(root, str(result.Target));
		for (const v of arr(result.Vulnerabilities)) {
			if (!isRecord(v)) continue;
			const id = str(v.VulnerabilityID) ?? "unknown";
			const pkg = str(v.PkgName) ?? "unknown";
			const installed = str(v.InstalledVersion) ?? "";
			const fixed = str(v.FixedVersion);
			const cwes = arr(v.CweIDs).filter(
				(c): c is string => typeof c === "string",
			);
			findings.push({
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
				references: str(v.PrimaryURL) ? [str(v.PrimaryURL) as string] : [],
				confidence: "high",
				tags: ["owasp-a06", ...cweTags(cwes), id.toLowerCase()],
			});
		}
		for (const s of arr(result.Secrets)) {
			if (!isRecord(s)) continue;
			const rule = str(s.RuleID) ?? "secret";
			findings.push({
				ruleId: `code.trivy-fs/secret-${kebab(rule)}`,
				title: str(s.Title) ?? `Secret detected (${rule})`,
				severity: severityOf(s.Severity, "high"),
				category: "security",
				message: `trivy secret rule \`${rule}\` matched in ${file ?? "a file"}.`,
				location: { file, line: num(s.StartLine) },
				// Trivy masks secrets with `*`; scrub defensively anyway.
				evidence: str(s.Match)
					? truncate(scrubLine(str(s.Match) as string), 120)
					: undefined,
				remediation:
					"Revoke and rotate the credential, remove it from the repository and history, and load it from a secret manager.",
				references: [cweUrl(798)],
				confidence: "medium",
				tags: ["cwe-798", "owasp-a07", "secrets"],
			});
		}
		for (const m of arr(result.Misconfigurations)) {
			if (!isRecord(m)) continue;
			const id = str(m.AVDID) ?? str(m.ID) ?? "misconfig";
			const cause = isRecord(m.CauseMetadata) ? m.CauseMetadata : {};
			findings.push({
				ruleId: `code.trivy-fs/misconfig-${kebab(id)}`,
				title: str(m.Title) ?? id,
				severity: severityOf(m.Severity),
				category: "security",
				message: str(m.Message) ?? str(m.Description) ?? id,
				location: { file, line: num(cause.StartLine) },
				remediation: str(m.Resolution) ?? "See the referenced documentation.",
				references: [
					...(str(m.PrimaryURL) ? [str(m.PrimaryURL) as string] : []),
					...arr(m.References)
						.filter((u): u is string => typeof u === "string")
						.slice(0, 2),
				],
				confidence: "high",
				tags: ["owasp-a05"],
			});
		}
	}
	return findings;
};

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
			const res = yield* runTool(
				ctx,
				[
					bin,
					"fs",
					"--format",
					"json",
					"--scanners",
					"vuln,secret,misconfig",
					...DEFAULT_IGNORES.flatMap((d) => ["--skip-dirs", `**/${d}`]),
					"--quiet",
					ws.root,
				],
				ws.root,
				[0],
			);
			return parseTrivyReport(
				yield* parseJson(res.stdout, "trivy"),
				ws.root,
			).filter((f) => !inIgnoredDir(f.location?.file));
		}),
});
