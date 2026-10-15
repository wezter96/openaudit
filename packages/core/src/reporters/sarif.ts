import type { Finding, Location, Report, Severity } from "../model";
import { isWebUrl, sortedFindings } from "./shared";

export interface SarifOptions {
	/** Indentation; defaults to 2. */
	readonly indent?: number;
}

type SarifLevel = "error" | "warning" | "note";

const LEVEL: Record<Severity, SarifLevel> = {
	critical: "error",
	high: "error",
	medium: "warning",
	low: "note",
	info: "note",
};

/** GitHub code scanning reads `security-severity` (0–10) to rank alerts. */
const SECURITY_SEVERITY: Record<Severity, string> = {
	critical: "9.5",
	high: "8.0",
	medium: "5.5",
	low: "3.0",
	info: "0.0",
};

const SRCROOT = "%SRCROOT%";

/** `code.secrets/aws-key` → `CodeSecretsAwsKey` (SARIF rule `name`). */
const ruleName = (ruleId: string): string =>
	ruleId
		.split(/[^A-Za-z0-9]+/)
		.filter(Boolean)
		.map((p) => p[0]?.toUpperCase() + p.slice(1))
		.join("");

/** Encodes a relative POSIX path as a URI reference. */
const pathUri = (path: string): string =>
	path.replace(/^\.\//, "").split("/").map(encodeURIComponent).join("/");

const fileRootUri = (root: string): string => {
	const posix = root.replaceAll("\\", "/");
	const withSlash = posix.endsWith("/") ? posix : `${posix}/`;
	const absolute = withSlash.startsWith("/") ? withSlash : `/${withSlash}`;
	return `file://${absolute.split("/").map(encodeURIComponent).join("/")}`;
};

const logical = (selector: string | undefined) =>
	selector ? { logicalLocations: [{ fullyQualifiedName: selector }] } : {};

/** Line and column, when the finding has a usable start line. */
const regionOf = (loc: Location): Record<string, number> => {
	const region: Record<string, number> = {};
	if (loc.line === undefined || loc.line < 1) return region;
	region.startLine = Math.floor(loc.line);
	if (loc.column !== undefined && loc.column >= 1)
		region.startColumn = Math.floor(loc.column);
	return region;
};

const fileLocation = (loc: Location, file: string, report: Report) => {
	const region = regionOf(loc);
	return {
		physicalLocation: {
			artifactLocation: report.target.root
				? { uri: pathUri(file), uriBaseId: SRCROOT }
				: { uri: pathUri(file) },
			...(region.startLine ? { region } : {}),
		},
		...logical(loc.selector),
	};
};

const location = (finding: Finding, report: Report) => {
	const loc = finding.location;
	if (loc?.file) return fileLocation(loc, loc.file, report);
	const url = loc?.url ?? report.target.url;
	if (!url) return undefined;
	return {
		physicalLocation: { artifactLocation: { uri: url } },
		...logical(loc?.selector),
	};
};

/**
 * GitHub code scanning rejects a result without a location. An info finding
 * with nowhere to point (a summary, the truck factor) has nothing to show
 * there, so SARIF leaves it out; the other formats keep it.
 */
const hasPlace = (f: Finding, report: Report): boolean =>
	f.severity !== "info" || location(f, report) !== undefined;

const markdownHelp = (f: Finding): string => {
	const parts = [`**${f.title}**`, "", f.message];
	if (f.remediation) parts.push("", `**Remediation:** ${f.remediation}`);
	const refs = (f.references ?? []).filter(isWebUrl);
	if (refs.length) parts.push("", ...refs.map((r) => `- ${r}`));
	return parts.join("\n");
};

const isSecurity = (f: Finding): boolean =>
	f.category === "security" || f.category === "supply-chain";

const sarifRule = (f: Finding): Record<string, unknown> => {
	const helpUri = (f.references ?? []).find(isWebUrl);
	return {
		id: f.ruleId,
		name: ruleName(f.ruleId),
		shortDescription: { text: f.title },
		fullDescription: { text: f.message },
		...(helpUri ? { helpUri } : {}),
		help: {
			text: f.remediation ?? f.message,
			markdown: markdownHelp(f),
		},
		defaultConfiguration: { level: LEVEL[f.severity] },
		properties: {
			category: f.category,
			tags: [...new Set([f.category, ...(f.tags ?? [])])],
			...(isSecurity(f)
				? { "security-severity": SECURITY_SEVERITY[f.severity] }
				: {}),
		},
	};
};

/** One rule per ruleId; the most severe finding defines its defaults. */
const sarifRules = (findings: ReadonlyArray<Finding>) => {
	const ruleIndex = new Map<string, number>();
	const rules: Array<Record<string, unknown>> = [];
	for (const f of findings) {
		if (ruleIndex.has(f.ruleId)) continue;
		ruleIndex.set(f.ruleId, rules.length);
		rules.push(sarifRule(f));
	}
	return { rules, ruleIndex };
};

const resultProperties = (f: Finding) => ({
	severity: f.severity,
	category: f.category,
	auditor: f.auditor,
	...(f.alsoReportedBy?.length
		? { alsoReportedBy: [...f.alsoReportedBy] }
		: {}),
	...(f.confidence ? { confidence: f.confidence } : {}),
	...(f.evidence ? { evidence: f.evidence } : {}),
	...(f.tags?.length ? { tags: [...f.tags] } : {}),
});

const sarifResult = (
	f: Finding,
	report: Report,
	ruleIndex: ReadonlyMap<string, number>,
) => {
	const loc = location(f, report);
	return {
		ruleId: f.ruleId,
		ruleIndex: ruleIndex.get(f.ruleId) ?? 0,
		level: LEVEL[f.severity],
		message: {
			text: f.remediation ? `${f.message}\n\n${f.remediation}` : f.message,
		},
		...(loc ? { locations: [loc] } : {}),
		partialFingerprints: { "openaudit/v1": f.fingerprint },
		properties: resultProperties(f),
	};
};

const notificationsOf = (report: Report) =>
	report.results
		.filter((r) => r.status === "error" || r.status === "skipped")
		.map((r) => ({
			level: r.status === "error" ? "error" : "note",
			message: {
				text: `${r.auditor} ${r.status}${r.message ? `: ${r.message}` : ""}`,
			},
			descriptor: { id: r.auditor },
		}));

const uriBaseIds = (root: string | undefined) =>
	root ? { originalUriBaseIds: { [SRCROOT]: { uri: fileRootUri(root) } } } : {};

/** Builds the SARIF 2.1.0 log object (useful when callers want to post-process). */
export const toSarifLog = (report: Report) => {
	const findings = sortedFindings(report);
	const { rules, ruleIndex } = sarifRules(findings);
	return {
		$schema: "https://json.schemastore.org/sarif-2.1.0.json",
		version: "2.1.0" as const,
		runs: [
			{
				tool: {
					driver: {
						name: report.tool.name,
						version: report.tool.version,
						semanticVersion: report.tool.version,
						informationUri: "https://github.com/openaudit/openaudit",
						rules,
					},
				},
				...uriBaseIds(report.target.root),
				invocations: [
					{
						executionSuccessful: true,
						startTimeUtc: report.startedAt,
						endTimeUtc: report.finishedAt,
						toolExecutionNotifications: notificationsOf(report),
					},
				],
				results: findings
					.filter((f) => hasPlace(f, report))
					.map((f) => sarifResult(f, report, ruleIndex)),
				properties: {
					target: report.target.input,
					score: report.summary.score,
					grade: report.summary.grade,
				},
			},
		],
	};
};

export const toSarif = (report: Report, options: SarifOptions = {}): string =>
	`${JSON.stringify(toSarifLog(report), null, options.indent ?? 2)}\n`;
