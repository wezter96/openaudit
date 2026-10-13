import type { Finding, Report, Severity } from "../model";
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

const location = (finding: Finding, report: Report) => {
	const loc = finding.location;
	if (loc?.file) {
		const region: Record<string, number> = {};
		if (loc.line !== undefined && loc.line >= 1) {
			region.startLine = Math.floor(loc.line);
			if (loc.column !== undefined && loc.column >= 1)
				region.startColumn = Math.floor(loc.column);
		}
		return {
			physicalLocation: {
				artifactLocation: report.target.root
					? { uri: pathUri(loc.file), uriBaseId: SRCROOT }
					: { uri: pathUri(loc.file) },
				...(region.startLine ? { region } : {}),
			},
			...(loc.selector
				? { logicalLocations: [{ fullyQualifiedName: loc.selector }] }
				: {}),
		};
	}
	const url = loc?.url ?? report.target.url;
	if (url) {
		return {
			physicalLocation: { artifactLocation: { uri: url } },
			...(loc?.selector
				? { logicalLocations: [{ fullyQualifiedName: loc.selector }] }
				: {}),
		};
	}
	return undefined;
};

const markdownHelp = (f: Finding): string => {
	const parts = [`**${f.title}**`, "", f.message];
	if (f.remediation) parts.push("", `**Remediation:** ${f.remediation}`);
	const refs = (f.references ?? []).filter(isWebUrl);
	if (refs.length) parts.push("", ...refs.map((r) => `- ${r}`));
	return parts.join("\n");
};

/** Builds the SARIF 2.1.0 log object (useful when callers want to post-process). */
export const toSarifLog = (report: Report) => {
	const findings = sortedFindings(report);

	// One rule per ruleId; the most severe finding defines its defaults.
	const ruleIndex = new Map<string, number>();
	const rules: Array<Record<string, unknown>> = [];
	for (const f of findings) {
		if (ruleIndex.has(f.ruleId)) continue;
		ruleIndex.set(f.ruleId, rules.length);
		const helpUri = (f.references ?? []).find(isWebUrl);
		rules.push({
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
				...(f.category === "security" || f.category === "supply-chain"
					? { "security-severity": SECURITY_SEVERITY[f.severity] }
					: {}),
			},
		});
	}

	const results = findings.map((f) => {
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
			properties: {
				severity: f.severity,
				category: f.category,
				auditor: f.auditor,
				...(f.alsoReportedBy?.length
					? { alsoReportedBy: [...f.alsoReportedBy] }
					: {}),
				...(f.confidence ? { confidence: f.confidence } : {}),
				...(f.evidence ? { evidence: f.evidence } : {}),
				...(f.tags?.length ? { tags: [...f.tags] } : {}),
			},
		};
	});

	const notifications = report.results
		.filter((r) => r.status === "error" || r.status === "skipped")
		.map((r) => ({
			level: r.status === "error" ? "error" : "note",
			message: {
				text: `${r.auditor} ${r.status}${r.message ? `: ${r.message}` : ""}`,
			},
			descriptor: { id: r.auditor },
		}));

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
				...(report.target.root
					? {
							originalUriBaseIds: {
								[SRCROOT]: { uri: fileRootUri(report.target.root) },
							},
						}
					: {}),
				invocations: [
					{
						executionSuccessful: true,
						startTimeUtc: report.startedAt,
						endTimeUtc: report.finishedAt,
						toolExecutionNotifications: notifications,
					},
				],
				results,
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
