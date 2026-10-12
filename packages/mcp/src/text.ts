import {
	type Finding,
	formatLocation,
	type Report,
	SEVERITIES,
	targetLabel,
} from "@openaudit/core";

import { allFindingsOf } from "./reports";

/** One line per finding, with the fingerprint agents need for `get_finding`. */
export const findingLine = (f: Finding): string => {
	const loc = formatLocation(f.location);
	return `- [${f.severity}] ${f.title} (${f.ruleId}${loc ? ` @ ${loc}` : ""}) fp=${f.fingerprint}`;
};

export const countsText = (counts: Report["summary"]["counts"]): string => {
	const parts = SEVERITIES.filter((s) => counts[s] > 0).map(
		(s) => `${counts[s]} ${s}`,
	);
	return parts.length ? parts.join(", ") : "no findings";
};

/** Concise markdown summary of a report for tool results. */
export const reportSummaryText = (
	report: Report,
	reportId: string,
	options: { readonly maxFindings?: number; readonly saveNote?: string } = {},
): string => {
	const max = options.maxFindings ?? 50;
	const { summary } = report;
	const findings = allFindingsOf(report);
	const lines = [
		`# openaudit report ${reportId}`,
		`Target: ${targetLabel(report)} (${report.target.kinds.join(", ")}${report.target.technologies.length ? `; ${report.target.technologies.join(", ")}` : ""})`,
		`Score: ${summary.score}/100 (${summary.grade}) | ${countsText(summary.counts)}`,
	];
	if (summary.categories.length)
		lines.push(
			`Categories: ${summary.categories.map((c) => `${c.category} ${c.score} ${c.grade}`).join(" | ")}`,
		);
	if (options.saveNote) lines.push(options.saveNote);
	if (findings.length) {
		lines.push(
			"",
			`## Findings (${Math.min(max, findings.length)} of ${findings.length}, most severe first)`,
			...findings.slice(0, max).map(findingLine),
		);
		if (findings.length > max)
			lines.push(
				`- … ${findings.length - max} more in structuredContent.report or get_report`,
			);
	}
	const notRun = report.results.filter(
		(r) => r.status === "skipped" || r.status === "error",
	);
	if (notRun.length) {
		lines.push(
			"",
			"## Not run",
			...notRun.map(
				(r) =>
					`- ${r.auditor}: ${r.status}${r.message ? ` (${r.message})` : ""}`,
			),
		);
	}
	return lines.join("\n");
};
