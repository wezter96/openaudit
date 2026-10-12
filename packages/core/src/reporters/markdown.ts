import { type Finding, type Report, SEVERITIES, type Severity } from "../model";
import {
	formatDuration,
	formatLocation,
	isWebUrl,
	plural,
	SEVERITY_LABEL,
	sortedFindings,
	targetLabel,
} from "./shared";

export interface MarkdownOptions {
	/** Max findings listed (info excluded). Defaults to 100; the rest are counted. */
	readonly maxFindings?: number;
	/** Heading level of the title (1–4). Defaults to 2, which suits PR comments. */
	readonly headingLevel?: number;
}

/** Escapes text so it renders literally inside a table cell or list item. */
const md = (text: string): string =>
	text
		.replace(/\r?\n+/g, " ")
		.replace(/([\\`*_[\]|<>])/g, "\\$1")
		.trim();

/** Inline code that survives backticks in the value. */
const code = (text: string): string => {
	const clean = text.replace(/\r?\n+/g, " ");
	const fence = clean.includes("`") ? "``" : "`";
	return `${fence}${clean.includes("`") ? ` ${clean} ` : clean}${fence}`;
};

const findingLines = (f: Finding): string[] => {
	const loc = formatLocation(f.location);
	const head = `- **${md(f.title)}** ${code(f.ruleId)}${loc ? ` at ${code(loc)}` : ""}`;
	const lines = [head, `  ${md(f.message)}`];
	if (f.evidence) lines.push(`  Evidence: ${code(f.evidence)}`);
	if (f.remediation) lines.push(`  **Fix:** ${md(f.remediation)}`);
	const refs = (f.references ?? []).filter(isWebUrl);
	if (refs.length)
		lines.push(`  Refs: ${refs.map((r) => `<${r}>`).join(", ")}`);
	return lines;
};

const countsLine = (counts: Record<Severity, number>): string => {
	const parts = SEVERITIES.filter((s) => counts[s] > 0).map(
		(s) => `${counts[s]} ${s}`,
	);
	return parts.length ? parts.join(" · ") : "no findings";
};

export const toMarkdown = (
	report: Report,
	options: MarkdownOptions = {},
): string => {
	const max = options.maxFindings ?? 100;
	const h = "#".repeat(Math.min(4, Math.max(1, options.headingLevel ?? 2)));
	const { summary } = report;
	const out: string[] = [];

	out.push(`${h} openaudit: ${md(targetLabel(report))}`, "");
	out.push(
		`**Score ${summary.score}/100 (${summary.grade})** · ${countsLine(summary.counts)} · ${plural(report.results.length, "auditor")} in ${formatDuration(report.durationMs)}`,
		"",
	);

	if (summary.categories.length) {
		out.push(
			"| Category | Score | Grade | Critical | High | Medium | Low | Info |",
			"| --- | ---: | :---: | ---: | ---: | ---: | ---: | ---: |",
		);
		for (const c of summary.categories) {
			const n = c.counts;
			out.push(
				`| ${c.category} | ${c.score} | ${c.grade} | ${n.critical} | ${n.high} | ${n.medium} | ${n.low} | ${n.info} |`,
			);
		}
		out.push("");
	}

	if (report.ai) {
		out.push(`${h}# AI insights`, "", md(report.ai.summary), "");
		report.ai.priorities.forEach((p, i) => {
			out.push(
				`${i + 1}. **${md(p.title)}**: ${md(p.why)} **Fix:** ${md(p.fix)}`,
			);
		});
		out.push("");
	}

	const findings = sortedFindings(report);
	const actionable = findings.filter((f) => f.severity !== "info");
	const info = findings.filter((f) => f.severity === "info");

	if (findings.length === 0) {
		out.push("No findings.", "");
	} else {
		let shown = 0;
		for (const severity of SEVERITIES) {
			if (severity === "info") continue;
			const group = actionable.filter((f) => f.severity === severity);
			if (!group.length || shown >= max) continue;
			out.push(`${h}# ${SEVERITY_LABEL[severity]} (${group.length})`, "");
			for (const f of group.slice(0, max - shown)) out.push(...findingLines(f));
			shown += Math.min(group.length, max - shown);
			out.push("");
		}
		if (actionable.length > shown) {
			out.push(
				`_…and ${plural(actionable.length - shown, "more finding")}. Use the JSON or HTML report for the full list._`,
				"",
			);
		}
		if (info.length) {
			out.push(
				"<details>",
				`<summary>Info (${info.length})</summary>`,
				"",
				...info.slice(0, max).flatMap(findingLines),
				"",
				"</details>",
				"",
			);
		}
	}

	const notRun = report.results.filter(
		(r) => r.status === "skipped" || r.status === "error",
	);
	out.push(
		"<details>",
		`<summary>Auditors: ${summary.auditors.passed} passed, ${summary.auditors.failed} failed, ${summary.auditors.skipped} skipped, ${summary.auditors.error} errored</summary>`,
		"",
		"| Auditor | Status | Findings | Duration | Note |",
		"| --- | --- | ---: | ---: | --- |",
		...report.results.map(
			(r) =>
				`| ${code(r.auditor)} | ${r.status} | ${r.findings.length} | ${formatDuration(r.durationMs)} | ${md(r.message ?? "")} |`,
		),
		"",
		"</details>",
		"",
	);
	if (notRun.some((r) => r.status === "error")) {
		out.push(
			`> Some auditors errored, so results may be incomplete: ${notRun
				.filter((r) => r.status === "error")
				.map((r) => code(r.auditor))
				.join(", ")}`,
			"",
		);
	}

	return `${out.join("\n").trimEnd()}\n`;
};
