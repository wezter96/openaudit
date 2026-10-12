import { type Finding, type Report, SEVERITIES, type Severity } from "../model";
import {
	formatDuration,
	formatLocation,
	isWebUrl,
	plural,
	SEVERITY_LABEL,
	type SuppressionSummary,
	sanitizeText,
	sortedFindings,
	suppressedTotal,
	suppressionLine,
	targetLabel,
} from "./shared";

export interface MarkdownOptions {
	/** Max findings listed (info excluded). Defaults to 100; the rest are counted. */
	readonly maxFindings?: number;
	/** Heading level of the title (1–4). Defaults to 2, which suits PR comments. */
	readonly headingLevel?: number;
	/** Suppression counts to disclose (config ignores, baselines). */
	readonly suppressed?: ReadonlyArray<SuppressionSummary>;
}

/**
 * Renders untrusted text (from audited repos and sites) literally on one line,
 * so it cannot inject HTML (`<img>` beacons, `<details>`), links, images,
 * emphasis, table cells, emoji shortcodes (fake ":white_check_mark: passed")
 * or @mentions into a PR comment.
 */
const md = (text: unknown): string =>
	sanitizeText(text)
		.trim()
		.replace(/([\\`*_{}[\]()<>|~&!])/g, "\\$1")
		.replace(/:(?=[\w+-]+:)/g, "\\:")
		.replace(/@(?=\w)/g, "@\u2060")
		// Block markers would start a heading, quote or list when the text leads a line.
		.replace(/^([#+=-])/, "\\$1")
		.replace(/^(\d+)([.)])/, "$1\\$2");

/**
 * Inline code for untrusted text. The fence is longer than any backtick run in
 * the value, so the value cannot close it; inside code spans HTML is inert.
 */
const code = (text: unknown, options: { readonly table?: boolean } = {}) => {
	let clean = sanitizeText(text).trim() || " ";
	if (options.table) clean = clean.replaceAll("|", "\\|");
	const longest = Math.max(
		0,
		...(clean.match(/`+/g) ?? []).map((run) => run.length),
	);
	const fence = "`".repeat(longest + 1);
	const pad = clean.startsWith("`") || clean.endsWith("`") ? " " : "";
	return `${fence}${pad}${clean}${pad}${fence}`;
};

/** A normalised http(s) URL that cannot break out of `<...>`, or undefined. */
const safeUrl = (value: string): string | undefined => {
	if (!isWebUrl(value)) return undefined;
	try {
		const href = new URL(value).href;
		return /^https?:\/\/[^\s<>`"]+$/.test(href) ? href : undefined;
	} catch {
		return undefined;
	}
};

const findingLines = (f: Finding): string[] => {
	const loc = formatLocation(f.location);
	const head = `- **${md(f.title)}** ${code(f.ruleId)}${loc ? ` at ${code(loc)}` : ""}`;
	const lines = [head, `  ${md(f.message)}`];
	if (f.evidence) lines.push(`  Evidence: ${code(f.evidence)}`);
	if (f.remediation) lines.push(`  **Fix:** ${md(f.remediation)}`);
	const refs = (f.references ?? []).flatMap((r) => safeUrl(r) ?? []);
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

	const suppressed = (options.suppressed ?? []).filter(
		(s) => suppressedTotal(s) > 0,
	);
	for (const s of suppressed) out.push(`> **Note:** ${md(suppressionLine(s))}`);
	if (suppressed.length) out.push("");

	if (summary.categories.length) {
		out.push(
			"| Category | Score | Grade | Critical | High | Medium | Low | Info |",
			"| --- | ---: | :---: | ---: | ---: | ---: | ---: | ---: |",
		);
		for (const c of summary.categories) {
			const n = c.counts;
			out.push(
				`| ${md(c.category)} | ${c.score} | ${md(c.grade)} | ${n.critical} | ${n.high} | ${n.medium} | ${n.low} | ${n.info} |`,
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
				`| ${code(r.auditor, { table: true })} | ${md(r.status)} | ${r.findings.length} | ${formatDuration(r.durationMs)} | ${md(r.message ?? "")} |`,
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
