import { type Finding, type Report, SEVERITIES, type Severity } from "../model";
import {
	formatDuration,
	formatLocation,
	hasSuppressionNotice,
	isWebUrl,
	plural,
	SEVERITY_LABEL,
	type SuppressionSummary,
	sanitizeText,
	sortedFindings,
	suppressionDetails,
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

const escapeInline = (text: string): string =>
	text
		.replace(/([\\`*_{}[\]()<>|~&!])/g, "\\$1")
		.replace(/:(?=[\w+-]+:)/g, "\\:")
		.replace(/@(?=\w)/g, "@\u2060");

/** A web address inside prose; `|` ends it so it cannot split a table cell. */
const URL_IN_TEXT = /https?:\/\/[^\s<>`"|]+/g;

/** Drops the sentence's punctuation, and a `)` the address doesn't open, from its end. */
const trimUrl = (url: string): string => {
	let u = url;
	for (;;) {
		const last = u.at(-1);
		const unopened =
			last === ")" &&
			(u.match(/\)/g)?.length ?? 0) > (u.match(/\(/g)?.length ?? 0);
		if (!(last && (/[.,;:!?'\]]/.test(last) || unopened))) return u;
		u = u.slice(0, -1);
	}
};

/**
 * Renders untrusted text (from audited repos and sites) literally on one line,
 * so it cannot inject HTML (`<img>` beacons, `<details>`), images, emphasis,
 * table cells, emoji shortcodes (fake ":white_check_mark: passed") or
 * @mentions into a PR comment. Web addresses become `<...>` autolinks, as a
 * renderer would autolink them anyway, so escapes can't end up inside them
 * and break the link (`\u2026#installation\)`).
 */
const md = (text: unknown): string => {
	const clean = sanitizeText(text).trim();
	let out = "";
	let from = 0;
	for (const m of clean.matchAll(URL_IN_TEXT)) {
		const url = trimUrl(m[0]);
		const href = safeUrl(url);
		if (!href) continue;
		out += `${escapeInline(clean.slice(from, m.index))}<${href}>`;
		from = m.index + url.length;
	}
	return (
		`${out}${escapeInline(clean.slice(from))}`
			// Block markers would start a heading, quote or list when the text leads a line.
			.replace(/^([#+=-])/, "\\$1")
			.replace(/^(\d+)([.)])/, "$1\\$2")
	);
};

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
	if (f.alsoReportedBy?.length)
		lines.push(
			`  Also reported by ${f.alsoReportedBy.map((a) => code(a)).join(", ")}`,
		);
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

	const suppressed = (options.suppressed ?? []).filter(hasSuppressionNotice);
	for (const s of suppressed) {
		out.push(`> **Note:** ${md(suppressionLine(s))}`);
		for (const d of suppressionDetails(s)) out.push(`> - ${md(d)}`);
	}
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

	// Skip reasons are install hints for whoever ran the audit; a reader of
	// the file only needs to know what didn't run.
	const ran = report.results.filter((r) => r.status !== "skipped");
	const skipped = report.results.filter((r) => r.status === "skipped");
	const errored = ran.filter((r) => r.status === "error");
	out.push(
		"<details>",
		`<summary>Auditors: ${summary.auditors.passed} passed, ${summary.auditors.failed} failed, ${summary.auditors.skipped} skipped, ${summary.auditors.error} errored</summary>`,
		"",
	);
	if (ran.length) {
		out.push(
			"| Auditor | Status | Findings | Duration | Note |",
			"| --- | --- | ---: | ---: | --- |",
			...ran.map(
				(r) =>
					`| ${code(r.auditor, { table: true })} | ${md(r.status)} | ${r.findings.length} | ${formatDuration(r.durationMs)} | ${md(r.message ?? "")} |`,
			),
			"",
		);
	}
	if (skipped.length) {
		out.push(`Skipped: ${skipped.map((r) => code(r.auditor)).join(", ")}`, "");
	}
	out.push("</details>", "");
	if (errored.length) {
		out.push(
			`> Some auditors errored, so results may be incomplete: ${errored
				.map((r) => code(r.auditor))
				.join(", ")}`,
			"",
		);
	}

	return `${out.join("\n").trimEnd()}\n`;
};

/**
 * The report as a prompt for an AI chat, for readers who aren't security
 * experts: explain the risks plainly, order the fixes, flag false alarms.
 */
export const toAiPrompt = (
	report: Report,
	options: MarkdownOptions = {},
): string => {
	const { score, grade } = report.summary;
	return `Here's an openaudit report for ${sanitizeText(targetLabel(report))}. It scored ${score}/100 (grade ${grade}).

Please:
1. Explain the biggest risks in plain language and why they matter. Assume I'm not a security expert.
2. List what to fix first, in order, with the steps for each.
3. Point out anything that looks like a false alarm.

If you can see my code, make the fixes and tell me what you changed.

The report:

${toMarkdown(report, options)}`;
};
