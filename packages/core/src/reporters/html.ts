import type { Finding, Report } from "../model";
import { toCsv } from "./csv";
import {
	auditorsPanel,
	CATEGORY_LABEL,
	type CategoryView,
	categoryPanel,
	categoryViews,
	ICON,
	overviewPanel,
	standardsPanel,
	t,
	type View,
} from "./html/panels";
import { SCRIPT } from "./html/script";
import { STYLE } from "./html/style";
import { tinyRing } from "./html/viz";
import { canonicalize } from "./json";
import { toMarkdown } from "./markdown";
import { toSarifLog } from "./sarif";
import {
	baseName,
	escapeHtml as e,
	formatDuration,
	plural,
	type SuppressionSummary,
	scriptSafeJson,
	sortedFindings,
	targetLabel,
} from "./shared";

export interface HtmlOptions {
	/** Overrides the document title. */
	readonly title?: string;
	/** Suppression counts to disclose (config ignores, baselines). */
	readonly suppressed?: ReadonlyArray<SuppressionSummary>;
}

/*
 * A single self-contained page: no external requests (enforced by a CSP that
 * only allows the hashed inline style and script), every report string
 * escaped, and built to pass the accessibility checks openaudit itself runs.
 *
 * Everything is rendered server-side; without JavaScript the panels show
 * stacked. The script turns them into tabs, adds filters and the JSON download.
 */

const sha256 = (text: string): string =>
	new Bun.CryptoHasher("sha256").update(text).digest("base64");

const CSP = [
	"default-src 'none'",
	`style-src 'sha256-${sha256(STYLE)}'`,
	`script-src 'sha256-${sha256(SCRIPT)}'`,
	"img-src data:",
	"base-uri 'none'",
	"form-action 'none'",
].join("; ");

const MAX_TECH = 8;

const MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(" ");

/** "13 Oct 2026, 09:04 UTC", independent of the reader's locale. */
const formatTime = (iso: string): string => {
	const d = new Date(iso);
	if (Number.isNaN(d.getTime())) return iso;
	const pad = (n: number) => String(n).padStart(2, "0");
	return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}, ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
};

interface Tab {
	readonly id: string;
	readonly label: string;
	/** Leading glyph: a grade letter or an icon. */
	readonly glyph: string;
	/** Trailing mono figure, e.g. a score. */
	readonly figure?: string;
	/** Score hairline under the label. */
	readonly bar?: string;
	/** What the decorations say, for screen readers. */
	readonly spoken?: string;
	/** Starts a new group in the rail. */
	readonly sep?: boolean;
}

const RAIL_ICON = {
	standards:
		'<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M12 3 4.5 6v5.5c0 4.6 3.1 8.3 7.5 9.5 4.4-1.2 7.5-4.9 7.5-9.5V6z"/><path d="M8.5 12h7M8.5 15h4.5M8.5 9h7"/></svg>',
	auditors:
		'<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M4 6h16M4 12h16M4 18h10"/></svg>',
};

const scoreBar = (score: number, grade: string): string =>
	`<svg class="tbar" viewBox="0 0 100 2" preserveAspectRatio="none" aria-hidden="true" focusable="false"><rect class="tr" width="100" height="2"/><rect class="af-${grade}" width="${Math.max(0, Math.min(100, score))}" height="2"/></svg>`;

const categoryTab = (c: CategoryView, i: number): Tab => {
	const n = c.findings.length;
	const g = c.summary.grade;
	return {
		id: c.category,
		label: CATEGORY_LABEL[c.category] ?? c.category,
		glyph: `<span class="gm-${g}">${g}</span>`,
		figure: String(c.summary.score),
		bar: scoreBar(c.summary.score, g),
		spoken: `, grade ${g}, score ${c.summary.score}, ${plural(n, "finding")}`,
		sep: i === 0,
	};
};

const tabButton = (tab: Tab, i: number): string =>
	`<button type="button" class="tab${tab.sep ? " sep" : ""}" role="tab" id="tab-${tab.id}" aria-controls="${tab.id}" aria-selected="${i === 0}" tabindex="${i === 0 ? 0 : -1}"><span class="tg" aria-hidden="true">${tab.glyph}</span><span class="tl">${e(tab.label)}${tab.spoken ? `<span class="sr-only">${e(tab.spoken)}</span>` : ""}</span>${tab.figure ? `<span class="ts" aria-hidden="true">${e(tab.figure)}</span>` : ""}${tab.bar ?? ""}</button>`;

/**
 * The page is made to be shared, so its embedded copy of the report (also the
 * "Download JSON" file) names the folder or file, not the local path.
 */
const shareable = (report: Report): Report => {
	const t = report.target;
	if (t.url || t.image || t.cloud) return report;
	const name = targetLabel(report);
	return {
		...report,
		target: {
			...t,
			input: name,
			...(t.root ? { root: name } : {}),
			...(t.file ? { file: baseName(t.file) } : {}),
		},
	};
};

/** One file the Download menu offers. */
interface Download {
	readonly id: string;
	readonly label: string;
	readonly hint: string;
	readonly file: string;
	readonly type: string;
	/** `json` blocks are pretty-printed on download; `text` blocks hold a string. */
	readonly format: "json" | "text";
	readonly data: unknown;
}

/**
 * Every format is rendered here by the core reporters, from the shareable
 * report, and embedded for the browser to save. SARIF gets no `root` at all,
 * so it carries no `originalUriBaseIds` and its paths stay relative.
 */
const downloads = (
	report: Report,
	suppressed: HtmlOptions["suppressed"],
): Download[] => {
	const shared = shareable(report);
	const { root: _root, ...target } = shared.target;
	return [
		{
			id: "json",
			label: "JSON",
			hint: "The full report, for tools and baselines",
			file: "openaudit-report.json",
			type: "application/json",
			format: "json",
			data: canonicalize(shared),
		},
		{
			id: "sarif",
			label: "SARIF",
			hint: "For GitHub code scanning and IDEs",
			file: "openaudit-report.sarif",
			type: "application/sarif+json",
			format: "json",
			data: toSarifLog({ ...shared, target }),
		},
		{
			id: "markdown",
			label: "Markdown",
			hint: "For pull request comments",
			file: "openaudit-report.md",
			type: "text/markdown",
			format: "text",
			data: toMarkdown(shared, { suppressed }),
		},
		{
			id: "csv",
			label: "CSV",
			hint: "One row per finding, for spreadsheets",
			file: "openaudit-findings.csv",
			type: "text/csv",
			format: "text",
			data: toCsv(shared),
		},
	];
};

const downloadMenu = (items: ReadonlyArray<Download>): string =>
	`<div class="dl" data-js hidden>
<button class="btn" type="button" id="dl-button" aria-haspopup="menu" aria-expanded="false" aria-controls="dl-menu" data-action="menu">${ICON.download}Download${ICON.chevron}</button>
<ul class="dl-menu" id="dl-menu" role="menu" aria-labelledby="dl-button" hidden>${items
		.map(
			(d) =>
				`<li role="none"><button type="button" role="menuitem" tabindex="-1" data-action="download" data-src="data-${d.id}"><span class="dl-l">${d.label}</span> <span class="dl-h">${d.hint}</span> <span class="dl-f">${e(d.file)}</span></button></li>`,
		)
		.join("")}</ul>
</div>`;

const dataBlocks = (items: ReadonlyArray<Download>): string =>
	items
		.map(
			(d) =>
				`<script type="application/json" id="data-${d.id}" data-file="${e(d.file)}" data-type="${e(d.type)}" data-format="${d.format}">${scriptSafeJson(d.data)}</script>`,
		)
		.join("\n");

export const toHtml = (report: Report, options: HtmlOptions = {}): string => {
	const { summary, target } = report;
	const label = targetLabel(report);
	const title = options.title ?? `openaudit report: ${label}`;

	// Duplicates confirm a finding another auditor kept; they are not listed.
	const findings = sortedFindings(report).filter(
		(f) => f.duplicateOf === undefined,
	);
	const ids = new Map<Finding, string>(
		findings.map((f, i) => [f, `f-${i + 1}`]),
	);
	const categories = categoryViews(report, findings);
	const files = downloads(report, options.suppressed ?? report.suppressed);
	const view: View = {
		report,
		findings,
		ids,
		categories,
		suppressed: options.suppressed ?? report.suppressed ?? [],
	};

	const tabs: Tab[] = [
		{
			id: "overview",
			label: "Overview",
			glyph: `<span class="gm-${summary.grade}">${summary.grade}</span>`,
			figure: String(summary.score),
			bar: scoreBar(summary.score, summary.grade),
			spoken: `, grade ${summary.grade}, score ${summary.score}`,
		},
		...categories.map(categoryTab),
		{
			id: "standards",
			label: "OWASP and CWE",
			glyph: RAIL_ICON.standards,
			sep: true,
		},
		{
			id: "auditors",
			label: "Auditors",
			glyph: RAIL_ICON.auditors,
			figure: String(report.results.length),
			spoken: `, ${plural(report.results.length, "auditor")}`,
		},
	];

	const tech = target.technologies;
	const meta: Array<[string, string]> = [
		["Target", target.kinds.join(", ") || target.type],
	];
	if (target.cloud) meta.push(["Cloud", target.cloud]);
	meta.push(["Finished", formatTime(report.finishedAt)]);
	meta.push(["Took", formatDuration(report.durationMs)]);
	if (report.diff)
		meta.push([
			"Changes since",
			`${report.diff.base} (${plural(report.diff.changedFiles, "file")})`,
		]);
	if (tech.length)
		meta.push([
			"Stack",
			tech.slice(0, MAX_TECH).join(", ") +
				(tech.length > MAX_TECH ? `, and ${tech.length - MAX_TECH} more` : ""),
		]);

	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="${CSP}">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="light dark">
<meta name="generator" content="${t(report.tool.name)} ${t(report.tool.version)}">
<title>${t(title)}</title>
<style>${STYLE}</style>
</head>
<body>
<a class="skip" href="#main">Skip to report</a>
<header class="mast"><div class="wrap">
<div class="slug">
<p class="brand">${ICON.logo}<span>${t(report.tool.name)}</span><span class="ver">${t(report.tool.version)}</span></p>
<div class="actions" data-js hidden>
${downloadMenu(files)}
<button class="btn" type="button" data-action="print">${ICON.print}Print</button>
</div>
</div>
<h1><span class="h1-pre">Audit of</span> <span class="h1-target">${t(label)}</span></h1>
<dl class="meta">${meta.map(([k, v]) => `<div><dt>${k}</dt><dd>${t(v)}</dd></div>`).join("")}</dl>
</div></header>
<div class="frame">
<nav class="rail" id="tabbar" aria-label="Report sections" hidden>
<p class="mini" aria-hidden="true">${tinyRing(summary.score, summary.grade)}<b class="gm-${summary.grade}">${summary.grade}</b><span class="num">${summary.score}/100</span></p>
<div class="tablist" role="tablist" aria-label="Report sections" aria-orientation="vertical">${tabs.map(tabButton).join("")}<span class="tab-ink" aria-hidden="true"></span></div>
</nav>
<nav class="toc" id="toc" aria-label="Report sections"><ul>${tabs.map((tab) => `<li><a href="#${tab.id}">${e(tab.label)}</a></li>`).join("")}</ul></nav>
<main id="main" tabindex="-1">
${overviewPanel(view)}
${categories.map((c) => categoryPanel(c, view)).join("\n")}
${standardsPanel(view)}
${auditorsPanel(view)}
</main>
</div>
<footer><div class="wrap"><span>Generated by ${t(report.tool.name)} ${t(report.tool.version)}</span><span>Report schema v${t(report.schemaVersion)}</span><span>Started ${t(formatTime(report.startedAt))}</span><span>Finished ${t(formatTime(report.finishedAt))}</span></div></footer>
${dataBlocks(files)}
<script>${SCRIPT}</script>
</body>
</html>
`;
};
