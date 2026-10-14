import {
	type ComplianceMatch,
	groupByCweTop25,
	groupByOwasp,
	hasComplianceMapping,
} from "../../compliance";
import { CATEGORY_LABEL } from "../../labels";
import {
	type AuditorResult,
	CATEGORIES,
	type Category,
	type CategorySummary,
	type Finding,
	type Grade,
	type Location,
	type Report,
	SEVERITIES,
	type Severity,
	type SeverityCounts,
	severityRank,
} from "../../model";
import { countSeverities, gradeFor, scoreFor } from "../../scoring";
import {
	escapeHtml as e,
	formatDuration,
	formatLocation,
	hasSuppressionNotice,
	isWebUrl,
	plural,
	SEVERITY_LABEL,
	type SuppressionSummary,
	sanitizeText,
	suppressedTotal,
	suppressionDetails,
	suppressionLine,
} from "../shared";
import { dial, miniDial, runtimeStrip, spectrum } from "./viz";

/** Escaped single-line text from the report. */
export const t = (value: unknown): string => e(sanitizeText(value));
/** Escaped text that keeps its line breaks (shown with `white-space`). */
const tm = (value: unknown): string =>
	e(sanitizeText(value, { multiline: true }));

export { CATEGORY_LABEL };

const CATEGORY_LEDE: Record<Category, string> = {
	security:
		"Vulnerabilities, exposed secrets, insecure configuration and missing defences.",
	accessibility:
		"Barriers for people who use assistive technology, a keyboard or zoom (WCAG).",
	performance: "Load speed, payload size and runtime cost.",
	seo: "Discoverability: metadata, crawlability and structured data.",
	privacy: "Tracking, third-party data flows and exposure of personal data.",
	"best-practices": "Platform conventions and defensive defaults.",
	reliability: "Correctness risks, error handling and operational robustness.",
	maintainability:
		"Code health: complexity, duplication, dead code and hygiene.",
	"supply-chain": "Dependencies, provenance, pinning and build integrity.",
	compliance: "Licence and policy obligations.",
};

const categoryLabel = (c: string): string => CATEGORY_LABEL[c as Category] ?? c;

/** Everything the panels need, computed once. */
export interface View {
	readonly report: Report;
	/** Non-duplicate findings, most severe first. */
	readonly findings: ReadonlyArray<Finding>;
	/** Element id of each listed finding. */
	readonly ids: ReadonlyMap<Finding, string>;
	readonly categories: ReadonlyArray<CategoryView>;
	readonly suppressed: ReadonlyArray<SuppressionSummary>;
}

export interface CategoryView {
	readonly category: Category;
	readonly summary: CategorySummary;
	readonly findings: ReadonlyArray<Finding>;
	readonly auditors: ReadonlyArray<AuditorResult>;
}

const ran = (r: AuditorResult) =>
	r.status === "passed" || r.status === "failed";

/* ---------- small components ---------- */

const svg = (body: string, cls = "") =>
	`<svg${cls ? ` class="${cls}"` : ""} viewBox="0 0 24 24" aria-hidden="true" focusable="false">${body}</svg>`;

export const ICON = {
	download: svg('<path d="M12 4v11m0 0-4.5-4.5M12 15l4.5-4.5M5 20h14"/>'),
	copy: svg(
		'<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h8"/>',
	),
	print: svg(
		'<path d="M7 9V4h10v5M7 17H5a1 1 0 0 1-1-1v-5a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v5a1 1 0 0 1-1 1h-2M7 14h10v6H7z"/>',
	),
	info: svg('<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>'),
	alert: svg('<path d="M12 4 3 20h18L12 4zM12 10v4M12 17h.01"/>'),
	check: svg('<path d="m5 12.5 4.5 4.5L19 7.5"/>'),
	gap: svg('<circle cx="12" cy="12" r="9"/><path d="M8 12h8"/>'),
	branch: svg(
		'<circle cx="6" cy="6" r="2.2"/><circle cx="6" cy="18" r="2.2"/><circle cx="18" cy="8" r="2.2"/><path d="M6 8.2v7.6M18 10.2c0 4-6 3-11 6"/>',
	),
	sparkle: svg(
		'<path d="M12 2l1.9 5.6 5.6 1.9-5.6 1.9L12 17l-1.9-5.6-5.6-1.9 5.6-1.9zM19 15l.9 2.1L22 18l-2.1.9L19 21l-.9-2.1L16 18l2.1-.9z"/>',
	),
	chevron: svg('<path d="M9 6l6 6-6 6"/>', "chev"),
	logo: svg(
		'<path class="logo-a" d="M12 1.5 20.5 4.7v6.1c0 5.3-3.6 9.9-8.5 11.7-4.9-1.8-8.5-6.4-8.5-11.7V4.7z"/><path class="logo-b" d="m8.2 12.1 2.6 2.6 5-5.3"/>',
	),
};

export const sevMark = (s: Severity): string =>
	`<span class="sev sev-${s}">${SEVERITY_LABEL[s]}</span>`;

export const gradeMark = (g: Grade, cls = ""): string =>
	`<span class="gm-${g}${cls ? ` ${cls}` : ""}"><span class="sr-only">Grade </span>${g}</span>`;

/** "1 high, 3 low", or "No findings". */
const countsText = (c: SeverityCounts): string => {
	const parts = SEVERITIES.filter((s) => c[s] > 0).map((s) => `${c[s]} ${s}`);
	return parts.length ? parts.join(", ") : "No findings";
};

const statusMark = (status: AuditorResult["status"]): string =>
	`<span class="status"><span class="dot dot-${status}" aria-hidden="true"></span>${e(status)}</span>`;

const callout = (html: string, icon: string, cls = ""): string =>
	`<div class="callout${cls ? ` ${cls}` : ""}">${icon}<div>${html}</div></div>`;

const empty = (title: string, body: string, clean = true): string =>
	`<div class="empty">${
		clean
			? '<svg viewBox="0 0 64 64" aria-hidden="true" focusable="false"><circle class="er2" cx="32" cy="32" r="30"/><circle class="er" cx="32" cy="32" r="22"/><path class="ec" d="m23 32.5 6.5 6.5L42 26" pathLength="1" stroke-dasharray="1"/></svg>'
			: '<svg viewBox="0 0 64 64" aria-hidden="true" focusable="false"><circle class="eq" cx="28" cy="28" r="14"/><path class="eq" d="m38.5 38.5 11 11"/></svg>'
	}<strong>${title}</strong><p>${body}</p></div>`;

/* ---------- findings ---------- */

const locationFacts = (loc: Location | undefined): string => {
	if (!loc) return "";
	const lines: string[] = [];
	if (loc.file) {
		let file = loc.file;
		if (loc.line !== undefined) file += `:${loc.line}`;
		if (loc.line !== undefined && loc.column !== undefined)
			file += `:${loc.column}`;
		lines.push(`<code>${t(file)}</code>`);
	}
	if (loc.url)
		lines.push(
			isWebUrl(loc.url)
				? `<a href="${e(loc.url)}" rel="noopener noreferrer" target="_blank">${t(loc.url)}<span class="sr-only"> (opens in a new tab)</span></a>`
				: t(loc.url),
		);
	if (loc.selector) lines.push(`<code>${t(loc.selector)}</code>`);
	return lines.length ? `<dt>Location</dt><dd>${lines.join("<br>")}</dd>` : "";
};

const tagChip = (tag: string): string => {
	const cwe = /^cwe-(\d+)$/i.exec(tag)?.[1];
	return cwe
		? `<li><a href="https://cwe.mitre.org/data/definitions/${cwe}.html" rel="noopener noreferrer" target="_blank">${e(tag)}<span class="sr-only"> (opens in a new tab)</span></a></li>`
		: `<li>${t(tag)}</li>`;
};

/**
 * One finding. Standalone (a rule with a single finding) it shows its title
 * and rule; inside a rule group it leads with its location, and shows its
 * title only when it differs from the group's.
 */
const findingItem = (
	f: Finding,
	id: string,
	group?: { readonly title: string },
): string => {
	const loc = formatLocation(f.location);
	const others = f.alsoReportedBy ?? [];
	const refs = (f.references ?? []).map((r) =>
		isWebUrl(r)
			? `<li><a href="${e(r)}" rel="noopener noreferrer" target="_blank">${t(r)}<span class="sr-only"> (opens in a new tab)</span></a></li>`
			: `<li>${t(r)}</li>`,
	);
	const facts = [
		`<dt>Rule</dt><dd><code>${t(f.ruleId)}</code></dd>`,
		locationFacts(f.location),
		`<dt>Auditor</dt><dd><code>${t(f.auditor)}</code></dd>`,
		others.length
			? `<dt>Confirmed by</dt><dd>${others.map((a) => `<code>${t(a)}</code>`).join(", ")}</dd>`
			: "",
		`<dt>Confidence</dt><dd>${f.confidence ? e(f.confidence) : "Not stated"}</dd>`,
		f.tags?.length
			? `<dt>Tags</dt><dd><ul class="tags">${f.tags.map(tagChip).join("")}</ul></dd>`
			: "",
		`<dt>Fingerprint</dt><dd><code>${t(f.fingerprint)}</code></dd>`,
	].join("");
	const auditors = [f.auditor, ...others].map((a) => sanitizeText(a));
	const confirm = others.length
		? `<span class="confirm">${ICON.check}Confirmed by ${others.map(t).join(", ")}</span>`
		: "";
	const main = group
		? `<span class="main">${f.title !== group.title ? `<span class="ft">${t(f.title)}</span>` : ""}<span class="loc">${loc ? t(loc) : "No location"}</span>${confirm}</span>`
		: `<span class="main"><span class="ft">${t(f.title)}</span>${loc ? `<span class="loc">${t(loc)}</span>` : ""}${confirm}</span>`;
	const side = group
		? `<span class="side">${ICON.chevron}</span>`
		: `<span class="side"><span class="mono">${t(f.ruleId)}</span>${ICON.chevron}</span>`;
	return `<li id="${id}" class="fs-${f.severity}" data-sev="${f.severity}" data-conf="${e(f.confidence ?? "")}" data-auditors="${e(` ${auditors.join(" ")} `)}">
<details class="finding"><summary class="row">${group ? `<span class="sev sev-${f.severity} bare"><span class="sr-only">${SEVERITY_LABEL[f.severity]}</span></span>` : sevMark(f.severity)}${main}${side}</summary>
<div class="fbody"><div class="fmain">
<p class="msg-text">${tm(f.message)}</p>
${f.evidence ? `<div><h3>Evidence</h3><pre><code>${tm(f.evidence)}</code></pre></div>` : ""}
${f.remediation ? `<div><h3>Remediation</h3><p class="msg-text">${tm(f.remediation)}</p></div>` : ""}
${refs.length ? `<div><h3>References</h3><ul>${refs.join("")}</ul></div>` : ""}
</div><dl class="facts">${facts}</dl></div>
</details></li>`;
};

const humanize = (ruleId: string): string => {
	const tail = ruleId.split("/").pop() || ruleId;
	const words = tail.replace(/[-_.]+/g, " ").trim();
	return words ? (words[0]?.toUpperCase() ?? "") + words.slice(1) : ruleId;
};

interface RuleGroup {
	readonly ruleId: string;
	readonly findings: Finding[];
}

const ruleGroups = (findings: ReadonlyArray<Finding>): RuleGroup[] => {
	const groups = new Map<string, Finding[]>();
	for (const f of findings) {
		const list = groups.get(f.ruleId);
		if (list) list.push(f);
		else groups.set(f.ruleId, [f]);
	}
	return [...groups]
		.map(([ruleId, list]) => ({ ruleId, findings: list }))
		.sort(
			(a, b) =>
				severityRank(a.findings[0]?.severity ?? "info") -
					severityRank(b.findings[0]?.severity ?? "info") ||
				b.findings.length - a.findings.length ||
				a.ruleId.localeCompare(b.ruleId),
		);
};

/** A rule with one finding is just that finding; several make a group. */
const ruleItem = (g: RuleGroup, view: View, open: boolean): string => {
	const first = g.findings[0] as Finding;
	if (g.findings.length === 1)
		return findingItem(first, view.ids.get(first) ?? "");
	const sameTitle = g.findings.every((f) => f.title === first.title);
	const title = sameTitle ? first.title : humanize(g.ruleId);
	return `<li class="rule-item"><details class="rule"${open ? " open" : ""}>
<summary class="row">${sevMark(first.severity)}<span class="main"><span class="ft">${t(title)}</span><span class="loc">${t(g.ruleId)}</span></span><span class="side"><span class="count" data-shown>${plural(g.findings.length, "finding")}</span>${ICON.chevron}</span></summary>
<div class="rule-body"><ol class="findings">${g.findings.map((f) => findingItem(f, view.ids.get(f) ?? "", { title })).join("\n")}</ol></div>
</details></li>`;
};

/* ---------- panels ---------- */

const panel = (
	id: string,
	title: string,
	lede: string,
	body: string,
	aside = "",
	headExtra = "",
) =>
	`<section class="panel" id="${id}" aria-labelledby="${id}-h">
<div class="panel-head"><div><h2 id="${id}-h">${title}</h2>${lede ? `<p class="lede">${lede}</p>` : ""}${headExtra}</div>${aside}</div>
${body}
</section>`;

const findingRow = (f: Finding, view: View, extra = ""): string => {
	const loc = formatLocation(f.location);
	const sub = [loc ? t(loc) : "", t(f.ruleId), extra]
		.filter(Boolean)
		.join("&ensp;");
	return `<li><a class="frow" href="#${view.ids.get(f) ?? ""}">${sevMark(f.severity)}<span class="t">${t(f.title)}<span class="sub">${sub}</span></span><span class="cat">${e(categoryLabel(f.category))}</span></a></li>`;
};

/** The headline of the overview: what needs attention, in one sentence. */
const verdict = (c: SeverityCounts, categories: number): string => {
	const urgent = c.critical + c.high;
	const lower = c.medium + c.low;
	if (urgent) {
		const parts = [
			c.critical ? `${c.critical} critical` : "",
			c.high ? `${c.high} high` : "",
		].filter(Boolean);
		return `${parts.join(" and ")} severity ${urgent === 1 ? "finding needs" : "findings need"} attention`;
	}
	if (lower)
		return `Nothing critical or high; ${plural(lower, "lower-severity finding")} to review`;
	return categories
		? "No findings from the auditors that ran"
		: "No auditor could examine this target";
};

const auditorsKey = (a: Report["summary"]["auditors"]): string =>
	(["passed", "failed", "error", "skipped"] as const)
		.map(
			(s) =>
				`<span><i class="key k-${s}" aria-hidden="true"></i><b>${a[s]}</b> ${s === "error" ? "errored" : s}</span>`,
		)
		.join("");

const coverage = (view: View): string => {
	const { report } = view;
	const examined = new Set(view.categories.map((c) => c.category));
	const considered = new Set(report.results.flatMap((r) => r.categories));
	const missing = CATEGORIES.filter(
		(c) => considered.has(c) && !examined.has(c),
	);
	const lines: string[] = [];
	lines.push(
		examined.size
			? `<li class="ok">${ICON.check}<span>Examined ${view.categories.map((c) => `<a href="#${c.category}">${e(CATEGORY_LABEL[c.category])}</a>`).join(", ")}.</span></li>`
			: `<li class="gap">${ICON.gap}<span>No category was examined: no auditor ran.</span></li>`,
	);
	for (const c of missing) {
		const skipped = report.results.filter((r) => r.categories.includes(c));
		lines.push(
			`<li class="gap">${ICON.gap}<span>${e(CATEGORY_LABEL[c])} was not examined: its ${plural(skipped.length, "auditor")} did not run (${skipped.map((r) => `<code>${t(r.auditor)}</code> ${e(r.status)}`).join(", ")}).</span></li>`,
		);
	}
	const partial = view.categories.filter((c) =>
		c.auditors.some((r) => !ran(r)),
	);
	if (partial.length)
		lines.push(
			`<li>${ICON.info}<span>Partly covered, because some of their auditors did not run: ${partial.map((c) => `${e(CATEGORY_LABEL[c.category])} <span class="num small">${c.auditors.filter(ran).length}/${c.auditors.length}</span>`).join(", ")}. <a href="#auditors">See why on the Auditors tab</a>.</span></li>`,
		);
	const suppressed = view.suppressed.filter(hasSuppressionNotice).map((s) => {
		const details = suppressionDetails(s);
		return callout(
			`<strong>${t(suppressionLine(s))}.</strong>${suppressedTotal(s) > 0 ? " Suppressed findings are not listed or scored." : ""}${details.length ? `<ul>${details.map((d) => `<li>${t(d)}</li>`).join("")}</ul>` : ""}`,
			ICON.alert,
			"warn",
		);
	});
	return `<div class="sh"><h3>Coverage</h3><p>${plural(report.summary.auditors.skipped, "auditor")} skipped, ${report.summary.auditors.error} errored</p></div><ul class="cov">${lines.join("")}</ul>${suppressed.join("")}`;
};

/** Severity counts as glyph and number pairs, e.g. ◆ 1  ▲ 2. */
const sevCounts = (c: SeverityCounts): string => {
	const present = SEVERITIES.filter((s) => c[s] > 0);
	return present.length
		? present
				.map(
					(s) =>
						`<span><i class="glyph g-${s}" aria-hidden="true"></i>${c[s]}<span class="sr-only"> ${s}</span></span>`,
				)
				.join("")
		: `<span class="ch-clean">${ICON.check}Clean</span>`;
};

const scoreMeter = (score: number, grade: Grade): string =>
	`<svg viewBox="0 0 100 4" preserveAspectRatio="none" aria-hidden="true" focusable="false"><rect class="f-none" width="100" height="4"/><rect class="af-${grade}" width="${Math.max(0, Math.min(100, score))}" height="4"/></svg>`;

const rackRow = (c: CategoryView): string => {
	const s = c.summary;
	const ranN = c.auditors.filter(ran).length;
	return `<li><a class="ch" href="#${c.category}" data-rise>
<span class="ch-grade">${gradeMark(s.grade)}</span>
<span class="ch-name">${e(CATEGORY_LABEL[c.category])}</span>
<span class="ch-meter">${scoreMeter(s.score, s.grade)}<span class="num">${s.score}</span></span>
<span class="ch-sev">${sevCounts(s.counts)}</span>
<span class="ch-dots"><span class="dots" aria-hidden="true">${c.auditors.map((r) => `<i class="d-${r.status}"></i>`).join("")}</span><span class="sr-only">${ranN} of ${plural(c.auditors.length, "auditor")} ran</span></span>
</a></li>`;
};

export const overviewPanel = (view: View): string => {
	const { report } = view;
	const { summary } = report;
	const n = view.findings.length;
	const catCount = view.categories.length;

	const dialLabel = `Overall score ${summary.score} out of 100, grade ${summary.grade}.${
		catCount
			? ` Category scores: ${view.categories.map((c) => `${CATEGORY_LABEL[c.category]} ${c.summary.score}`).join(", ")}.`
			: ""
	}`;

	const legend = SEVERITIES.map(
		(s) =>
			`<li${summary.counts[s] ? "" : ' class="zero"'}><span class="n">${summary.counts[s]}</span>${sevMark(s)}</li>`,
	).join("");

	const diff = report.diff
		? `<p class="diffnote">${ICON.branch}<span>Changes since <code>${t(report.diff.base)}</code>, ${plural(report.diff.changedFiles, "file")}</span></p>`
		: "";

	const hero = `<div class="hero" data-hero>
${dial(
	summary.score,
	summary.grade,
	view.categories.map((c) => ({
		label: CATEGORY_LABEL[c.category],
		score: c.summary.score,
		grade: c.summary.grade,
	})),
	dialLabel,
)}
<div class="readout">
<p class="verdict">${verdict(summary.counts, catCount)}</p>
<p class="verdict-sub">Grade ${summary.grade}, score ${summary.score} of 100: the average of ${plural(catCount, "category score")}. The outer ring is one arc per category; the inner ring is the overall score.</p>
${diff}
<dl class="spec">
<div><dt>Severity<span>${plural(n, "finding")}</span></dt><dd>${spectrum(summary.counts)}<ul class="legend">${legend}</ul></dd></div>
<div><dt>Auditors<span>${report.results.length} in ${e(formatDuration(report.durationMs))}</span></dt><dd>${runtimeStrip(report.results)}<p class="strip-key">${auditorsKey(summary.auditors)}<a href="#auditors">Details</a></p></dd></div>
</dl>
</div>
</div>`;

	const ai = report.ai
		? `<div class="section"><div class="ai"><div class="ai-head">${ICON.sparkle}<h3>AI insights</h3></div>
<p class="ai-sum msg-text">${tm(report.ai.summary)}</p>
${
	report.ai.priorities.length
		? `<ol>${report.ai.priorities
				.map((p) => {
					const linked = view.findings.filter((f) =>
						p.fingerprints.includes(f.fingerprint),
					);
					return `<li><strong>${t(p.title)}</strong><p>${t(p.why)}</p><p><b>Fix:</b> ${t(p.fix)}</p>${
						linked.length
							? `<p>Related: ${linked
									.slice(0, 5)
									.map((f) => `<a href="#${view.ids.get(f)}">${t(f.title)}</a>`)
									.join(", ")}</p>`
							: ""
					}</li>`;
				})
				.join("")}</ol>`
		: ""
}
<p class="model">Written by ${t(report.ai.model)}. AI output can be wrong; check it against the findings before acting.</p></div></div>`
		: "";

	const rack = catCount
		? `<div class="rack-head" aria-hidden="true"><span>Grade</span><span>Category</span><span>Score</span><span>Findings</span><span>Coverage</span></div><ul class="rack">${view.categories.map(rackRow).join("")}</ul>`
		: empty(
				"No categories were examined",
				"No auditor could run against this target. The Auditors tab lists why each one was skipped.",
				false,
			);

	const top = view.findings.slice(0, 10);
	const topList = top.length
		? `<ol class="flist">${top.map((f) => findingRow(f, view)).join("")}</ol>`
		: empty(
				"No findings",
				"The auditors that ran reported nothing. The coverage notes below say what was not examined.",
			);

	return `<section class="panel" id="overview" aria-labelledby="overview-h">
<h2 id="overview-h" class="sr-only">Overview</h2>
${hero}
${ai}
<div class="section"><div class="sh"><h3>Categories</h3><p>Open a category for its findings</p></div>${rack}</div>
<div class="section"><div class="sh"><h3>Most severe findings</h3>${n > top.length ? `<p>Top ${top.length} of ${n}</p>` : ""}</div>${topList}</div>
<div class="section">${coverage(view)}</div>
</section>`;
};

const filterForm = (
	id: string,
	label: string,
	findings: ReadonlyArray<Finding>,
): string => {
	const counts = countSeverities(findings);
	const auditors = [
		...new Set(
			findings.flatMap((f) => [f.auditor, ...(f.alsoReportedBy ?? [])]),
		),
	].sort();
	const checks = SEVERITIES.filter((s) => counts[s] > 0)
		.map(
			(s) =>
				`<label class="check sev-${s}"><input type="checkbox" name="severity" value="${s}" checked><span>${SEVERITY_LABEL[s]} <b>${counts[s]}</b></span></label>`,
		)
		.join("");
	return `<form class="filters" role="search" aria-label="Filter ${e(label)} findings" data-js hidden>
<fieldset><legend>Severity</legend><div class="checks">${checks}</div></fieldset>
<div class="field"><label for="${id}-auditor">Auditor</label><select id="${id}-auditor" name="auditor"><option value="">All auditors</option>${auditors.map((a) => `<option value="${t(a)}">${t(a)}</option>`).join("")}</select></div>
<div class="field"><label for="${id}-confidence">Confidence</label><select id="${id}-confidence" name="confidence"><option value="">Any</option><option value="medium">Hide low confidence</option><option value="high">High only</option></select></div>
<div class="field grow"><label for="${id}-q">Search</label><input id="${id}-q" name="q" type="search" placeholder="Title, file, rule or text" autocomplete="off"></div>
<button class="btn quiet" type="reset">Reset</button>
</form>`;
};

const liveCount = (shown: number, totalN: number, rules: number) =>
	`<p class="live"><span aria-hidden="true" data-vis>Showing <b data-n>${shown}</b> of ${totalN} findings in <b data-r>${rules}</b> ${rules === 1 ? "rule" : "rules"}</span><span class="sr-only" data-live role="status" aria-live="polite"></span></p>`;

export const categoryPanel = (c: CategoryView, view: View): string => {
	const id = c.category;
	const label = CATEGORY_LABEL[c.category] ?? c.category;
	const s = c.summary;
	const groups = ruleGroups(c.findings);
	const openAll =
		groups.length <= 2 && groups.every((g) => g.findings.length > 1);
	const ranList = c.auditors.filter(ran);

	const aside = `<div class="cat-score">${miniDial(s.score, s.grade, `${label} score ${s.score} out of 100, grade ${s.grade}`)}<p><b>${s.score}<small> /100</small></b>${countsText(s.counts)}</p></div>`;

	const contributors = c.auditors.length
		? `<ul class="contrib" aria-label="Auditors for ${e(label)}">${c.auditors.map((r) => `<li${ran(r) ? "" : ' class="off"'}><span class="dot dot-${r.status}" aria-hidden="true"></span><code>${t(r.auditor)}</code><span class="sr-only"> ${e(r.status)}</span></li>`).join("")}</ul>`
		: "";

	const body = c.findings.length
		? `${filterForm(id, label, c.findings)}
<div class="toolbar">${liveCount(c.findings.length, c.findings.length, groups.length)}
<span class="actions" data-js hidden><button class="btn quiet" type="button" data-action="expand">Expand all</button><button class="btn quiet" type="button" data-action="collapse">Collapse all</button></span></div>
<ol class="rules">${groups.map((g) => ruleItem(g, view, openAll)).join("\n")}</ol>
<div data-empty hidden>${empty("No matches", "No findings match these filters. Reset them to see everything.", false)}</div>`
		: empty(
				`${e(label)} is clean`,
				ranList.length
					? `${plural(ranList.length, "auditor")} checked ${e(label.toLowerCase())} and reported nothing.`
					: "No auditor that covers this category ran, so there is nothing to show.",
				ranList.length > 0,
			);

	return panel(
		id,
		e(label),
		e(CATEGORY_LEDE[c.category] ?? ""),
		body,
		aside,
		contributors,
	);
};

const MAX_LISTED = 200;

const matchList = (
	matches: ReadonlyArray<ComplianceMatch>,
	view: View,
): string => {
	const sorted = [...matches].sort(
		(a, b) =>
			severityRank(a.finding.severity) - severityRank(b.finding.severity),
	);
	const rows = sorted
		.slice(0, MAX_LISTED)
		.map((m) =>
			findingRow(
				m.finding,
				view,
				m.viaCwe !== undefined ? `mapped via CWE-${m.viaCwe}` : "",
			),
		)
		.join("");
	const more = sorted.length - MAX_LISTED;
	return `<ol class="flist">${rows}</ol>${more > 0 ? `<p class="small muted">And ${plural(more, "more finding")}.</p>` : ""}`;
};

const control = (
	code: string,
	title: string,
	sub: string,
	matches: ReadonlyArray<ComplianceMatch>,
	view: View,
): string => {
	if (!matches.length)
		return `<li><div class="ctrl-row"><span class="cid">${code}</span><span class="ctitle">${title}${sub}</span><span class="cside"><span class="nf">no findings</span></span></div></li>`;
	const counts = countSeverities(matches.map((m) => m.finding));
	const top = SEVERITIES.find((s) => counts[s] > 0) ?? "info";
	return `<li><details class="ctrl"><summary><span class="cid">${code}</span><span class="ctitle">${title}${sub}</span><span class="cside">${sevMark(top)}<span class="mono">${plural(matches.length, "finding")}</span>${ICON.chevron}</span></summary>
<div class="ctrl-body">${matchList(matches, view)}</div></details></li>`;
};

export const standardsPanel = (view: View): string => {
	const owasp = groupByOwasp(view.findings);
	const cwe = groupByCweTop25(view.findings);
	const unmapped = view.findings.filter(
		(f) => f.category === "security" && !hasComplianceMapping(f),
	).length;
	const securityRan = view.report.results.some(
		(r) => ran(r) && r.categories.includes("security"),
	);
	const hits = (g: ReadonlyArray<{ matches: ReadonlyArray<unknown> }>) =>
		g.filter((x) => x.matches.length > 0).length;

	const intro = `${callout("<strong>“No findings” is not the same as compliant.</strong> It only means none of the auditors that ran reported an issue mapped to that control. Many controls, such as access control and insecure design, need a manual review that tools cannot do.", ICON.alert, "warn")}
${callout(`Findings are grouped by their <code>owasp-a01</code> to <code>owasp-a10</code> and <code>cwe-N</code> tags. A finding with a CWE but no OWASP tag is placed through MITRE's CWE-1344 view of the OWASP Top Ten 2021. Duplicates confirmed by several tools count once.${unmapped ? ` ${plural(unmapped, "security finding")} carry no OWASP or CWE tag and are not shown here.` : ""}${securityRan ? "" : " <strong>No security auditor ran</strong>, so these lists are empty by construction."}`, ICON.info)}`;

	const owaspList = `<ol class="controls">${owasp
		.map((g) =>
			control(g.category.id, e(g.category.title), "", g.matches, view),
		)
		.join("")}</ol>`;
	const cweList = `<ol class="controls">${cwe
		.map((g) =>
			control(
				`#${g.entry.rank}`,
				e(g.entry.name),
				`<small>CWE-${g.entry.cwe}</small>`,
				g.matches,
				view,
			),
		)
		.join("")}</ol>`;

	return panel(
		"standards",
		"OWASP and CWE",
		"Findings mapped to the OWASP Top 10 (2021) and the 2024 CWE Top 25 Most Dangerous Software Weaknesses.",
		`${intro}
<div class="two section">
<div><div class="sh"><h3>OWASP Top 10 (2021)</h3><p>${hits(owasp)} of 10 with findings</p></div>${owaspList}</div>
<div><div class="sh"><h3>CWE Top 25 (2024)</h3><p>${hits(cwe)} of 25 with findings</p></div>${cweList}</div>
</div>`,
	);
};

const STATUS_ORDER = { error: 0, failed: 1, skipped: 2, passed: 3 } as const;

export const auditorsPanel = (view: View): string => {
	const { report } = view;
	const a = report.summary.auditors;
	const rows = report.results
		.map((r, i) => {
			const counted = r.findings.filter(
				(f) => f.duplicateOf === undefined,
			).length;
			const dups = r.findings.length - counted;
			return `<tr data-i="${i}" data-status="${e(r.status)}" data-id="${t(r.auditor)}" data-st="${STATUS_ORDER[r.status] ?? 9}" data-n="${counted}" data-dur="${Number(r.durationMs) || 0}">
<th scope="row"><code>${t(r.auditor)}</code><span class="rid">${t(r.title)}</span></th>
<td class="eng">${e(r.engine)}</td>
<td class="cats">${r.categories.map((c) => e(categoryLabel(c))).join(", ")}</td>
<td class="st">${statusMark(r.status)}</td>
<td class="n" data-label="Findings">${counted}${dups ? `<span class="rid">+${dups} duplicate${dups === 1 ? "" : "s"}</span>` : ""}</td>
<td class="n" data-label="Took">${e(formatDuration(r.durationMs))}</td>
<td class="note">${r.message ? `<p class="msg">${tm(r.message)}</p>` : ""}</td>
</tr>`;
		})
		.join("\n");
	const sortTh = (label: string, key: string, num = false, cls = "") =>
		`<th scope="col"${cls ? ` class="${cls}"` : ""}><button type="button" data-action="sort" data-key="${key}"${num ? " data-num" : ""}>${label}</button></th>`;

	return panel(
		"auditors",
		"Auditors",
		`${plural(report.results.length, "auditor")}: ${a.passed} passed, ${a.failed} failed, ${a.skipped} skipped and ${a.error} errored. Skipped auditors give the reason, often with an install hint.`,
		`<div class="runtime"><h3>Runtime <span>longest first, skipped at the end</span></h3>${runtimeStrip(report.results)}<p class="strip-key">${auditorsKey(a)}</p></div>
<form class="filters" role="search" aria-label="Filter auditors" data-kind="auditors" data-js hidden>
<div class="field"><label for="auditors-status">Status</label><select id="auditors-status" name="status"><option value="">All statuses</option>${(["failed", "passed", "skipped", "error"] as const).map((s) => `<option value="${s}">${s} (${a[s]})</option>`).join("")}</select></div>
<div class="field grow"><label for="auditors-q">Search</label><input id="auditors-q" name="q" type="search" placeholder="Auditor, engine or message" autocomplete="off"></div>
<button class="btn quiet" type="reset">Reset</button>
</form>
<div class="toolbar"><p class="live"><span aria-hidden="true" data-vis>Showing <b data-n>${report.results.length}</b> of ${report.results.length} auditors</span><span class="sr-only" data-live role="status" aria-live="polite"></span></p></div>
<div class="table-wrap" role="region" aria-label="Auditor results" tabindex="0">
<table><thead><tr>${sortTh("Auditor", "id")}<th scope="col" class="plain">Engine</th><th scope="col" class="plain">Categories</th>${sortTh("Status", "st", true)}${sortTh("Findings", "n", true, "n")}${sortTh("Duration", "dur", true, "n")}<th scope="col" class="plain">Notes</th></tr></thead>
<tbody>${rows}</tbody></table></div>`,
	);
};

/** Category views for the tabs, in model order, falling back to computed scores. */
export const categoryViews = (
	report: Report,
	findings: ReadonlyArray<Finding>,
): CategoryView[] => {
	const summaries = new Map(
		report.summary.categories.map((c) => [c.category, c]),
	);
	const present = new Set<Category>([
		...summaries.keys(),
		...findings.map((f) => f.category),
	]);
	return CATEGORIES.filter((c) => present.has(c)).map((category) => {
		const inCategory = findings.filter((f) => f.category === category);
		const score = scoreFor(inCategory);
		return {
			category,
			summary: summaries.get(category) ?? {
				category,
				score,
				grade: gradeFor(score),
				counts: countSeverities(inCategory),
			},
			findings: inCategory,
			auditors: report.results.filter((r) => r.categories.includes(category)),
		};
	});
};
