import type { AuditorResult, Finding, Grade, Report, Severity } from "../model";
import { SEVERITIES } from "../model";
import {
	escapeHtml as e,
	formatDuration,
	formatLocation,
	isWebUrl,
	plural,
	SEVERITY_LABEL,
	type SuppressionSummary,
	sortedFindings,
	suppressedTotal,
	suppressionLine,
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
 * only allows the hashed inline style and script), every report string escaped,
 * and it is built to pass the accessibility checks openaudit itself runs.
 */

const STYLE = `
:root{color-scheme:light dark;--bg:#fff;--fg:#1b1f24;--muted:#4b5563;--panel:#f6f7f9;--border:#c9ced6;--link:#0b57d0;--focus:#0b57d0;
--critical:#8b0d0d;--high:#b42318;--medium:#93370d;--low:#175cd3;--info:#475467;--good:#067647;--warn:#93370d;--bad:#b42318}
@media (prefers-color-scheme:dark){:root{--bg:#0f1216;--fg:#e8eaed;--muted:#aab2bd;--panel:#181c22;--border:#3a414b;--link:#8ab4f8;--focus:#8ab4f8;
--good:#4ade80;--warn:#fbbf24;--bad:#f87171}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--link)}
:focus-visible{outline:3px solid var(--focus);outline-offset:2px}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.875em}
pre{background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:.75rem;overflow:auto;white-space:pre-wrap;word-break:break-word}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
.skip{position:absolute;left:-999px;top:0;background:var(--bg);padding:.5rem 1rem;z-index:10}
.skip:focus{left:1rem;top:1rem}
.wrap{max-width:72rem;margin:0 auto;padding:0 1rem}
header.top{border-bottom:1px solid var(--border);padding:1.5rem 0}
header.top .wrap{display:flex;gap:1.5rem;align-items:center;justify-content:space-between;flex-wrap:wrap}
.brand{margin:0;color:var(--muted);font-size:.875rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase}
h1{margin:.25rem 0;font-size:1.75rem;line-height:1.2;overflow-wrap:anywhere}
h2{font-size:1.35rem;margin:2rem 0 1rem}
h3{font-size:1rem;margin:0}
.meta{margin:0;color:var(--muted);font-size:.9rem}
.ring{position:relative;width:7.5rem;height:7.5rem;flex:none}
.ring svg{width:100%;height:100%;transform:rotate(-90deg)}
.ring .track{stroke:var(--border)}
.ring-label{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;line-height:1.1}
.ring-score{font-size:2rem;font-weight:700}
.ring-grade{color:var(--muted);font-weight:600}
.g-A,.g-B{color:var(--good);stroke:var(--good)}.g-C{color:var(--warn);stroke:var(--warn)}.g-D,.g-F{color:var(--bad);stroke:var(--bad)}
.chips,.cards{list-style:none;margin:0;padding:0;display:flex;flex-wrap:wrap;gap:.5rem}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(11rem,1fr));gap:.75rem;margin-top:1rem}
.card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:.85rem 1rem}
.card .score{font-size:1.6rem;font-weight:700;margin:.25rem 0}
.card .score span{font-size:1rem;margin-left:.35rem}
.card p{margin:0}
.small{color:var(--muted);font-size:.85rem}
.badge{display:inline-block;min-width:4.6rem;text-align:center;border-radius:999px;padding:.05rem .6rem;font-size:.8rem;font-weight:700;color:#fff;background:var(--info)}
.s-critical{background:var(--critical)}.s-high{background:var(--high)}.s-medium{background:var(--medium)}.s-low{background:var(--low)}.s-info{background:var(--info)}
.chips .badge{min-width:0}
.filters{display:flex;flex-wrap:wrap;gap:1rem;align-items:flex-end;background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:1rem;margin-bottom:.75rem}
.filters fieldset{border:0;margin:0;padding:0;display:flex;flex-wrap:wrap;gap:.25rem .9rem}
.filters legend{font-weight:600;padding:0;margin-bottom:.25rem;width:100%}
.field{display:flex;flex-direction:column;gap:.25rem}
.field label{font-weight:600}
input[type=search],select{font:inherit;color:var(--fg);background:var(--bg);border:1px solid var(--muted);border-radius:6px;padding:.35rem .5rem;min-height:2.25rem}
input[type=checkbox]{width:1.1rem;height:1.1rem;accent-color:var(--link);vertical-align:-.15rem}
button{font:inherit;color:var(--fg);background:var(--bg);border:1px solid var(--muted);border-radius:6px;padding:.35rem .75rem;min-height:2.25rem;cursor:pointer}
.toolbar{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap;margin:.5rem 0}
.toolbar p{margin:0 auto 0 0;color:var(--muted)}
ol.findings{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:.5rem}
.finding details{border:1px solid var(--border);border-left-width:4px;border-radius:6px;background:var(--bg)}
.finding.f-critical details{border-left-color:var(--critical)}.finding.f-high details{border-left-color:var(--high)}
.finding.f-medium details{border-left-color:var(--medium)}.finding.f-low details{border-left-color:var(--low)}.finding.f-info details{border-left-color:var(--info)}
.finding summary{cursor:pointer;padding:.6rem .85rem;display:flex;gap:.6rem;flex-wrap:wrap;align-items:baseline;list-style:none}
.finding summary::-webkit-details-marker{display:none}
.finding summary::before{content:"\\25B8";color:var(--muted)}
.finding details[open]>summary::before{content:"\\25BE"}
.finding summary .ftitle{font-weight:600}
.finding summary code,.finding summary .loc{color:var(--muted);overflow-wrap:anywhere}
.fbody{padding:0 1rem 1rem;border-top:1px solid var(--border)}
.fbody h3{font-size:.95rem;margin:1rem 0 .35rem}
dl.facts{display:grid;grid-template-columns:max-content 1fr;gap:.2rem 1rem;margin:.75rem 0 0}
dl.facts dt{color:var(--muted);font-weight:600}
dl.facts dd{margin:0;overflow-wrap:anywhere}
.table-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:8px}
table{border-collapse:collapse;width:100%;font-size:.9rem}
th,td{text-align:left;padding:.5rem .75rem;border-bottom:1px solid var(--border);vertical-align:top}
th{background:var(--panel)}
tbody tr:last-child td{border-bottom:0}
.st-passed{color:var(--good)}.st-failed{color:var(--bad)}.st-error{color:var(--bad)}.st-skipped{color:var(--muted)}
td.num,th.num{text-align:right}
.ai{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:1rem 1.25rem}
.ai ol{padding-left:1.25rem}
footer{border-top:1px solid var(--border);margin-top:3rem;padding:1.5rem 0;color:var(--muted);font-size:.85rem}
[hidden]{display:none!important}
@media (prefers-reduced-motion:no-preference){.ring circle{transition:stroke-dasharray .6s}}
`;

const SCRIPT = `
(function(){
var form=document.getElementById("filters");
if(!form)return;
form.hidden=false;
var tools=document.getElementById("finding-tools");if(tools)tools.hidden=false;
var items=Array.prototype.slice.call(document.querySelectorAll("li.finding"));
var text=items.map(function(li){return li.textContent.toLowerCase();});
var status=document.getElementById("filter-status");
var empty=document.getElementById("filter-empty");
function apply(){
var sev={};
Array.prototype.forEach.call(form.querySelectorAll("input[name=severity]"),function(i){sev[i.value]=i.checked;});
var cat=form.elements.category.value,aud=form.elements.auditor.value,q=form.elements.q.value.trim().toLowerCase();
var shown=0;
items.forEach(function(li,i){
var ok=sev[li.getAttribute("data-severity")]&&(!cat||li.getAttribute("data-category")===cat)&&(!aud||li.getAttribute("data-auditor")===aud)&&(!q||text[i].indexOf(q)!==-1);
li.hidden=!ok;if(ok)shown++;
});
status.textContent="Showing "+shown+" of "+items.length+" findings";
empty.hidden=shown!==0;
}
form.addEventListener("input",apply);
form.addEventListener("change",apply);
form.addEventListener("submit",function(ev){ev.preventDefault();});
form.addEventListener("reset",function(){setTimeout(apply,0);});
function toggle(open){items.forEach(function(li){if(!li.hidden)li.querySelector("details").open=open;});}
document.getElementById("expand-all").addEventListener("click",function(){toggle(true);});
document.getElementById("collapse-all").addEventListener("click",function(){toggle(false);});
apply();
})();
`;

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

const gradeClass = (g: Grade) => `g-${g}`;

const scoreRing = (score: number, grade: Grade): string => {
	const r = 42;
	const c = 2 * Math.PI * r;
	const filled = (Math.max(0, Math.min(100, score)) / 100) * c;
	return `<div class="ring" role="img" aria-label="Overall score ${score} out of 100, grade ${grade}">
<svg viewBox="0 0 100 100" aria-hidden="true" focusable="false"><circle class="track" cx="50" cy="50" r="${r}" fill="none" stroke-width="10"/><circle class="${gradeClass(grade)}" cx="50" cy="50" r="${r}" fill="none" stroke-width="10" stroke-linecap="round" stroke-dasharray="${filled.toFixed(2)} ${c.toFixed(2)}"/></svg>
<div class="ring-label" aria-hidden="true"><span class="ring-score">${score}</span><span class="ring-grade ${gradeClass(grade)}">Grade ${grade}</span></div>
</div>`;
};

const badge = (s: Severity) =>
	`<span class="badge s-${s}">${SEVERITY_LABEL[s]}</span>`;

const findingItem = (f: Finding, index: number): string => {
	const loc = formatLocation(f.location);
	const facts: Array<[string, string]> = [
		["Rule", `<code>${e(f.ruleId)}</code>`],
		["Category", e(f.category)],
		["Auditor", `<code>${e(f.auditor)}</code>`],
	];
	if (loc) facts.push(["Location", `<code>${e(loc)}</code>`]);
	if (f.confidence) facts.push(["Confidence", e(f.confidence)]);
	if (f.tags?.length) facts.push(["Tags", e(f.tags.join(", "))]);
	facts.push(["Fingerprint", `<code>${e(f.fingerprint)}</code>`]);

	const refs = (f.references ?? []).map((r) =>
		isWebUrl(r)
			? `<li><a href="${e(r)}" rel="noopener noreferrer" target="_blank">${e(r)}<span class="sr-only"> (opens in a new tab)</span></a></li>`
			: `<li>${e(r)}</li>`,
	);

	return `<li class="finding f-${f.severity}" data-severity="${f.severity}" data-category="${e(f.category)}" data-auditor="${e(f.auditor)}">
<details id="finding-${index}">
<summary>${badge(f.severity)}<span class="ftitle">${e(f.title)}</span>${loc ? `<span class="loc">${e(loc)}</span>` : ""}</summary>
<div class="fbody">
<p>${e(f.message)}</p>
<dl class="facts">${facts.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl>
${f.evidence ? `<h3>Evidence</h3><pre><code>${e(f.evidence)}</code></pre>` : ""}
${f.remediation ? `<h3>Remediation</h3><p>${e(f.remediation)}</p>` : ""}
${refs.length ? `<h3>References</h3><ul>${refs.join("")}</ul>` : ""}
</div>
</details>
</li>`;
};

const auditorRow = (r: AuditorResult): string =>
	`<tr><th scope="row"><code>${e(r.auditor)}</code><br><span class="small">${e(r.title)}</span></th><td>${e(r.engine)}</td><td class="st-${r.status}">${e(r.status)}</td><td class="num">${r.findings.length}</td><td class="num">${e(formatDuration(r.durationMs))}</td><td>${e(r.message ?? "")}</td></tr>`;

export const toHtml = (report: Report, options: HtmlOptions = {}): string => {
	const { summary, target } = report;
	const label = targetLabel(report);
	const title = options.title ?? `openaudit report: ${label}`;
	const findings = sortedFindings(report);
	const categories = [...new Set(findings.map((f) => f.category))].sort();
	const auditors = [...new Set(findings.map((f) => f.auditor))].sort();
	const date = new Date(report.finishedAt);
	const when = Number.isNaN(date.getTime())
		? report.finishedAt
		: date.toISOString().replace("T", " ").slice(0, 16);

	const meta = [
		target.kinds.join(", "),
		target.technologies.length ? target.technologies.join(", ") : undefined,
		`${when} UTC`,
		formatDuration(report.durationMs),
	].filter(Boolean);

	const chips = SEVERITIES.map(
		(s) =>
			`<li><span class="badge s-${s}">${summary.counts[s]} ${SEVERITY_LABEL[s].toLowerCase()}</span></li>`,
	).join("");

	const cards = summary.categories
		.map(
			(c) => `<li class="card"><h3>${e(c.category)}</h3>
<p class="score ${gradeClass(c.grade)}">${c.score}<span>${c.grade}</span></p>
<p class="small">${SEVERITIES.filter((s) => s !== "info")
				.map((s) => `${c.counts[s]} ${s}`)
				.join(" · ")}</p></li>`,
		)
		.join("");

	const ai = report.ai
		? `<section aria-labelledby="ai-h"><h2 id="ai-h">AI insights</h2><div class="ai">
<p>${e(report.ai.summary)}</p>
${report.ai.priorities.length ? `<ol>${report.ai.priorities.map((p) => `<li><strong>${e(p.title)}</strong>: ${e(p.why)} <em>Fix:</em> ${e(p.fix)}</li>`).join("")}</ol>` : ""}
<p class="small">Model: ${e(report.ai.model)}</p></div></section>`
		: "";

	const severityBoxes = SEVERITIES.map((s) => {
		const n = findings.filter((f) => f.severity === s).length;
		return `<label><input type="checkbox" name="severity" value="${s}" checked> ${SEVERITY_LABEL[s]} (${n})</label>`;
	}).join("");

	const filters = findings.length
		? `<form id="filters" class="filters" role="search" aria-label="Filter findings" hidden>
<fieldset><legend>Severity</legend>${severityBoxes}</fieldset>
<div class="field"><label for="f-category">Category</label><select id="f-category" name="category"><option value="">All categories</option>${categories.map((c) => `<option value="${e(c)}">${e(c)}</option>`).join("")}</select></div>
<div class="field"><label for="f-auditor">Auditor</label><select id="f-auditor" name="auditor"><option value="">All auditors</option>${auditors.map((a) => `<option value="${e(a)}">${e(a)}</option>`).join("")}</select></div>
<div class="field"><label for="f-q">Search</label><input id="f-q" name="q" type="search" placeholder="Rule, file, text…" autocomplete="off"></div>
<button type="reset">Reset filters</button>
</form>
<div class="toolbar"><p id="filter-status" role="status" aria-live="polite">Showing ${findings.length} of ${findings.length} findings</p>
<span id="finding-tools" hidden><button type="button" id="expand-all">Expand all</button> <button type="button" id="collapse-all">Collapse all</button></span></div>
<ol class="findings">${findings.map(findingItem).join("\n")}</ol>
<p id="filter-empty" hidden>No findings match the current filters.</p>`
		: "<p>No findings. Nice work.</p>";

	const a = summary.auditors;

	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="${CSP}">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="light dark">
<meta name="generator" content="${e(report.tool.name)} ${e(report.tool.version)}">
<title>${e(title)}</title>
<style>${STYLE}</style>
</head>
<body>
<a class="skip" href="#findings-h">Skip to findings</a>
<header class="top"><div class="wrap">
<div><p class="brand">${e(report.tool.name)} ${e(report.tool.version)}</p>
<h1>Audit report: ${e(label)}</h1>
<p class="meta">${meta.map((m) => e(m)).join(" · ")}</p></div>
${scoreRing(summary.score, summary.grade)}
</div></header>
<main class="wrap">
<section aria-labelledby="summary-h">
<h2 id="summary-h">Summary</h2>
${(options.suppressed ?? [])
	.filter((s) => suppressedTotal(s) > 0)
	.map(
		(s) =>
			`<p class="small"><strong>Note:</strong> ${e(suppressionLine(s))}</p>`,
	)
	.join("\n")}
<ul class="chips" aria-label="Findings by severity">${chips}</ul>
${cards ? `<ul class="cards" aria-label="Scores by category">${cards}</ul>` : `<p class="small">No categories were examined.</p>`}
</section>
${ai}
<section aria-labelledby="findings-h">
<h2 id="findings-h" tabindex="-1">Findings (${findings.length})</h2>
${filters}
</section>
<section aria-labelledby="auditors-h">
<h2 id="auditors-h">Auditors</h2>
<p class="small">${plural(report.results.length, "auditor")}: ${a.passed} passed, ${a.failed} failed, ${a.skipped} skipped, ${a.error} errored.</p>
<div class="table-wrap" role="region" aria-label="Auditor results table" tabindex="0">
<table><thead><tr><th scope="col">Auditor</th><th scope="col">Engine</th><th scope="col">Status</th><th scope="col" class="num">Findings</th><th scope="col" class="num">Duration</th><th scope="col">Notes</th></tr></thead>
<tbody>${report.results.map(auditorRow).join("\n")}</tbody></table>
</div>
</section>
</main>
<footer><div class="wrap">Generated by ${e(report.tool.name)} ${e(report.tool.version)} · report schema v${e(report.schemaVersion)} · started ${e(report.startedAt)}</div></footer>
<script>${SCRIPT}</script>
</body>
</html>
`;
};
