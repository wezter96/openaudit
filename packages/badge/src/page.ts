/**
 * The public verification page at /v/:id: plain HTML in the openaudit.se
 * look, light and dark, with no scripts. Every value is escaped.
 */
import type { ScanSummary, TargetSummary } from "./api";
import { PAGE_CSS } from "./page-css";
import { escapeXml as esc, formatDate, type Text } from "./svg";
import type { BadgeView } from "./view";

/** The site's origin, such as `https://openaudit.se`. */
export type Origin = string;

export interface VerifyPage {
	readonly badge: BadgeView;
	/** The newest finished scans, newest first. */
	readonly scans: ReadonlyArray<ScanSummary>;
	readonly origin: Origin;
}

const STATUS_TEXT: Record<string, Text> = {
	pending: "Waiting for verification or the first scan",
	ok: "Verified and up to date",
	stale: "No scan in the last 14 days",
	failed: "The last scan failed",
};

const COMMIT = /^[0-9a-f]{7,40}$/;

const commitLink = (repo: Text, sha: string | null) => {
	if (!sha || !COMMIT.test(sha)) return "unknown";
	const href = `https://github.com/${repo}/commit/${sha}`;
	return `<a href="${esc(href)}"><code>${esc(sha.slice(0, 7))}</code></a>`;
};

const row = (name: Text, value: Text) => `<dt>${name}</dt><dd>${value}</dd>`;

const auditorsText = (s: TargetSummary) => {
	const ran = s.auditors.passed + s.auditors.failed + s.auditors.error;
	return `${ran} ran (${s.auditors.passed} passed, ${s.auditors.failed} with findings, ${s.auditors.error} errored), ${s.auditors.skipped} skipped`;
};

const suppressionText = (s: TargetSummary) => {
	const config = s.configApplied
		? "The repo's own openaudit config applied."
		: "No project config applied.";
	return `${s.suppressed} findings suppressed. ${config}`;
};

const categories = (s: TargetSummary) =>
	s.categories
		.map(
			(c) =>
				`<li><span>${esc(c.category)}</span><b class="g-${c.grade}">${c.score} ${c.grade}</b></li>`,
		)
		.join("");

const target = (name: Text, s: TargetSummary, report: Text) =>
	`<section class="target"><h3>${name} <b class="score g-${s.grade}">${s.score} ${s.grade}</b></h3><ul class="cats">${categories(s)}</ul><dl>${row("Auditors", esc(auditorsText(s)))}${row("Suppressions", esc(suppressionText(s)))}${row("openaudit", esc(s.openauditVersion))}</dl><p><a href="${report}">Open the full report</a></p></section>`;

const reportPath = (id: Text, file: "report" | "site-report", scan?: Text) =>
	`/v/${esc(id)}/${file}${scan ? `?scan=${esc(scan)}` : ""}`;

const latest = (id: Text, repo: Text, scan: ScanSummary) => {
	const meta = `<dl>${row("Scanned", formatDate(scan.finishedAt))}${row("Commit", commitLink(repo, scan.commit))}${row("openaudit", esc(scan.openauditVersion ?? "unknown"))}</dl>`;
	const codebase = scan.codebase
		? target("Codebase", scan.codebase, reportPath(id, "report"))
		: "";
	const site = scan.site
		? target("Website", scan.site, reportPath(id, "site-report"))
		: "";
	return `<h2>Latest scan</h2>${meta}${codebase}${site}`;
};

const cell = (s: TargetSummary | null) => (s ? `${s.score} ${s.grade}` : "");

const historyRow = (id: Text, scan: ScanSummary) => {
	const links = [
		scan.codebase
			? `<a href="${reportPath(id, "report", scan.id)}">codebase</a>`
			: "",
		scan.site
			? `<a href="${reportPath(id, "site-report", scan.id)}">website</a>`
			: "",
	].join(" ");
	return `<tr><td>${formatDate(scan.finishedAt)}</td><td>${scan.status}</td><td>${cell(scan.codebase)}</td><td>${cell(scan.site)}</td><td>${links}</td></tr>`;
};

const history = (id: Text, scans: ReadonlyArray<ScanSummary>) =>
	scans.length === 0
		? ""
		: `<h2>Recent scans</h2><table><thead><tr><th>Date</th><th>Result</th><th>Codebase</th><th>Website</th><th>Reports</th></tr></thead><tbody>${scans.map((s) => historyRow(id, s)).join("")}</tbody></table>`;

const snippet = (title: Text, code: Text) =>
	`<h3>${title}</h3><pre><code>${esc(code)}</code></pre>`;

const embeds = (id: Text, origin: Origin) => {
	const page = `${origin}/v/${id}`; // escaped by snippet()
	const badge = `${origin}/badge/${id}.svg`;
	const card = `${origin}/badge/${id}/card.svg`;
	return `<h2>Embed</h2>${snippet("Badge, Markdown", `[![openaudit](${badge})](${page})`)}${snippet("Badge, HTML", `<a href="${page}"><img src="${badge}" alt="openaudit score"></a>`)}${snippet("Card, Markdown", `[![openaudit](${card})](${page})`)}${snippet("Card, HTML", `<a href="${page}"><img src="${card}" alt="openaudit score card" width="440" height="150"></a>`)}`;
};

const failure = (scans: ReadonlyArray<ScanSummary>) => {
	const last = scans[0];
	return last?.status === "failed"
		? `<p class="warn">The last scan failed: ${esc(last.error ?? "unknown error")}</p>`
		: "";
};

const siteLine = (site: Text | null) =>
	site ? `<p>Website: <a href="${esc(site)}">${esc(site)}</a></p>` : "";

const shell = (title: Text, main: Text) =>
	`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex"><title>${title}</title><style>${PAGE_CSS}</style></head><body><header><a href="/" class="brand">openaudit</a><a href="/badge/">Get a badge</a></header><main>${main}</main><footer><p>openaudit scans this project itself every 7 days, so the badge can't be faked. <a href="/badge/">How it works</a></p></footer></body></html>`;

const missing = (view: BadgeView) =>
	view.state === "removed"
		? "<h1>Badge removed</h1><p>The owner removed this badge and its reports.</p>"
		: "<h1>No such badge</h1><p>There's no badge with this id.</p>";

/** The verification page, or a short notice for a missing or removed badge. */
export const verifyPageHtml = ({ badge, scans, origin }: VerifyPage): Text => {
	const project = badge.project;
	if (!project) return shell("openaudit badge", missing(badge));
	const id = project.id;
	const repo = esc(project.repo);
	const status = STATUS_TEXT[badge.state] ?? badge.state;
	const preview = `<p class="preview"><img src="/badge/${esc(id)}.svg" alt="openaudit badge"> <img src="/badge/${esc(id)}/card.svg" alt="openaudit card" width="440" height="150"></p>`;
	const main = `<p class="kicker">openaudit verified badge</p><h1><a href="https://github.com/${repo}">${repo}</a></h1>${siteLine(project.site)}<p class="status s-${badge.state}">${esc(status)}</p>${preview}${failure(scans)}${badge.scan ? latest(id, project.repo, badge.scan) : ""}${history(id, scans)}${embeds(id, origin)}`;
	return shell(`${repo}: openaudit badge`, main);
};
