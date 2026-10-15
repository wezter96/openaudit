/**
 * The public verification page at /v/:id: plain HTML in the openaudit.se
 * look, light and dark, with no scripts. Every value is escaped for its
 * context, and links are built only from parts validated here (links.ts),
 * because scan errors and report text can be shaped by repo content.
 */
import type { Grade, ProjectState, ScanSummary, TargetSummary } from "./api";
import { hiddenText } from "./card";
import {
	gradeClass,
	httpsUrl,
	num,
	safeOrigin,
	validProjectId,
	validRepo,
	validScanId,
	validSha,
} from "./links";
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

/** Escaped markup, ready to concatenate. */
type Html = string;

const commitLink = (repo: Text, sha: string | null): Html => {
	if (sha === null || !validSha(sha)) return "unknown";
	const code = `<code>${esc(sha.slice(0, 7))}</code>`;
	if (!validRepo(repo)) return code;
	return `<a href="${esc(`https://github.com/${repo}/commit/${sha}`)}">${code}</a>`;
};

const row = (name: Text, value: Html): Html =>
	`<dt>${esc(name)}</dt><dd>${value}</dd>`;

interface Scored {
	readonly score: number;
	readonly grade: Grade;
}

const score = (s: Scored): Html =>
	`<b class="score ${gradeClass(s.grade)}">${esc(`${num(s.score)} ${s.grade}`)}</b>`;

const auditorsText = (s: TargetSummary) => {
	const a = s.auditors;
	const ran = a.passed + a.failed + a.error;
	return `${num(ran)} ran (${num(a.passed)} passed, ${num(a.failed)} with findings, ${num(a.error)} errored), ${num(a.skipped)} skipped`;
};

const entry = (e: TargetSummary["hiddenBy"][number]): Html => {
	const reason = e.reason ? `: ${esc(e.reason)}` : "";
	return `<li><code>${esc(`${e.kind} ${e.value}`)}</code> (${esc(num(e.count))})${reason}</li>`;
};

const hiddenBy = (s: TargetSummary): Html => {
	const list = s.hiddenBy.length
		? `<ul class="hidden">${s.hiddenBy.map(entry).join("")}</ul>`
		: "";
	return `${esc(hiddenText(s))}${list}`;
};

const categories = (s: TargetSummary): Html =>
	s.categories
		.map((c) => `<li><span>${esc(c.category)}</span>${score(c)}</li>`)
		.join("");

const target = (name: Text, s: TargetSummary, report: Html): Html =>
	`<section class="target"><h3>${esc(name)} ${score(s)}</h3><ul class="cats">${categories(s)}</ul><dl>${row("Auditors", esc(auditorsText(s)))}${row("Config", hiddenBy(s))}${row("openaudit", esc(s.openauditVersion))}</dl><p><a href="${report}">Open the full report</a></p></section>`;

type ReportFile = "report" | "site-report";

const reportPath = (id: Text, file: ReportFile, scan?: Text): Html => {
	const query = scan && validScanId(scan) ? `?scan=${scan}` : "";
	return esc(`/v/${id}/${file}${query}`);
};

/** A note from the scanner, such as why the site wasn't scanned. */
const note = (scan: ScanSummary): Html =>
	scan.error ? `<p class="warn">From this scan: ${esc(scan.error)}</p>` : "";

const siteMissing = (project: ProjectState, scan: ScanSummary): Html =>
	project.site !== null && scan.site === null
		? "<p>The website wasn't available in this scan.</p>"
		: "";

const latest = (project: ProjectState, scan: ScanSummary): Html => {
	const id = project.id;
	const meta = `<dl>${row("Scanned", esc(formatDate(scan.finishedAt)))}${row("Commit", commitLink(project.repo, scan.commit))}${row("openaudit", esc(scan.openauditVersion ?? "unknown"))}</dl>`;
	const codebase = scan.codebase
		? target("Codebase", scan.codebase, reportPath(id, "report"))
		: "";
	const site = scan.site
		? target("Website", scan.site, reportPath(id, "site-report"))
		: siteMissing(project, scan);
	return `<h2>Latest scan</h2>${meta}${note(scan)}${codebase}${site}`;
};

const cell = (s: TargetSummary | null) =>
	s ? esc(`${num(s.score)} ${s.grade}`) : "";

const resultText = (scan: ScanSummary) => {
	if (scan.status === "failed") return "failed";
	return scan.error ? "ok, with a note" : "ok";
};

const historyRow = (id: Text, scan: ScanSummary): Html => {
	const links = [
		scan.codebase
			? `<a href="${reportPath(id, "report", scan.id)}">codebase</a>`
			: "",
		scan.site
			? `<a href="${reportPath(id, "site-report", scan.id)}">website</a>`
			: "",
	].join(" ");
	return `<tr><td>${esc(formatDate(scan.finishedAt))}</td><td>${esc(resultText(scan))}</td><td>${cell(scan.codebase)}</td><td>${cell(scan.site)}</td><td>${links}</td></tr>`;
};

const history = (id: Text, scans: ReadonlyArray<ScanSummary>): Html =>
	scans.length === 0
		? ""
		: `<h2>Recent scans</h2><table><thead><tr><th>Date</th><th>Result</th><th>Codebase</th><th>Website</th><th>Reports</th></tr></thead><tbody>${scans.map((s) => historyRow(id, s)).join("")}</tbody></table>`;

const snippet = (title: Text, code: Text): Html =>
	`<h3>${esc(title)}</h3><pre><code>${esc(code)}</code></pre>`;

const embeds = (id: Text, origin: Origin): Html => {
	const base = safeOrigin(origin);
	const page = `${base}/v/${id}`;
	const badge = `${base}/badge/${id}.svg`;
	const card = `${base}/badge/${id}/card.svg`;
	return `<h2>Embed</h2>${snippet("Badge, Markdown", `[![openaudit](${badge})](${page})`)}${snippet("Badge, HTML", `<a href="${page}"><img src="${badge}" alt="openaudit score"></a>`)}${snippet("Card, Markdown", `[![openaudit](${card})](${page})`)}${snippet("Card, HTML", `<a href="${page}"><img src="${card}" alt="openaudit score card" width="440" height="170"></a>`)}`;
};

const failure = (scans: ReadonlyArray<ScanSummary>): Html => {
	const last = scans[0];
	return last?.status === "failed"
		? `<p class="warn">The last scan failed: ${esc(last.error ?? "unknown error")}</p>`
		: "";
};

const siteLine = (site: Text | null): Html => {
	if (site === null) return "";
	const href = httpsUrl(site);
	const shown = esc(site);
	return `<p>Website: ${href ? `<a href="${esc(href)}">${shown}</a>` : shown}</p>`;
};

const repoHeading = (repo: Text): Html =>
	validRepo(repo)
		? `<h1><a href="${esc(`https://github.com/${repo}`)}">${esc(repo)}</a></h1>`
		: `<h1>${esc(repo)}</h1>`;

const shell = (title: Text, main: Html): Html =>
	`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex"><title>${esc(title)}</title><style>${PAGE_CSS}</style></head><body><header><a href="/" class="brand">openaudit</a><a href="/badge/">Get a badge</a></header><main>${main}</main><footer><p>openaudit scans this project itself every 7 days, so the badge can't be faked. <a href="/badge/">How it works</a></p></footer></body></html>`;

const missing = (view: BadgeView): Html =>
	view.state === "removed"
		? "<h1>Badge removed</h1><p>The owner removed this badge and its reports.</p>"
		: "<h1>No such badge</h1><p>There's no badge with this id.</p>";

const statusLine = (badge: BadgeView): Html => {
	const text = STATUS_TEXT[badge.state] ?? badge.state;
	return `<p class="status s-${esc(badge.state)}">${esc(text)}</p>`;
};

const preview = (id: Text): Html =>
	`<p class="preview"><img src="${esc(`/badge/${id}.svg`)}" alt="openaudit badge"> <img src="${esc(`/badge/${id}/card.svg`)}" alt="openaudit card" width="440" height="170"></p>`;

/** The verification page, or a short notice for a missing or removed badge. */
export const verifyPageHtml = ({ badge, scans, origin }: VerifyPage): Html => {
	const project = badge.project;
	if (!project || !validProjectId(project.id))
		return shell("openaudit badge", missing(badge));
	const id = project.id;
	const scan = badge.scan ? latest(project, badge.scan) : "";
	const main = `<p class="kicker">openaudit verified badge</p>${repoHeading(project.repo)}${siteLine(project.site)}${statusLine(badge)}${preview(id)}${failure(scans)}${scan}${history(id, scans)}${embeds(id, origin)}`;
	return shell(`${project.repo}: openaudit badge`, main);
};
