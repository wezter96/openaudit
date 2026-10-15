/**
 * The public, cacheable badge routes: the badge and card SVGs, the
 * verification page and the stored HTML reports.
 */
import {
	badgeSvg,
	cardSvg,
	type ProjectId,
	type ScanId,
	type ScanSummary,
	verifyPageHtml,
	viewOf,
} from "@openaudit/badge";
import { PAGE_CSS } from "@openaudit/badge/page-css";
import { sha256 } from "./crypto";
import { type BadgeBindings, nowSeconds } from "./env";
import { finishedScans, reportKey } from "./scans";
import { findProject, stateOf } from "./store";

const loadView = async (env: BadgeBindings, id: ProjectId) => {
	const row = await findProject(env.BADGES, id);
	const now = nowSeconds();
	if (!row) return { badge: viewOf(undefined, now), scans: [] };
	if (row.status === "removed")
		return { badge: viewOf("removed", now), scans: [] };
	const scans = await finishedScans(env.BADGES, id);
	return { badge: viewOf(stateOf(row, scans), now), scans };
};

const SVG_HEADERS = {
	"Content-Type": "image/svg+xml; charset=utf-8",
	"Cache-Control": "public, max-age=900",
	"Access-Control-Allow-Origin": "*",
	"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
	"X-Content-Type-Options": "nosniff",
};

export type SvgKind = "badge" | "card";

export const svgResponse = async (
	env: BadgeBindings,
	id: ProjectId,
	kind: SvgKind,
) => {
	const { badge } = await loadView(env, id);
	const svg = kind === "badge" ? badgeSvg(badge) : cardSvg(badge);
	const status = badge.state === "notfound" ? 404 : 200;
	return new Response(svg, { status, headers: SVG_HEADERS });
};

const base64 = (hexText: string) =>
	btoa(
		String.fromCharCode(
			...(hexText.match(/../g) ?? []).map((h) => Number.parseInt(h, 16)),
		),
	);

/** The page's CSP: its one inline stylesheet by hash, nothing else. */
const pagePolicy = async () =>
	[
		"default-src 'none'",
		`style-src 'sha256-${base64(await sha256(PAGE_CSS))}'`,
		"img-src 'self'",
		"base-uri 'none'",
		"form-action 'none'",
		"frame-ancestors 'none'",
	].join("; ");

/** The site's origin, such as `https://openaudit.se`. */
export type Origin = string;

export const verifyPage = async (
	env: BadgeBindings,
	id: ProjectId,
	origin: Origin,
) => {
	const { badge, scans } = await loadView(env, id);
	const html = verifyPageHtml({ badge, scans, origin });
	return new Response(html, {
		status: badge.state === "notfound" ? 404 : 200,
		headers: {
			"Content-Type": "text/html; charset=utf-8",
			"Cache-Control": "public, max-age=60",
			"Content-Security-Policy": await pagePolicy(),
			"X-Content-Type-Options": "nosniff",
			"Referrer-Policy": "strict-origin-when-cross-origin",
		},
	});
};

export type ReportTarget = "codebase" | "site";

const hasTarget = (scan: ScanSummary, target: ReportTarget) =>
	scan.status === "ok" && scan[target] !== null;

const isWanted = (scan: ScanSummary, wanted: ScanId | null) =>
	wanted === null || scan.id === wanted;

/** The asked-for scan, or the newest one with that target's report. */
const pickScan = (
	scans: ReadonlyArray<ScanSummary>,
	target: ReportTarget,
	wanted: ScanId | null,
) => scans.find((s) => hasTarget(s, target) && isWanted(s, wanted));

const REPORT_HEADERS = {
	"Content-Type": "text/html; charset=utf-8",
	"Content-Security-Policy":
		"sandbox allow-scripts allow-downloads allow-popups",
	"X-Content-Type-Options": "nosniff",
	"Cache-Control": "public, max-age=300",
	"Referrer-Policy": "no-referrer",
};

const notFound = () =>
	new Response("Report not found.\n", {
		status: 404,
		headers: { "Content-Type": "text/plain; charset=utf-8" },
	});

export interface ReportRequest {
	readonly id: ProjectId;
	readonly target: ReportTarget;
	/** `?scan=`, or null for the newest. */
	readonly scan: ScanId | null;
}

/** A stored HTML report, sandboxed so it can't touch openaudit.se. */
export const reportResponse = async (env: BadgeBindings, r: ReportRequest) => {
	const row = await findProject(env.BADGES, r.id);
	if (!row || row.status === "removed") return notFound();
	const scan = pickScan(
		await finishedScans(env.BADGES, r.id),
		r.target,
		r.scan,
	);
	if (!scan) return notFound();
	const object = await env.BADGE_REPORTS.get(
		reportKey(r.id, scan.id, `${r.target}.html`),
	);
	if (!object) return notFound();
	return new Response(object.body, { headers: REPORT_HEADERS });
};
