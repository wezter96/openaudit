/**
 * Quick audits: anyone can queue one public site, no sign-up. The badge
 * scanner claims them before badge scans and runs openaudit's default URL
 * auditors, which send only low-volume GET/HEAD requests. Each audit and its
 * report are kept QUICK_KEEP, under an unguessable id.
 */
import {
	Full,
	InvalidInput,
	NotFound,
	type QuickClaimResult,
	type QuickCreated,
	type QuickPayload,
	type QuickReport,
	type QuickState,
	type QuickStatus,
	RateLimited,
	type ScanId,
	type SiteUrl,
	summarize,
	type TargetSummary,
} from "@openaudit/badge";
import { Effect } from "effect";
import { ipDayHash } from "./crypto";
import type { BadgeRequest, D1, R2, Seconds } from "./env";
import { parseSite } from "./input";
import { DAY } from "./store";

/** Audits one address may start in a day. */
export const QUICK_PER_IP = 5;
/** Audits everyone together may start in a day; at the 5-minute timeout, at most half the scanner's day. */
export const QUICK_PER_DAY = 150;
/** Audits waiting at once; more are refused until the queue drains. */
export const QUICK_QUEUE = 20;
/** How long the scanner may hold a quick audit. */
export const QUICK_LEASE: Seconds = 15 * 60;
/** A finished audit of the same site this recent is reused. */
export const QUICK_REUSE: Seconds = 60 * 60;
/** How long audits and reports are kept. */
export const QUICK_KEEP: Seconds = 7 * DAY;

export interface QuickRow {
	readonly id: ScanId;
	readonly site: SiteUrl;
	readonly status: QuickStatus;
	readonly ip_day: string;
	readonly created_at: Seconds;
	readonly lease_until: Seconds | null;
	readonly finished_at: Seconds | null;
	readonly openaudit_version: string | null;
	readonly summary: string | null;
	readonly error: string | null;
}

/** R2 keys sit under `_quick/`, which no project id (`[a-z0-9]…`) can be. */
export const quickKey = (id: ScanId, ext: "json" | "html") =>
	`_quick/${id}/site.${ext}`;

const promise = <A>(run: () => Promise<A>) => Effect.promise(run);

/** `example.com` is read as `https://example.com/`. */
const parseQuickSite = (input: string) => {
	const text = input.trim();
	return parseSite(
		/^[a-z][a-z0-9+.-]*:/i.test(text) ? text : `https://${text}`,
	);
};

const findQuick = (db: D1, id: ScanId) =>
	db
		.prepare("SELECT * FROM quick_scans WHERE id = ?")
		.bind(id)
		.first<QuickRow>();

/** A queued or running audit of the site, or an ok one from the last hour. */
const reusable = (db: D1, site: SiteUrl, now: Seconds) =>
	db
		.prepare(
			"SELECT id FROM quick_scans WHERE site = ? AND (status IN ('queued', 'running') OR (status = 'ok' AND finished_at > ?)) ORDER BY created_at DESC LIMIT 1",
		)
		.bind(site, now - QUICK_REUSE)
		.first<{ id: ScanId }>();

/** Queues the audit in one statement, so parallel requests can't pass a limit. */
const insertQuick = async (
	db: D1,
	row: { id: ScanId; site: SiteUrl; ipDay: string; now: Seconds },
) => {
	const result = await db
		.prepare(
			"INSERT INTO quick_scans (id, site, status, ip_day, created_at) SELECT ?, ?, 'queued', ?, ? WHERE (SELECT count(*) FROM quick_scans WHERE ip_day = ? AND created_at > ?) < ? AND (SELECT count(*) FROM quick_scans WHERE created_at > ?) < ? AND (SELECT count(*) FROM quick_scans WHERE status = 'queued') < ?",
		)
		.bind(
			row.id,
			row.site,
			row.ipDay,
			row.now,
			row.ipDay,
			row.now - DAY,
			QUICK_PER_IP,
			row.now - DAY,
			QUICK_PER_DAY,
			QUICK_QUEUE,
		)
		.run();
	return result.meta.changes === 1;
};

const count = async (db: D1, sql: string, ...values: unknown[]) =>
	(
		await db
			.prepare(sql)
			.bind(...values)
			.first<{ n: number }>()
	)?.n ?? 0;

/** Why the insert was refused. */
const refusal = (db: D1, ipDay: string, now: Seconds) =>
	Effect.gen(function* () {
		const mine = yield* promise(() =>
			count(
				db,
				"SELECT count(*) AS n FROM quick_scans WHERE ip_day = ? AND created_at > ?",
				ipDay,
				now - DAY,
			),
		);
		if (mine >= QUICK_PER_IP)
			return yield* new RateLimited({
				message: `You can run ${QUICK_PER_IP} quick audits a day. Try again tomorrow, or run openaudit yourself.`,
			});
		return yield* new Full({
			message: "We're busy running other audits. Try again in a few minutes.",
		});
	});

/** Deletes audits past QUICK_KEEP and their reports, a batch at a time. */
const pruneQuick = async (db: D1, reports: R2, now: Seconds) => {
	const { results } = await db
		.prepare("SELECT id FROM quick_scans WHERE created_at < ? LIMIT 50")
		.bind(now - QUICK_KEEP)
		.all<{ id: ScanId }>();
	if (results.length === 0) return;
	await reports.delete(
		results.flatMap((r) => [quickKey(r.id, "json"), quickKey(r.id, "html")]),
	);
	await db.batch(
		results.map((r) =>
			db.prepare("DELETE FROM quick_scans WHERE id = ?").bind(r.id),
		),
	);
};

export const startQuick = (req: BadgeRequest, payload: QuickPayload) =>
	Effect.gen(function* () {
		const site = parseQuickSite(payload.site);
		if (!site)
			return yield* new InvalidInput({
				message:
					"Give a public https:// address with no port or login, like https://example.com.",
			});
		if (req.ip === "")
			return yield* new InvalidInput({
				message: "We couldn't tell where your request came from.",
			});
		const db = req.env.BADGES;
		yield* promise(() => pruneQuick(db, req.env.BADGE_REPORTS, req.now));
		const existing = yield* promise(() => reusable(db, site, req.now));
		if (existing) return { id: existing.id } satisfies QuickCreated;
		const ipDay = yield* promise(() =>
			ipDayHash(
				req.ip,
				new Date(req.now * 1000).toISOString().slice(0, 10),
				req.env.SCANNER_TOKEN ?? "",
			),
		);
		const id = crypto.randomUUID();
		const queued = yield* promise(() =>
			insertQuick(db, { id, site, ipDay, now: req.now }),
		);
		if (!queued) return yield* refusal(db, ipDay, req.now);
		return { id } satisfies QuickCreated;
	});

const notFound = () =>
	new NotFound({ message: "No quick audit with this id." });

const parseSummary = (text: string | null): TargetSummary | null =>
	text ? (JSON.parse(text) as TargetSummary) : null;

export const getQuick = (req: BadgeRequest, id: ScanId) =>
	Effect.gen(function* () {
		const db = req.env.BADGES;
		const row = yield* promise(() => findQuick(db, id));
		if (!row) return yield* notFound();
		const ahead =
			row.status === "queued"
				? yield* promise(() =>
						count(
							db,
							"SELECT count(*) AS n FROM quick_scans WHERE status = 'queued' AND created_at < ?",
							row.created_at,
						),
					)
				: 0;
		return {
			id: row.id,
			site: row.site,
			status: row.status,
			createdAt: row.created_at,
			finishedAt: row.finished_at,
			ahead,
			summary: parseSummary(row.summary),
			error: row.error,
		} satisfies QuickState;
	});

/** Fails running audits past their lease. */
const expireQuick = (db: D1, now: Seconds) =>
	db
		.prepare(
			"UPDATE quick_scans SET status = 'failed', error = 'the audit timed out', finished_at = ?, lease_until = NULL WHERE status = 'running' AND lease_until < ?",
		)
		.bind(now, now)
		.run();

export const claimQuick = (req: BadgeRequest) =>
	Effect.gen(function* () {
		const db = req.env.BADGES;
		yield* promise(() => expireQuick(db, req.now));
		const next = yield* promise(() =>
			db
				.prepare(
					"SELECT * FROM quick_scans WHERE status = 'queued' ORDER BY created_at LIMIT 1",
				)
				.first<QuickRow>(),
		);
		if (!next) return { job: null } satisfies QuickClaimResult;
		const claimed = yield* promise(() =>
			db
				.prepare(
					"UPDATE quick_scans SET status = 'running', lease_until = ? WHERE id = ? AND status = 'queued'",
				)
				.bind(req.now + QUICK_LEASE, next.id)
				.run(),
		);
		if (claimed.meta.changes !== 1)
			return { job: null } satisfies QuickClaimResult;
		return { job: { id: next.id, site: next.site } } satisfies QuickClaimResult;
	});

const notRunning = () =>
	new NotFound({ message: "No running quick audit with this id." });

const storeReport = (req: BadgeRequest, id: ScanId, report: QuickReport) =>
	Effect.gen(function* () {
		if (report.status !== "ok") return null;
		const summary = report.site ? summarize(report.site.json) : undefined;
		if (!report.site || !summary)
			return yield* new InvalidInput({
				message: "An ok quick audit needs the site's openaudit report.",
			});
		const { json, html } = report.site;
		yield* promise(() =>
			Promise.all([
				req.env.BADGE_REPORTS.put(quickKey(id, "json"), json, {
					httpMetadata: { contentType: "application/json" },
				}),
				req.env.BADGE_REPORTS.put(quickKey(id, "html"), html, {
					httpMetadata: { contentType: "text/html; charset=utf-8" },
				}),
			]),
		);
		return summary;
	});

export const reportQuick = (
	req: BadgeRequest,
	id: ScanId,
	report: QuickReport,
) =>
	Effect.gen(function* () {
		const db = req.env.BADGES;
		const row = yield* promise(() => findQuick(db, id));
		if (row?.status !== "running" || (row.lease_until ?? 0) < req.now)
			return yield* notRunning();
		const summary = yield* storeReport(req, id, report);
		const error =
			report.error ?? (report.status === "ok" ? null : "the audit failed");
		const done = yield* promise(() =>
			db
				.prepare(
					"UPDATE quick_scans SET status = ?, finished_at = ?, lease_until = NULL, openaudit_version = ?, summary = ?, error = ? WHERE id = ? AND status = 'running' AND lease_until >= ?",
				)
				.bind(
					report.status,
					req.now,
					report.openauditVersion ?? null,
					summary ? JSON.stringify(summary) : null,
					error,
					id,
					req.now,
				)
				.run(),
		);
		if (done.meta.changes === 1) return;
		// Lost the race to finish: its files go with it.
		if (summary)
			yield* promise(() =>
				req.env.BADGE_REPORTS.delete([
					quickKey(id, "json"),
					quickKey(id, "html"),
				]),
			);
		return yield* notRunning();
	});

/** An ok audit's stored HTML report, or undefined. */
export const quickReportObject = async (
	env: BadgeRequest["env"],
	id: ScanId,
) => {
	const row = await findQuick(env.BADGES, id);
	if (row?.status !== "ok") return undefined;
	return (await env.BADGE_REPORTS.get(quickKey(id, "html"))) ?? undefined;
};
