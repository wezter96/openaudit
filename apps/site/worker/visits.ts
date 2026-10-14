/**
 * Anonymous page-view counting in Workers Analytics Engine, with no script
 * in the page. One data point per page or Markdown view:
 *
 * | Column | Value |
 * | --- | --- |
 * | blob1 | path |
 * | blob2 | kind: `page` (HTML) or `markdown` (what agents fetch) |
 * | blob3 | who: `human` or `bot` |
 * | blob4 | the bot's name when blob3 is `bot` (e.g. `googlebot`, `claudebot`) |
 * | blob5 | the referring site's host, empty for direct visits and this site |
 * | blob6 | country (two letters, from Cloudflare) |
 * | blob7 | device: `mobile` or `desktop` |
 *
 * No IP address, no user agent string, no cookie: a view can't be tied to a
 * person or to another view. scripts/stats.ts reads the numbers back.
 */

/** The Analytics Engine binding, as far as this module uses it. */
export interface Visits {
	writeDataPoint(point: {
		blobs?: string[];
		doubles?: number[];
		indexes?: string[];
	}): void;
}

export type Kind = "page" | "markdown";

/**
 * Crawlers, agents (including the `*-User` fetchers that read a page for a
 * person, like ChatGPT-User), monitors and HTTP libraries; the first match
 * names it.
 */
const BOT =
	/[a-z0-9_-]*(?:bot|crawl|spider|slurp|agent|fetcher|scraper|preview|monitor|uptime|lighthouse|headless|curl|wget|python|httpx|axios|node-fetch|undici|go-http|okhttp|java\/|libwww|scrapy|-user)[a-z0-9_-]*/i;

/** `who` and the bot's name for a user agent string. */
export const classify = (
	ua: string | null,
): { who: "human" | "bot"; name: string } => {
	if (!ua) return { who: "bot", name: "unknown" };
	const m = BOT.exec(ua);
	return m
		? { who: "bot", name: m[0].toLowerCase().replace(/\/$/, "").slice(0, 40) }
		: { who: "human", name: "" };
};

/** The referring host, or "" for direct visits and links within this site. */
const referrer = (request: Request, self: string): string => {
	try {
		const host = new URL(request.headers.get("referer") ?? "").hostname;
		return host === self || host === `www.${self}` ? "" : host;
	} catch {
		return "";
	}
};

/** Records one view, unless it's a HEAD or a prefetch. Never throws. */
export const recordVisit = (
	visits: Visits | undefined,
	request: Request,
	path: string,
	kind: Kind,
): void => {
	if (!visits || request.method !== "GET") return;
	const purpose =
		request.headers.get("sec-purpose") ?? request.headers.get("purpose") ?? "";
	if (/prefetch|prerender/i.test(purpose)) return;
	const ua = request.headers.get("user-agent");
	const { who, name } = classify(ua);
	const cf = (request as Request & { cf?: { country?: string } }).cf;
	try {
		visits.writeDataPoint({
			blobs: [
				path,
				kind,
				who,
				name,
				referrer(request, new URL(request.url).hostname),
				cf?.country ?? "",
				/mobi|android|iphone|ipad/i.test(ua ?? "") ? "mobile" : "desktop",
			],
			doubles: [1],
			indexes: [path.slice(0, 96)],
		});
	} catch {
		// swallow: counting must never break a page
	}
};
