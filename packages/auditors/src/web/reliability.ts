import {
	type AuditContext,
	defineAuditor,
	type FindingInput,
	type HttpResponse,
} from "@openaudit/core";
import { Effect, type Option } from "effect";

import { domainScope } from "./dns";
import { type Crawl, crawl, fetchCached, isLoopback } from "./page";
import { truncate } from "./util";

const MAX_HOPS = 10;
const MAX_REPORTED_5XX = 10;
const MDN_STATUS = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status";

export interface RedirectHop {
	readonly url: string;
	readonly status: number;
	readonly location: string;
}

/** An absolute URL. */
type Url = string;
/** A URL's origin, such as `https://example.com`. */
type Origin = string;
/** A host name. */
type Hostname = string;
/** An HTTP status code. */
type Status = number;

const isRedirect = (status: Status) => status >= 300 && status < 400;

/** Walks redirects one request at a time so every hop is visible. */
const walkRedirects = (ctx: AuditContext, startUrl: Url) =>
	Effect.gen(function* () {
		const hops: RedirectHop[] = [];
		const seen = new Set<string>();
		let url = startUrl;
		let loop = false;
		while (hops.length < MAX_HOPS) {
			seen.add(url);
			const res = yield* fetchCached(ctx, url, {
				redirect: "manual",
				timeoutMs: 8_000,
				maxBytes: 1024,
			}).pipe(Effect.option);
			if (res._tag === "None") break;
			const location = res.value.headers.get("location");
			if (!isRedirect(res.value.status) || !location) break;
			const next = new URL(location, url).toString();
			hops.push({ url, status: res.value.status, location: next });
			if (seen.has(next)) {
				loop = true;
				break;
			}
			url = next;
		}
		return { hops, loop };
	});

/** Default error pages of common servers and frameworks. */
const DEFAULT_404 =
	/<center><h1>404 Not Found<\/h1><\/center>\s*<hr><center>nginx|<h1>Not Found<\/h1>\s*<p>The requested URL [^<]* was not found on this server|<title>404 Not Found<\/title>\s*<\/head><body>\s*<h1>Not Found<\/h1>|Cannot (GET|POST) \/|HTTP Error 404\.0|<h1>Server Error<\/h1>\s*<h2>404|Whitelabel Error Page|<pre>Cannot GET|<title>Error response<\/title>|404 page not found\s*$/i;

export const isDefault404 = (res: Pick<HttpResponse, "body">): boolean => {
	const body = res.body.trim();
	return body.length < 40 || DEFAULT_404.test(body);
};

/** Apex <-> www counterpart of a host, or undefined when neither applies. */
export const wwwCounterpart = (hostname: Hostname): string | undefined => {
	const scope = domainScope(hostname);
	if (scope.kind !== "domain") return undefined;
	if (scope.host === scope.domain) return `www.${scope.domain}`;
	if (scope.host === `www.${scope.domain}`) return scope.domain;
	return undefined;
};

type RedirectWalk = Effect.Success<ReturnType<typeof walkRedirects>>;

const chainOf = (hops: ReadonlyArray<RedirectHop>) =>
	[...hops.map((h) => h.url), hops.at(-1)?.location].join(" → ");

const isUnreachable = (walked: RedirectWalk) =>
	walked.loop || walked.hops.length >= MAX_HOPS;

const redirectLoopFinding = (
	targetUrl: Url,
	walked: RedirectWalk,
): FindingInput => ({
	ruleId: "web.reliability/redirect-loop",
	title: walked.loop
		? "Redirect loop"
		: `Redirect chain exceeds ${MAX_HOPS} hops`,
	severity: "high",
	category: "reliability",
	message: `${targetUrl} redirects ${walked.loop ? "back to a URL it already visited" : `more than ${MAX_HOPS} times`}. Browsers give up after about 20 redirects and crawlers after fewer, so the page is effectively unreachable.`,
	location: { url: targetUrl },
	evidence: truncate(chainOf(walked.hops), 300),
	remediation:
		"Fix the conflicting redirect rules (often HTTP/HTTPS or www/apex rules fighting each other, or a CDN and origin both redirecting).",
	references: [`${MDN_STATUS}/301`],
	tags: ["redirects"],
});

const redirectChainFindings = (
	targetUrl: Url,
	hops: ReadonlyArray<RedirectHop>,
): FindingInput[] =>
	hops.length > 2
		? [
				{
					ruleId: "web.reliability/redirect-chain",
					title: `Redirect chain of ${hops.length} hops`,
					severity: "low",
					category: "reliability",
					message: `Reaching the page takes ${hops.length} sequential redirects. Each one adds a round trip, widens the failure surface and dilutes crawl budget; ideal is one hop to the final URL.`,
					location: { url: targetUrl },
					evidence: truncate(chainOf(hops), 300),
					remediation:
						"Redirect straight to the canonical https URL in one step (combine the http→https and apex↔www rules).",
					references: ["https://web.dev/articles/redirects"],
					tags: ["redirects"],
				},
			]
		: [];

interface AltProbe {
	readonly host: string;
	readonly alt: string;
	readonly altUrl: string;
	readonly status: number;
	readonly error: string | undefined;
}

const apexWwwFinding = (p: AltProbe): FindingInput => {
	const failed = p.error !== undefined;
	return {
		ruleId: "web.reliability/apex-www-inconsistent",
		title: `${p.alt} does not answer while ${p.host} does`,
		severity: "low",
		category: "reliability",
		message: `${p.host} works, but ${p.altUrl} ${failed ? `fails (${truncate((p.error ?? "").replace(/^Request to \S+ failed: /, ""), 100)})` : `returns ${p.status}`}. Visitors and links using the other spelling get an error. If the host is intentionally single-name, ignore this.`,
		location: { url: p.altUrl },
		evidence: failed
			? truncate(p.error ?? "", 160)
			: `GET ${p.altUrl} → ${p.status}`,
		remediation: `Point both ${p.host} and ${p.alt} at the site (with a valid certificate for each) and redirect one to the other.`,
		references: ["https://web.dev/articles/redirects"],
		tags: ["dns", "redirects"],
		confidence: "low",
	};
};

/** Checks that the apex/www counterpart of the start host answers too. */
const apexWwwFindings = (ctx: AuditContext, startUrl: Url) =>
	Effect.gen(function* () {
		const start = new URL(startUrl);
		const host = start.hostname;
		const alt = isLoopback(startUrl) ? undefined : wwwCounterpart(host);
		if (!alt) return [];
		const altUrl = `${start.protocol}//${alt}${start.port ? `:${start.port}` : ""}/`;
		const res = yield* fetchCached(ctx, altUrl, {
			redirect: "manual",
			timeoutMs: 8_000,
			maxBytes: 4 * 1024,
		}).pipe(
			Effect.map((r) => ({ status: r.status, error: undefined })),
			Effect.catch((e) => Effect.succeed({ status: 0, error: e.message })),
		);
		if (res.status >= 500 || res.error !== undefined)
			return [apexWwwFinding({ host, alt, altUrl, ...res })];
		return [];
	});

interface ServerError {
	readonly url: string;
	readonly status: number;
	/** The page the user asked to audit. */
	readonly isStart: boolean;
	readonly linkedFrom: string | undefined;
}

const serverErrorFinding = (e: ServerError): FindingInput => ({
	ruleId: "web.reliability/server-error",
	title: `Server error ${e.status} on ${new URL(e.url).pathname}`,
	severity: e.isStart ? "high" : "medium",
	category: "reliability",
	message: `${e.url} responded ${e.status}${e.isStart ? " (the page you asked to audit)" : `, linked from ${e.linkedFrom ?? "another page"}`}. Users and crawlers see a failure instead of content.`,
	location: { url: e.url },
	evidence: `GET ${e.url} → ${e.status}`,
	remediation:
		"Check the server logs for this request, fix the underlying error, and add monitoring/alerting on 5xx rates.",
	references: [`${MDN_STATUS}/${e.status}`],
	tags: ["errors"],
	confidence: "medium",
});

const noRetryAfterFinding = (url: Url): FindingInput => ({
	ruleId: "web.reliability/503-no-retry-after",
	title: "503 without a Retry-After header",
	severity: "low",
	category: "reliability",
	message: `${url} answers 503 Service Unavailable without Retry-After, so crawlers and clients cannot tell how long to back off and may keep hammering or de-index the page.`,
	location: { url },
	evidence: `GET ${url} → 503, no Retry-After`,
	remediation:
		"Send Retry-After (seconds or an HTTP date) with every 503, especially for maintenance pages.",
	references: [`${MDN_STATUS}/503`],
	tags: ["errors"],
});

const lacksRetryAfter = (res: Option.Option<HttpResponse>) =>
	res._tag === "Some" && !res.value.headers.get("retry-after");

/** Refetches one 5xx URL to report it and a 503 without Retry-After. */
const urlErrorFindings = (ctx: AuditContext, e: ServerError) =>
	Effect.gen(function* () {
		const res = yield* fetchCached(ctx, e.url).pipe(Effect.option);
		const findings = [serverErrorFinding(e)];
		if (e.status === 503 && lacksRetryAfter(res))
			findings.push(noRetryAfterFinding(e.url));
		return findings;
	});

const manyServerErrorsFinding = (
	count: number,
	startUrl: Url,
): FindingInput => ({
	ruleId: "web.reliability/server-error-many",
	title: `${count - MAX_REPORTED_5XX} more pages return 5xx`,
	severity: "medium",
	category: "reliability",
	message: `${count} crawled URLs returned a 5xx status; only the first ${MAX_REPORTED_5XX} are listed.`,
	location: { url: startUrl },
	remediation: "Fix the server errors listed and re-run the audit.",
	references: [`${MDN_STATUS}/500`],
	tags: ["errors"],
});

const serverErrorFindings = (ctx: AuditContext, c: Crawl, targetUrl: Url) =>
	Effect.gen(function* () {
		const findings: FindingInput[] = [];
		const errors = [...c.statuses.entries()].filter(([, s]) => s >= 500);
		for (const [url, status] of errors.slice(0, MAX_REPORTED_5XX)) {
			const isStart = url === c.start.url || url === targetUrl;
			const linkedFrom = c.linkedFrom.get(url);
			findings.push(
				...(yield* urlErrorFindings(ctx, { url, status, isStart, linkedFrom })),
			);
		}
		if (errors.length > MAX_REPORTED_5XX)
			findings.push(manyServerErrorsFinding(errors.length, c.start.url));
		return findings;
	});

/** A redirect from the 404 probe to the site's home page. */
const redirectsHome = (
	res: HttpResponse,
	probeUrl: Url,
	origin: Origin,
): boolean => {
	const target = res.headers.get("location");
	if (!isRedirect(res.status) || target === null) return false;
	const dest = new URL(target, probeUrl);
	return dest.pathname === "/" && dest.origin === origin;
};

const soft404Finding = (
	status: Status,
	toHome: boolean,
	location: FindingInput["location"],
): FindingInput => ({
	ruleId: "web.reliability/soft-404",
	title: "Unknown URLs do not return 404 (soft 404)",
	severity: "low",
	category: "reliability",
	message: `A random non-existent path answered ${status}${toHome ? " and redirected to the home page" : ""} instead of 404. Search engines treat these as soft 404s and monitoring cannot tell missing pages from real ones. Single-page apps with client-side routing commonly cause this.`,
	location,
	evidence: `GET /openaudit-…-not-found → ${status}${toHome ? " → /" : ""}`,
	remediation:
		"Return a real 404 status for unknown routes (server-side rendering, or a 404.html fallback), or have the client router trigger a noindex/404 response.",
	references: [
		"https://developers.google.com/search/docs/crawling-indexing/http-network-errors#soft-404-errors",
	],
	tags: ["404"],
	confidence: "low",
});

const notFoundServerErrorFinding = (
	status: Status,
	location: FindingInput["location"],
): FindingInput => ({
	ruleId: "web.reliability/404-server-error",
	title: `Unknown URLs cause a server error (${status})`,
	severity: "medium",
	category: "reliability",
	message: `A random non-existent path answered ${status} instead of 404, which usually means the router or error handler itself crashes on unmatched requests.`,
	location,
	evidence: `GET /openaudit-…-not-found → ${status}`,
	remediation:
		"Add a catch-all route returning 404 and make sure the error handler cannot throw.",
	references: [`${MDN_STATUS}/404`],
	tags: ["404", "errors"],
});

const default404Finding = (
	res: HttpResponse,
	location: FindingInput["location"],
): FindingInput => ({
	ruleId: "web.reliability/default-404-page",
	title: "No custom 404 page",
	severity: "info",
	category: "reliability",
	message:
		"The 404 response is the web server's or framework's default page (or nearly empty), giving visitors who follow a broken link no way back into the site.",
	location,
	evidence: truncate(res.body.replace(/\s+/g, " ").trim(), 120),
	remediation:
		"Serve a branded 404 page with a search box and links to key sections, still with status 404.",
	references: [
		"https://developers.google.com/search/docs/crawling-indexing/http-network-errors",
	],
	tags: ["404"],
	confidence: "low",
});

/** How the site answers a random unknown path, or undefined when it is fine. */
const notFoundFinding = (
	res: HttpResponse,
	probeUrl: Url,
	origin: Origin,
): FindingInput | undefined => {
	const { status } = res;
	const location = { url: `${origin}/<random-path>` };
	const toHome = redirectsHome(res, probeUrl, origin);
	if (status === 200 || toHome) return soft404Finding(status, toHome, location);
	if (status >= 500) return notFoundServerErrorFinding(status, location);
	if (status === 404 && isDefault404(res))
		return default404Finding(res, location);
	return undefined;
};

const notFoundFindings = (ctx: AuditContext, origin: Origin) =>
	Effect.gen(function* () {
		const probeUrl = `${origin}/openaudit-${Date.now().toString(36)}-not-found`;
		const nf = yield* fetchCached(ctx, probeUrl, {
			redirect: "manual",
			timeoutMs: 8_000,
			maxBytes: 128 * 1024,
		}).pipe(Effect.option);
		if (nf._tag === "None") return [];
		const finding = notFoundFinding(nf.value, probeUrl, origin);
		return finding ? [finding] : [];
	});

export const reliability = defineAuditor({
	id: "web.reliability",
	title: "Availability and error handling",
	description:
		"Looks for long redirect chains and loops, apex/www inconsistency, 5xx responses on crawled pages, 503s without Retry-After, and 404 handling (soft 404s, default server error pages). HTTP→HTTPS redirects and slow responses are covered by web.tls and web.performance.",
	categories: ["reliability"],
	targets: ["url"],
	engine: "builtin",
	run: (ctx: AuditContext) =>
		Effect.gen(function* () {
			const targetUrl = ctx.target.url ?? "";
			// One manual request when nothing redirects; the crawl below reuses its own cache.
			const walked = yield* walkRedirects(ctx, targetUrl);
			if (isUnreachable(walked))
				return [redirectLoopFinding(targetUrl, walked)];
			const findings = redirectChainFindings(targetUrl, walked.hops);
			const c = yield* crawl(ctx);
			const origin = new URL(c.start.url).origin;
			findings.push(...(yield* apexWwwFindings(ctx, c.start.url)));
			findings.push(...(yield* serverErrorFindings(ctx, c, targetUrl)));
			findings.push(...(yield* notFoundFindings(ctx, origin)));
			return findings;
		}),
});
