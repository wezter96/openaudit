import {
	type AuditContext,
	type AuditorError,
	type HttpRequest,
	type HttpResponse,
	requireUrl,
	SkipAudit,
} from "@openaudit/core";
import { Effect, type Exit } from "effect";

import { attr, type El, findAll, findFirst, parseHtml } from "./dom";

/** A fetched URL, parsed once and shared by every web auditor. */
export interface Page {
	/** Final URL after redirects. */
	readonly url: string;
	readonly requestedUrl: string;
	readonly response: HttpResponse;
	readonly status: number;
	readonly isHtml: boolean;
	/** Parsed document; an empty `#document` when the response is not HTML. */
	readonly doc: El;
	/** Absolute, hash-less links to the same origin found on the page. */
	readonly links: ReadonlyArray<string>;
}

export interface Crawl {
	readonly start: Page;
	/** HTML pages that answered < 400, start page first. */
	readonly pages: ReadonlyArray<Page>;
	/** Every URL fetched during the crawl and its status (0 = network error). */
	readonly statuses: ReadonlyMap<string, number>;
	/** First page that linked to each discovered URL. */
	readonly linkedFrom: ReadonlyMap<string, string>;
	/** Same-origin links discovered but not fetched because of `maxPages`. */
	readonly unvisited: ReadonlyArray<string>;
}

export const DEFAULT_MAX_PAGES = 10;
const CRAWL_CONCURRENCY = 3;

const ASSET_EXT =
	/\.(png|jpe?g|gif|webp|avif|svg|ico|bmp|tiff?|pdf|zip|gz|tgz|rar|7z|dmg|exe|msi|apk|ipa|mp[34]|m4a|wav|ogg|webm|mov|avi|woff2?|ttf|otf|eot|css|js|mjs|map|json|xml|txt|csv|docx?|xlsx?|pptx?)$/i;

interface Cache {
	readonly responses: Map<
		string,
		Promise<Exit.Exit<HttpResponse, AuditorError>>
	>;
	readonly pages: Map<string, Promise<Exit.Exit<Page, AuditorError>>>;
	crawl?: Promise<Exit.Exit<Crawl, AuditorError | SkipAudit>>;
}

const caches = new WeakMap<AuditContext, Cache>();

const cacheFor = (ctx: AuditContext): Cache => {
	let cache = caches.get(ctx);
	if (!cache) {
		cache = { responses: new Map(), pages: new Map() };
		caches.set(ctx, cache);
	}
	return cache;
};

/** Runs `effect` once per key and shares the outcome with later callers. */
const memo = <A, E>(
	map: Map<string, Promise<Exit.Exit<A, E>>>,
	key: string,
	effect: Effect.Effect<A, E>,
): Effect.Effect<A, E> =>
	Effect.suspend(() => {
		let pending = map.get(key);
		if (!pending) {
			pending = Effect.runPromiseExit(effect);
			map.set(key, pending);
		}
		const p = pending;
		return Effect.flatMap(
			Effect.promise(() => p),
			(exit) => exit,
		);
	});

/** `ctx.http`, cached per audit so auditors never refetch the same URL. */
export const fetchCached = (
	ctx: AuditContext,
	url: Url,
	init: HttpRequest = {},
): Effect.Effect<HttpResponse, AuditorError> =>
	memo(
		cacheFor(ctx).responses,
		JSON.stringify([
			init.method ?? "GET",
			init.redirect ?? "follow",
			url,
			init.headers ?? {},
		]),
		ctx.http(url, init),
	);

/** An absolute or relative URL as found in a page or the target. */
export type Url = string;

const NON_HTTP_SCHEME = /^(javascript|mailto|tel|data|blob|about):/i;
const HTTP_PROTOCOLS = new Set(["http:", "https:"]);

const parseUrl = (raw: Url, base?: Url): URL | undefined => {
	try {
		return new URL(raw, base);
	} catch {
		return undefined;
	}
};

const isHttp = (url: URL | undefined): url is URL =>
	url !== undefined && HTTP_PROTOCOLS.has(url.protocol);

export const resolveUrl = (
	base: Url,
	href: Url | undefined,
): Url | undefined => {
	const trimmed = href?.trim();
	if (!trimmed || NON_HTTP_SCHEME.test(trimmed)) return undefined;
	const url = parseUrl(trimmed, base);
	return isHttp(url) ? url.toString() : undefined;
};

export const stripHash = (url: Url): Url => {
	const i = url.indexOf("#");
	return i === -1 ? url : url.slice(0, i);
};

export const originOf = (url: Url): string | undefined => parseUrl(url)?.origin;

export const sameOrigin = (a: Url, b: Url): boolean => {
	// Exact origin match; opaque origins ("null", e.g. data:) never match.
	const oa = originOf(a);
	return oa !== undefined && oa !== "null" && oa === originOf(b);
};

const isLoopbackHost = (host: string): boolean =>
	host === "localhost" ||
	host.endsWith(".localhost") ||
	host === "::1" ||
	host.startsWith("127.");

export const isLoopback = (url: Url): boolean => {
	const host = parseUrl(url)?.hostname.replace(/^\[|\]$/g, "");
	return host !== undefined && isLoopbackHost(host);
};

const looksLikeHtml = (res: HttpResponse): boolean => {
	const type = res.headers.get("content-type");
	if (type) return /text\/html|application\/xhtml\+xml/i.test(type);
	return /^\s*(<!doctype html|<html)/i.test(res.body);
};

/** Base URL for resolving relative references, honouring `<base href>`. */
export const baseUrlOf = (page: { url: string; doc: El }): string =>
	resolveUrl(page.url, attr(findFirst(page.doc, "base") ?? page.doc, "href")) ??
	page.url;

const EMPTY_DOC = (): El => ({
	type: "el",
	name: "#document",
	attrs: {},
	children: [],
	parent: undefined,
	start: 0,
});

/** Absolute, hash-less same-origin links of a parsed document. */
const linksOf = (doc: El, base: Url, pageUrl: Url): string[] => {
	const links = new Set<string>();
	for (const a of findAll(doc, ["a", "area"], (el) => "href" in el.attrs)) {
		const abs = resolveUrl(base, attr(a, "href"));
		if (abs && sameOrigin(abs, pageUrl)) links.add(stripHash(abs));
	}
	return [...links];
};

const toPage = (requestedUrl: Url, response: HttpResponse): Page => {
	const isHtml = looksLikeHtml(response);
	const doc = isHtml ? parseHtml(response.body) : EMPTY_DOC();
	const base = baseUrlOf({ url: response.url, doc });
	return {
		url: response.url,
		requestedUrl,
		response,
		status: response.status,
		isHtml,
		doc,
		links: linksOf(doc, base, response.url),
	};
};

/** Fetches and parses a URL once per audit. */
export const getPage = (
	ctx: AuditContext,
	url: Url,
): Effect.Effect<Page, AuditorError> =>
	memo(
		cacheFor(ctx).pages,
		url,
		Effect.map(fetchCached(ctx, url), (res) => toPage(url, res)),
	);

/** The target URL's page, or skip when the target is not a URL. */
export const startPage = (
	ctx: AuditContext,
): Effect.Effect<Page, AuditorError | SkipAudit> =>
	Effect.flatMap(requireUrl(ctx), (url) => getPage(ctx, url));

interface CrawlState {
	readonly statuses: Map<string, number>;
	readonly linkedFrom: Map<string, string>;
	readonly pages: Page[];
	readonly queue: string[];
}

const isHtmlOk = (page: Page): boolean => page.isHtml && page.status < 400;

const isKnown = (state: CrawlState, link: Url): boolean =>
	state.statuses.has(link) || state.queue.includes(link);

const enqueue = (state: CrawlState, page: Page) => {
	for (const link of page.links) {
		if (!state.linkedFrom.has(link)) state.linkedFrom.set(link, page.url);
		if (!isKnown(state, link)) state.queue.push(link);
	}
};

const isCrawlable = (state: CrawlState, url: Url): boolean =>
	!state.statuses.has(url) && !ASSET_EXT.test(new URL(url).pathname);

/** Takes up to `room` crawlable URLs off the queue. */
const nextBatch = (state: CrawlState, room: number): string[] => {
	const batch: string[] = [];
	while (state.queue.length > 0 && batch.length < room) {
		const next = state.queue.shift() as string;
		if (isCrawlable(state, next)) batch.push(next);
	}
	return batch;
};

const fetchBatch = (ctx: AuditContext, batch: ReadonlyArray<Url>) =>
	Effect.forEach(
		batch,
		(url) =>
			getPage(ctx, url).pipe(
				Effect.map((page) => ({ url, page })),
				Effect.orElseSucceed(() => ({ url, page: undefined })),
			),
		{ concurrency: CRAWL_CONCURRENCY },
	);

const record = (
	state: CrawlState,
	start: Page,
	fetched: { readonly url: Url; readonly page: Page | undefined },
) => {
	const { url, page } = fetched;
	state.statuses.set(url, page?.status ?? 0);
	if (!page) return;
	state.statuses.set(stripHash(page.url), page.status);
	if (isHtmlOk(page) && sameOrigin(page.url, start.url)) {
		state.pages.push(page);
		enqueue(state, page);
	}
};

const doCrawl = (
	ctx: AuditContext,
): Effect.Effect<Crawl, AuditorError | SkipAudit> =>
	Effect.gen(function* () {
		const startUrl = yield* requireUrl(ctx);
		const max = Math.max(1, ctx.options.maxPages ?? DEFAULT_MAX_PAGES);
		const start = yield* getPage(ctx, startUrl);
		const state: CrawlState = {
			statuses: new Map<string, number>([
				[stripHash(startUrl), start.status],
				[stripHash(start.url), start.status],
			]),
			linkedFrom: new Map<string, string>(),
			pages: isHtmlOk(start) ? [start] : [],
			queue: [],
		};
		enqueue(state, start);

		while (state.pages.length < max && state.queue.length > 0) {
			const batch = nextBatch(state, max - state.pages.length);
			if (batch.length === 0) break;
			const fetched = yield* fetchBatch(ctx, batch);
			for (const f of fetched) record(state, start, f);
		}

		const { statuses, linkedFrom, pages, queue } = state;
		return {
			start,
			pages,
			statuses,
			linkedFrom,
			unvisited: queue.filter((u) => !statuses.has(u)),
		};
	});

/** Same-origin crawl from the target URL, capped by `maxPages`. Shared per audit. */
export const crawl = (
	ctx: AuditContext,
): Effect.Effect<Crawl, AuditorError | SkipAudit> =>
	Effect.suspend(() => {
		const cache = cacheFor(ctx);
		cache.crawl ??= Effect.runPromiseExit(doCrawl(ctx));
		const p = cache.crawl;
		return Effect.flatMap(
			Effect.promise(() => p),
			(exit) => exit,
		);
	});

/** HTML pages from the crawl, or skip when the target serves no HTML. */
export const htmlPages = (
	ctx: AuditContext,
): Effect.Effect<ReadonlyArray<Page>, AuditorError | SkipAudit> =>
	Effect.flatMap(crawl(ctx), (c) =>
		c.pages.length > 0
			? Effect.succeed(c.pages)
			: Effect.fail(
					new SkipAudit({
						reason: `${c.start.url} did not return an HTML page (status ${c.start.status}, ${c.start.response.headers.get("content-type") ?? "no content-type"})`,
					}),
				),
	);

/* ------------------------------ subresources ------------------------------ */

export type ResourceKind =
	| "script"
	| "stylesheet"
	| "image"
	| "iframe"
	| "media"
	| "font"
	| "object"
	| "form"
	| "other";

export interface Resource {
	readonly kind: ResourceKind;
	readonly url: string;
	readonly el: El;
}

/** Elements whose kind and URL attribute are fixed by their tag name. */
const TAG_REFERENCES = new Map<string, readonly [ResourceKind, string]>([
	["script", ["script", "src"]],
	["img", ["image", "src"]],
	["iframe", ["iframe", "src"]],
	["frame", ["iframe", "src"]],
	["video", ["media", "src"]],
	["audio", ["media", "src"]],
	["source", ["media", "src"]],
	["track", ["media", "src"]],
	["object", ["object", "data"]],
	["embed", ["object", "src"]],
	["form", ["form", "action"]],
]);

const PRELOAD_AS = new Map<string, ResourceKind>([
	["font", "font"],
	["style", "stylesheet"],
	["script", "script"],
]);

const preloadKind = (as: string | undefined, rel: string[]): ResourceKind => {
	const explicit = PRELOAD_AS.get(as ?? "");
	if (explicit) return explicit;
	if (rel.includes("modulepreload")) return "script";
	return as === "image" ? "image" : "other";
};

const linkKind = (el: El): ResourceKind | undefined => {
	const rel = (el.attrs.rel ?? "").toLowerCase().split(/\s+/);
	if (rel.includes("stylesheet")) return "stylesheet";
	if (rel.includes("preload") || rel.includes("modulepreload"))
		return preloadKind(el.attrs.as, rel);
	if (rel.includes("icon")) return "image";
	return undefined;
};

const referenceOf = (
	el: El,
): { kind: ResourceKind; value: Url | undefined } | undefined => {
	if (el.name === "link") {
		const kind = linkKind(el);
		return kind && { kind, value: el.attrs.href };
	}
	const known = TAG_REFERENCES.get(el.name);
	return known && { kind: known[0], value: el.attrs[known[1]] };
};

const resourceOf = (base: Url, el: El): Resource | undefined => {
	const ref = referenceOf(el);
	if (!ref) return undefined;
	const url = resolveUrl(base, ref.value);
	return url ? { kind: ref.kind, url, el } : undefined;
};

/** Subresources referenced by a page, resolved to absolute URLs. */
export const resourcesOf = (page: Page): ReadonlyArray<Resource> => {
	const base = baseUrlOf(page);
	return findAll(page.doc, "*")
		.map((el) => resourceOf(base, el))
		.filter((r): r is Resource => r !== undefined);
};
