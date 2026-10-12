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
	url: string,
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

export const resolveUrl = (
	base: string,
	href: string | undefined,
): string | undefined => {
	if (!href) return undefined;
	const trimmed = href.trim();
	if (!trimmed || /^(javascript|mailto|tel|data|blob|about):/i.test(trimmed))
		return undefined;
	try {
		const url = new URL(trimmed, base);
		if (url.protocol !== "http:" && url.protocol !== "https:") return undefined;
		return url.toString();
	} catch {
		return undefined;
	}
};

export const stripHash = (url: string): string => {
	const i = url.indexOf("#");
	return i === -1 ? url : url.slice(0, i);
};

export const originOf = (url: string): string | undefined => {
	try {
		return new URL(url).origin;
	} catch {
		return undefined;
	}
};

export const sameOrigin = (a: string, b: string): boolean => {
	const oa = originOf(a);
	return oa !== undefined && oa === originOf(b);
};

export const isLoopback = (url: string): boolean => {
	try {
		const host = new URL(url).hostname.replace(/^\[|\]$/g, "");
		return (
			host === "localhost" ||
			host.endsWith(".localhost") ||
			host === "::1" ||
			/^127\./.test(host)
		);
	} catch {
		return false;
	}
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

const toPage = (requestedUrl: string, response: HttpResponse): Page => {
	const isHtml = looksLikeHtml(response);
	const doc = isHtml ? parseHtml(response.body) : EMPTY_DOC();
	const base = baseUrlOf({ url: response.url, doc });
	const links = new Set<string>();
	for (const a of findAll(doc, ["a", "area"], (el) => "href" in el.attrs)) {
		const abs = resolveUrl(base, attr(a, "href"));
		if (abs && sameOrigin(abs, response.url)) links.add(stripHash(abs));
	}
	return {
		url: response.url,
		requestedUrl,
		response,
		status: response.status,
		isHtml,
		doc,
		links: [...links],
	};
};

/** Fetches and parses a URL once per audit. */
export const getPage = (
	ctx: AuditContext,
	url: string,
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

const doCrawl = (
	ctx: AuditContext,
): Effect.Effect<Crawl, AuditorError | SkipAudit> =>
	Effect.gen(function* () {
		const startUrl = yield* requireUrl(ctx);
		const max = Math.max(1, ctx.options.maxPages ?? DEFAULT_MAX_PAGES);
		const start = yield* getPage(ctx, startUrl);
		const statuses = new Map<string, number>([
			[stripHash(startUrl), start.status],
			[stripHash(start.url), start.status],
		]);
		const linkedFrom = new Map<string, string>();
		const pages: Page[] = start.isHtml && start.status < 400 ? [start] : [];
		const queue: string[] = [];
		const enqueue = (page: Page) => {
			for (const link of page.links) {
				if (!linkedFrom.has(link)) linkedFrom.set(link, page.url);
				if (!statuses.has(link) && !queue.includes(link)) queue.push(link);
			}
		};
		enqueue(start);

		while (pages.length < max && queue.length > 0) {
			const batch: string[] = [];
			while (queue.length > 0 && batch.length < max - pages.length) {
				const next = queue.shift() as string;
				if (statuses.has(next)) continue;
				if (ASSET_EXT.test(new URL(next).pathname)) continue;
				batch.push(next);
			}
			if (batch.length === 0) break;
			const fetched = yield* Effect.forEach(
				batch,
				(url) =>
					getPage(ctx, url).pipe(
						Effect.map((page) => ({ url, page })),
						Effect.orElseSucceed(() => ({ url, page: undefined })),
					),
				{ concurrency: CRAWL_CONCURRENCY },
			);
			for (const { url, page } of fetched) {
				statuses.set(url, page?.status ?? 0);
				if (!page) continue;
				statuses.set(stripHash(page.url), page.status);
				if (
					page.isHtml &&
					page.status < 400 &&
					sameOrigin(page.url, start.url)
				) {
					pages.push(page);
					enqueue(page);
				}
			}
		}

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

/** Subresources referenced by a page, resolved to absolute URLs. */
export const resourcesOf = (page: Page): ReadonlyArray<Resource> => {
	const base = baseUrlOf(page);
	const out: Resource[] = [];
	const add = (kind: ResourceKind, el: El, value: string | undefined) => {
		const url = resolveUrl(base, value);
		if (url) out.push({ kind, url, el });
	};
	for (const el of findAll(page.doc, "*")) {
		switch (el.name) {
			case "script":
				add("script", el, el.attrs.src);
				break;
			case "link": {
				const rel = (el.attrs.rel ?? "").toLowerCase().split(/\s+/);
				if (rel.includes("stylesheet")) add("stylesheet", el, el.attrs.href);
				else if (rel.includes("preload") || rel.includes("modulepreload"))
					add(
						el.attrs.as === "font"
							? "font"
							: el.attrs.as === "style"
								? "stylesheet"
								: el.attrs.as === "script" || rel.includes("modulepreload")
									? "script"
									: el.attrs.as === "image"
										? "image"
										: "other",
						el,
						el.attrs.href,
					);
				else if (rel.includes("icon")) add("image", el, el.attrs.href);
				break;
			}
			case "img":
				add("image", el, el.attrs.src);
				break;
			case "iframe":
			case "frame":
				add("iframe", el, el.attrs.src);
				break;
			case "video":
			case "audio":
			case "source":
			case "track":
				add("media", el, el.attrs.src);
				break;
			case "object":
				add("object", el, el.attrs.data);
				break;
			case "embed":
				add("object", el, el.attrs.src);
				break;
			case "form":
				if (el.attrs.action) add("form", el, el.attrs.action);
				break;
		}
	}
	return out;
};
