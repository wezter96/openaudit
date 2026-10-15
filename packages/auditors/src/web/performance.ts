import {
	type AuditContext,
	defineAuditor,
	type FindingInput,
	type HttpResponse,
} from "@openaudit/core";
import { Effect } from "effect";

import { closest, type El, findAll, selectorOf, snippetOf } from "./dom";
import {
	crawl,
	fetchCached,
	originOf,
	type Page,
	type Resource,
	resourcesOf,
	sameOrigin,
} from "./page";
import { formatBytes, maxAgeOf } from "./util";

const MAX_SAMPLED = 20;
/** Images after this many in document order are assumed to be below the fold. */
const ABOVE_FOLD_IMAGES = 3;
const WEEK = 7 * 86_400;
const ACCEPT_ENCODING = { "accept-encoding": "br, gzip, deflate" };

interface Sampled {
	readonly resource: Resource;
	readonly res: HttpResponse;
	/** Transfer size: content-length when known, otherwise decoded bytes. */
	readonly size: number;
}

const sizeOf = (res: HttpResponse) => {
	const len = Number(res.headers.get("content-length"));
	return Number.isFinite(len) && len > 0 ? len : res.bytes;
};

const isCompressed = (res: HttpResponse) =>
	/\b(br|gzip|deflate|zstd)\b/i.test(res.headers.get("content-encoding") ?? "");

const sample = (ctx: AuditContext, resources: ReadonlyArray<Resource>) =>
	Effect.forEach(
		resources,
		(resource) =>
			// GET (not HEAD) so content-encoding reflects what browsers receive; bodies are capped.
			fetchCached(ctx, resource.url, {
				headers: ACCEPT_ENCODING,
				timeoutMs: 10_000,
				maxBytes: 64 * 1024,
			}).pipe(
				Effect.map((res): Sampled | undefined =>
					res.status < 400 ? { resource, res, size: sizeOf(res) } : undefined,
				),
				Effect.orElseSucceed(() => undefined),
			),
		{ concurrency: 4 },
	).pipe(Effect.map((all) => all.filter((s): s is Sampled => s !== undefined)));

type DocCheck = (page: Page) => FindingInput[];

const slowTtfb: DocCheck = (page) => {
	const res = page.response;
	if (res.ttfbMs <= 800) return [];
	return [
		{
			ruleId: "web.performance/slow-ttfb",
			title: `Slow server response (${Math.round(res.ttfbMs)} ms TTFB)`,
			severity: res.ttfbMs > 1800 ? "high" : "medium",
			category: "performance",
			message: `The document's time to first byte was ${Math.round(res.ttfbMs)} ms (good ≤ 800 ms, poor > 1800 ms). Everything else on the page waits for it. Measured from this machine, so network distance contributes.`,
			location: { url: page.url },
			evidence: `ttfb=${Math.round(res.ttfbMs)}ms`,
			remediation:
				"Cache rendered HTML (CDN/edge or server-side), speed up backend queries, and serve from a region close to users.",
			references: ["https://web.dev/articles/ttfb"],
			confidence: "medium",
		},
	];
};

const largeHtml: DocCheck = (page) => {
	const res = page.response;
	if (res.bytes <= 200 * 1024) return [];
	return [
		{
			ruleId: "web.performance/large-html",
			title: `Large HTML document (${formatBytes(res.bytes)})`,
			severity: res.bytes > 1024 * 1024 ? "medium" : "low",
			category: "performance",
			message: `The HTML is ${formatBytes(res.bytes)} uncompressed, often from inlined data, large hydration payloads or huge DOM trees.`,
			location: { url: page.url },
			remediation:
				"Trim inlined JSON/state, paginate long lists and move large inline assets to cacheable files.",
			references: [
				"https://developer.chrome.com/docs/lighthouse/performance/dom-size",
			],
		},
	];
};

const uncompressedDocument: DocCheck = (page) => {
	const res = page.response;
	if (res.bytes <= 1024 || isCompressed(res)) return [];
	return [
		{
			ruleId: "web.performance/uncompressed-document",
			title: "HTML is not compressed",
			severity: "medium",
			category: "performance",
			message: `The ${formatBytes(res.bytes)} document was served without gzip/Brotli although the client accepts it; compression typically shrinks HTML by 70–80%.`,
			location: { url: page.url },
			evidence: `content-encoding: ${res.headers.get("content-encoding") ?? "(none)"}`,
			remediation:
				"Enable Brotli or gzip for text/html, text/css, application/javascript, application/json and image/svg+xml.",
			references: [
				"https://developer.chrome.com/docs/lighthouse/performance/uses-text-compression",
			],
		},
	];
};

const hasValidators = (res: HttpResponse): boolean =>
	["cache-control", "etag", "last-modified"].some((h) => !!res.headers.get(h));

const noValidators: DocCheck = (page) => {
	if (hasValidators(page.response)) return [];
	return [
		{
			ruleId: "web.performance/document-no-validators",
			title: "Document has no caching headers",
			severity: "low",
			category: "performance",
			message:
				"The HTML has no Cache-Control, ETag or Last-Modified, so browsers and CDNs cannot revalidate it cheaply and must refetch it in full.",
			location: { url: page.url },
			remediation:
				"Send `Cache-Control: no-cache` with an ETag (or a short max-age/stale-while-revalidate) for HTML.",
			references: ["https://web.dev/articles/http-cache"],
		},
	];
};

/** A classic script that blocks parsing: no async/defer, not a module, and a JavaScript type. */
const isBlockingScript = (s: El): boolean => {
	const type = (s.attrs.type ?? "").toLowerCase();
	if ("async" in s.attrs || "defer" in s.attrs) return false;
	if (type === "module") return false;
	return !type || /javascript|ecmascript/.test(type);
};

const renderBlockingScripts: DocCheck = (page) =>
	findAll(page.doc, "script", (el) => !!el.attrs.src && !!closest(el, "head"))
		.filter(isBlockingScript)
		.map((s) => ({
			ruleId: "web.performance/render-blocking-script",
			title: "Render-blocking script in <head>",
			severity: "medium",
			category: "performance",
			message: `${s.attrs.src} is loaded synchronously in <head>; the browser stops parsing and rendering until it downloads and executes.`,
			location: { url: page.url, selector: selectorOf(s) },
			evidence: snippetOf(s),
			remediation:
				"Add `defer` (or `async` for independent scripts), or load it as type=module.",
			references: [
				"https://developer.chrome.com/docs/lighthouse/performance/render-blocking-resources",
			],
		}));

const CSS_SIZED =
	/(^|;)\s*(aspect-ratio|width\s*:[^;]+;[\s\S]*height|height\s*:[^;]+;[\s\S]*width)/i;

const isSized = (img: El): boolean =>
	!!(img.attrs.width && img.attrs.height) ||
	CSS_SIZED.test(img.attrs.style ?? "");

const imagesOf = (page: Page): El[] =>
	findAll(page.doc, "img", (i) => !!(i.attrs.src || i.attrs.srcset));

const unsizedImages: DocCheck = (page) =>
	imagesOf(page)
		.filter((i) => !isSized(i))
		.slice(0, 15)
		.map((img) => ({
			ruleId: "web.performance/image-no-dimensions",
			title: "Image without width and height",
			severity: "low",
			category: "performance",
			message:
				"Without width/height attributes the browser cannot reserve space before the image loads, causing layout shifts (CLS).",
			location: { url: page.url, selector: selectorOf(img) },
			evidence: snippetOf(img),
			remediation:
				"Set width and height attributes matching the intrinsic aspect ratio (CSS can still make it responsive).",
			references: [
				"https://web.dev/articles/optimize-cls#images-without-dimensions",
			],
			confidence: "medium",
		}));

const isEager = (img: El): boolean =>
	(img.attrs.loading ?? "").toLowerCase() !== "lazy" &&
	!closest(img, "noscript");

const eagerImages: DocCheck = (page) => {
	const images = imagesOf(page);
	const eager = images.slice(ABOVE_FOLD_IMAGES).filter(isEager);
	if (eager.length < 3) return [];
	return [
		{
			ruleId: "web.performance/images-not-lazy",
			title: `${eager.length} images likely below the fold load eagerly`,
			severity: "low",
			category: "performance",
			message: `${eager.length} of ${images.length} images appear after the first ${ABOVE_FOLD_IMAGES} in document order but are not lazy-loaded, competing with critical resources.`,
			location: {
				url: page.url,
				selector: eager[0] ? selectorOf(eager[0]) : undefined,
			},
			evidence: eager
				.slice(0, 3)
				.map((i) => snippetOf(i, 80))
				.join(" "),
			remediation:
				'Add loading="lazy" to images below the fold (never to the LCP image).',
			references: ["https://web.dev/articles/browser-level-image-lazy-loading"],
			confidence: "low",
		},
	];
};

const DOC_CHECKS: ReadonlyArray<DocCheck> = [
	slowTtfb,
	largeHtml,
	uncompressedDocument,
	noValidators,
	renderBlockingScripts,
	unsizedImages,
	eagerImages,
];

const docFindings = (page: Page): FindingInput[] =>
	DOC_CHECKS.flatMap((check) => check(page));

interface ResourceInput {
	readonly page: Page;
	readonly sampled: ReadonlyArray<Sampled>;
	readonly resources: ReadonlyArray<Resource>;
}

type ResourceCheck = (input: ResourceInput) => FindingInput[];

const CACHEABLE_KINDS = ["script", "stylesheet", "image", "font"];

const isPoorlyCached = ({ resource, res }: Sampled): boolean => {
	if (!CACHEABLE_KINDS.includes(resource.kind)) return false;
	const cc = res.headers.get("cache-control") ?? "";
	if (/immutable/i.test(cc)) return false;
	return /no-store|no-cache/i.test(cc) || (maxAgeOf(cc) ?? 0) < WEEK;
};

const shortStaticCache: ResourceCheck = ({ page, sampled }) => {
	const poorlyCached = sampled.filter(isPoorlyCached);
	if (poorlyCached.length === 0) return [];
	return [
		{
			ruleId: "web.performance/static-cache-short",
			title: `${poorlyCached.length} static asset(s) have short cache lifetimes`,
			severity: "low",
			category: "performance",
			message: `${poorlyCached.length} of ${sampled.length} sampled same-origin assets are cached for less than a week (or not at all), so repeat visits redownload them.`,
			location: { url: page.url },
			evidence: poorlyCached
				.slice(0, 5)
				.map(
					({ resource, res }) =>
						`${new URL(resource.url).pathname} (${res.headers.get("cache-control") ?? "no cache-control"})`,
				)
				.join(", "),
			remediation:
				"Serve fingerprinted assets with `Cache-Control: public, max-age=31536000, immutable`.",
			references: [
				"https://developer.chrome.com/docs/lighthouse/performance/uses-long-cache-ttl",
			],
		},
	];
};

const isTextAsset = ({ resource, res }: Sampled): boolean =>
	resource.kind === "script" ||
	resource.kind === "stylesheet" ||
	/svg|json/.test(res.headers.get("content-type") ?? "");

const isUncompressedText = (s: Sampled): boolean =>
	isTextAsset(s) && s.res.bytes > 1024 && !isCompressed(s.res);

const uncompressedAssets: ResourceCheck = ({ page, sampled }) => {
	const uncompressed = sampled.filter(isUncompressedText);
	if (uncompressed.length === 0) return [];
	return [
		{
			ruleId: "web.performance/uncompressed-assets",
			title: `${uncompressed.length} text asset(s) served uncompressed`,
			severity: "medium",
			category: "performance",
			message:
				"JavaScript/CSS files are served without gzip or Brotli, multiplying their transfer size.",
			location: { url: page.url },
			evidence: uncompressed
				.slice(0, 5)
				.map(
					({ resource, res }) =>
						`${new URL(resource.url).pathname} (${formatBytes(res.bytes)})`,
				)
				.join(", "),
			remediation: "Enable Brotli/gzip for text assets at the server or CDN.",
			references: [
				"https://developer.chrome.com/docs/lighthouse/performance/uses-text-compression",
			],
		},
	];
};

const sampledBytes = (
	sampled: ReadonlyArray<Sampled>,
	kind: Resource["kind"],
): number =>
	sampled
		.filter((s) => s.resource.kind === kind)
		.reduce((n, s) => n + s.size, 0);

const heavyJavascript: ResourceCheck = ({ page, sampled, resources }) => {
	const scripts = resources.filter((r) => r.kind === "script");
	const jsBytes = sampledBytes(sampled, "script");
	if (scripts.length <= 20 && jsBytes <= 500 * 1024) return [];
	return [
		{
			ruleId: "web.performance/heavy-javascript",
			title: "Heavy JavaScript payload",
			severity: jsBytes > 1024 * 1024 ? "high" : "medium",
			category: "performance",
			message: `The page loads ${scripts.length} external scripts; sampled same-origin JS totals ${formatBytes(jsBytes)} transferred. Large bundles delay interactivity (INP/TBT) especially on mobile CPUs.`,
			location: { url: page.url },
			evidence: `scripts=${scripts.length}; sampledJs=${formatBytes(jsBytes)}`,
			remediation:
				"Code-split by route, remove unused dependencies, and defer non-critical third-party scripts.",
			references: [
				"https://web.dev/articles/reduce-javascript-payloads-with-code-splitting",
			],
			confidence: "medium",
		},
	];
};

const heavyCss: ResourceCheck = ({ page, sampled, resources }) => {
	const styles = resources.filter((r) => r.kind === "stylesheet");
	const cssBytes = sampledBytes(sampled, "stylesheet");
	if (styles.length <= 10 && cssBytes <= 150 * 1024) return [];
	return [
		{
			ruleId: "web.performance/heavy-css",
			title: "Heavy CSS payload",
			severity: "low",
			category: "performance",
			message: `The page loads ${styles.length} stylesheets; sampled same-origin CSS totals ${formatBytes(cssBytes)}. All of it blocks first render.`,
			location: { url: page.url },
			evidence: `stylesheets=${styles.length}; sampledCss=${formatBytes(cssBytes)}`,
			remediation:
				"Inline critical CSS, purge unused rules and combine small stylesheets.",
			references: ["https://web.dev/articles/extract-critical-css"],
			confidence: "medium",
		},
	];
};

const isLargeLegacyImage = ({ resource, size }: Sampled): boolean =>
	resource.kind === "image" &&
	size >= 100 * 1024 &&
	/\.(jpe?g|png|gif|bmp)(\?|$)/i.test(resource.url);

const legacyImages: ResourceCheck = ({ page, sampled }) =>
	sampled.filter(isLargeLegacyImage).map(({ resource, size }) => ({
		ruleId: "web.performance/legacy-image-format",
		title: `Large ${resource.url.match(/\.(\w+)(\?|$)/)?.[1]?.toUpperCase() ?? "legacy"} image (${formatBytes(size)})`,
		severity: size > 500 * 1024 ? "medium" : "low",
		category: "performance",
		message: `${resource.url} is ${formatBytes(size)} in a legacy format; WebP/AVIF are typically 25–50% smaller at equal quality.`,
		location: { url: page.url, selector: selectorOf(resource.el) },
		evidence: snippetOf(resource.el),
		remediation:
			"Serve AVIF/WebP (e.g. via <picture> or an image CDN) and size images to their display dimensions.",
		references: [
			"https://developer.chrome.com/docs/lighthouse/performance/uses-webp-images",
		],
	}));

const preconnectedOrigins = (page: Page) =>
	new Set(
		findAll(page.doc, "link", (l) =>
			/\b(preconnect|dns-prefetch)\b/i.test(l.attrs.rel ?? ""),
		)
			.map((l) =>
				l.attrs.href
					? originOf(new URL(l.attrs.href, page.url).toString())
					: undefined,
			)
			.filter(Boolean),
	);

const CRITICAL_KINDS = ["script", "stylesheet", "font"];

const isThirdPartyCritical = (r: Resource, page: Page): boolean =>
	CRITICAL_KINDS.includes(r.kind) && !sameOrigin(r.url, page.url);

const missingPreconnect: ResourceCheck = ({ page, resources }) => {
	const preconnected = preconnectedOrigins(page);
	const thirdParty = new Set(
		resources
			.filter((r) => isThirdPartyCritical(r, page))
			.map((r) => originOf(r.url))
			.filter((o): o is string => !!o && !preconnected.has(o)),
	);
	if (thirdParty.size === 0) return [];
	return [
		{
			ruleId: "web.performance/missing-preconnect",
			title: "Third-party origins without preconnect",
			severity: "info",
			category: "performance",
			message: `Critical resources come from ${[...thirdParty].join(", ")} without <link rel="preconnect">, adding DNS/TCP/TLS round-trips to the critical path.`,
			location: { url: page.url },
			evidence: [...thirdParty].slice(0, 5).join(", "),
			remediation:
				'Add <link rel="preconnect" href="https://…" crossorigin> for the most important third-party origins (or self-host them).',
			references: ["https://web.dev/articles/uses-rel-preconnect"],
			confidence: "medium",
		},
	];
};

const RESOURCE_CHECKS: ReadonlyArray<ResourceCheck> = [
	shortStaticCache,
	uncompressedAssets,
	heavyJavascript,
	heavyCss,
	legacyImages,
	missingPreconnect,
];

const resourceFindings = (
	page: Page,
	sampled: ReadonlyArray<Sampled>,
	resources: ReadonlyArray<Resource>,
): FindingInput[] =>
	RESOURCE_CHECKS.flatMap((check) => check({ page, sampled, resources }));

/** Server timing, compression, caching and front-end weight of the start page. */
export const performanceAuditor = defineAuditor({
	id: "web.performance",
	title: "Performance",
	description:
		"Measures TTFB and HTML size, checks compression and caching of the document and sampled assets, render-blocking scripts, JS/CSS weight, image sizing, lazy-loading, formats and preconnects.",
	categories: ["performance"],
	targets: ["url"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const { start, pages } = yield* crawl(ctx);
			// Re-request the start page with explicit Accept-Encoding so compression is measured fairly.
			const doc = yield* fetchCached(ctx, start.url, {
				headers: ACCEPT_ENCODING,
			}).pipe(
				Effect.map((response): Page => ({ ...start, response })),
				Effect.orElseSucceed(() => start),
			);
			const findings = [...docFindings(doc)];
			for (const page of pages.slice(1))
				findings.push(
					...docFindings(page).filter(
						(f) => f.ruleId !== "web.performance/uncompressed-document",
					),
				);
			if (!start.isHtml) return findings;
			const resources = resourcesOf(start).filter(
				(r) => r.kind !== "form" && r.kind !== "iframe",
			);
			const seen = new Set<string>();
			const candidates = resources.filter((r) => {
				if (!sameOrigin(r.url, start.url) || seen.has(r.url)) return false;
				seen.add(r.url);
				return true;
			});
			const sampled = yield* sample(ctx, candidates.slice(0, MAX_SAMPLED));
			findings.push(...resourceFindings(start, sampled, resources));
			return findings;
		}),
});
