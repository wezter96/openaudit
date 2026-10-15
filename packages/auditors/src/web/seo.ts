import {
	type AuditContext,
	defineAuditor,
	type FindingInput,
	type HttpResponse,
	type Severity,
} from "@openaudit/core";
import { Effect, type Option } from "effect";

import {
	attr,
	closest,
	type El,
	findAll,
	findFirst,
	rawText,
	selectorOf,
	snippetOf,
	textOf,
} from "./dom";
import {
	baseUrlOf,
	type Crawl,
	crawl,
	fetchCached,
	type Page,
	resolveUrl,
} from "./page";
import { truncate } from "./util";

const GOOGLE = "https://developers.google.com/search/docs";
const MAX_LINK_CHECKS = 30;
const HREFLANG = /^(x-default|[a-z]{2,3}(-[a-z]{4})?(-([a-z]{2}|\d{3}))?)$/i;

const metaContent = (page: Page, key: string): string | undefined => {
	const m = findFirst(
		page.doc,
		"meta",
		(el) =>
			(el.attrs.name ?? "").toLowerCase() === key ||
			(el.attrs.property ?? "").toLowerCase() === key,
	);
	return m ? (attr(m, "content") ?? "").trim() : undefined;
};

type PageFinding = Omit<
	FindingInput,
	"ruleId" | "severity" | "category" | "location"
> & {
	location?: FindingInput["location"];
};

/** Rule name within web.seo, e.g. `title-missing`. */
type SeoRule = string;

/** A web.seo finding located on the page unless `f` says otherwise. */
const pageFinding = (
	page: Page,
	rule: SeoRule,
	severity: Severity,
	f: PageFinding,
): FindingInput => ({
	ruleId: `web.seo/${rule}`,
	severity,
	category: "seo",
	location: { url: page.url },
	...f,
});

const titleFindings = (page: Page): FindingInput[] => {
	const titleEl = findFirst(page.doc, "title", (t) => !closest(t, "svg"));
	const title = titleEl ? textOf(titleEl) : "";
	if (!title)
		return [
			pageFinding(page, "title-missing", "medium", {
				title: "Page has no <title>",
				message:
					"Search engines use the title as the result headline; without one they invent a title from page content.",
				remediation:
					"Add a unique, descriptive <title> of roughly 30–60 characters.",
				references: [`${GOOGLE}/appearance/title-link`],
			}),
		];
	if (title.length < 10 || title.length > 60)
		return [
			pageFinding(page, "title-length", "low", {
				title: `Title is ${title.length < 10 ? "very short" : "long"} (${title.length} chars)`,
				message: `The title "${truncate(title, 80)}" is ${title.length} characters; titles around 30–60 characters display fully in search results and describe the page well.`,
				evidence: truncate(title, 120),
				remediation:
					"Rewrite the title to be descriptive and between ~30 and 60 characters.",
				references: [`${GOOGLE}/appearance/title-link`],
				confidence: "medium",
			}),
		];
	return [];
};

const descriptionFindings = (page: Page): FindingInput[] => {
	const description = metaContent(page, "description");
	if (!description)
		return [
			pageFinding(page, "meta-description-missing", "low", {
				title: "Meta description is missing",
				message:
					"Without a meta description, search engines pick an arbitrary snippet from the page for the result summary.",
				remediation:
					'Add <meta name="description" content="…"> summarising the page in ~50–160 characters.',
				references: [`${GOOGLE}/appearance/snippet`],
			}),
		];
	if (description.length < 50 || description.length > 160)
		return [
			pageFinding(page, "meta-description-length", "info", {
				title: `Meta description is ${description.length < 50 ? "short" : "long"} (${description.length} chars)`,
				message:
					"Descriptions of roughly 50–160 characters are shown in full and give searchers enough context.",
				evidence: truncate(description, 120),
				remediation: "Adjust the description to ~50–160 characters.",
				references: [`${GOOGLE}/appearance/snippet`],
				confidence: "medium",
			}),
		];
	return [];
};

const isCanonicalLink = (l: El) =>
	(l.attrs.rel ?? "").toLowerCase().split(/\s+/).includes("canonical");

const canonicalInvalidFinding = (page: Page, canonical: El | undefined) =>
	pageFinding(page, "canonical-invalid", "medium", {
		title: "Canonical URL is invalid",
		message:
			"The rel=canonical link has an empty or invalid href, so it is ignored.",
		evidence: canonical ? snippetOf(canonical) : undefined,
		remediation:
			"Point rel=canonical at the absolute preferred URL of this page.",
		references: [`${GOOGLE}/crawling-indexing/consolidate-duplicate-urls`],
	});

const canonicalFindings = (page: Page): FindingInput[] => {
	const canonicals = findAll(page.doc, "link", isCanonicalLink);
	if (canonicals.length === 0)
		return [
			pageFinding(page, "canonical-missing", "low", {
				title: "No canonical URL",
				message:
					"The page declares no rel=canonical, so duplicate URLs (tracking parameters, trailing slashes, http/https) may split ranking signals.",
				remediation:
					'<link rel="canonical" href="https://example.com/page"> with the preferred absolute URL.',
				references: [`${GOOGLE}/crawling-indexing/consolidate-duplicate-urls`],
			}),
		];
	if (canonicals.length > 1)
		return [
			pageFinding(page, "canonical-multiple", "medium", {
				title: "Multiple canonical URLs",
				message: `The page declares ${canonicals.length} canonical links; search engines ignore conflicting canonicals.`,
				evidence: canonicals.map((c) => c.attrs.href ?? "").join(", "),
				remediation: "Keep exactly one rel=canonical link.",
				references: [`${GOOGLE}/crawling-indexing/consolidate-duplicate-urls`],
			}),
		];
	const href = canonicals[0]?.attrs.href;
	if (!href || !resolveUrl(baseUrlOf(page), href))
		return [canonicalInvalidFinding(page, canonicals[0])];
	return [];
};

const headingFindings = (page: Page): FindingInput[] => {
	const h1s = findAll(page.doc, "h1");
	if (h1s.length === 0)
		return [
			pageFinding(page, "h1-missing", "low", {
				title: "Page has no <h1>",
				message:
					"A single, descriptive <h1> tells users and search engines what the page is about.",
				remediation: "Add one <h1> that describes the main topic of the page.",
				references: ["https://web.dev/learn/html/headings-and-sections"],
			}),
		];
	if (h1s.length > 1)
		return [
			pageFinding(page, "h1-multiple", "info", {
				title: `Page has ${h1s.length} <h1> elements`,
				message:
					"Multiple <h1> elements dilute the main topic signal; prefer one <h1> with <h2>–<h6> for sections.",
				evidence: h1s.map((h) => truncate(textOf(h), 40)).join(" | "),
				remediation: "Keep one <h1> and demote the others.",
				confidence: "low",
			}),
		];
	return [];
};

const langFindings = (page: Page): FindingInput[] => {
	const html = findFirst(page.doc, "html");
	if (html?.attrs.lang?.trim()) return [];
	return [
		pageFinding(page, "lang-missing", "low", {
			title: "Document language is not declared",
			message:
				"The <html> element has no lang attribute, which search engines use (along with content) to serve the page to the right audience.",
			remediation: 'Set <html lang="en"> (or the appropriate BCP 47 code).',
			references: [
				`${GOOGLE}/specialty/international/managing-multi-regional-sites`,
			],
		}),
	];
};

const viewportFindings = (page: Page): FindingInput[] => {
	const viewport = findFirst(
		page.doc,
		"meta",
		(m) => (m.attrs.name ?? "").toLowerCase() === "viewport",
	);
	if (viewport) return [];
	return [
		pageFinding(page, "viewport-missing", "medium", {
			title: "No viewport meta tag",
			message:
				"Without a viewport meta tag the page renders as a zoomed-out desktop layout on phones, hurting mobile-first indexing.",
			remediation:
				'<meta name="viewport" content="width=device-width, initial-scale=1">',
			references: [
				"https://web.dev/articles/responsive-web-design-basics#viewport",
			],
		}),
	];
};

const openGraphFindings = (page: Page): FindingInput[] => {
	const missingOg = ["og:title", "og:description", "og:image"].filter(
		(k) => !metaContent(page, k),
	);
	if (missingOg.length === 0) return [];
	return [
		pageFinding(page, "open-graph-missing", "low", {
			title: "Open Graph tags are incomplete",
			message: `Missing ${missingOg.join(", ")}; links shared on social platforms and chat apps will render without a proper preview.`,
			remediation:
				"Add og:title, og:description, og:image (and og:url) meta tags.",
			references: ["https://ogp.me/"],
		}),
	];
};

const twitterCardFindings = (page: Page): FindingInput[] => {
	if (metaContent(page, "twitter:card")) return [];
	return [
		pageFinding(page, "twitter-card-missing", "info", {
			title: "No Twitter/X card",
			message:
				"No twitter:card meta tag; X falls back to Open Graph but cannot choose the large-image layout.",
			remediation: '<meta name="twitter:card" content="summary_large_image">',
			references: [
				"https://developer.x.com/en/docs/x-for-websites/cards/overview/markup",
			],
		}),
	];
};

const noindexFindings = (page: Page): FindingInput[] => {
	const robotsMeta = [
		metaContent(page, "robots"),
		metaContent(page, "googlebot"),
		page.response.headers.get("x-robots-tag"),
	]
		.filter(Boolean)
		.join(", ");
	if (!/noindex|none/i.test(robotsMeta)) return [];
	return [
		pageFinding(page, "noindex", "medium", {
			title: "Page is excluded from search results",
			message:
				"A robots directive (meta tag or X-Robots-Tag header) contains noindex, so search engines will drop this page. Intended for staging, a bug in production.",
			evidence: robotsMeta,
			remediation: "Remove noindex from pages that should be found in search.",
			references: [`${GOOGLE}/crawling-indexing/block-indexing`],
			confidence: "medium",
		}),
	];
};

/* ---------------------------- structured data ---------------------------- */

const isJsonLdScript = (s: El) =>
	(s.attrs.type ?? "").toLowerCase() === "application/ld+json";

const isObject = (i: unknown): i is object =>
	Boolean(i) && typeof i === "object";

/** A JSON-LD object item without @context. */
const lacksContext = (i: unknown) => isObject(i) && !("@context" in i);

/** Findings for one JSON-LD script: unparsable JSON or items without @context. */
const jsonLdFindings = (page: Page, s: El): FindingInput[] => {
	const body = rawText(s).trim();
	const location = { url: page.url, selector: selectorOf(s) };
	let parsed: unknown;
	try {
		parsed = JSON.parse(body);
	} catch (e) {
		return [
			pageFinding(page, "structured-data-invalid", "medium", {
				title: "JSON-LD structured data does not parse",
				message: `A JSON-LD block is not valid JSON (${e instanceof Error ? e.message : String(e)}), so search engines ignore it.`,
				location,
				evidence: truncate(body.replace(/\s+/g, " "), 120),
				remediation:
					"Fix the JSON syntax and validate with Google's Rich Results Test.",
				references: [
					"https://search.google.com/test/rich-results",
					`${GOOGLE}/appearance/structured-data/intro-structured-data`,
				],
			}),
		];
	}
	const items = Array.isArray(parsed) ? parsed : [parsed];
	if (!items.some(lacksContext)) return [];
	return [
		pageFinding(page, "structured-data-context-missing", "low", {
			title: "JSON-LD lacks @context",
			message:
				"A JSON-LD item has no @context (e.g. https://schema.org), so its types are not understood.",
			location,
			evidence: truncate(body.replace(/\s+/g, " "), 120),
			remediation: 'Add "@context": "https://schema.org".',
			references: [
				`${GOOGLE}/appearance/structured-data/intro-structured-data`,
			],
		}),
	];
};

const structuredDataFindings = (page: Page): FindingInput[] =>
	findAll(page.doc, "script", isJsonLdScript).flatMap((s) =>
		jsonLdFindings(page, s),
	);

/* -------------------------------- hreflang ------------------------------- */

const isHreflangAlternate = (l: El) =>
	"hreflang" in l.attrs &&
	(l.attrs.rel ?? "").toLowerCase().includes("alternate");

const hreflangInvalidFindings = (
	page: Page,
	alternates: ReadonlyArray<El>,
): FindingInput[] => {
	const bad = alternates.filter((l) => !HREFLANG.test(l.attrs.hreflang ?? ""));
	if (bad.length === 0) return [];
	return [
		pageFinding(page, "hreflang-invalid", "low", {
			title: "Invalid hreflang code",
			message: `hreflang values ${bad.map((b) => `"${b.attrs.hreflang}"`).join(", ")} are not valid language(-region) codes, so they are ignored.`,
			evidence: bad.map((b) => snippetOf(b)).join(" "),
			remediation:
				"Use ISO 639-1 language codes with optional ISO 3166-1 region, e.g. en, en-GB, or x-default.",
			references: [`${GOOGLE}/specialty/international/localized-versions`],
		}),
	];
};

const hreflangRelativeFindings = (
	page: Page,
	alternates: ReadonlyArray<El>,
): FindingInput[] => {
	const relative = alternates.filter(
		(l) => !/^https?:\/\//i.test(l.attrs.href ?? ""),
	);
	if (relative.length === 0) return [];
	return [
		pageFinding(page, "hreflang-relative", "low", {
			title: "hreflang links are not absolute",
			message: "Google requires fully-qualified URLs in hreflang annotations.",
			evidence: relative.map((b) => snippetOf(b)).join(" "),
			remediation: "Use absolute URLs including scheme and host.",
			references: [`${GOOGLE}/specialty/international/localized-versions`],
		}),
	];
};

const hreflangSelfFindings = (
	page: Page,
	alternates: ReadonlyArray<El>,
): FindingInput[] => {
	const base = baseUrlOf(page);
	const self = page.url.replace(/[#?].*$/, "").replace(/\/$/, "");
	const listsSelf = alternates.some((l) => {
		const abs = resolveUrl(base, l.attrs.href);
		return abs !== undefined && abs.replace(/\/$/, "") === self;
	});
	if (listsSelf) return [];
	return [
		pageFinding(page, "hreflang-no-self-reference", "low", {
			title: "hreflang set lacks a self-reference",
			message:
				"Each page in an hreflang cluster should list itself; otherwise annotations may be ignored.",
			remediation:
				"Add an alternate link with this page's own URL and language.",
			references: [`${GOOGLE}/specialty/international/localized-versions`],
			confidence: "medium",
		}),
	];
};

const hreflangFindings = (page: Page): FindingInput[] => {
	const alternates = findAll(page.doc, "link", isHreflangAlternate);
	if (alternates.length === 0) return [];
	return [
		...hreflangInvalidFindings(page, alternates),
		...hreflangRelativeFindings(page, alternates),
		...hreflangSelfFindings(page, alternates),
	];
};

/** On-page checks, in report order. */
const PAGE_CHECKS: ReadonlyArray<(page: Page) => FindingInput[]> = [
	titleFindings,
	descriptionFindings,
	canonicalFindings,
	headingFindings,
	langFindings,
	viewportFindings,
	openGraphFindings,
	twitterCardFindings,
	noindexFindings,
	structuredDataFindings,
	hreflangFindings,
];

/** Findings for one page's on-page SEO. */
const pageFindings = (page: Page): FindingInput[] =>
	PAGE_CHECKS.flatMap((check) => check(page));

const duplicates = (
	pages: ReadonlyArray<Page>,
	keyOf: (p: Page) => string | undefined,
) => {
	const groups = new Map<string, string[]>();
	for (const p of pages) {
		const v = keyOf(p);
		if (!v) continue;
		groups.set(v, [...(groups.get(v) ?? []), p.url]);
	}
	return [...groups.entries()].filter(([, urls]) => urls.length > 1);
};

/* ------------------------------ robots.txt ------------------------------ */

const looksLikeHtml = (res: HttpResponse) =>
	/text\/html/i.test(res.headers.get("content-type") ?? "") ||
	/^\s*</.test(res.body);

/** The robots.txt body when the site serves a real (non-HTML) one. */
const robotsBody = (
	robots: Option.Option<HttpResponse>,
): string | undefined => {
	if (robots._tag === "None") return undefined;
	const res = robots.value;
	return res.status === 200 && !looksLikeHtml(res) ? res.body : undefined;
};

const parseRobotsLine = (raw: string) => {
	const m = raw
		.replace(/#.*/, "")
		.trim()
		.match(/^([\w-]+)\s*:\s*(.*)$/);
	if (!m) return undefined;
	return { key: (m[1] ?? "").toLowerCase(), value: (m[2] ?? "").trim() };
};

const isDisallowAll = (key: string, value: string) =>
	key === "disallow" && value === "/";

/** Disallow: / inside the `User-agent: *` group blocks the whole site. */
const blocksAllCrawlers = (robotsText: string): boolean => {
	let inStar = false;
	let lastWasAgent = false;
	let blocksAll = false;
	for (const raw of robotsText.split(/\r?\n/)) {
		const line = parseRobotsLine(raw);
		if (!line) continue;
		const { key, value } = line;
		if (key === "user-agent") {
			inStar = lastWasAgent ? inStar || value === "*" : value === "*";
			lastWasAgent = true;
			continue;
		}
		lastWasAgent = false;
		if (inStar && isDisallowAll(key, value)) blocksAll = true;
	}
	return blocksAll;
};

const robotsFindings = (
	robotsUrl: string,
	robots: Option.Option<HttpResponse>,
	robotsText: string | undefined,
): FindingInput[] => {
	if (robotsText === undefined)
		return [
			{
				ruleId: "web.seo/robots-txt-missing",
				title: "robots.txt is missing",
				severity: "low",
				category: "seo",
				message:
					"No valid /robots.txt was found. Crawlers will assume everything is allowed and cannot discover your sitemap from it.",
				location: { url: robotsUrl },
				evidence:
					robots._tag === "Some"
						? `status ${robots.value.status}`
						: "request failed",
				remediation:
					"Serve a plain-text /robots.txt with crawl rules and a `Sitemap:` line.",
				references: [`${GOOGLE}/crawling-indexing/robots/intro`],
			},
		];
	if (!blocksAllCrawlers(robotsText)) return [];
	return [
		{
			ruleId: "web.seo/robots-txt-blocks-all",
			title: "robots.txt blocks all crawlers",
			severity: "high",
			category: "seo",
			message:
				"robots.txt contains `Disallow: /` for `User-agent: *`, telling every search engine not to crawl the site.",
			location: { url: robotsUrl },
			evidence: "User-agent: * / Disallow: /",
			remediation:
				"Remove the blanket Disallow unless this is a non-public environment.",
			references: [`${GOOGLE}/crawling-indexing/robots/create-robots-txt`],
		},
	];
};

/* -------------------------------- sitemap -------------------------------- */

/** A 200 response that is an XML sitemap (or a gzipped one we cannot inspect). */
const isSitemapServed = (
	sitemap: Option.Option<HttpResponse>,
	sitemapUrl: string,
): boolean => {
	if (sitemap._tag === "None" || sitemap.value.status !== 200) return false;
	return (
		sitemapUrl.endsWith(".gz") ||
		/<(urlset|sitemapindex)[\s>]/i.test(sitemap.value.body)
	);
};

const sitemapMissingFinding = (
	sitemapUrl: string,
	declared: boolean,
	sitemap: Option.Option<HttpResponse>,
): FindingInput => ({
	ruleId: "web.seo/sitemap-missing",
	title: declared ? "Sitemap is not valid" : "No XML sitemap",
	severity: "low",
	category: "seo",
	message: declared
		? `The sitemap declared in robots.txt (${sitemapUrl}) did not return a <urlset> or <sitemapindex> document.`
		: "No sitemap was declared in robots.txt and /sitemap.xml does not exist, making it harder for crawlers to discover all pages.",
	location: { url: sitemapUrl },
	evidence:
		sitemap._tag === "Some"
			? `status ${sitemap.value.status}`
			: "request failed",
	remediation:
		"Publish an XML sitemap and reference it with a `Sitemap:` line in robots.txt.",
	references: [`${GOOGLE}/crawling-indexing/sitemaps/overview`],
});

const sitemapFindings = (
	ctx: AuditContext,
	origin: string,
	robotsText: string | undefined,
) =>
	Effect.gen(function* () {
		const declared = [
			...(robotsText ?? "").matchAll(/^\s*sitemap\s*:\s*(\S+)/gim),
		]
			.map((m) => m[1])
			.filter((u): u is string => !!u);
		// Hosted elsewhere (CDN); don't fetch off-origin.
		if (declared.some((u) => !u.startsWith(origin))) return [];
		const sitemapUrl =
			declared.find((u) => u.startsWith(origin)) ?? `${origin}/sitemap.xml`;
		const sitemap = yield* fetchCached(ctx, sitemapUrl, {
			maxBytes: 2 * 1024 * 1024,
		}).pipe(Effect.option);
		if (isSitemapServed(sitemap, sitemapUrl)) return [];
		return [sitemapMissingFinding(sitemapUrl, declared.length > 0, sitemap)];
	});

/* ------------------------------ duplicates ------------------------------- */

const titleOf = (p: Page) => {
	const t = findFirst(p.doc, "title");
	return t ? textOf(t) : undefined;
};

interface DuplicateRule {
	readonly keyOf: (p: Page) => string | undefined;
	readonly ruleId: string;
	readonly title: string;
	readonly message: (value: string, urls: ReadonlyArray<string>) => string;
	readonly remediation: string;
	readonly reference: string;
}

const DUPLICATE_RULES: ReadonlyArray<DuplicateRule> = [
	{
		keyOf: titleOf,
		ruleId: "web.seo/title-duplicate",
		title: "Duplicate page titles",
		message: (title, urls) =>
			`${urls.length} pages share the title "${truncate(title, 80)}", making them hard to tell apart in search results.`,
		remediation: "Give every page a unique title.",
		reference: `${GOOGLE}/appearance/title-link`,
	},
	{
		keyOf: (p) => metaContent(p, "description"),
		ruleId: "web.seo/meta-description-duplicate",
		title: "Duplicate meta descriptions",
		message: (desc, urls) =>
			`${urls.length} pages share the description "${truncate(desc, 80)}".`,
		remediation: "Write a unique description for each page.",
		reference: `${GOOGLE}/appearance/snippet`,
	},
];

const duplicateFindings = (pages: ReadonlyArray<Page>): FindingInput[] =>
	DUPLICATE_RULES.flatMap((rule) =>
		duplicates(pages, rule.keyOf).map(
			([value, urls]): FindingInput => ({
				ruleId: rule.ruleId,
				title: rule.title,
				severity: "low",
				category: "seo",
				message: rule.message(value, urls),
				location: { url: urls[0] },
				evidence: urls.slice(0, 5).join(", "),
				remediation: rule.remediation,
				references: [rule.reference],
			}),
		),
	);

/* ----------------------------- broken links ------------------------------ */

/** HEAD, falling back to GET for servers that reject HEAD; 0 when the request fails. */
const linkStatus = (ctx: AuditContext, u: string) =>
	fetchCached(ctx, u, { method: "HEAD", timeoutMs: 8_000 }).pipe(
		Effect.flatMap((res) =>
			res.status === 405 || res.status === 501
				? fetchCached(ctx, u, { timeoutMs: 8_000, maxBytes: 64 * 1024 })
				: Effect.succeed(res),
		),
		Effect.map((res) => [u, res.status] as const),
		Effect.orElseSucceed(() => [u, 0] as const),
	);

const brokenLinkFinding = (
	u: string,
	status: number,
	from: string,
): FindingInput => ({
	ruleId: "web.seo/broken-link",
	title: `Broken internal link (${status})`,
	severity: "medium",
	category: "seo",
	message: `${from} links to ${u}, which returns HTTP ${status}. Broken links waste crawl budget and frustrate users.`,
	location: { url: from, selector: `a[href="${new URL(u).pathname}"]` },
	evidence: `${u} → ${status}`,
	remediation:
		"Fix or remove the link, or redirect the old URL (301) to its replacement.",
	references: [`${GOOGLE}/crawling-indexing/http-network-errors`],
});

const brokenLinkFindings = (ctx: AuditContext, c: Crawl) =>
	Effect.gen(function* () {
		const statuses = new Map(c.statuses);
		const unchecked = c.unvisited
			.filter((u) => !statuses.has(u))
			.slice(0, MAX_LINK_CHECKS);
		const checked = yield* Effect.forEach(
			unchecked,
			(u) => linkStatus(ctx, u),
			{ concurrency: 3 },
		);
		for (const [u, s] of checked) statuses.set(u, s);
		const findings: FindingInput[] = [];
		for (const [u, status] of statuses) {
			const from = status < 400 ? undefined : c.linkedFrom.get(u);
			if (from) findings.push(brokenLinkFinding(u, status, from));
		}
		return findings;
	});

const siteFindings = (ctx: AuditContext, c: Crawl) =>
	Effect.gen(function* () {
		const origin = new URL(c.start.url).origin;
		const robotsUrl = `${origin}/robots.txt`;
		const robots = yield* fetchCached(ctx, robotsUrl, {
			maxBytes: 512 * 1024,
		}).pipe(Effect.option);
		const robotsText = robotsBody(robots);
		const findings = robotsFindings(robotsUrl, robots, robotsText);
		findings.push(...(yield* sitemapFindings(ctx, origin, robotsText)));
		findings.push(...duplicateFindings(c.pages));
		findings.push(...(yield* brokenLinkFindings(ctx, c)));
		return findings;
	});

const hasJsonLd = (p: Page) => findFirst(p.doc, "script", isJsonLdScript);

const structuredDataMissingFinding = (c: Crawl): FindingInput[] =>
	c.pages.length > 0 && !c.pages.some(hasJsonLd)
		? [
				{
					ruleId: "web.seo/structured-data-missing",
					title: "No structured data",
					severity: "info",
					category: "seo",
					message:
						"None of the crawled pages include JSON-LD structured data, which enables rich results (breadcrumbs, products, articles, FAQs…).",
					location: { url: c.start.url },
					remediation:
						"Add schema.org JSON-LD describing your organisation and key content types.",
					references: [`${GOOGLE}/appearance/structured-data/search-gallery`],
				},
			]
		: [];

/** On-page and site-level SEO checks over a small same-origin crawl. */
export const seo = defineAuditor({
	id: "web.seo",
	title: "SEO",
	description:
		"Checks titles, descriptions, canonicals, headings, viewport, social cards, robots directives, robots.txt, sitemap, JSON-LD, hreflang and broken internal links.",
	categories: ["seo"],
	targets: ["url"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const c = yield* crawl(ctx);
			const findings = c.pages.flatMap(pageFindings);
			findings.push(...structuredDataMissingFinding(c));
			findings.push(...(yield* siteFindings(ctx, c)));
			return findings;
		}),
});
