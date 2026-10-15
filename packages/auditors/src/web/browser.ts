import {
	type AuditContext,
	AuditorError,
	defineAuditor,
	type FindingInput,
	requireUrl,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";
import type {
	Browser,
	BrowserContext,
	ConsoleMessage,
	Page,
	Request,
} from "playwright-core";

import { collectConsent, consentFindings } from "./browser-consent";
import { crawl, isLoopback, sameOrigin, type Url } from "./page";
import { formatBytes, truncate } from "./util";

export {
	type ConsentCookie,
	type ConsentSnapshot,
	consentFindings,
} from "./browser-consent";

const INSTALL_HINT =
	"Install a browser with `bunx playwright install chromium` (or install Google Chrome).";
const NAV_TIMEOUT = 30_000;
/** Time after `load` for late LCP candidates, layout shifts and long tasks. */
const SETTLE_MS = 1_500;
const MAX_NODES_PER_RULE = 10;
/** Requests remembered per page for the consent check. */
const MAX_REQUESTS = 3_000;

/** Collected in the page before any of its scripts run. */
const VITALS_SCRIPT = `(() => {
	const v = (window.__openaudit = { lcp: 0, cls: 0, tbt: 0, longTasks: 0 });
	const observe = (type, cb) => { try { new PerformanceObserver((l) => l.getEntries().forEach(cb)).observe({ type, buffered: true }); } catch {} };
	observe("largest-contentful-paint", (e) => { v.lcp = e.startTime; });
	observe("layout-shift", (e) => { if (!e.hadRecentInput) v.cls += e.value; });
	observe("longtask", (e) => { v.longTasks++; v.tbt += Math.max(0, e.duration - 50); });
})();`;

const METRICS_EXPR = `(() => {
	const v = window.__openaudit || { lcp: 0, cls: 0, tbt: 0, longTasks: 0 };
	const nav = performance.getEntriesByType("navigation")[0];
	const resources = performance.getEntriesByType("resource");
	const transfer = resources.reduce((n, r) => n + (r.transferSize || 0), nav ? nav.transferSize || 0 : 0);
	const heap = performance.memory ? performance.memory.usedJSHeapSize : 0;
	return { lcp: v.lcp, cls: v.cls, tbt: v.tbt, longTasks: v.longTasks, transfer, requests: resources.length + 1, heap };
})()`;

const AXE_EXPR = `axe.run(document, { resultTypes: ["violations"] }).then((r) => r.violations.map((v) => ({
	id: v.id, impact: v.impact, help: v.help, description: v.description, helpUrl: v.helpUrl, tags: v.tags,
	nodes: v.nodes.map((n) => ({ target: n.target, html: n.html, summary: n.failureSummary })),
})))`;

interface AxeViolation {
	readonly id: string;
	readonly impact: "critical" | "serious" | "moderate" | "minor" | null;
	readonly help: string;
	readonly description: string;
	readonly helpUrl: string;
	readonly tags: ReadonlyArray<string>;
	readonly nodes: ReadonlyArray<{
		target: ReadonlyArray<unknown>;
		html: string;
		summary?: string;
	}>;
}

interface Metrics {
	readonly lcp: number;
	readonly cls: number;
	readonly tbt: number;
	readonly longTasks: number;
	readonly transfer: number;
	readonly requests: number;
	readonly heap: number;
}

const IMPACT: Record<string, Severity> = {
	critical: "high",
	serious: "medium",
	moderate: "low",
	minor: "info",
};

/** `wcag2aa`, `wcag111` → `wcag-1.1.1`; other axe tags pass through. */
const wcagTags = (tags: ReadonlyArray<string>): string[] =>
	tags.map((t) => {
		const m = t.match(/^wcag(\d)(\d)(\d+)$/);
		return m ? `wcag-${m[1]}.${m[2]}.${m[3]}` : t;
	});

/** Maps axe-core violations to findings. Exported for tests. */
export const axeFindings = (
	url: Url,
	violations: ReadonlyArray<AxeViolation>,
): FindingInput[] =>
	violations.flatMap((v) =>
		v.nodes.slice(0, MAX_NODES_PER_RULE).map(
			(node): FindingInput => ({
				ruleId: `webapp.browser/axe-${v.id}`,
				title: v.help,
				severity: IMPACT[v.impact ?? "moderate"] ?? "low",
				category: "accessibility",
				message: `${v.description}${node.summary ? ` ${node.summary.replace(/\s+/g, " ")}` : ""}`,
				location: { url, selector: node.target.map(String).join(" ") },
				evidence: truncate(node.html.replace(/\s+/g, " "), 200),
				remediation: `${v.help}. See ${v.helpUrl}`,
				references: [v.helpUrl],
				tags: wcagTags(v.tags),
			}),
		),
	);

interface Vital {
	readonly id: "lcp" | "cls" | "tbt";
	readonly name: string;
	readonly good: number;
	readonly poor: number;
	readonly shown: (value: number) => string;
	readonly remediation: string;
	readonly reference: string;
}

const ms = (value: number) => `${Math.round(value)} ms`;

const VITALS: ReadonlyArray<Vital> = [
	{
		id: "lcp",
		name: "Largest Contentful Paint",
		good: 2500,
		poor: 4000,
		shown: ms,
		remediation:
			"Speed up the server response, preload the LCP image or font, avoid render-blocking resources and lazy-loading the LCP element.",
		reference: "https://web.dev/articles/lcp",
	},
	{
		id: "cls",
		name: "Cumulative Layout Shift",
		good: 0.1,
		poor: 0.25,
		shown: (value) => value.toFixed(3),
		remediation:
			"Reserve space for images, embeds and ads (width/height or aspect-ratio) and avoid inserting content above existing content.",
		reference: "https://web.dev/articles/cls",
	},
	{
		id: "tbt",
		name: "Total Blocking Time",
		good: 200,
		poor: 600,
		shown: ms,
		remediation:
			"Break up long tasks, defer non-critical JavaScript and reduce third-party script cost.",
		reference: "https://web.dev/articles/tbt",
	},
];

const vitalFindings = (url: Url, v: Vital, value: number): FindingInput[] => {
	if (value <= v.good) return [];
	const shown = v.shown(value);
	const poor = value > v.poor;
	return [
		{
			ruleId: `webapp.browser/${v.id}`,
			title: `${v.name} ${poor ? "is poor" : "needs improvement"} (${shown})`,
			severity: poor ? "high" : "medium",
			category: "performance",
			message: `${v.name} measured ${shown} in a lab run (good ≤ ${v.id === "cls" ? v.good : `${v.good} ms`}, poor > ${v.id === "cls" ? v.poor : `${v.poor} ms`}). Lab values vary with machine and network; confirm with field data (CrUX).`,
			location: { url },
			evidence: `${v.id}=${shown}`,
			remediation: v.remediation,
			references: [v.reference],
			confidence: "medium",
		},
	];
};

const pageWeightFindings = (url: Url, m: Metrics): FindingInput[] =>
	m.transfer > 3 * 1024 * 1024
		? [
				{
					ruleId: "webapp.browser/page-weight",
					title: `Heavy page (${formatBytes(m.transfer)} transferred)`,
					severity: m.transfer > 6 * 1024 * 1024 ? "high" : "medium",
					category: "performance",
					message: `Loading the page transferred ${formatBytes(m.transfer)} over ${m.requests} requests. Large payloads are slow and costly on mobile data.`,
					location: { url },
					evidence: `transfer=${formatBytes(m.transfer)}; requests=${m.requests}`,
					remediation:
						"Compress and resize images, code-split JavaScript and remove unused third-party resources.",
					references: [
						"https://developer.chrome.com/docs/lighthouse/performance/total-byte-weight",
					],
				},
			]
		: [];

const heapFindings = (url: Url, m: Metrics): FindingInput[] =>
	m.heap > 50 * 1024 * 1024
		? [
				{
					ruleId: "webapp.browser/js-heap",
					title: `Large JavaScript heap (${formatBytes(m.heap)})`,
					severity: m.heap > 150 * 1024 * 1024 ? "medium" : "low",
					category: "performance",
					message: `The page uses ${formatBytes(m.heap)} of JS heap right after load, which strains low-memory devices.`,
					location: { url },
					evidence: `usedJSHeapSize=${formatBytes(m.heap)}`,
					remediation:
						"Profile memory in DevTools; avoid loading large datasets and libraries up front.",
					references: [
						"https://developer.chrome.com/docs/devtools/memory-problems",
					],
					confidence: "medium",
				},
			]
		: [];

/** Web Vitals thresholds (web.dev "good" / "poor"). Exported for tests. */
export const vitalsFindings = (url: Url, m: Metrics): FindingInput[] => [
	...VITALS.flatMap((v) => vitalFindings(url, v, m[v.id])),
	...pageWeightFindings(url, m),
	...heapFindings(url, m),
];

const launch = Effect.gen(function* () {
	const pw = yield* Effect.tryPromise(() => import("playwright-core")).pipe(
		Effect.catch(() =>
			skip(
				`playwright-core is not installed. Install it with \`bun add playwright-core\`. ${INSTALL_HINT}`,
			),
		),
	);
	const chromium =
		pw.chromium ?? (pw as unknown as { default: typeof pw }).default.chromium;
	const attempt = (options: Parameters<typeof chromium.launch>[0]) =>
		Effect.tryPromise(() => chromium.launch({ headless: true, ...options }));
	return yield* attempt({}).pipe(
		Effect.catch(() => attempt({ channel: "chrome" })),
		Effect.catch((e) =>
			skip(
				`Could not launch Chromium or Chrome (${truncate(String(e.cause ?? e).split("\n")[0] ?? "", 160)}). ${INSTALL_HINT}`,
			),
		),
	);
});

const axeSource = Effect.tryPromise(async () => {
	const mod = (await import("axe-core")) as unknown as {
		source?: string;
		default?: { source?: string };
	};
	return mod.source ?? mod.default?.source;
}).pipe(Effect.orElseSucceed(() => undefined));

/** What a page did while loading, gathered from its events. */
interface PageEvents {
	readonly consoleErrors: string[];
	readonly pageErrors: string[];
	readonly failed: Map<string, number>;
	readonly insecure: Set<string>;
	readonly requested: string[];
}

/** Failed loads and mixed content are reported from network events instead. */
const REPORTED_ELSEWHERE = /^(Failed to load resource|Mixed Content)/;

const isReportedConsoleError = (msg: ConsoleMessage): boolean =>
	msg.type() === "error" && !REPORTED_ELSEWHERE.test(msg.text());

const isAborted = (req: Request): boolean =>
	/ERR_ABORTED|NS_BINDING_ABORTED/.test(req.failure()?.errorText ?? "");

const recordRequest = (events: PageEvents, https: boolean, url: Url) => {
	if (events.requested.length < MAX_REQUESTS) events.requested.push(url);
	if (https && url.startsWith("http:")) events.insecure.add(url);
};

const listen = (page: Page, https: boolean): PageEvents => {
	const events: PageEvents = {
		consoleErrors: [],
		pageErrors: [],
		failed: new Map(),
		insecure: new Set(),
		requested: [],
	};
	page.on("console", (msg) => {
		if (isReportedConsoleError(msg)) events.consoleErrors.push(msg.text());
	});
	page.on("pageerror", (err) =>
		events.pageErrors.push(err.stack ?? err.message),
	);
	page.on("request", (req) => recordRequest(events, https, req.url()));
	page.on("response", (res) => {
		if (res.status() >= 400) events.failed.set(res.url(), res.status());
	});
	page.on("requestfailed", (req) => {
		if (!isAborted(req)) events.failed.set(req.url(), 0);
	});
	return events;
};

const consoleErrorFinding = (url: Url, text: string): FindingInput => ({
	ruleId: "webapp.browser/console-error",
	title: "Console error",
	severity: "low",
	category: "reliability",
	message: `The page logged an error to the console: ${truncate(text, 200)}`,
	location: { url },
	evidence: truncate(text, 200),
	remediation:
		"Fix the underlying error; console errors often indicate broken features or failed requests.",
	references: [
		"https://developer.chrome.com/docs/lighthouse/best-practices/errors-in-console",
	],
});

const uncaughtExceptionFinding = (url: Url, stack: string): FindingInput => ({
	ruleId: "webapp.browser/uncaught-exception",
	title: "Uncaught JavaScript exception",
	severity: "medium",
	category: "reliability",
	message: `An uncaught exception was thrown while loading the page: ${truncate(stack.split("\n")[0] ?? stack, 200)}`,
	location: { url },
	evidence: truncate(stack.replace(/\s+/g, " "), 200),
	remediation:
		"Handle the error or fix its cause; uncaught exceptions can leave the UI half-initialised.",
	references: [
		"https://developer.mozilla.org/en-US/docs/Web/API/Window/error_event",
	],
});

/** A network error or 5xx, as opposed to a 4xx. */
const isHardFailure = (status: number): boolean =>
	status === 0 || status >= 500;

const isServerFault = (reqUrl: Url, status: number, pageUrl: Url): boolean =>
	sameOrigin(reqUrl, pageUrl) && isHardFailure(status);

const failedRequestFinding = (
	url: Url,
	[reqUrl, status]: readonly [Url, number],
): FindingInput => ({
	ruleId: "webapp.browser/failed-request",
	title: status ? `Request failed with HTTP ${status}` : "Request failed",
	severity: isServerFault(reqUrl, status, url) ? "medium" : "low",
	category: "reliability",
	message: `${reqUrl} ${status ? `returned HTTP ${status}` : "failed at the network level"} while loading the page.`,
	location: { url },
	evidence: `${status || "network error"} ${truncate(reqUrl, 160)}`,
	remediation:
		"Fix or remove the reference to the missing or failing resource.",
	references: ["https://developer.chrome.com/docs/devtools/network"],
});

const mixedContentFinding = (url: Url, reqUrl: Url): FindingInput => ({
	ruleId: "webapp.browser/mixed-content",
	title: "Mixed content request",
	severity: "medium",
	category: "security",
	message: `This HTTPS page requested ${reqUrl} over plain HTTP at runtime.`,
	location: { url },
	evidence: truncate(reqUrl, 160),
	remediation: "Load every resource over HTTPS.",
	references: [
		"https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
	],
	tags: ["cwe-319"],
});

const eventFindings = (events: PageEvents, url: Url): FindingInput[] => [
	...events.consoleErrors
		.slice(0, 10)
		.map((text) => consoleErrorFinding(url, text)),
	...events.pageErrors
		.slice(0, 10)
		.map((stack) => uncaughtExceptionFinding(url, stack)),
	...[...events.failed]
		.slice(0, 20)
		.map((entry) => failedRequestFinding(url, entry)),
	...[...events.insecure]
		.slice(0, 20)
		.map((reqUrl) => mixedContentFinding(url, reqUrl)),
];

const runAxe = async (
	page: Page,
	axe: string,
	url: Url,
): Promise<FindingInput[]> => {
	// Evaluated through the DevTools protocol rather than an inline
	// <script>, so a strict CSP on the audited page can't block it.
	await page.evaluate(axe);
	const violations = (await page.evaluate(AXE_EXPR)) as AxeViolation[];
	return axeFindings(url, violations);
};

interface PageAudit {
	readonly context: BrowserContext;
	readonly url: Url;
	readonly axe: string | undefined;
	/** Only the first page of a fresh profile shows what happens before consent. */
	readonly checkConsent: boolean;
}

const loadAndInspect = async (
	audit: PageAudit,
	page: Page,
	events: PageEvents,
): Promise<FindingInput[]> => {
	const findings: FindingInput[] = [];
	const response = await page.goto(audit.url, {
		waitUntil: "load",
		timeout: NAV_TIMEOUT,
	});
	await page.waitForTimeout(SETTLE_MS);
	const finalUrl = page.url();
	// Passive snapshot of the initial load, before axe or anything else
	// touches the page; nothing is clicked.
	if (audit.checkConsent)
		findings.push(
			...consentFindings(
				await collectConsent(audit.context, page, finalUrl, [
					...events.requested,
				]),
			),
		);

	if (response && response.status() >= 400)
		events.failed.delete(response.url());
	const metrics = (await page.evaluate(METRICS_EXPR)) as Metrics;
	findings.push(...vitalsFindings(finalUrl, metrics));

	if (audit.axe) findings.push(...(await runAxe(page, audit.axe, finalUrl)));

	findings.push(...eventFindings(events, finalUrl));
	return findings;
};

const auditPage = (
	context: BrowserContext,
	url: Url,
	axe: string | undefined,
	/** Only the first page of a fresh profile shows what happens before consent. */
	checkConsent: boolean,
) =>
	Effect.tryPromise({
		try: async () => {
			const page = await context.newPage();
			await page.addInitScript(VITALS_SCRIPT);
			const events = listen(page, url.startsWith("https:"));
			try {
				return await loadAndInspect(
					{ context, url, axe, checkConsent },
					page,
					events,
				);
			} finally {
				await page.close().catch(() => {});
			}
		},
		catch: (cause) =>
			new AuditorError({
				message: `Browser audit of ${url} failed: ${cause instanceof Error ? cause.message.split("\n")[0] : String(cause)}`,
				cause,
			}),
	});

/** Crawled pages to render, or just the start URL. */
const pageUrls = (ctx: AuditContext, start: Url) =>
	crawl(ctx).pipe(
		Effect.map((c) =>
			c.pages.length > 0 ? c.pages.map((p) => p.url) : [start],
		),
		Effect.orElseSucceed(() => [start]),
	);

const openContext = (b: Browser) =>
	Effect.tryPromise({
		try: () =>
			b.newContext({
				ignoreHTTPSErrors: false,
				serviceWorkers: "block",
				// Responses we fulfil ourselves (header injection below) lose their
				// address space, so Chrome's Local Network Access would block a local
				// dev server's own loopback hops. Grant it only for loopback targets;
				// remote pages must never reach the auditor's local network.
			}),
		catch: (cause) =>
			new AuditorError({
				message: "Failed to open a browser context",
				cause,
			}),
	});

// Responses we fulfil ourselves (header injection below) lose their
// address space, so Chrome's Local Network Access would block a local
// dev server's own loopback hops. Grant it only to a loopback target's
// own origin; other origins must never reach the auditor's network.
const grantLoopback = (context: BrowserContext, start: Url) =>
	isLoopback(start)
		? Effect.promise(() =>
				context
					.grantPermissions(["local-network-access"], {
						origin: new URL(start).origin,
					})
					.catch(() => {}),
			)
		: Effect.void;

// Only send user-supplied headers (e.g. auth cookies) to the target origin.
// `route.continue({ headers })` would also apply them to redirects, so a
// same-origin 3xx to another host would leak them. Instead fetch without
// following redirects and hand the 3xx back to the browser, whose next hop
// is routed (and origin-checked) again.
const routeHeaders = (
	context: BrowserContext,
	start: Url,
	headers: Readonly<Record<string, string>>,
) =>
	Object.keys(headers).length > 0
		? Effect.promise(() =>
				context.route("**/*", async (route) => {
					const request = route.request();
					if (!sameOrigin(request.url(), start)) return route.continue();
					try {
						const response = await route.fetch({
							headers: { ...request.headers(), ...headers },
							maxRedirects: 0,
						});
						await route.fulfill({ response });
					} catch {
						await route.abort().catch(() => {});
					}
				}),
			)
		: Effect.void;

/** Loads pages in headless Chromium: axe-core, console errors, failed requests, mixed content, Web Vitals and pre-consent tracking. */
export const browser = defineAuditor({
	id: "webapp.browser",
	title: "Browser audit (Playwright + axe-core)",
	description:
		"Renders each crawled page in headless Chromium, runs axe-core, records console errors, uncaught exceptions, failed and mixed-content requests, measures LCP, CLS, TBT, page weight and JS heap, and passively checks what loads before consent (tracker requests, tracking cookies, third-party hosts, consent platforms).",
	categories: [
		"accessibility",
		"performance",
		"privacy",
		"reliability",
		"security",
	],
	targets: ["webapp"],
	engine: "builtin",
	run: (ctx) =>
		Effect.scoped(
			Effect.gen(function* () {
				const start = yield* requireUrl(ctx);
				// Reuse the static crawl for page discovery; fall back to just the start URL.
				const urls = yield* pageUrls(ctx, start);
				const b: Browser = yield* Effect.acquireRelease(launch, (b) =>
					Effect.promise(() => b.close().catch(() => {})),
				);
				const context = yield* openContext(b);
				yield* grantLoopback(context, start);
				yield* routeHeaders(context, start, ctx.options.headers ?? {});
				const axe = yield* axeSource;
				if (!axe)
					yield* ctx.log(
						"webapp.browser: axe-core not installed; skipping accessibility checks",
					);
				const max = Math.max(1, ctx.options.maxPages ?? 10);
				const results = yield* Effect.forEach(
					urls.slice(0, max).map((url, i) => [url, i === 0] as const),
					([url, first]) => auditPage(context, url, axe, first),
					{ concurrency: 1 },
				);
				return results.flat();
			}),
		),
});
