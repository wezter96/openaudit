import {
	AuditorError,
	defineAuditor,
	type FindingInput,
	requireUrl,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";
import type { Browser, BrowserContext } from "playwright-core";

import { crawl, sameOrigin } from "./page";
import { formatBytes, truncate } from "./util";

const INSTALL_HINT =
	"Install a browser with `bunx playwright install chromium` (or install Google Chrome).";
const NAV_TIMEOUT = 30_000;
/** Time after `load` for late LCP candidates, layout shifts and long tasks. */
const SETTLE_MS = 1_500;
const MAX_NODES_PER_RULE = 10;

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
	url: string,
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

/** Web Vitals thresholds (web.dev "good" / "poor"). Exported for tests. */
export const vitalsFindings = (url: string, m: Metrics): FindingInput[] => {
	const findings: FindingInput[] = [];
	const metric = (
		id: string,
		name: string,
		value: number,
		good: number,
		poor: number,
		shown: string,
		remediation: string,
		reference: string,
	) => {
		if (value <= good) return;
		findings.push({
			ruleId: `webapp.browser/${id}`,
			title: `${name} ${value > poor ? "is poor" : "needs improvement"} (${shown})`,
			severity: value > poor ? "high" : "medium",
			category: "performance",
			message: `${name} measured ${shown} in a lab run (good ≤ ${id === "cls" ? good : `${good} ms`}, poor > ${id === "cls" ? poor : `${poor} ms`}). Lab values vary with machine and network; confirm with field data (CrUX).`,
			location: { url },
			evidence: `${id}=${shown}`,
			remediation,
			references: [reference],
			confidence: "medium",
		});
	};
	metric(
		"lcp",
		"Largest Contentful Paint",
		m.lcp,
		2500,
		4000,
		`${Math.round(m.lcp)} ms`,
		"Speed up the server response, preload the LCP image or font, avoid render-blocking resources and lazy-loading the LCP element.",
		"https://web.dev/articles/lcp",
	);
	metric(
		"cls",
		"Cumulative Layout Shift",
		m.cls,
		0.1,
		0.25,
		m.cls.toFixed(3),
		"Reserve space for images, embeds and ads (width/height or aspect-ratio) and avoid inserting content above existing content.",
		"https://web.dev/articles/cls",
	);
	metric(
		"tbt",
		"Total Blocking Time",
		m.tbt,
		200,
		600,
		`${Math.round(m.tbt)} ms`,
		"Break up long tasks, defer non-critical JavaScript and reduce third-party script cost.",
		"https://web.dev/articles/tbt",
	);
	if (m.transfer > 3 * 1024 * 1024)
		findings.push({
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
		});
	if (m.heap > 50 * 1024 * 1024)
		findings.push({
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
		});
	return findings;
};

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

const auditPage = (
	context: BrowserContext,
	url: string,
	axe: string | undefined,
) =>
	Effect.tryPromise({
		try: async () => {
			const page = await context.newPage();
			await page.addInitScript(VITALS_SCRIPT);
			const findings: FindingInput[] = [];
			const consoleErrors: string[] = [];
			const pageErrors: string[] = [];
			const failed = new Map<string, number>();
			const insecure = new Set<string>();
			const https = url.startsWith("https:");
			page.on("console", (msg) => {
				// Failed loads and mixed content are reported from network events instead.
				if (
					msg.type() === "error" &&
					!/^(Failed to load resource|Mixed Content)/.test(msg.text())
				)
					consoleErrors.push(msg.text());
			});
			page.on("pageerror", (err) => pageErrors.push(err.stack ?? err.message));
			page.on("request", (req) => {
				if (https && req.url().startsWith("http:")) insecure.add(req.url());
			});
			page.on("response", (res) => {
				if (res.status() >= 400) failed.set(res.url(), res.status());
			});
			page.on("requestfailed", (req) => {
				const reason = req.failure()?.errorText ?? "";
				if (!/ERR_ABORTED|NS_BINDING_ABORTED/.test(reason))
					failed.set(req.url(), 0);
			});
			try {
				const response = await page.goto(url, {
					waitUntil: "load",
					timeout: NAV_TIMEOUT,
				});
				await page.waitForTimeout(SETTLE_MS);
				const finalUrl = page.url();

				if (response && response.status() >= 400) failed.delete(response.url());
				const metrics = (await page.evaluate(METRICS_EXPR)) as Metrics;
				findings.push(...vitalsFindings(finalUrl, metrics));

				if (axe) {
					await page.addScriptTag({ content: axe });
					const violations = (await page.evaluate(AXE_EXPR)) as AxeViolation[];
					findings.push(...axeFindings(finalUrl, violations));
				}

				for (const text of consoleErrors.slice(0, 10))
					findings.push({
						ruleId: "webapp.browser/console-error",
						title: "Console error",
						severity: "low",
						category: "reliability",
						message: `The page logged an error to the console: ${truncate(text, 200)}`,
						location: { url: finalUrl },
						evidence: truncate(text, 200),
						remediation:
							"Fix the underlying error; console errors often indicate broken features or failed requests.",
						references: [
							"https://developer.chrome.com/docs/lighthouse/best-practices/errors-in-console",
						],
					});
				for (const stack of pageErrors.slice(0, 10))
					findings.push({
						ruleId: "webapp.browser/uncaught-exception",
						title: "Uncaught JavaScript exception",
						severity: "medium",
						category: "reliability",
						message: `An uncaught exception was thrown while loading the page: ${truncate(stack.split("\n")[0] ?? stack, 200)}`,
						location: { url: finalUrl },
						evidence: truncate(stack.replace(/\s+/g, " "), 200),
						remediation:
							"Handle the error or fix its cause; uncaught exceptions can leave the UI half-initialised.",
						references: [
							"https://developer.mozilla.org/en-US/docs/Web/API/Window/error_event",
						],
					});
				for (const [reqUrl, status] of [...failed].slice(0, 20))
					findings.push({
						ruleId: "webapp.browser/failed-request",
						title: status
							? `Request failed with HTTP ${status}`
							: "Request failed",
						severity:
							sameOrigin(reqUrl, finalUrl) && (status === 0 || status >= 500)
								? "medium"
								: "low",
						category: "reliability",
						message: `${reqUrl} ${status ? `returned HTTP ${status}` : "failed at the network level"} while loading the page.`,
						location: { url: finalUrl },
						evidence: `${status || "network error"} ${truncate(reqUrl, 160)}`,
						remediation:
							"Fix or remove the reference to the missing or failing resource.",
						references: ["https://developer.chrome.com/docs/devtools/network"],
					});
				for (const reqUrl of [...insecure].slice(0, 20))
					findings.push({
						ruleId: "webapp.browser/mixed-content",
						title: "Mixed content request",
						severity: "medium",
						category: "security",
						message: `This HTTPS page requested ${reqUrl} over plain HTTP at runtime.`,
						location: { url: finalUrl },
						evidence: truncate(reqUrl, 160),
						remediation: "Load every resource over HTTPS.",
						references: [
							"https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
						],
						tags: ["cwe-319"],
					});
				return findings;
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

/** Loads pages in headless Chromium: axe-core, console errors, failed requests, mixed content and Web Vitals. */
export const browser = defineAuditor({
	id: "webapp.browser",
	title: "Browser audit (Playwright + axe-core)",
	description:
		"Renders each crawled page in headless Chromium, runs axe-core, records console errors, uncaught exceptions, failed and mixed-content requests, and measures LCP, CLS, TBT, page weight and JS heap.",
	categories: ["accessibility", "performance", "reliability", "security"],
	targets: ["webapp"],
	engine: "builtin",
	run: (ctx) =>
		Effect.scoped(
			Effect.gen(function* () {
				const start = yield* requireUrl(ctx);
				// Reuse the static crawl for page discovery; fall back to just the start URL.
				const urls = yield* crawl(ctx).pipe(
					Effect.map((c) =>
						c.pages.length > 0 ? c.pages.map((p) => p.url) : [start],
					),
					Effect.orElseSucceed(() => [start]),
				);
				const b: Browser = yield* Effect.acquireRelease(launch, (b) =>
					Effect.promise(() => b.close().catch(() => {})),
				);
				const context = yield* Effect.tryPromise({
					try: () =>
						b.newContext({ ignoreHTTPSErrors: false, serviceWorkers: "block" }),
					catch: (cause) =>
						new AuditorError({
							message: "Failed to open a browser context",
							cause,
						}),
				});
				const headers = ctx.options.headers ?? {};
				if (Object.keys(headers).length > 0)
					// Only send user-supplied headers (e.g. auth cookies) to the target origin.
					yield* Effect.promise(() =>
						context.route("**/*", (route) =>
							sameOrigin(route.request().url(), start)
								? route.continue({
										headers: { ...route.request().headers(), ...headers },
									})
								: route.continue(),
						),
					);
				const axe = yield* axeSource;
				if (!axe)
					yield* ctx.log(
						"webapp.browser: axe-core not installed; skipping accessibility checks",
					);
				const max = Math.max(1, ctx.options.maxPages ?? 10);
				const results = yield* Effect.forEach(
					urls.slice(0, max),
					(url) => auditPage(context, url, axe),
					{ concurrency: 1 },
				);
				return results.flat();
			}),
		),
});
