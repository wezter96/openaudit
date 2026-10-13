import {
	AuditorError,
	defineAuditor,
	type FindingInput,
	requireUrl,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";
import type { Browser, BrowserContext, Page } from "playwright-core";

import {
	CONSENT_EXEMPT_KINDS,
	CONSENT_PLATFORMS,
	GENERIC_BANNER_SELECTORS,
	hostMatches,
	isTrackingCookie,
	isTrackingStorageKey,
	registrableDomain,
	type Tracker,
	trackerForUrl,
} from "../privacy-data";
import { crawl, isLoopback, sameOrigin } from "./page";
import { formatBytes, truncate } from "./util";

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

/**
 * Detects consent-management platforms (globals, known banner elements) and
 * whether a banner is visible. Read-only: nothing is clicked or changed.
 */
const BANNER_EXPR = `(() => {
	const platforms = ${JSON.stringify(CONSENT_PLATFORMS)};
	const generic = ${JSON.stringify(GENERIC_BANNER_SELECTORS)};
	const box = (el) => {
		const r = el.getBoundingClientRect();
		const s = getComputedStyle(el);
		return r.width > 0 && r.height > 0 && s.display !== "none" && s.visibility !== "hidden" && s.opacity !== "0";
	};
	const visible = (el) => box(el) || (el.shadowRoot ? [...el.shadowRoot.querySelectorAll("*")].some(box) : false);
	const query = (sel) => { try { return [...document.querySelectorAll(sel)]; } catch { return []; } };
	const cmps = [];
	let shown = false;
	for (const p of platforms) {
		let present = p.globals.some((g) => typeof window[g] !== "undefined");
		for (const sel of p.selectors) {
			const els = query(sel);
			if (els.length) present = true;
			if (els.some(visible)) shown = true;
		}
		if (present) cmps.push(p.name);
	}
	if (generic.some((sel) => query(sel).some(visible))) {
		shown = true;
		cmps.push("unidentified cookie banner");
	}
	let storage = [];
	try { storage = Object.keys(localStorage); } catch {}
	const names = document.cookie.split(";").map((c) => c.split("=")[0].trim()).filter(Boolean);
	return { cmps, shown, storage, names };
})()`;

export interface ConsentCookie {
	readonly name: string;
	readonly domain: string;
	readonly httpOnly: boolean;
	readonly secure: boolean;
	readonly sameSite?: string;
	/** Unix seconds; -1 for session cookies. */
	readonly expires: number;
	readonly viaScript: boolean;
}

/** What the page did on its own, before any interaction. Values are never kept. */
export interface ConsentSnapshot {
	readonly pageUrl: string;
	readonly requests: ReadonlyArray<string>;
	readonly cookies: ReadonlyArray<ConsentCookie>;
	readonly storageKeys: ReadonlyArray<string>;
	/** Consent platforms detected via globals or banner elements. */
	readonly cmps: ReadonlyArray<string>;
	readonly bannerVisible: boolean;
}

const list = (items: ReadonlyArray<string>, max = 8) =>
	items.length > max
		? `${items.slice(0, max).join(", ")} and ${items.length - max} more`
		: items.join(", ");

const cookieDescription = (c: ConsentCookie, now: number) => {
	const days =
		c.expires > 0 ? Math.round((c.expires - now / 1000) / 86_400) : undefined;
	return `${truncate(c.name, 40)} (${[
		c.domain,
		days === undefined ? "session" : `${days}d`,
		c.secure ? "Secure" : undefined,
		c.httpOnly ? "HttpOnly" : undefined,
		c.sameSite ? `SameSite=${c.sameSite}` : undefined,
		c.viaScript ? "script" : undefined,
	]
		.filter(Boolean)
		.join("; ")})`;
};

/**
 * Turns what a page did before consent into findings. Pure, so it is
 * testable without a browser. Exported for tests.
 */
export const consentFindings = (
	snap: ConsentSnapshot,
	now = Date.now(),
): FindingInput[] => {
	const findings: FindingInput[] = [];
	const url = snap.pageUrl;
	let targetHost = "";
	try {
		targetHost = new URL(url).hostname;
	} catch {
		return findings;
	}
	const home = registrableDomain(targetHost);

	const hosts = new Map<string, number>();
	const trackers = new Map<string, { tracker: Tracker; hosts: Set<string> }>();
	const cmps = new Set(snap.cmps);
	for (const raw of snap.requests) {
		let host: string;
		try {
			const u = new URL(raw);
			if (u.protocol !== "http:" && u.protocol !== "https:") continue;
			host = u.hostname.toLowerCase();
		} catch {
			continue;
		}
		const thirdParty = registrableDomain(host) !== home;
		if (!thirdParty) continue;
		hosts.set(host, (hosts.get(host) ?? 0) + 1);
		for (const p of CONSENT_PLATFORMS)
			if (p.hosts.some((h) => hostMatches(host, h))) cmps.add(p.name);
		const tracker = trackerForUrl(raw);
		if (tracker && !CONSENT_EXEMPT_KINDS.has(tracker.kind)) {
			const entry = trackers.get(tracker.name) ?? {
				tracker,
				hosts: new Set<string>(),
			};
			entry.hosts.add(host);
			trackers.set(tracker.name, entry);
		}
	}
	const cmpList = [...cmps];
	// A visible banner means the site claims to ask first, so trackers that
	// already fired are a clear violation. Without one, the site may rely on
	// another legal basis or jurisdiction, so confidence stays lower.
	const confidence = snap.bannerVisible ? "high" : "medium";
	const state = snap.bannerVisible
		? `A consent banner is shown (${cmpList.join(", ") || "unidentified"}) yet it did not hold these back.`
		: cmpList.length > 0
			? `A consent platform (${cmpList.join(", ")}) is present but no banner was visible.`
			: "No consent banner or consent platform was detected.";
	const refs = [
		"https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-052020-consent-under-regulation-2016679_en",
	];
	const tags = ["gdpr", "eprivacy"];

	for (const { tracker, hosts: trackerHosts } of trackers.values()) {
		const count = [...trackerHosts].reduce(
			(n, h) => n + (hosts.get(h) ?? 0),
			0,
		);
		findings.push({
			ruleId: "webapp.browser/tracker-before-consent",
			title: `${tracker.name} contacted before consent`,
			severity: "medium",
			category: "privacy",
			message: `During the initial load, with no interaction, the page sent ${count} request${count === 1 ? "" : "s"} to ${tracker.name} (${tracker.kind}) at ${list([...trackerHosts])}. Under the ePrivacy Directive and GDPR such tracking needs the visitor's prior opt-in. ${state}`,
			location: { url, selector: tracker.name },
			evidence: truncate(
				`${list([...trackerHosts])} (${count} request${count === 1 ? "" : "s"})`,
				200,
			),
			remediation:
				"Block the tag until the visitor consents (consent-management platform, Google Consent Mode v2 or a script blocker), and verify with a clean browser profile.",
			references: refs,
			tags: [...tags, tracker.kind.replace(/\s+/g, "-")],
			confidence,
		});
	}

	const trackingCookies = snap.cookies.filter((c) => isTrackingCookie(c.name));
	if (trackingCookies.length > 0)
		findings.push({
			ruleId: "webapp.browser/tracking-cookie-before-consent",
			title: "Tracking cookies set before consent",
			severity: "medium",
			category: "privacy",
			message: `${trackingCookies.length} analytics/advertising cookie${trackingCookies.length === 1 ? " was" : "s were"} stored during the initial load, before any interaction: ${list(trackingCookies.map((c) => truncate(c.name, 40)))}. These are not strictly necessary and need prior consent. ${state}`,
			location: { url },
			evidence: truncate(
				trackingCookies.map((c) => cookieDescription(c, now)).join("; "),
				240,
			),
			remediation:
				"Set tracking cookies only after the visitor opts in; delete any that were set earlier.",
			references: refs,
			tags,
			confidence,
		});

	const trackingKeys = snap.storageKeys.filter(isTrackingStorageKey);
	if (trackingKeys.length > 0)
		findings.push({
			ruleId: "webapp.browser/tracking-storage-before-consent",
			title: "Tracker identifiers in localStorage before consent",
			severity: "medium",
			category: "privacy",
			message: `localStorage holds tracker identifiers (${list(trackingKeys.map((k) => truncate(k, 40)))}) after the initial load. Storing identifiers on the device falls under ePrivacy Art. 5(3) just like cookies. ${state}`,
			location: { url },
			evidence: truncate(trackingKeys.join(", "), 200),
			remediation:
				"Do not initialise the tracker, or its storage, until the visitor consents.",
			references: refs,
			tags,
			confidence: "medium",
		});

	if (snap.bannerVisible && (trackers.size > 0 || trackingCookies.length > 0))
		findings.push({
			ruleId: "webapp.browser/consent-banner-bypassed",
			title: "Consent banner shown but trackers already active",
			severity: "medium",
			category: "privacy",
			message: `A cookie banner (${cmpList.join(", ") || "unidentified"}) is visible, yet before any choice the page contacted ${trackers.size} tracker vendor${trackers.size === 1 ? "" : "s"} (${list([...trackers.keys()])}) and set ${trackingCookies.length} tracking cookie${trackingCookies.length === 1 ? "" : "s"}. Asking for consent that has already been acted on is not valid consent.`,
			location: { url },
			evidence: truncate(
				`banner=${cmpList.join("+") || "unidentified"}; trackers=${[...trackers.keys()].join(",")}`,
				200,
			),
			remediation:
				"Hold all non-essential scripts, cookies and storage back until the visitor accepts; test with cleared storage.",
			references: refs,
			tags,
			confidence: "high",
		});

	if (cmpList.length > 0)
		findings.push({
			ruleId: "webapp.browser/consent-platform",
			title: `Consent platform detected: ${list(cmpList, 3)}`,
			severity: "info",
			category: "privacy",
			message: `${cmpList.join(", ")} detected on the page (${snap.bannerVisible ? "banner visible on load" : "no banner visible on load"}).`,
			location: { url },
			evidence: cmpList.join(", "),
			remediation: "No action needed.",
			tags,
		});

	if (hosts.size > 0) {
		const sorted = [...hosts].sort(
			(a, b) => b[1] - a[1] || a[0].localeCompare(b[0]),
		);
		const total = sorted.reduce((n, [, c]) => n + c, 0);
		const known = new Set(
			sorted.flatMap(([h]) => {
				const t = trackerForUrl(`https://${h}/`);
				return t ? [t.name] : [];
			}),
		);
		findings.push({
			ruleId: "webapp.browser/third-party-requests",
			title: `Third-party requests to ${hosts.size} host${hosts.size === 1 ? "" : "s"} on initial load`,
			severity: "info",
			category: "privacy",
			message: `The initial load, before any interaction, made ${total} request${total === 1 ? "" : "s"} to ${hosts.size} host${hosts.size === 1 ? "" : "s"} outside ${home}: ${sorted
				.slice(0, 25)
				.map(([h, c]) => `${h} (${c})`)
				.join(
					", ",
				)}${sorted.length > 25 ? `, and ${sorted.length - 25} more` : ""}.${known.size > 0 ? ` Known tracker vendors: ${[...known].join(", ")}.` : ""} List these processors in your privacy policy.`,
			location: { url },
			evidence: truncate(
				sorted
					.slice(0, 10)
					.map(([h, c]) => `${h} (${c})`)
					.join(", "),
				200,
			),
			remediation:
				"Check that every third party is needed, disclosed, covered by a data-processing agreement and consent where required.",
			tags: ["gdpr"],
		});
	}

	if (snap.cookies.length > 0 || snap.storageKeys.length > 0)
		findings.push({
			ruleId: "webapp.browser/storage-before-interaction",
			title: `${snap.cookies.length} cookie${snap.cookies.length === 1 ? "" : "s"} and ${snap.storageKeys.length} localStorage key${snap.storageKeys.length === 1 ? "" : "s"} set on load`,
			severity: "info",
			category: "privacy",
			message: `Before any interaction the page stored ${snap.cookies.length} cookie${snap.cookies.length === 1 ? "" : "s"}${
				snap.cookies.length > 0
					? ` (${list(
							snap.cookies.map((c) => cookieDescription(c, now)),
							6,
						)})`
					: ""
			} and ${snap.storageKeys.length} localStorage key${snap.storageKeys.length === 1 ? "" : "s"}${snap.storageKeys.length > 0 ? ` (${list(snap.storageKeys.map((k) => truncate(k, 40)))})` : ""}. Values are not recorded. Use this for your cookie policy and consent configuration.`,
			location: { url },
			evidence: truncate(
				[
					...snap.cookies.map((c) => truncate(c.name, 40)),
					...snap.storageKeys.map((k) => `ls:${truncate(k, 40)}`),
				].join(", "),
				200,
			),
			remediation:
				"Classify each item as strictly necessary or not; only the former may be stored before consent.",
			tags,
		});

	return findings;
};

const collectConsent = async (
	context: BrowserContext,
	page: Page,
	pageUrl: string,
	requests: ReadonlyArray<string>,
): Promise<ConsentSnapshot> => {
	const dom = (await page.evaluate(BANNER_EXPR).catch(() => undefined)) as
		| {
				cmps: string[];
				shown: boolean;
				storage: string[];
				names: string[];
		  }
		| undefined;
	const scriptNames = new Set(dom?.names ?? []);
	const stored = await context.cookies().catch(() => []);
	const seen = new Set<string>();
	const cookies: ConsentCookie[] = stored
		.filter((c) => {
			const key = `${c.domain}|${c.name}`;
			if (seen.has(key)) return false;
			seen.add(key);
			return true;
		})
		.map((c) => ({
			name: c.name,
			domain: c.domain,
			httpOnly: c.httpOnly,
			secure: c.secure,
			sameSite: c.sameSite,
			expires: c.expires,
			viaScript: !c.httpOnly && scriptNames.has(c.name),
		}));
	return {
		pageUrl,
		requests,
		cookies,
		storageKeys: dom?.storage ?? [],
		cmps: dom?.cmps ?? [],
		bannerVisible: dom?.shown ?? false,
	};
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
	/** Only the first page of a fresh profile shows what happens before consent. */
	checkConsent: boolean,
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
			const requested: string[] = [];
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
				if (requested.length < MAX_REQUESTS) requested.push(req.url());
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
				// Passive snapshot of the initial load, before axe or anything else
				// touches the page; nothing is clicked.
				if (checkConsent)
					findings.push(
						...consentFindings(
							await collectConsent(context, page, finalUrl, [...requested]),
						),
					);

				if (response && response.status() >= 400) failed.delete(response.url());
				const metrics = (await page.evaluate(METRICS_EXPR)) as Metrics;
				findings.push(...vitalsFindings(finalUrl, metrics));

				if (axe) {
					// Evaluated through the DevTools protocol rather than an inline
					// <script>, so a strict CSP on the audited page can't block it.
					await page.evaluate(axe);
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
				if (isLoopback(start))
					yield* Effect.promise(() =>
						context
							.grantPermissions(["local-network-access"], {
								origin: new URL(start).origin,
							})
							.catch(() => {}),
					);
				const headers = ctx.options.headers ?? {};
				if (Object.keys(headers).length > 0)
					// Only send user-supplied headers (e.g. auth cookies) to the target origin.
					// `route.continue({ headers })` would also apply them to redirects, so a
					// same-origin 3xx to another host would leak them. Instead fetch without
					// following redirects and hand the 3xx back to the browser, whose next hop
					// is routed (and origin-checked) again.
					yield* Effect.promise(() =>
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
					);
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
