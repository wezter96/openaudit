import type { FindingInput } from "@openaudit/core";
import type { BrowserContext, Page } from "playwright-core";

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
import type { Url } from "./page";
import { truncate } from "./util";

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

const REFS = [
	"https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-052020-consent-under-regulation-2016679_en",
];
const TAGS = ["gdpr", "eprivacy"];

/** Third-party traffic of the initial load. */
interface Requests {
	/** Requests per third-party host. */
	readonly hosts: Map<string, number>;
	readonly trackers: Map<string, { tracker: Tracker; hosts: Set<string> }>;
	readonly cmps: Set<string>;
}

/** Everything the individual findings below are built from. */
interface ConsentInput extends Requests {
	readonly snap: ConsentSnapshot;
	readonly url: Url;
	readonly home: string;
	readonly now: number;
	readonly cmpList: ReadonlyArray<string>;
	readonly trackingCookies: ReadonlyArray<ConsentCookie>;
	readonly confidence: "high" | "medium";
	/** Sentence describing the consent banner, appended to violations. */
	readonly state: string;
}

const HTTP_PROTOCOLS = new Set(["http:", "https:"]);

/** Lowercased host of an http(s) URL, or undefined. */
const httpHostOf = (raw: Url): string | undefined => {
	try {
		const u = new URL(raw);
		return HTTP_PROTOCOLS.has(u.protocol)
			? u.hostname.toLowerCase()
			: undefined;
	} catch {
		return undefined;
	}
};

const recordTracker = (requests: Requests, raw: Url, host: string) => {
	const tracker = trackerForUrl(raw);
	if (!tracker || CONSENT_EXEMPT_KINDS.has(tracker.kind)) return;
	const entry = requests.trackers.get(tracker.name) ?? {
		tracker,
		hosts: new Set<string>(),
	};
	entry.hosts.add(host);
	requests.trackers.set(tracker.name, entry);
};

const recordRequest = (requests: Requests, raw: Url, host: string) => {
	requests.hosts.set(host, (requests.hosts.get(host) ?? 0) + 1);
	for (const p of CONSENT_PLATFORMS.filter((p) =>
		p.hosts.some((h) => hostMatches(host, h)),
	))
		requests.cmps.add(p.name);
	recordTracker(requests, raw, host);
};

const thirdPartyRequests = (snap: ConsentSnapshot, home: string): Requests => {
	const requests: Requests = {
		hosts: new Map(),
		trackers: new Map(),
		cmps: new Set(snap.cmps),
	};
	for (const raw of snap.requests) {
		const host = httpHostOf(raw);
		if (host !== undefined && registrableDomain(host) !== home)
			recordRequest(requests, raw, host);
	}
	return requests;
};

const consentState = (
	bannerVisible: boolean,
	cmpList: ReadonlyArray<string>,
): string => {
	if (bannerVisible)
		return `A consent banner is shown (${cmpList.join(", ") || "unidentified"}) yet it did not hold these back.`;
	if (cmpList.length > 0)
		return `A consent platform (${cmpList.join(", ")}) is present but no banner was visible.`;
	return "No consent banner or consent platform was detected.";
};

const trackerFindings = (c: ConsentInput): FindingInput[] =>
	[...c.trackers.values()].map(({ tracker, hosts: trackerHosts }) => {
		const count = [...trackerHosts].reduce(
			(n, h) => n + (c.hosts.get(h) ?? 0),
			0,
		);
		return {
			ruleId: "webapp.browser/tracker-before-consent",
			title: `${tracker.name} contacted before consent`,
			severity: "medium",
			category: "privacy",
			message: `During the initial load, with no interaction, the page sent ${count} request${count === 1 ? "" : "s"} to ${tracker.name} (${tracker.kind}) at ${list([...trackerHosts])}. Under the ePrivacy Directive and GDPR such tracking needs the visitor's prior opt-in. ${c.state}`,
			location: { url: c.url, selector: tracker.name },
			evidence: truncate(
				`${list([...trackerHosts])} (${count} request${count === 1 ? "" : "s"})`,
				200,
			),
			remediation:
				"Block the tag until the visitor consents (consent-management platform, Google Consent Mode v2 or a script blocker), and verify with a clean browser profile.",
			references: REFS,
			tags: [...TAGS, tracker.kind.replace(/\s+/g, "-")],
			confidence: c.confidence,
		};
	});

const trackingCookieFindings = (c: ConsentInput): FindingInput[] => {
	const { trackingCookies } = c;
	if (trackingCookies.length === 0) return [];
	return [
		{
			ruleId: "webapp.browser/tracking-cookie-before-consent",
			title: "Tracking cookies set before consent",
			severity: "medium",
			category: "privacy",
			message: `${trackingCookies.length} analytics/advertising cookie${trackingCookies.length === 1 ? " was" : "s were"} stored during the initial load, before any interaction: ${list(trackingCookies.map((k) => truncate(k.name, 40)))}. These are not strictly necessary and need prior consent. ${c.state}`,
			location: { url: c.url },
			evidence: truncate(
				trackingCookies.map((k) => cookieDescription(k, c.now)).join("; "),
				240,
			),
			remediation:
				"Set tracking cookies only after the visitor opts in; delete any that were set earlier.",
			references: REFS,
			tags: TAGS,
			confidence: c.confidence,
		},
	];
};

const trackingStorageFindings = (c: ConsentInput): FindingInput[] => {
	const trackingKeys = c.snap.storageKeys.filter(isTrackingStorageKey);
	if (trackingKeys.length === 0) return [];
	return [
		{
			ruleId: "webapp.browser/tracking-storage-before-consent",
			title: "Tracker identifiers in localStorage before consent",
			severity: "medium",
			category: "privacy",
			message: `localStorage holds tracker identifiers (${list(trackingKeys.map((k) => truncate(k, 40)))}) after the initial load. Storing identifiers on the device falls under ePrivacy Art. 5(3) just like cookies. ${c.state}`,
			location: { url: c.url },
			evidence: truncate(trackingKeys.join(", "), 200),
			remediation:
				"Do not initialise the tracker, or its storage, until the visitor consents.",
			references: REFS,
			tags: TAGS,
			confidence: "medium",
		},
	];
};

const trackedBeforeChoice = (c: ConsentInput): boolean =>
	c.trackers.size > 0 || c.trackingCookies.length > 0;

const bannerBypassedFindings = (c: ConsentInput): FindingInput[] => {
	if (!c.snap.bannerVisible) return [];
	if (!trackedBeforeChoice(c)) return [];
	const { trackers, trackingCookies, cmpList } = c;
	return [
		{
			ruleId: "webapp.browser/consent-banner-bypassed",
			title: "Consent banner shown but trackers already active",
			severity: "medium",
			category: "privacy",
			message: `A cookie banner (${cmpList.join(", ") || "unidentified"}) is visible, yet before any choice the page contacted ${trackers.size} tracker vendor${trackers.size === 1 ? "" : "s"} (${list([...trackers.keys()])}) and set ${trackingCookies.length} tracking cookie${trackingCookies.length === 1 ? "" : "s"}. Asking for consent that has already been acted on is not valid consent.`,
			location: { url: c.url },
			evidence: truncate(
				`banner=${cmpList.join("+") || "unidentified"}; trackers=${[...trackers.keys()].join(",")}`,
				200,
			),
			remediation:
				"Hold all non-essential scripts, cookies and storage back until the visitor accepts; test with cleared storage.",
			references: REFS,
			tags: TAGS,
			confidence: "high",
		},
	];
};

const platformFindings = (c: ConsentInput): FindingInput[] => {
	const { cmpList } = c;
	if (cmpList.length === 0) return [];
	return [
		{
			ruleId: "webapp.browser/consent-platform",
			title: `Consent platform detected: ${list(cmpList, 3)}`,
			severity: "info",
			category: "privacy",
			message: `${cmpList.join(", ")} detected on the page (${c.snap.bannerVisible ? "banner visible on load" : "no banner visible on load"}).`,
			location: { url: c.url },
			evidence: cmpList.join(", "),
			remediation: "No action needed.",
			tags: TAGS,
		},
	];
};

/** Tracker vendors among the contacted hosts. */
const knownVendors = (hosts: ReadonlyArray<string>): Set<string> =>
	new Set(
		hosts.flatMap((h) => {
			const t = trackerForUrl(`https://${h}/`);
			return t ? [t.name] : [];
		}),
	);

const thirdPartyFindings = (c: ConsentInput): FindingInput[] => {
	const { hosts, home } = c;
	if (hosts.size === 0) return [];
	const sorted = [...hosts].sort(
		(a, b) => b[1] - a[1] || a[0].localeCompare(b[0]),
	);
	const total = sorted.reduce((n, [, count]) => n + count, 0);
	const known = knownVendors(sorted.map(([h]) => h));
	return [
		{
			ruleId: "webapp.browser/third-party-requests",
			title: `Third-party requests to ${hosts.size} host${hosts.size === 1 ? "" : "s"} on initial load`,
			severity: "info",
			category: "privacy",
			message: `The initial load, before any interaction, made ${total} request${total === 1 ? "" : "s"} to ${hosts.size} host${hosts.size === 1 ? "" : "s"} outside ${home}: ${sorted
				.slice(0, 25)
				.map(([h, count]) => `${h} (${count})`)
				.join(
					", ",
				)}${sorted.length > 25 ? `, and ${sorted.length - 25} more` : ""}.${known.size > 0 ? ` Known tracker vendors: ${[...known].join(", ")}.` : ""} List these processors in your privacy policy.`,
			location: { url: c.url },
			evidence: truncate(
				sorted
					.slice(0, 10)
					.map(([h, count]) => `${h} (${count})`)
					.join(", "),
				200,
			),
			remediation:
				"Check that every third party is needed, disclosed, covered by a data-processing agreement and consent where required.",
			tags: ["gdpr"],
		},
	];
};

const storageFindings = (c: ConsentInput): FindingInput[] => {
	const { snap, now } = c;
	if (snap.cookies.length === 0 && snap.storageKeys.length === 0) return [];
	return [
		{
			ruleId: "webapp.browser/storage-before-interaction",
			title: `${snap.cookies.length} cookie${snap.cookies.length === 1 ? "" : "s"} and ${snap.storageKeys.length} localStorage key${snap.storageKeys.length === 1 ? "" : "s"} set on load`,
			severity: "info",
			category: "privacy",
			message: `Before any interaction the page stored ${snap.cookies.length} cookie${snap.cookies.length === 1 ? "" : "s"}${
				snap.cookies.length > 0
					? ` (${list(
							snap.cookies.map((k) => cookieDescription(k, now)),
							6,
						)})`
					: ""
			} and ${snap.storageKeys.length} localStorage key${snap.storageKeys.length === 1 ? "" : "s"}${snap.storageKeys.length > 0 ? ` (${list(snap.storageKeys.map((k) => truncate(k, 40)))})` : ""}. Values are not recorded. Use this for your cookie policy and consent configuration.`,
			location: { url: c.url },
			evidence: truncate(
				[
					...snap.cookies.map((k) => truncate(k.name, 40)),
					...snap.storageKeys.map((k) => `ls:${truncate(k, 40)}`),
				].join(", "),
				200,
			),
			remediation:
				"Classify each item as strictly necessary or not; only the former may be stored before consent.",
			tags: TAGS,
		},
	];
};

const CONSENT_CHECKS: ReadonlyArray<(c: ConsentInput) => FindingInput[]> = [
	trackerFindings,
	trackingCookieFindings,
	trackingStorageFindings,
	bannerBypassedFindings,
	platformFindings,
	thirdPartyFindings,
	storageFindings,
];

const hostnameOf = (url: Url): string | undefined => {
	try {
		return new URL(url).hostname;
	} catch {
		return undefined;
	}
};

/**
 * Turns what a page did before consent into findings. Pure, so it is
 * testable without a browser. Exported for tests.
 */
export const consentFindings = (
	snap: ConsentSnapshot,
	now = Date.now(),
): FindingInput[] => {
	const url = snap.pageUrl;
	const targetHost = hostnameOf(url);
	if (targetHost === undefined) return [];
	const home = registrableDomain(targetHost);
	const requests = thirdPartyRequests(snap, home);
	const cmpList = [...requests.cmps];
	const input: ConsentInput = {
		...requests,
		snap,
		url,
		home,
		now,
		cmpList,
		trackingCookies: snap.cookies.filter((c) => isTrackingCookie(c.name)),
		// A visible banner means the site claims to ask first, so trackers that
		// already fired are a clear violation. Without one, the site may rely on
		// another legal basis or jurisdiction, so confidence stays lower.
		confidence: snap.bannerVisible ? "high" : "medium",
		state: consentState(snap.bannerVisible, cmpList),
	};
	return CONSENT_CHECKS.flatMap((check) => check(input));
};

interface BannerState {
	cmps: string[];
	shown: boolean;
	storage: string[];
	names: string[];
}

type StoredCookie = Awaited<ReturnType<BrowserContext["cookies"]>>[number];

/** First cookie per domain and name. */
const uniqueCookies = (stored: ReadonlyArray<StoredCookie>): StoredCookie[] => {
	const seen = new Set<string>();
	return stored.filter((c) => {
		const key = `${c.domain}|${c.name}`;
		if (seen.has(key)) return false;
		seen.add(key);
		return true;
	});
};

const toConsentCookie = (
	c: StoredCookie,
	scriptNames: ReadonlySet<string>,
): ConsentCookie => ({
	name: c.name,
	domain: c.domain,
	httpOnly: c.httpOnly,
	secure: c.secure,
	sameSite: c.sameSite,
	expires: c.expires,
	viaScript: !c.httpOnly && scriptNames.has(c.name),
});

export const collectConsent = async (
	context: BrowserContext,
	page: Page,
	pageUrl: Url,
	requests: ReadonlyArray<Url>,
): Promise<ConsentSnapshot> => {
	const dom: Partial<BannerState> =
		((await page.evaluate(BANNER_EXPR).catch(() => undefined)) as
			| BannerState
			| undefined) ?? {};
	const scriptNames = new Set(dom.names ?? []);
	const stored = await context.cookies().catch(() => []);
	return {
		pageUrl,
		requests,
		cookies: uniqueCookies(stored).map((c) => toConsentCookie(c, scriptNames)),
		storageKeys: dom.storage ?? [],
		cmps: dom.cmps ?? [],
		bannerVisible: dom.shown ?? false,
	};
};
