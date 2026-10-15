import {
	defineAuditor,
	type FindingInput,
	type Severity,
} from "@openaudit/core";
import { Effect } from "effect";
import {
	isTrackingCookie,
	staticPattern,
	TRACKERS as TRACKERS_ALL,
	type Tracker,
} from "../privacy-data";
import {
	type El,
	findAll,
	rawText,
	selectorOf,
	snippetOf,
	textOf,
} from "./dom";
import {
	type Crawl,
	crawl,
	isLoopback,
	type Page,
	resolveUrl,
	resourcesOf,
} from "./page";
import { type Cookie, parseSetCookie } from "./util";

/** Static HTML scanning skips monitoring SDKs: they are not consent-gated tracking. */
const TRACKERS = TRACKERS_ALL.filter((t) => t.kind !== "monitoring").flatMap(
	(tracker) => {
		const pattern = staticPattern(tracker);
		return pattern ? [{ tracker, pattern }] : [];
	},
);

const THIRD_PARTY_HOSTS: ReadonlyArray<[RegExp, string]> = [
	[/^fonts\.(googleapis|gstatic)\.com$/, "Google Fonts"],
	[/^use\.typekit\.net$|^p\.typekit\.net$/, "Adobe Fonts"],
	[
		/^(cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|code\.jquery\.com|ajax\.googleapis\.com|stackpath\.bootstrapcdn\.com|maxcdn\.bootstrapcdn\.com)$/,
		"public CDN",
	],
];

const PRIVACY_LINK =
	/privacy|datenschutz|confidentialit|privacidad|privacit|integritet|privatliv|tietosuoja|prywatno|gdpr|rgpd|cookie[- ]?policy/i;

type Source = { text: string; evidence: string };

interface FoundTracker {
	readonly tracker: Tracker;
	readonly pattern: RegExp;
	readonly page: Page;
	readonly evidence: string;
}

const INVASIVE_KINDS = new Set<string>([
	"session-replay",
	"advertising",
	"fingerprinting",
]);

/** Resource URLs and inline scripts of a page, where tracker patterns are looked for. */
const trackerSources = (page: Page): Source[] => [
	...resourcesOf(page).map((r) => ({
		text: r.url,
		evidence: snippetOf(r.el),
	})),
	...findAll(page.doc, ["script", "noscript"], (s) => !s.attrs.src).map(
		(s) => ({ text: rawText(s), evidence: "inline script" }),
	),
];

const trackerEvidence = (hit: Source, pattern: RegExp): string =>
	hit.evidence === "inline script"
		? `inline script matching ${pattern.source.slice(0, 60)}`
		: hit.evidence;

/** The first page each tracker shows up on. */
const findTrackers = (
	pages: ReadonlyArray<Page>,
): Map<string, FoundTracker> => {
	const found = new Map<string, FoundTracker>();
	for (const page of pages) {
		const sources = trackerSources(page);
		for (const { tracker, pattern } of TRACKERS) {
			if (found.has(tracker.name)) continue;
			const hit = sources.find((s) => pattern.test(s.text));
			if (hit)
				found.set(tracker.name, {
					tracker,
					pattern,
					page,
					evidence: trackerEvidence(hit, pattern),
				});
		}
	}
	return found;
};

const trackerSeverity = (tracker: Tracker, friendly: boolean): Severity => {
	if (friendly) return "info";
	return INVASIVE_KINDS.has(tracker.kind) ? "medium" : "low";
};

const trackerFinding = ({
	tracker,
	page,
	evidence,
}: FoundTracker): FindingInput => {
	const friendly = tracker.kind === "privacy-friendly analytics";
	return {
		ruleId: "web.privacy/tracker",
		title: `${tracker.name} detected`,
		severity: trackerSeverity(tracker, friendly),
		category: "privacy",
		message: friendly
			? `${tracker.name} (${tracker.kind}) is used. It is cookieless by default but still processes visitor data; mention it in your privacy notice.`
			: `${tracker.name} (${tracker.kind}) is loaded. In the EU/UK (GDPR, ePrivacy) it must not run before the visitor opts in, and it must be disclosed in the privacy policy.${tracker.kind === "session-replay" ? " Session replay can capture form input and personal data." : ""}`,
		location: { url: page.url, selector: tracker.name },
		evidence,
		remediation: friendly
			? "Disclose the tool in your privacy policy."
			: "Load it only after consent via a consent-management platform (e.g. Google Consent Mode v2), or replace it with a privacy-friendly alternative.",
		references: [
			"https://commission.europa.eu/law/law-topic/data-protection/rules-business-and-organisations/principles-gdpr_en",
			"https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-22023-technical-scope-art-53-eprivacy-directive_en",
		],
		tags: ["gdpr", "eprivacy", tracker.kind.replace(/\s+/g, "-")],
		confidence: "medium",
	};
};

/** Cookie lifetime in milliseconds from Max-Age, else Expires, else 0. */
const cookieLifetime = (c: Cookie): number => {
	const maxAge = Number(c.attrs.get("max-age") ?? "");
	const expires = Date.parse(c.attrs.get("expires") ?? "");
	if (Number.isFinite(maxAge) && maxAge > 0) return maxAge * 1000;
	return Number.isFinite(expires) ? expires - Date.now() : 0;
};

const isLongLived = (c: Cookie): boolean =>
	!isTrackingCookie(c.name) && cookieLifetime(c) > 30 * 86_400_000;

const cookieFindings = (
	start: Page,
	cookies: ReadonlyArray<Cookie>,
): FindingInput[] => {
	const findings: FindingInput[] = [];
	const tracking = cookies.filter((c) => isTrackingCookie(c.name));
	const longLived = cookies.filter(isLongLived);
	if (tracking.length > 0)
		findings.push({
			ruleId: "web.privacy/tracking-cookie-before-consent",
			title: "Tracking cookies set before consent",
			severity: "medium",
			category: "privacy",
			message: `The first response sets ${tracking.map((c) => c.name).join(", ")} before any user interaction. Analytics/advertising cookies require prior opt-in consent under the ePrivacy Directive.`,
			location: { url: start.url },
			evidence: tracking.map((c) => c.name).join(", "),
			remediation: "Set tracking cookies only after the visitor consents.",
			references: [
				"https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-052020-consent-under-regulation-2016679_en",
			],
			tags: ["gdpr", "eprivacy"],
		});
	if (longLived.length > 0)
		findings.push({
			ruleId: "web.privacy/persistent-cookie-before-consent",
			title: "Long-lived cookies set on first visit",
			severity: "low",
			category: "privacy",
			message: `The first response sets persistent cookies (${longLived.map((c) => c.name).join(", ")}) lasting more than 30 days before any interaction. Unless strictly necessary, they need consent. Only server-set cookies were checked; scripts may set more.`,
			location: { url: start.url },
			evidence: longLived.map((c) => c.name).join(", "),
			remediation:
				"Confirm each cookie is strictly necessary, or defer it until consent and shorten its lifetime.",
			references: ["https://gdpr.eu/cookies/"],
			tags: ["gdpr", "eprivacy"],
			confidence: "low",
		});
	return findings;
};

/** Records the first page each third-party host group is loaded on. */
const addLeaks = (
	leaks: Map<string, { host: string; page: Page }>,
	page: Page,
): void => {
	for (const r of resourcesOf(page)) {
		if (r.kind === "form") continue;
		const host = new URL(r.url).hostname;
		for (const [re, label] of THIRD_PARTY_HOSTS)
			if (re.test(host) && !leaks.has(label)) leaks.set(label, { host, page });
	}
};

const leakFinding = (
	label: string,
	host: string,
	page: Page,
): FindingInput => ({
	ruleId:
		label === "public CDN"
			? "web.privacy/third-party-cdn"
			: "web.privacy/third-party-fonts",
	title:
		label === "public CDN"
			? `Assets loaded from a public CDN (${host})`
			: `${label} loaded from ${host}`,
	severity: label === "Google Fonts" ? "low" : "info",
	category: "privacy",
	message: `Every visit sends the visitor's IP address and user agent to ${host}.${label === "Google Fonts" ? " German courts have ruled that embedding Google Fonts this way without consent violates GDPR (LG München I, 3 O 17493/20)." : ""}`,
	location: { url: page.url },
	evidence: host,
	remediation: "Self-host fonts and libraries from your own origin.",
	references: ["https://developers.google.com/fonts/faq/privacy"],
	tags: ["gdpr"],
});

const thirdPartyFindings = (pages: ReadonlyArray<Page>): FindingInput[] => {
	const leaks = new Map<string, { host: string; page: Page }>();
	for (const page of pages) addLeaks(leaks, page);
	return [...leaks].map(([label, { host, page }]) =>
		leakFinding(label, host, page),
	);
};

const isPersonalInput = (i: El): boolean =>
	/password|email|tel/i.test(i.attrs.type ?? "") ||
	/email|phone|name|address|password/i.test(i.attrs.name ?? "");

const submitsOverHttp = (action: string): boolean =>
	action.startsWith("http:") && !isLoopback(action);

const formFindings = (page: Page): FindingInput[] =>
	findAll(page.doc, "form").flatMap((form): FindingInput[] => {
		const action = resolveUrl(page.url, form.attrs.action) ?? page.url;
		const hasPersonal = findAll(form, "input", isPersonalInput).length > 0;
		if (!submitsOverHttp(action) || !hasPersonal) return [];
		return [
			{
				ruleId: "web.privacy/form-over-http",
				title: "Personal data submitted over HTTP",
				severity: "high",
				category: "privacy",
				message: `A form collecting personal data submits to ${action} without TLS, exposing it to anyone on the network path.`,
				location: { url: page.url, selector: selectorOf(form) },
				evidence: snippetOf(form),
				remediation: "Serve the page and the form action over HTTPS.",
				references: ["https://gdpr-info.eu/art-32-gdpr/"],
				tags: ["cwe-319", "gdpr"],
			},
		];
	});

const isPrivacyLink = (a: El): boolean =>
	PRIVACY_LINK.test(a.attrs.href ?? "") || PRIVACY_LINK.test(textOf(a));

/** Whether the site visibly handles personal data: trackers, cookies or a form. */
const handlesPersonalData = (
	trackers: number,
	cookies: number,
	start: Page,
): boolean =>
	trackers > 0 || cookies > 0 || findAll(start.doc, "form").length > 0;

const policyFindings = (
	{ start, pages }: Crawl,
	trackers: number,
	cookies: number,
): FindingInput[] => {
	const hasPolicy = pages.some(
		(p) => findAll(p.doc, "a", isPrivacyLink).length > 0,
	);
	if (pages.length === 0 || hasPolicy) return [];
	return [
		{
			ruleId: "web.privacy/privacy-policy-missing",
			title: "No privacy policy link found",
			severity: handlesPersonalData(trackers, cookies, start)
				? "medium"
				: "low",
			category: "compliance",
			message:
				"None of the crawled pages link to a privacy policy. Sites that process personal data (analytics, forms, cookies) must provide one (GDPR Art. 13, CCPA).",
			location: { url: start.url },
			remediation:
				"Publish a privacy policy and link it from the footer of every page.",
			references: ["https://gdpr-info.eu/art-13-gdpr/"],
			tags: ["gdpr", "ccpa"],
			confidence: "low",
		},
	];
};

/** Trackers, consent-relevant cookies, third-party IP leaks and privacy-policy presence. */
export const privacy = defineAuditor({
	id: "web.privacy",
	title: "Privacy",
	description:
		"Detects analytics/advertising trackers and session replay, cookies set before consent, third-party fonts and CDNs that leak visitor IPs, forms posting over HTTP, and a missing privacy-policy link.",
	categories: ["privacy", "compliance"],
	targets: ["url"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const site = yield* crawl(ctx);
			const found = findTrackers(site.pages);
			const cookies = site.start.response.cookies
				.map(parseSetCookie)
				.filter((c) => c.name);
			return [
				...[...found.values()].map(trackerFinding),
				...cookieFindings(site.start, cookies),
				...thirdPartyFindings(site.pages),
				...site.pages.flatMap(formFindings),
				...policyFindings(site, found.size, cookies.length),
			];
		}),
});
