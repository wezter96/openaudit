import {
	defineAuditor,
	type FindingInput,
	type Severity,
} from "@openaudit/core";
import { Effect } from "effect";

import { findAll, rawText, selectorOf, snippetOf, textOf } from "./dom";
import { crawl, isLoopback, type Page, resolveUrl, resourcesOf } from "./page";
import { parseSetCookie } from "./util";

interface Tracker {
	readonly name: string;
	readonly kind:
		| "analytics"
		| "advertising"
		| "session-replay"
		| "marketing"
		| "privacy-friendly analytics";
	/** Matched against resource URLs and inline script source. */
	readonly pattern: RegExp;
}

const TRACKERS: ReadonlyArray<Tracker> = [
	{
		name: "Google Analytics",
		kind: "analytics",
		pattern:
			/google-analytics\.com\/|googletagmanager\.com\/gtag\/js|\bgtag\(\s*['"]config['"]\s*,\s*['"](G|UA)-/,
	},
	{
		name: "Google Tag Manager",
		kind: "marketing",
		pattern: /googletagmanager\.com\/gtm\.js|GTM-[A-Z0-9]{4,}/,
	},
	{
		name: "Google Ads / DoubleClick",
		kind: "advertising",
		pattern:
			/doubleclick\.net|googleadservices\.com|googlesyndication\.com|AW-\d{6,}/,
	},
	{
		name: "Meta Pixel",
		kind: "advertising",
		pattern:
			/connect\.facebook\.net\/[^"']*fbevents|facebook\.com\/tr\?|\bfbq\(\s*['"]init/,
	},
	{
		name: "Hotjar",
		kind: "session-replay",
		pattern: /static\.hotjar\.com|script\.hotjar\.com|\bhjid\s*:/,
	},
	{
		name: "Microsoft Clarity",
		kind: "session-replay",
		pattern: /clarity\.ms\/tag/,
	},
	{
		name: "FullStory",
		kind: "session-replay",
		pattern:
			/fullstory\.com\/s\/fs\.js|edge\.fullstory\.com|window\['_fs_org'\]/,
	},
	{
		name: "LogRocket",
		kind: "session-replay",
		pattern: /cdn\.logrocket\.io|cdn\.lr-ingest\.io/,
	},
	{
		name: "Segment",
		kind: "analytics",
		pattern: /cdn\.segment\.com\/analytics\.js/,
	},
	{
		name: "Mixpanel",
		kind: "analytics",
		pattern: /cdn\.mxpnl\.com|mixpanel\.init\(/,
	},
	{
		name: "Amplitude",
		kind: "analytics",
		pattern: /cdn\.amplitude\.com|amplitude\.getInstance\(/,
	},
	{
		name: "Heap",
		kind: "analytics",
		pattern: /cdn\.heapanalytics\.com|heap\.load\(/,
	},
	{
		name: "LinkedIn Insight",
		kind: "advertising",
		pattern: /snap\.licdn\.com|_linkedin_partner_id/,
	},
	{
		name: "TikTok Pixel",
		kind: "advertising",
		pattern: /analytics\.tiktok\.com|ttq\.load\(/,
	},
	{
		name: "X (Twitter) Pixel",
		kind: "advertising",
		pattern: /static\.ads-twitter\.com|\btwq\(\s*['"]init/,
	},
	{
		name: "Microsoft Advertising (Bing UET)",
		kind: "advertising",
		pattern: /bat\.bing\.com/,
	},
	{
		name: "HubSpot",
		kind: "marketing",
		pattern: /js\.hs-scripts\.com|js\.hs-analytics\.net/,
	},
	{
		name: "Intercom",
		kind: "marketing",
		pattern: /widget\.intercom\.io|js\.intercomcdn\.com/,
	},
	{
		name: "Yandex Metrica",
		kind: "analytics",
		pattern: /mc\.yandex\.ru\/metrika/,
	},
	{
		name: "Plausible",
		kind: "privacy-friendly analytics",
		pattern: /plausible\.io\/js\//,
	},
	{
		name: "Fathom",
		kind: "privacy-friendly analytics",
		pattern: /cdn\.usefathom\.com/,
	},
	{
		name: "Matomo",
		kind: "privacy-friendly analytics",
		pattern: /matomo\.(js|php)|piwik\.(js|php)/,
	},
];

const TRACKING_COOKIE =
	/^(_ga|_gid|_gat|_gcl_|_fbp|_fbc|_hj|_clck|_clsk|ajs_|mp_|amplitude|_uet|_ttp|li_|IDE$|NID$|_pin_)/i;

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
			const { start, pages } = yield* crawl(ctx);
			const findings: FindingInput[] = [];

			/* -------------------------------- trackers ------------------------------- */
			const found = new Map<
				string,
				{ tracker: Tracker; page: Page; evidence: string }
			>();
			for (const page of pages) {
				const sources = [
					...resourcesOf(page).map((r) => ({
						text: r.url,
						evidence: snippetOf(r.el),
					})),
					...findAll(page.doc, ["script", "noscript"], (s) => !s.attrs.src).map(
						(s) => ({ text: rawText(s), evidence: "inline script" }),
					),
				];
				for (const tracker of TRACKERS) {
					if (found.has(tracker.name)) continue;
					const hit = sources.find((s) => tracker.pattern.test(s.text));
					if (hit)
						found.set(tracker.name, {
							tracker,
							page,
							evidence:
								hit.evidence === "inline script"
									? `inline script matching ${tracker.pattern.source.slice(0, 60)}`
									: hit.evidence,
						});
				}
			}
			for (const { tracker, page, evidence } of found.values()) {
				const friendly = tracker.kind === "privacy-friendly analytics";
				const severity: Severity = friendly
					? "info"
					: tracker.kind === "session-replay" || tracker.kind === "advertising"
						? "medium"
						: "low";
				findings.push({
					ruleId: "web.privacy/tracker",
					title: `${tracker.name} detected`,
					severity,
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
				});
			}

			/* --------------------------- cookies before consent --------------------------- */
			const cookies = start.response.cookies
				.map(parseSetCookie)
				.filter((c) => c.name);
			const tracking = cookies.filter((c) => TRACKING_COOKIE.test(c.name));
			const longLived = cookies.filter((c) => {
				if (TRACKING_COOKIE.test(c.name)) return false;
				const maxAge = Number(c.attrs.get("max-age") ?? "");
				const expires = Date.parse(c.attrs.get("expires") ?? "");
				const lifetime =
					Number.isFinite(maxAge) && maxAge > 0
						? maxAge * 1000
						: Number.isFinite(expires)
							? expires - Date.now()
							: 0;
				return lifetime > 30 * 86_400_000;
			});
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

			/* ------------------------ third-party fonts and CDNs ------------------------ */
			const leaks = new Map<string, { host: string; page: Page }>();
			for (const page of pages)
				for (const r of resourcesOf(page)) {
					if (r.kind === "form") continue;
					const host = new URL(r.url).hostname;
					for (const [re, label] of THIRD_PARTY_HOSTS)
						if (re.test(host) && !leaks.has(label))
							leaks.set(label, { host, page });
				}
			for (const [label, { host, page }] of leaks)
				findings.push({
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

			/* ------------------------------- insecure forms ------------------------------ */
			for (const page of pages) {
				for (const form of findAll(page.doc, "form")) {
					const action = resolveUrl(page.url, form.attrs.action) ?? page.url;
					const hasPersonal =
						findAll(
							form,
							"input",
							(i) =>
								/password|email|tel/i.test(i.attrs.type ?? "") ||
								/email|phone|name|address|password/i.test(i.attrs.name ?? ""),
						).length > 0;
					if (!action.startsWith("http:") || isLoopback(action) || !hasPersonal)
						continue;
					findings.push({
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
					});
				}
			}

			/* ------------------------------ privacy policy ------------------------------ */
			const hasPolicy = pages.some(
				(p) =>
					findAll(
						p.doc,
						"a",
						(a) =>
							PRIVACY_LINK.test(a.attrs.href ?? "") ||
							PRIVACY_LINK.test(textOf(a)),
					).length > 0,
			);
			if (pages.length > 0 && !hasPolicy)
				findings.push({
					ruleId: "web.privacy/privacy-policy-missing",
					title: "No privacy policy link found",
					severity:
						found.size > 0 ||
						cookies.length > 0 ||
						findAll(start.doc, "form").length > 0
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
				});

			return findings;
		}),
});
