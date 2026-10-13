/**
 * Shared privacy knowledge for `web.privacy`, `webapp.browser` (consent
 * checks) and `code.privacy`: tracker vendors with their hosts and SDK
 * package names, tracking-cookie name patterns and consent platforms.
 * Prefer a short list of well-known vendors over a long guessed one: every
 * entry produces findings that people must triage.
 */

export type TrackerKind =
	| "analytics"
	| "advertising"
	| "session-replay"
	| "fingerprinting"
	| "attribution"
	| "marketing"
	| "tag-manager"
	/** Error tracking and real-user monitoring. */
	| "monitoring"
	| "privacy-friendly analytics";

export type Ecosystem =
	| "npm"
	| "pypi"
	| "go"
	| "gem"
	| "pod"
	| "gradle"
	| "pub"
	| "composer";

export interface Tracker {
	readonly name: string;
	readonly kind: TrackerKind;
	/** Domains (and their subdomains) the vendor's browser traffic goes to. */
	readonly hosts: ReadonlyArray<string>;
	/** Matched against resource URLs and inline script source (static HTML). */
	readonly pattern?: RegExp;
	/** Matched against a full request URL for vendors on shared hosts. */
	readonly urlPattern?: RegExp;
	/** SDK package names per ecosystem, matched case-insensitively. */
	readonly packages?: Partial<Record<Ecosystem, ReadonlyArray<string>>>;
}

export const TRACKERS: ReadonlyArray<Tracker> = [
	{
		name: "Google Analytics",
		kind: "analytics",
		hosts: ["google-analytics.com", "analytics.google.com"],
		urlPattern: /^https?:\/\/www\.googletagmanager\.com\/gtag\/js/i,
		pattern:
			/google-analytics\.com\/|googletagmanager\.com\/gtag\/js|\bgtag\(\s*['"]config['"]\s*,\s*['"](G|UA)-/,
		packages: {
			npm: [
				"react-ga",
				"react-ga4",
				"vue-gtag",
				"ngx-google-analytics",
				"universal-analytics",
				"@analytics/google-analytics",
				"@react-native-google-analytics/google-analytics",
			],
		},
	},
	{
		name: "Firebase Analytics",
		kind: "analytics",
		hosts: ["app-measurement.com"],
		packages: {
			npm: ["@react-native-firebase/analytics"],
			pub: ["firebase_analytics"],
			gradle: [
				"com.google.firebase:firebase-analytics",
				"com.google.firebase:firebase-analytics-ktx",
			],
			pod: ["FirebaseAnalytics", "Firebase/Analytics"],
		},
	},
	{
		name: "Google Tag Manager",
		kind: "tag-manager",
		hosts: [],
		urlPattern: /^https?:\/\/www\.googletagmanager\.com\/(gtm\.js|ns\.html)/i,
		pattern: /googletagmanager\.com\/gtm\.js|GTM-[A-Z0-9]{4,}/,
		packages: { npm: ["react-gtm-module", "@next/third-parties"] },
	},
	{
		name: "Google Ads / DoubleClick",
		kind: "advertising",
		hosts: ["doubleclick.net", "googleadservices.com", "googlesyndication.com"],
		pattern:
			/doubleclick\.net|googleadservices\.com|googlesyndication\.com|AW-\d{6,}/,
	},
	{
		name: "Meta Pixel / Facebook SDK",
		kind: "advertising",
		hosts: ["connect.facebook.net"],
		urlPattern: /^https?:\/\/www\.facebook\.com\/tr[/?]/i,
		pattern:
			/connect\.facebook\.net\/[^"']*fbevents|facebook\.com\/tr\?|\bfbq\(\s*['"]init/,
		packages: {
			npm: [
				"react-facebook-pixel",
				"react-native-fbsdk-next",
				"react-native-fbsdk",
			],
			gradle: ["com.facebook.android:facebook-android-sdk"],
			pod: ["FBSDKCoreKit", "FacebookSDK", "FacebookCore"],
			pub: ["facebook_app_events"],
		},
	},
	{
		name: "Hotjar",
		kind: "session-replay",
		hosts: ["hotjar.com", "hotjar.io"],
		pattern: /static\.hotjar\.com|script\.hotjar\.com|\bhjid\s*:/,
		packages: { npm: ["@hotjar/browser", "react-hotjar"] },
	},
	{
		name: "Microsoft Clarity",
		kind: "session-replay",
		hosts: ["clarity.ms"],
		pattern: /clarity\.ms\/tag/,
		packages: { npm: ["@microsoft/clarity"] },
	},
	{
		name: "FullStory",
		kind: "session-replay",
		hosts: ["fullstory.com"],
		pattern:
			/fullstory\.com\/s\/fs\.js|edge\.fullstory\.com|window\['_fs_org'\]/,
		packages: {
			npm: ["@fullstory/browser", "@fullstory/react-native"],
			pub: ["fullstory_flutter"],
		},
	},
	{
		name: "LogRocket",
		kind: "session-replay",
		hosts: ["logrocket.io", "lr-ingest.io"],
		pattern: /cdn\.logrocket\.io|cdn\.lr-ingest\.io/,
		packages: {
			npm: [
				"logrocket",
				"logrocket-react",
				"logrocket-react-native",
				"@logrocket/react-native",
			],
		},
	},
	{
		name: "Mouseflow",
		kind: "session-replay",
		hosts: ["mouseflow.com"],
	},
	{
		name: "Lucky Orange",
		kind: "session-replay",
		hosts: ["luckyorange.com", "luckyorange.net"],
	},
	{
		name: "Smartlook",
		kind: "session-replay",
		hosts: ["smartlook.com"],
		packages: { npm: ["smartlook-client", "smartlook-react-native-wrapper"] },
	},
	{
		name: "Crazy Egg",
		kind: "session-replay",
		hosts: ["crazyegg.com"],
	},
	{
		name: "PostHog",
		kind: "analytics",
		hosts: ["posthog.com"],
		pattern: /posthog\.com\/static\/|\bposthog\.init\(/,
		packages: {
			npm: ["posthog-js", "posthog-react-native"],
			pypi: ["posthog"],
			go: ["github.com/posthog/posthog-go"],
			gem: ["posthog-ruby"],
			gradle: ["com.posthog:posthog-android"],
			pod: ["PostHog"],
			pub: ["posthog_flutter"],
		},
	},
	{
		name: "Segment",
		kind: "analytics",
		hosts: ["segment.com", "segment.io"],
		pattern: /cdn\.segment\.com\/analytics\.js/,
		packages: {
			npm: [
				"@segment/analytics-next",
				"@segment/analytics-node",
				"@segment/analytics-react-native",
				"analytics-node",
			],
			pypi: ["analytics-python", "segment-analytics-python"],
			go: ["github.com/segmentio/analytics-go"],
			gem: ["analytics-ruby"],
			gradle: ["com.segment.analytics.android:analytics"],
		},
	},
	{
		name: "Mixpanel",
		kind: "analytics",
		hosts: ["mxpnl.com", "mixpanel.com"],
		pattern: /cdn\.mxpnl\.com|mixpanel\.init\(/,
		packages: {
			npm: ["mixpanel", "mixpanel-browser", "mixpanel-react-native"],
			pypi: ["mixpanel"],
			gem: ["mixpanel-ruby"],
			gradle: ["com.mixpanel.android:mixpanel-android"],
			pod: ["Mixpanel", "Mixpanel-swift"],
			pub: ["mixpanel_flutter"],
		},
	},
	{
		name: "Amplitude",
		kind: "analytics",
		hosts: ["amplitude.com"],
		pattern: /cdn\.amplitude\.com|amplitude\.getInstance\(/,
		packages: {
			npm: [
				"@amplitude/analytics-browser",
				"@amplitude/analytics-node",
				"@amplitude/analytics-react-native",
				"amplitude-js",
			],
			pypi: ["amplitude-analytics"],
			gradle: ["com.amplitude:android-sdk", "com.amplitude:analytics-android"],
			pod: ["Amplitude", "AmplitudeSwift"],
			pub: ["amplitude_flutter"],
		},
	},
	{
		name: "Heap",
		kind: "analytics",
		hosts: ["heapanalytics.com"],
		pattern: /cdn\.heapanalytics\.com|heap\.load\(/,
		packages: { npm: ["@heap/react-native-heap"] },
	},
	{
		name: "Pendo",
		kind: "analytics",
		hosts: ["pendo.io"],
	},
	{
		name: "Adobe Analytics",
		kind: "analytics",
		hosts: ["omtrdc.net", "demdex.net", "2o7.net"],
	},
	{
		name: "Yandex Metrica",
		kind: "analytics",
		hosts: ["mc.yandex.ru", "mc.yandex.com"],
		pattern: /mc\.yandex\.ru\/metrika/,
	},
	{
		name: "Comscore / Quantcast measurement",
		kind: "analytics",
		hosts: ["scorecardresearch.com", "quantserve.com"],
	},
	{
		name: "Chartbeat",
		kind: "analytics",
		hosts: ["chartbeat.com", "chartbeat.net"],
	},
	{
		name: "LinkedIn Insight",
		kind: "advertising",
		hosts: ["snap.licdn.com", "px.ads.linkedin.com"],
		pattern: /snap\.licdn\.com|_linkedin_partner_id/,
	},
	{
		name: "TikTok Pixel",
		kind: "advertising",
		hosts: ["analytics.tiktok.com"],
		pattern: /analytics\.tiktok\.com|ttq\.load\(/,
	},
	{
		name: "X (Twitter) Pixel",
		kind: "advertising",
		hosts: ["static.ads-twitter.com", "analytics.twitter.com"],
		pattern: /static\.ads-twitter\.com|\btwq\(\s*['"]init/,
	},
	{
		name: "Microsoft Advertising (Bing UET)",
		kind: "advertising",
		hosts: ["bat.bing.com"],
		pattern: /bat\.bing\.com/,
	},
	{
		name: "Pinterest Tag",
		kind: "advertising",
		hosts: ["ct.pinterest.com"],
		pattern: /ct\.pinterest\.com|\bpintrk\(\s*['"]load/,
	},
	{
		name: "Snapchat Pixel",
		kind: "advertising",
		hosts: ["tr.snapchat.com", "sc-static.net"],
	},
	{
		name: "Criteo",
		kind: "advertising",
		hosts: ["criteo.com", "criteo.net"],
	},
	{
		name: "Taboola / Outbrain",
		kind: "advertising",
		hosts: ["taboola.com", "outbrain.com"],
	},
	{
		name: "HubSpot",
		kind: "marketing",
		hosts: ["hs-scripts.com", "hs-analytics.net", "track.hubspot.com"],
		pattern: /js\.hs-scripts\.com|js\.hs-analytics\.net/,
	},
	{
		name: "Intercom",
		kind: "marketing",
		hosts: ["intercom.io", "intercomcdn.com"],
		pattern: /widget\.intercom\.io|js\.intercomcdn\.com/,
	},
	{
		name: "Braze",
		kind: "marketing",
		hosts: ["braze.com", "appboy.com"],
		packages: {
			npm: ["@braze/web-sdk", "@braze/react-native-sdk", "appboy-web-sdk"],
			gradle: ["com.braze:android-sdk-ui", "com.braze:android-sdk-base"],
			pod: ["BrazeKit", "Appboy-iOS-SDK"],
			pub: ["braze_plugin"],
		},
	},
	{
		name: "FingerprintJS",
		kind: "fingerprinting",
		hosts: ["fingerprint.com", "fpjs.io", "fpcdn.io"],
		packages: {
			npm: [
				"@fingerprintjs/fingerprintjs",
				"@fingerprintjs/fingerprintjs-pro",
				"@fingerprintjs/fingerprintjs-pro-react",
				"@fingerprintjs/fingerprintjs-pro-react-native",
				"fingerprintjs2",
			],
			pub: ["fpjs_pro_plugin"],
		},
	},
	{
		name: "AppsFlyer",
		kind: "attribution",
		hosts: ["appsflyer.com"],
		packages: {
			npm: ["react-native-appsflyer", "appsflyer-capacitor-plugin"],
			pub: ["appsflyer_sdk"],
			gradle: ["com.appsflyer:af-android-sdk"],
			pod: ["AppsFlyerFramework"],
		},
	},
	{
		name: "Adjust",
		kind: "attribution",
		hosts: ["adjust.com"],
		packages: {
			npm: ["react-native-adjust", "@adjust/web-sdk", "@adjust/react-native"],
			pub: ["adjust_sdk"],
			gradle: ["com.adjust.sdk:adjust-android"],
			pod: ["Adjust"],
		},
	},
	{
		name: "Branch",
		kind: "attribution",
		hosts: ["branch.io"],
		packages: {
			npm: ["branch-sdk", "react-native-branch"],
			pub: ["flutter_branch_sdk"],
			gradle: ["io.branch.sdk.android:library"],
			pod: ["Branch"],
		},
	},
	{
		name: "Sentry",
		kind: "monitoring",
		hosts: ["sentry.io"],
		packages: {
			npm: [
				"@sentry/browser",
				"@sentry/react",
				"@sentry/vue",
				"@sentry/angular",
				"@sentry/svelte",
				"@sentry/nextjs",
				"@sentry/node",
				"@sentry/react-native",
				"@sentry/electron",
			],
			pypi: ["sentry-sdk"],
			go: ["github.com/getsentry/sentry-go"],
			gem: ["sentry-ruby", "sentry-rails"],
			gradle: ["io.sentry:sentry-android", "io.sentry:sentry"],
			pod: ["Sentry"],
			pub: ["sentry_flutter"],
			composer: ["sentry/sentry", "sentry/sentry-laravel"],
		},
	},
	{
		name: "Datadog RUM",
		kind: "monitoring",
		hosts: ["datadoghq-browser-agent.com", "browser-intake-datadoghq.com"],
		packages: {
			npm: ["@datadog/browser-rum", "@datadog/mobile-react-native"],
			pub: ["datadog_flutter_plugin"],
			gradle: ["com.datadoghq:dd-sdk-android-rum"],
		},
	},
	{
		name: "New Relic Browser",
		kind: "monitoring",
		hosts: ["nr-data.net", "js-agent.newrelic.com"],
	},
	{
		name: "Vercel Web Analytics",
		kind: "privacy-friendly analytics",
		hosts: [],
		packages: { npm: ["@vercel/analytics"] },
	},
	{
		name: "Plausible",
		kind: "privacy-friendly analytics",
		hosts: ["plausible.io"],
		pattern: /plausible\.io\/js\//,
		packages: { npm: ["plausible-tracker", "next-plausible"] },
	},
	{
		name: "Fathom",
		kind: "privacy-friendly analytics",
		hosts: ["usefathom.com"],
		pattern: /cdn\.usefathom\.com/,
		packages: { npm: ["fathom-client"] },
	},
	{
		name: "Matomo",
		kind: "privacy-friendly analytics",
		hosts: ["matomo.cloud"],
		pattern: /matomo\.(js|php)|piwik\.(js|php)/,
	},
];

/** True when `host` is `domain` or one of its subdomains. */
export const hostMatches = (host: string, domain: string): boolean =>
	host === domain || host.endsWith(`.${domain}`);

/** The tracker a request URL belongs to, by host or shared-host URL pattern. */
export const trackerForUrl = (url: string): Tracker | undefined => {
	let host: string;
	try {
		host = new URL(url).hostname.toLowerCase();
	} catch {
		return undefined;
	}
	return TRACKERS.find(
		(t) => t.hosts.some((h) => hostMatches(host, h)) || t.urlPattern?.test(url),
	);
};

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Static-HTML pattern for a tracker: its explicit pattern, else its hosts as URLs. */
export const staticPattern = (t: Tracker): RegExp | undefined =>
	t.pattern ??
	(t.hosts.length > 0
		? new RegExp(
				`//(?:[\\w-]+\\.)*(?:${t.hosts.map(escapeRe).join("|")})(?![\\w-])`,
			)
		: undefined);

/** Kinds whose traffic is not consent-exempt tracking (or is debatable). */
export const CONSENT_EXEMPT_KINDS: ReadonlySet<TrackerKind> = new Set([
	"tag-manager",
	"monitoring",
	"privacy-friendly analytics",
]);

/**
 * Cookie names set by analytics, advertising and attribution vendors. They
 * are not strictly necessary and need prior consent (ePrivacy Art. 5(3)).
 */
const TRACKING_COOKIES: ReadonlyArray<RegExp> = [
	/^(?:_ga|_gid|_gat|_gcl_|__utm|_dc_gtm_|__gads$|__gpi$)/i,
	/^(?:_fbp|_fbc)$/i,
	/^(?:_hj|hjSession|hjAbsolute)/i,
	/^(?:_clck|_clsk)$/i,
	/^(?:ajs_|amplitude|mp_|__mp)/i,
	/^(?:_uet|_ttp|_tt_)/i,
	/^(?:li_sugr|li_gc|li_fat_id|UserMatchHistory)$/i,
	/^(?:IDE|NID|test_cookie)$/,
	/^(?:_pin_|_pinterest_)/i,
	/^(?:_scid|sc_at)$/i,
	/^(?:ph_phc_|__hstc|__hssc|__hssrc|hubspotutk)/i,
	/^(?:_ym_|_ym_uid)/i,
	/^(?:_pk_)/i,
	/^(?:_lr_|_fs_|fs_uid)/i,
	/^(?:_rdt_uuid|_vwo_|optimizelyEndUserId)/i,
];

export const isTrackingCookie = (name: string): boolean =>
	TRACKING_COOKIES.some((re) => re.test(name));

/** localStorage/sessionStorage keys that hold tracker identifiers. */
export const isTrackingStorageKey = (key: string): boolean =>
	/^(?:_ga|ajs_|amplitude_|AMP_|mp_|__mpq|ph_phc_|_hj|_clck|_lr_|_fs_|__fs|_pk_|_fbp|mixpanel)/i.test(
		key,
	);

export interface ConsentPlatform {
	readonly name: string;
	/** Hosts of the CMP's script/API. */
	readonly hosts: ReadonlyArray<string>;
	/** Window globals the CMP defines. */
	readonly globals: ReadonlyArray<string>;
	/** CSS selectors of the CMP's banner element. */
	readonly selectors: ReadonlyArray<string>;
}

export const CONSENT_PLATFORMS: ReadonlyArray<ConsentPlatform> = [
	{
		name: "OneTrust",
		hosts: ["cookielaw.org", "onetrust.com"],
		globals: ["OneTrust", "OptanonWrapper"],
		selectors: ["#onetrust-banner-sdk", "#onetrust-consent-sdk"],
	},
	{
		name: "Cookiebot",
		hosts: ["cookiebot.com"],
		globals: ["Cookiebot"],
		selectors: ["#CybotCookiebotDialog"],
	},
	{
		name: "Didomi",
		hosts: ["didomi.io"],
		globals: ["Didomi"],
		selectors: ["#didomi-host", "#didomi-popup"],
	},
	{
		name: "Usercentrics",
		hosts: ["usercentrics.eu"],
		globals: ["UC_UI", "usercentrics"],
		selectors: ["#usercentrics-root", "#usercentrics-cmp-ui"],
	},
	{
		name: "Quantcast Choice",
		hosts: ["quantcast.mgr.consensu.org", "cmp.quantcast.com"],
		globals: ["__qc"],
		selectors: [".qc-cmp2-container", "#qc-cmp2-container"],
	},
	{
		name: "TrustArc",
		hosts: ["trustarc.com", "truste.com"],
		globals: ["truste", "TrustArc"],
		selectors: ["#truste-consent-track", "#teconsent"],
	},
	{
		name: "Osano",
		hosts: ["osano.com"],
		globals: ["Osano"],
		selectors: [".osano-cm-window", ".osano-cm-dialog"],
	},
	{
		name: "CookieYes",
		hosts: ["cookieyes.com", "cdn-cookieyes.com"],
		globals: ["getCkyConsent"],
		selectors: [".cky-consent-container", "#cookie-law-info-bar"],
	},
	{
		name: "Iubenda",
		hosts: ["iubenda.com"],
		globals: ["_iub"],
		selectors: ["#iubenda-cs-banner"],
	},
	{
		name: "Sourcepoint",
		hosts: ["sourcepoint.com", "sp-prod.net"],
		globals: ["_sp_"],
		selectors: ['[id^="sp_message_container"]'],
	},
	{
		name: "IAB TCF consent platform",
		hosts: [],
		globals: ["__tcfapi"],
		selectors: [],
	},
];

/** Heuristic selectors for banners from CMPs that are not in the list. */
export const GENERIC_BANNER_SELECTORS: ReadonlyArray<string> = [
	'[id*="cookie-banner" i]',
	'[id*="cookiebanner" i]',
	'[id*="cookie-consent" i]',
	'[id*="cookieconsent" i]',
	'[class*="cookie-banner" i]',
	'[class*="cookiebanner" i]',
	'[class*="cookie-consent" i]',
	'[class*="cookieconsent" i]',
	'[role="dialog"][aria-label*="cookie" i]',
];

/** Registrable domain (eTLD+1), using a short list of common two-label suffixes. */
const TWO_LABEL_SUFFIXES = new Set([
	"co.uk",
	"org.uk",
	"ac.uk",
	"gov.uk",
	"com.au",
	"net.au",
	"org.au",
	"co.nz",
	"co.jp",
	"co.kr",
	"co.in",
	"co.za",
	"com.br",
	"com.mx",
	"com.ar",
	"com.tr",
	"com.cn",
	"com.hk",
	"com.sg",
]);

export const registrableDomain = (host: string): string => {
	const h = host.toLowerCase().replace(/\.$/, "");
	if (/^[\d.]+$/.test(h) || h.includes(":") || !h.includes(".")) return h;
	const labels = h.split(".");
	const last2 = labels.slice(-2).join(".");
	return TWO_LABEL_SUFFIXES.has(last2) ? labels.slice(-3).join(".") : last2;
};
