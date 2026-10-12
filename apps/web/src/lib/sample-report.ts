import type { Finding, Report } from "@openaudit/core/model";

/** Illustrative report for a fictional shop, used before a live audit runs. */

const f = (
	auditor: string,
	finding: Omit<Finding, "auditor" | "fingerprint">,
	fingerprint: string,
): Finding => ({ ...finding, auditor, fingerprint });

const url = "https://shop.example.com/";

const headers = [
	f(
		"web.headers",
		{
			ruleId: "web.headers/csp-missing",
			title: "No Content-Security-Policy",
			severity: "medium",
			category: "security",
			message:
				"The page is served without a Content-Security-Policy header, so injected scripts run with full privileges.",
			location: { url },
			remediation:
				"Start with `Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'` and tighten from report-only data.",
			references: [
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP",
			],
			tags: ["cwe-693", "owasp-a05"],
			confidence: "high",
		},
		"3f1c0a9b2d7e4410",
	),
	f(
		"web.headers",
		{
			ruleId: "web.headers/hsts-short-max-age",
			title: "HSTS max-age below six months",
			severity: "low",
			category: "security",
			message:
				"Strict-Transport-Security is set with max-age=86400 (1 day). Browsers forget the policy quickly.",
			location: { url },
			evidence: "strict-transport-security: max-age=86400",
			remediation: "Use max-age=31536000; includeSubDomains.",
			confidence: "high",
		},
		"a91e33c07b5d2f68",
	),
	f(
		"web.headers",
		{
			ruleId: "web.headers/security-txt-missing",
			title: "No /.well-known/security.txt",
			severity: "info",
			category: "best-practices",
			message:
				"Researchers have no published way to report vulnerabilities to you.",
			location: { url: "https://shop.example.com/.well-known/security.txt" },
			remediation:
				"Publish a security.txt with a Contact and Expires field (RFC 9116).",
		},
		"5d0e8f21c4b3a977",
	),
];

const cookies = [
	f(
		"web.cookies",
		{
			ruleId: "web.cookies/missing-secure",
			title: "Session cookie without Secure",
			severity: "medium",
			category: "security",
			message:
				"Cookie `sid` is set without the Secure attribute and can leak over plain HTTP.",
			location: { url },
			evidence: "set-cookie: sid=9f2c****; Path=/; HttpOnly",
			remediation: "Add `Secure; SameSite=Lax` to the session cookie.",
			tags: ["cwe-614"],
		},
		"c2b7d9e0a1f34b56",
	),
];

const a11y = [
	f(
		"web.a11y",
		{
			ruleId: "web.a11y/img-alt-missing",
			title: "Images without alternative text",
			severity: "high",
			category: "accessibility",
			message:
				"14 images have no alt attribute. Screen reader users hear the file name or nothing.",
			location: { url, selector: "main .product-card img" },
			evidence: '<img src="/img/p/3321.webp" class="thumb">',
			remediation:
				'Describe each product image in `alt`; use `alt=""` for decorative ones.',
			tags: ["wcag-1.1.1"],
		},
		"77ad01be9c3e4d20",
	),
	f(
		"web.a11y",
		{
			ruleId: "web.a11y/input-label-missing",
			title: "Form field without a label",
			severity: "medium",
			category: "accessibility",
			message: "The newsletter email field has a placeholder but no label.",
			location: { url, selector: "footer form input[type=email]" },
			remediation:
				"Associate a visible <label for> with the input, or at least aria-label.",
			tags: ["wcag-1.3.1", "wcag-4.1.2"],
		},
		"0b9f5e2d6c1a8e43",
	),
];

const seo = [
	f(
		"web.seo",
		{
			ruleId: "web.seo/meta-description-missing",
			title: "No meta description",
			severity: "low",
			category: "seo",
			message: "Search results will show an arbitrary text excerpt.",
			location: { url },
			remediation: "Add a 120–160 character <meta name=description>.",
		},
		"e4c1a7b9035d2f1e",
	),
	f(
		"web.seo",
		{
			ruleId: "web.seo/canonical-missing",
			title: "No canonical link",
			severity: "low",
			category: "seo",
			message:
				"Product pages are reachable with tracking parameters and have no rel=canonical.",
			location: { url: "https://shop.example.com/p/3321?ref=mail" },
			remediation: 'Add <link rel="canonical"> pointing at the clean URL.',
		},
		"9a3d6b0e1f7c2e85",
	),
];

const privacy = [
	f(
		"web.privacy",
		{
			ruleId: "web.privacy/third-party-before-consent",
			title: "Trackers load before consent",
			severity: "medium",
			category: "privacy",
			message:
				"Two analytics scripts from third-party origins load on first paint, before any consent choice.",
			location: { url },
			evidence: "connect.facebook.net, www.googletagmanager.com",
			remediation:
				"Load analytics only after opt-in, or switch to a cookieless first-party setup.",
			tags: ["gdpr", "eprivacy"],
			confidence: "medium",
		},
		"1e6c9d4a2b8f0c73",
	),
];

const perf = [
	f(
		"web.performance",
		{
			ruleId: "web.performance/oversized-images",
			title: "Oversized images",
			severity: "medium",
			category: "performance",
			message:
				"The home page transfers 3.8 MB of images; the largest is 1.2 MB for a 320 px slot.",
			location: { url: "https://shop.example.com/img/hero.jpg" },
			remediation:
				"Serve responsive AVIF/WebP with srcset and size images to their slot.",
		},
		"6b2e0f9c3d1a7e54",
	),
	f(
		"web.performance",
		{
			ruleId: "web.performance/no-compression",
			title: "JavaScript served uncompressed",
			severity: "low",
			category: "performance",
			message: "app.js (412 kB) is served without gzip or brotli.",
			location: { url: "https://shop.example.com/assets/app.js" },
			remediation: "Enable brotli or gzip for text assets at the CDN.",
		},
		"d8a1c3e7f2b05946",
	),
];

const counts = (findings: ReadonlyArray<Finding>) => {
	const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
	for (const x of findings) c[x.severity]++;
	return c;
};

const all = [...headers, ...cookies, ...a11y, ...seo, ...privacy, ...perf];
const inCat = (cat: Finding["category"]) =>
	counts(all.filter((x) => x.category === cat));

export const sampleReport: Report = {
	schemaVersion: "1",
	tool: { name: "openaudit", version: "0.1.0" },
	target: {
		input: url,
		type: "url",
		kinds: ["url"],
		url,
		technologies: [],
	},
	startedAt: "2026-10-12T09:14:03.000Z",
	finishedAt: "2026-10-12T09:14:11.400Z",
	durationMs: 8400,
	summary: {
		score: 86,
		grade: "B",
		counts: counts(all),
		categories: [
			{
				category: "security",
				score: 78,
				grade: "C",
				counts: inCat("security"),
			},
			{
				category: "accessibility",
				score: 67,
				grade: "D",
				counts: inCat("accessibility"),
			},
			{
				category: "performance",
				score: 87,
				grade: "B",
				counts: inCat("performance"),
			},
			{ category: "seo", score: 95, grade: "A", counts: inCat("seo") },
			{ category: "privacy", score: 89, grade: "B", counts: inCat("privacy") },
			{
				category: "best-practices",
				score: 100,
				grade: "A",
				counts: inCat("best-practices"),
			},
		],
		auditors: { passed: 1, failed: 6, skipped: 1, error: 0 },
	},
	results: [
		{
			auditor: "web.headers",
			title: "HTTP security headers",
			engine: "builtin",
			categories: ["security", "best-practices"],
			status: "failed",
			durationMs: 412,
			findings: headers,
		},
		{
			auditor: "web.tls",
			title: "TLS and HTTPS redirects",
			engine: "builtin",
			categories: ["security"],
			status: "passed",
			durationMs: 655,
			findings: [],
		},
		{
			auditor: "web.cookies",
			title: "Cookie attributes",
			engine: "builtin",
			categories: ["security", "privacy"],
			status: "failed",
			durationMs: 120,
			findings: cookies,
		},
		{
			auditor: "web.a11y",
			title: "Accessibility (static markup)",
			engine: "builtin",
			categories: ["accessibility"],
			status: "failed",
			durationMs: 980,
			findings: a11y,
		},
		{
			auditor: "web.seo",
			title: "SEO essentials",
			engine: "builtin",
			categories: ["seo"],
			status: "failed",
			durationMs: 1430,
			findings: seo,
		},
		{
			auditor: "web.privacy",
			title: "Third parties and consent",
			engine: "builtin",
			categories: ["privacy"],
			status: "failed",
			durationMs: 860,
			findings: privacy,
		},
		{
			auditor: "web.performance",
			title: "Transfer size and caching",
			engine: "builtin",
			categories: ["performance"],
			status: "failed",
			durationMs: 2210,
			findings: perf,
		},
		{
			auditor: "web.lighthouse",
			title: "Lighthouse",
			engine: "external",
			categories: ["performance", "accessibility", "seo", "best-practices"],
			status: "skipped",
			message:
				"lighthouse not found on PATH. Install with: npm i -g lighthouse",
			durationMs: 3,
			findings: [],
		},
	],
};
