import { afterAll, beforeAll, describe, expect, test } from "bun:test";

import {
	axeFindings,
	browser,
	type ConsentSnapshot,
	consentFindings,
	vitalsFindings,
} from "../src/web/browser";
import { runAuditor } from "./helpers";
import { browserSite, redirectingSite, type Site, serve } from "./web-server";

let site: Site;
beforeAll(() => {
	site = browserSite();
});
afterAll(() => site.stop());

describe("webapp.browser", () => {
	test("maps axe violations and web vitals", () => {
		const axe = axeFindings("http://x/", [
			{
				id: "image-alt",
				impact: "critical",
				help: "Images must have alternate text",
				description: "Ensures <img> elements have alternate text",
				helpUrl: "https://dequeuniversity.com/rules/axe/4.10/image-alt",
				tags: ["cat.text-alternatives", "wcag2a", "wcag111"],
				nodes: [
					{
						target: ["main > img"],
						html: '<img src="a.png">',
						summary: "Fix any of the following",
					},
				],
			},
		]);
		expect(axe).toHaveLength(1);
		expect(axe[0]).toMatchObject({
			ruleId: "webapp.browser/axe-image-alt",
			severity: "high",
			category: "accessibility",
			location: { url: "http://x/", selector: "main > img" },
		});
		expect(axe[0]?.tags).toContain("wcag-1.1.1");

		const vitals = vitalsFindings("http://x/", {
			lcp: 5000,
			cls: 0.15,
			tbt: 100,
			longTasks: 1,
			transfer: 1000,
			requests: 3,
			heap: 0,
		});
		expect(vitals.map((f) => [f.ruleId, f.severity])).toEqual([
			["webapp.browser/lcp", "high"],
			["webapp.browser/cls", "medium"],
		]);
	});

	test("audits a rendered page (or skips when no browser can launch)", async () => {
		const report = await runAuditor(browser, site.url, {
			browser: true,
			maxPages: 1,
		});
		const result = report.results[0];
		if (result?.status === "skipped") {
			expect(result.message).toContain("playwright install chromium");
			return;
		}
		expect(result?.status).toBe("failed");
		const ids = new Set(result?.findings.map((f) => f.ruleId));
		expect(ids.has("webapp.browser/axe-image-alt")).toBe(true);
		expect(ids.has("webapp.browser/axe-button-name")).toBe(true);
		expect(ids.has("webapp.browser/console-error")).toBe(true);
		expect(ids.has("webapp.browser/uncaught-exception")).toBe(true);
		expect(ids.has("webapp.browser/failed-request")).toBe(true);
	}, 90_000);

	test("runs axe on pages with a strict CSP", async () => {
		const strict = serve(
			{
				"/": () =>
					new Response(
						'<!doctype html><html lang="en"><head><title>CSP</title></head><body><main><img src="data:,"></main></body></html>',
						{
							headers: {
								"content-type": "text/html; charset=utf-8",
								"content-security-policy":
									"default-src 'none'; script-src 'none'; img-src data:",
							},
						},
					),
			},
			() => new Response("not found", { status: 404 }),
		);
		try {
			const report = await runAuditor(browser, strict.url, {
				browser: true,
				maxPages: 1,
			});
			const result = report.results[0];
			if (result?.status === "skipped") return;
			expect(result?.status).not.toBe("error");
			expect(result?.findings.map((f) => f.ruleId)).toContain(
				"webapp.browser/axe-image-alt",
			);
		} finally {
			strict.stop();
		}
	}, 90_000);

	test("is not selected without --browser", async () => {
		const report = await runAuditor(browser, site.url);
		expect(report.results).toEqual([]);
	});

	test("does not forward user headers across a same-origin redirect", async () => {
		const other = serve(
			{
				"/other.js": () =>
					new Response("void 0", {
						headers: { "content-type": "application/javascript" },
					}),
				"/other.png": () =>
					new Response(new Uint8Array(8), {
						headers: { "content-type": "image/png" },
					}),
			},
			() => new Response("not found", { status: 404 }),
		);
		const target = redirectingSite(other.url);
		try {
			const report = await runAuditor(browser, target.url, {
				browser: true,
				maxPages: 1,
				headers: { "x-openaudit-secret": "s3cret" },
			});
			if (report.results[0]?.status === "skipped") return;
			const secret = (s: Site) =>
				s.received
					.filter((r) => r.headers.get("x-openaudit-secret") === "s3cret")
					.map((r) => r.path);
			// The browser saw the target with the header and followed both redirects...
			expect(secret(target)).toContain("/hop.js");
			expect(secret(target)).toContain("/hop.png");
			expect(other.received.map((r) => r.path)).toEqual(
				expect.arrayContaining(["/other.js", "/other.png"]),
			);
			// ...but the other origin never received it.
			expect(secret(other)).toEqual([]);
		} finally {
			target.stop();
			other.stop();
		}
	}, 90_000);

	describe("consent", () => {
		const snapshot = (
			over: Partial<ConsentSnapshot> = {},
		): ConsentSnapshot => ({
			pageUrl: "https://www.example.com/",
			requests: [],
			cookies: [],
			storageKeys: [],
			cmps: [],
			bannerVisible: false,
			...over,
		});
		const cookie = (name: string, domain = ".example.com") => ({
			name,
			domain,
			httpOnly: false,
			secure: true,
			sameSite: "Lax",
			expires: Date.now() / 1000 + 400 * 86_400,
			viaScript: true,
		});
		const byRule = (fs: ReturnType<typeof consentFindings>, id: string) =>
			fs.filter((f) => f.ruleId === `webapp.browser/${id}`);

		test("reports trackers, tracking cookies and storage fired before consent", () => {
			const fs = consentFindings(
				snapshot({
					requests: [
						"https://www.example.com/app.js",
						"https://cdn.example.com/a.png",
						"https://www.google-analytics.com/g/collect?v=2&tid=G-X",
						"https://region1.google-analytics.com/g/collect",
						"https://www.googletagmanager.com/gtag/js?id=G-ABCDE12345",
						"https://connect.facebook.net/en_US/fbevents.js",
						"https://static.hotjar.com/c/hotjar-1.js",
						"https://o1.ingest.sentry.io/api/1/envelope/",
						"https://fonts.gstatic.com/s/x.woff2",
						"data:image/png;base64,AAAA",
					],
					cookies: [cookie("_ga"), cookie("session", "www.example.com")],
					storageKeys: ["ajs_user_id", "theme"],
					cmps: ["OneTrust"],
					bannerVisible: true,
				}),
			);
			const trackers = byRule(fs, "tracker-before-consent");
			expect(trackers.map((f) => f.title).sort()).toEqual([
				"Google Analytics contacted before consent",
				"Hotjar contacted before consent",
				"Meta Pixel / Facebook SDK contacted before consent",
			]);
			for (const f of trackers) {
				expect(f.severity).toBe("medium");
				expect(f.category).toBe("privacy");
				expect(f.tags).toEqual(expect.arrayContaining(["gdpr", "eprivacy"]));
				expect(f.confidence).toBe("high");
				// no query strings in evidence
				expect(f.evidence).not.toContain("?");
				expect(f.evidence).not.toContain("tid=");
			}
			const ga = trackers.find((f) => f.title.startsWith("Google Analytics"));
			expect(ga?.message).toContain("3 requests");
			const cookies = byRule(fs, "tracking-cookie-before-consent");
			expect(cookies).toHaveLength(1);
			expect(cookies[0]?.evidence).toContain("_ga");
			expect(cookies[0]?.evidence).not.toContain("session");
			expect(byRule(fs, "tracking-storage-before-consent")[0]?.evidence).toBe(
				"ajs_user_id",
			);
			expect(byRule(fs, "consent-banner-bypassed")).toHaveLength(1);
			expect(byRule(fs, "consent-platform")[0]?.evidence).toBe("OneTrust");

			const third = byRule(fs, "third-party-requests")[0];
			expect(third?.severity).toBe("info");
			expect(third?.message).toContain("www.google-analytics.com (1)");
			expect(third?.message).toContain("static.hotjar.com (1)");
			expect(third?.message).not.toContain("cdn.example.com");
			expect(byRule(fs, "storage-before-interaction")[0]?.severity).toBe(
				"info",
			);
		});

		test("uses lower confidence without a banner and detects CMPs by host", () => {
			const fs = consentFindings(
				snapshot({
					requests: [
						"https://cdn.cookielaw.org/scripttemplates/otSDKStub.js",
						"https://analytics.tiktok.com/i18n/pixel/events.js",
					],
				}),
			);
			const t = byRule(fs, "tracker-before-consent");
			expect(t).toHaveLength(1);
			expect(t[0]?.confidence).toBe("medium");
			expect(t[0]?.message).toContain("OneTrust");
			expect(byRule(fs, "consent-banner-bypassed")).toEqual([]);
			expect(byRule(fs, "consent-platform")[0]?.evidence).toBe("OneTrust");
		});

		test("does not flag first-party, consent-exempt or privacy-friendly requests", () => {
			const fs = consentFindings(
				snapshot({
					pageUrl: "https://www.hotjar.com/",
					requests: [
						"https://static.hotjar.com/c/hotjar-1.js",
						"https://www.googletagmanager.com/gtm.js?id=GTM-ABCD",
						"https://o1.ingest.sentry.io/api/1/envelope/",
						"https://plausible.io/api/event",
					],
					cookies: [cookie("csrftoken"), cookie("sid")],
				}),
			);
			expect(byRule(fs, "tracker-before-consent")).toEqual([]);
			expect(byRule(fs, "tracking-cookie-before-consent")).toEqual([]);
			expect(byRule(fs, "consent-banner-bypassed")).toEqual([]);
		});
	});

	test("passively records cookies, storage, banner and third-party hosts before consent", async () => {
		const other = serve(
			{
				"/lib.js": () =>
					new Response("void 0", {
						headers: { "content-type": "application/javascript" },
					}),
			},
			() => new Response("not found", { status: 404 }),
		);
		const thirdParty = other.url.replace("127.0.0.1", "localhost");
		const target = serve(
			{
				"/": () =>
					new Response(
						`<!doctype html><html lang="en"><head><title>Consent fixture</title>
<script src="${thirdParty}lib.js"></script>
<script>document.cookie = "_ga=GA1.1.123456; path=/; max-age=31536000"; document.cookie = "theme=dark; path=/"; localStorage.setItem("ajs_user_id", "secret-user-value"); localStorage.setItem("prefs", "x");</script>
</head><body><main><h1>Hello</h1>
<div id="onetrust-banner-sdk" style="position:fixed;bottom:0;width:100%;height:80px">We use cookies <button>Accept</button></div>
</main></body></html>`,
						{
							headers: {
								"content-type": "text/html",
								"set-cookie": "srv_session=abc123secret; Path=/; HttpOnly",
							},
						},
					),
			},
			() => new Response("not found", { status: 404 }),
		);
		try {
			const report = await runAuditor(browser, target.url, {
				browser: true,
				maxPages: 1,
			});
			const result = report.results[0];
			if (result?.status === "skipped") return;
			const findings = result?.findings ?? [];
			const rule = (id: string) =>
				findings.filter((f) => f.ruleId === `webapp.browser/${id}`);

			const cookies = rule("tracking-cookie-before-consent");
			expect(cookies).toHaveLength(1);
			expect(cookies[0]?.evidence).toContain("_ga");
			expect(cookies[0]?.confidence).toBe("high");
			expect(rule("tracking-storage-before-consent")[0]?.evidence).toBe(
				"ajs_user_id",
			);
			expect(rule("consent-platform")[0]?.evidence).toBe("OneTrust");
			const third = rule("third-party-requests")[0];
			expect(third?.message).toContain("localhost");
			const inventory = rule("storage-before-interaction")[0];
			expect(inventory?.message).toContain("srv_session");
			expect(inventory?.message).toContain("prefs");

			// Cookie and storage values never leave the browser.
			const all = JSON.stringify(findings);
			for (const value of ["GA1.1.123456", "abc123secret", "secret-user-value"])
				expect(all).not.toContain(value);
			// Passive: the page was only fetched.
			expect(target.requests.every((r) => /^(GET|HEAD) /.test(r))).toBe(true);
		} finally {
			target.stop();
			other.stop();
		}
	}, 90_000);
});
