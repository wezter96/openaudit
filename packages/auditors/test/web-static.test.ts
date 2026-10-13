import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import type { Report } from "@openaudit/core";

import { accessibility } from "../src/web/accessibility";
import { exposure } from "../src/web/exposure";
import { headers } from "../src/web/headers";
import { performanceAuditor } from "../src/web/performance";
import { privacy } from "../src/web/privacy";
import { seo } from "../src/web/seo";
import { ruleIds, runAuditor } from "./helpers";
import { badSite, goodSite, type Site, serve } from "./web-server";

let bad: Site;
let good: Site;
beforeAll(() => {
	bad = badSite();
	good = goodSite();
});
afterAll(() => {
	bad.stop();
	good.stop();
});

const unique = (report: Report) => [...new Set(ruleIds(report))];
const nonInfo = (report: Report) =>
	report.results.flatMap((r) =>
		r.findings.filter((f) => f.severity !== "info").map((f) => f.ruleId),
	);

describe("web auditors on a misconfigured site", () => {
	test("web.headers", async () => {
		const report = await runAuditor(headers, bad.url);
		expect(report.results[0]?.status).toBe("failed");
		expect(unique(report)).toEqual([
			"web.headers/clickjacking",
			"web.headers/cookie-no-samesite",
			"web.headers/cookie-not-httponly",
			"web.headers/coop-missing",
			"web.headers/corp-missing",
			"web.headers/cors-origin-reflected",
			"web.headers/csp-missing",
			"web.headers/permissions-policy-missing",
			"web.headers/referrer-policy-missing",
			"web.headers/version-disclosure",
			"web.headers/x-content-type-options-missing",
		]);
		const findings = report.results[0]?.findings ?? [];
		const cors = findings.find(
			(f) => f.ruleId === "web.headers/cors-origin-reflected",
		);
		expect(cors?.severity).toBe("high");
		const session = findings.find(
			(f) =>
				f.ruleId === "web.headers/cookie-not-httponly" &&
				f.location?.selector === "cookie:sessionid",
		);
		expect(session?.severity).toBe("medium");
		// Cookie values never appear in evidence.
		expect(findings.every((f) => !f.evidence?.includes("abc123"))).toBe(true);
	});

	test("web.seo", async () => {
		const report = await runAuditor(seo, bad.url);
		const ids = unique(report);
		for (const id of [
			"web.seo/robots-txt-blocks-all",
			"web.seo/title-missing",
			"web.seo/structured-data-invalid",
			"web.seo/broken-link",
			"web.seo/sitemap-missing",
			"web.seo/title-duplicate",
			"web.seo/meta-description-missing",
			"web.seo/canonical-missing",
			"web.seo/lang-missing",
		])
			expect(ids).toContain(id);
		const broken = report.results[0]?.findings.find(
			(f) => f.ruleId === "web.seo/broken-link",
		);
		expect(broken?.evidence).toContain("/missing.html → 404");
	});

	test("web.accessibility", async () => {
		const report = await runAuditor(accessibility, bad.url);
		const findings = report.results[0]?.findings ?? [];
		expect(unique(report)).toEqual([
			"web.accessibility/button-name",
			"web.accessibility/document-title-missing",
			"web.accessibility/duplicate-id",
			"web.accessibility/form-label",
			"web.accessibility/frame-title",
			"web.accessibility/heading-order",
			"web.accessibility/html-lang-missing",
			"web.accessibility/image-alt",
			"web.accessibility/link-name",
			"web.accessibility/positive-tabindex",
			"web.accessibility/table-headers",
			"web.accessibility/viewport-zoom-disabled",
		]);
		const alt = findings.find(
			(f) => f.ruleId === "web.accessibility/image-alt",
		);
		expect(alt?.location?.selector).toBe("body > img");
		expect(alt?.tags).toContain("wcag-1.1.1");
	});

	test("web.performance", async () => {
		const report = await runAuditor(performanceAuditor, bad.url);
		const ids = unique(report);
		for (const id of [
			"web.performance/render-blocking-script",
			"web.performance/uncompressed-assets",
			"web.performance/static-cache-short",
			"web.performance/image-no-dimensions",
			"web.performance/missing-preconnect",
		])
			expect(ids).toContain(id);
		// Only same-origin assets are sampled.
		expect(bad.requests.some((r) => r.includes("googletagmanager"))).toBe(
			false,
		);
	});

	test("web.exposure", async () => {
		const report = await runAuditor(exposure, bad.url);
		expect(unique(report)).toEqual([
			"web.exposure/directory-listing",
			"web.exposure/env-file-exposed",
			"web.exposure/git-exposed",
			"web.exposure/security-txt-missing",
			"web.exposure/source-map-exposed",
			"web.exposure/verbose-error",
		]);
		const env = report.results[0]?.findings.find(
			(f) => f.ruleId === "web.exposure/env-file-exposed",
		);
		expect(env?.severity).toBe("critical");
		expect(env?.evidence).toContain("DB_PASSWORD=");
		expect(env?.evidence).not.toContain("supersecretpassword");
	});

	test("web.privacy", async () => {
		const report = await runAuditor(privacy, bad.url);
		expect(unique(report)).toEqual([
			"web.privacy/privacy-policy-missing",
			"web.privacy/third-party-fonts",
			"web.privacy/tracker",
			"web.privacy/tracking-cookie-before-consent",
		]);
		const tracker = report.results[0]?.findings.find(
			(f) => f.ruleId === "web.privacy/tracker",
		);
		expect(tracker?.title).toBe("Google Analytics detected");
	});

	test("web.privacy uses the shared tracker list", async () => {
		const html = `<!doctype html><html lang="en"><head><title>t</title>
<script src="https://static.hotjar.com/c/hotjar-1.js"></script>
<script src="https://cdn.fpjs.io/v3/loader.js"></script>
<script src="https://static.criteo.net/js/ld/ld.js"></script>
<script src="https://browser.sentry-cdn.com/8.0.0/bundle.min.js"></script>
<script>Sentry.init({ dsn: "https://k@o1.ingest.sentry.io/1" });</script>
</head><body><a href="/privacy">Privacy</a></body></html>`;
		const site = serve(
			{
				"/": () =>
					new Response(html, { headers: { "content-type": "text/html" } }),
			},
			() => new Response("not found", { status: 404 }),
		);
		try {
			const report = await runAuditor(privacy, site.url);
			const trackers = report.results
				.flatMap((r) => r.findings)
				.filter((f) => f.ruleId === "web.privacy/tracker");
			expect(trackers.map((f) => [f.title, f.severity]).sort()).toEqual([
				["Criteo detected", "medium"],
				["FingerprintJS detected", "medium"],
				["Hotjar detected", "medium"],
			]);
		} finally {
			site.stop();
		}
	});

	test("respects maxPages and only sends GET/HEAD", async () => {
		const site = badSite();
		try {
			await runAuditor(seo, site.url, { maxPages: 1 });
			expect(site.requests).not.toContain("GET /about.html");
			expect(site.requests.every((r) => /^(GET|HEAD) /.test(r))).toBe(true);
		} finally {
			site.stop();
		}
	});
});

describe("web auditors on a healthy site", () => {
	for (const auditor of [
		headers,
		seo,
		accessibility,
		performanceAuditor,
		exposure,
		privacy,
	])
		test(`${auditor.id} reports nothing actionable`, async () => {
			const report = await runAuditor(auditor, good.url);
			expect(report.results[0]?.status).toBe("passed");
			expect(nonInfo(report)).toEqual([]);
		});

	test("soft-404 pages do not trigger exposure probes", async () => {
		const report = await runAuditor(exposure, good.url);
		expect(ruleIds(report)).toEqual([]);
	});
});

describe("non-URL targets", () => {
	test("skip", async () => {
		const report = await runAuditor(headers, import.meta.dir);
		expect(report.results).toEqual([]);
	});
});
