import { afterAll, beforeAll, describe, expect, test } from "bun:test";

import { axeFindings, browser, vitalsFindings } from "../src/web/browser";
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
});
