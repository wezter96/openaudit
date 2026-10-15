import { describe, expect, test } from "bun:test";

import {
	type LighthouseReport,
	lighthouse,
	parseLighthouse,
} from "../src/web/lighthouse";
import { fixture, runAuditor } from "./helpers";
import { must } from "./must";

const sample = (): Promise<LighthouseReport> =>
	Bun.file(fixture("web", "lighthouse", "report.json")).json();

describe("web.lighthouse", () => {
	test("maps failing audits to findings by category", async () => {
		const findings = parseLighthouse(await sample());
		const byRule = Object.fromEntries(findings.map((f) => [f.ruleId, f]));
		expect(Object.keys(byRule).sort()).toEqual([
			"web.lighthouse/errors-in-console",
			"web.lighthouse/image-alt",
			"web.lighthouse/largest-contentful-paint",
			"web.lighthouse/meta-description",
			"web.lighthouse/render-blocking-resources",
		]);

		const lcp = must(byRule["web.lighthouse/largest-contentful-paint"], "lcp");
		expect(lcp.severity).toBe("high");
		expect(lcp.category).toBe("performance");
		expect(lcp.message).toContain("5.1 s");
		expect(lcp.references).toEqual([
			"https://developer.chrome.com/docs/lighthouse/performance/lighthouse-largest-contentful-paint/",
		]);

		const alt = must(byRule["web.lighthouse/image-alt"], "image-alt");
		expect(alt.category).toBe("accessibility");
		expect(alt.severity).toBe("high");
		expect(alt.location).toEqual({
			url: "https://example.com/",
			selector: "body > main > img.hero",
		});
		expect(alt.evidence).toContain('<img class="hero"');

		expect(byRule["web.lighthouse/errors-in-console"]?.category).toBe(
			"best-practices",
		);
		expect(byRule["web.lighthouse/meta-description"]?.category).toBe("seo");
		// Passing (score ≥ 0.9), not-applicable and informative audits are ignored.
		expect(byRule["web.lighthouse/first-contentful-paint"]).toBeUndefined();
		expect(byRule["web.lighthouse/document-title"]).toBeUndefined();
	});

	test("skips with an install hint when lighthouse is not on PATH", async () => {
		if (Bun.which("lighthouse")) return;
		const report = await runAuditor(lighthouse, "http://127.0.0.1:9/");
		expect(report.results[0]?.status).toBe("skipped");
		expect(report.results[0]?.message).toContain("npm i -g lighthouse");
	});
});
