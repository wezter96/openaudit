import { describe, expect, test } from "bun:test";
import type { ProjectState, ScanSummary, TargetSummary } from "../src/api";
import { badgeSvg, cardSvg, verifyPageHtml } from "../src/render";
import { escapeXml, formatDate, textWidth } from "../src/svg";
import { STALE_AFTER, viewOf } from "../src/view";

const NOW = Date.UTC(2026, 9, 15, 12) / 1000;

const summary = (
	score: number,
	grade: TargetSummary["grade"],
): TargetSummary => ({
	score,
	grade,
	severities: { critical: 0, high: 1, medium: 2, low: 3, info: 0 },
	categories: [{ category: "security", score, grade }],
	auditors: { passed: 30, failed: 4, skipped: 12, error: 0 },
	suppressed: 3,
	configApplied: true,
	openauditVersion: "0.3.0",
});

const scan = (overrides: Partial<ScanSummary> = {}): ScanSummary => ({
	id: "0b6c2b8e-4c5a-4f55-9d9b-2f3d5a1c7e10",
	status: "ok",
	startedAt: NOW - 600,
	finishedAt: NOW - 300,
	commit: "0123456789abcdef0123456789abcdef01234567",
	openauditVersion: "0.3.0",
	codebase: summary(96, "A"),
	site: null,
	error: null,
	...overrides,
});

const project = (overrides: Partial<ProjectState> = {}): ProjectState => ({
	id: "acme-widgets",
	repo: "acme/widgets",
	site: null,
	status: "active",
	repoVerified: true,
	siteVerified: false,
	nextScanAt: NOW,
	...overrides,
});

describe("viewOf", () => {
	test("derives each state", () => {
		expect(viewOf(undefined, NOW).state).toBe("notfound");
		expect(viewOf("removed", NOW).state).toBe("removed");
		expect(viewOf(project(), NOW).state).toBe("pending");
		const ok = project({ latest: scan(), lastScan: scan() });
		expect(viewOf(ok, NOW).state).toBe("ok");
		expect(viewOf(ok, NOW + STALE_AFTER + 1).state).toBe("stale");
		const failed = scan({ status: "failed", codebase: null, error: "boom" });
		expect(
			viewOf(project({ latest: scan(), lastScan: failed }), NOW).state,
		).toBe("failed");
	});
});

describe("badgeSvg", () => {
	test("shows score, grade and date", () => {
		const svg = badgeSvg(
			viewOf(project({ latest: scan(), lastScan: scan() }), NOW),
		);
		expect(svg).toContain(">96 A<");
		expect(svg).toContain(">15 Oct 2026<");
		expect(svg).toContain('fill="#4c1"');
		expect(svg).toContain('aria-label="openaudit | 96 A | 15 Oct 2026"');
	});

	test("goes grey when stale and red when the scan failed", () => {
		const ok = project({ latest: scan(), lastScan: scan() });
		const stale = badgeSvg(viewOf(ok, NOW + STALE_AFTER + 1));
		expect(stale).not.toContain("#4c1");
		const failed = project({
			latest: scan(),
			lastScan: scan({ status: "failed", codebase: null }),
		});
		const svg = badgeSvg(viewOf(failed, NOW));
		expect(svg).toContain(">96 A<");
		expect(svg).toContain(">scan failed<");
	});

	test("labels pending, removed and unknown badges", () => {
		expect(badgeSvg(viewOf(project(), NOW))).toContain(">pending<");
		expect(badgeSvg(viewOf("removed", NOW))).toContain(">removed<");
		expect(badgeSvg(viewOf(undefined, NOW))).toContain(">not found<");
	});
});

describe("cardSvg", () => {
	test("shows the repo, both targets and severities", () => {
		const both = scan({ site: summary(81, "B") });
		const svg = cardSvg(viewOf(project({ latest: both, lastScan: both }), NOW));
		expect(svg).toContain(">acme/widgets<");
		expect(svg).toContain(">Codebase<");
		expect(svg).toContain(">Website<");
		expect(svg).toContain(">1 high<");
		expect(svg).toContain("scanned 15 Oct 2026");
	});

	test("escapes the repo name", () => {
		const svg = cardSvg(viewOf(project({ repo: 'a/<script>"&' }), NOW));
		expect(svg).not.toContain("<script>");
		expect(svg).toContain("a/&lt;script&gt;&quot;&amp;");
		expect(svg).toContain("Waiting for the first scan");
	});
});

describe("verifyPageHtml", () => {
	const origin = "https://openaudit.se";

	test("shows the latest scan, history and embed snippets", () => {
		const latest = scan({ site: summary(81, "B") });
		const html = verifyPageHtml({
			badge: viewOf(
				project({ site: "https://acme.dev/", latest, lastScan: latest }),
				NOW,
			),
			scans: [latest],
			origin,
		});
		expect(html).toContain(
			'href="https://github.com/acme/widgets/commit/0123456789abcdef0123456789abcdef01234567"',
		);
		expect(html).toContain('href="/v/acme-widgets/report"');
		expect(html).toContain('href="/v/acme-widgets/site-report"');
		expect(html).toContain(`?scan=${latest.id}`);
		expect(html).toContain("The repo&#39;s own openaudit config applied.");
		expect(html).toContain(
			"[![openaudit](https://openaudit.se/badge/acme-widgets.svg)](https://openaudit.se/v/acme-widgets)",
		);
		expect(html).toContain(
			"&lt;a href=&quot;https://openaudit.se/v/acme-widgets&quot;&gt;",
		);
		expect(html).not.toContain("<script");
	});

	test("escapes stored text and refuses odd commits", () => {
		const failed = scan({
			status: "failed",
			codebase: null,
			error: "<img src=x onerror=alert(1)>",
			commit: "javascript:alert(1)",
		});
		const html = verifyPageHtml({
			badge: viewOf(
				project({ latest: scan({ commit: "zz" }), lastScan: failed }),
				NOW,
			),
			scans: [failed],
			origin,
		});
		expect(html).not.toContain("<img src=x");
		expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
		expect(html).not.toContain("javascript:");
	});

	test("says when a badge is missing or removed", () => {
		expect(
			verifyPageHtml({ badge: viewOf(undefined, NOW), scans: [], origin }),
		).toContain("No such badge");
		expect(
			verifyPageHtml({ badge: viewOf("removed", NOW), scans: [], origin }),
		).toContain("Badge removed");
	});
});

describe("svg helpers", () => {
	test("escape, measure and date", () => {
		expect(escapeXml(`<a href="x">'&'</a>`)).toBe(
			"&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;",
		);
		expect(textWidth("openaudit")).toBeGreaterThan(40);
		expect(textWidth("mmm")).toBeGreaterThan(textWidth("iii"));
		expect(formatDate(NOW)).toBe("15 Oct 2026");
	});
});
