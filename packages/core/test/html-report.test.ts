import { describe, expect, test } from "bun:test";

import {
	type AuditorResult,
	CWE_TO_OWASP_2021,
	CWE_TOP25_2024,
	canonicalize,
	type Finding,
	groupByCweTop25,
	groupByOwasp,
	OWASP_TOP10_2021,
	owaspMatchesOf,
	type Report,
	summarize,
	toHtml,
} from "../src";
import { CSV_COLUMNS, csvCell, toCsv } from "../src/reporters/csv";

const finding = (overrides: Partial<Finding>): Finding => ({
	ruleId: "code.secrets/aws-key",
	title: "AWS access key committed",
	severity: "critical",
	category: "security",
	message: "An AWS access key is hard-coded.",
	location: { file: "src/config.ts", line: 12, column: 7 },
	evidence: "AKIA************",
	remediation: "Rotate the key and load it from the environment.",
	references: ["https://docs.aws.amazon.com/keys", "CWE-798"],
	tags: ["cwe-798", "owasp-a07"],
	auditor: "code.secrets",
	fingerprint: "aaaaaaaaaaaaaaaa",
	...overrides,
});

const results: AuditorResult[] = [
	{
		auditor: "code.secrets",
		title: "Secrets",
		engine: "builtin",
		categories: ["security"],
		status: "failed",
		durationMs: 12,
		findings: [
			finding({ alsoReportedBy: ["code.gitleaks"] }),
			finding({
				ruleId: "code.secrets/generic",
				title: "<script>alert('xss')</script>",
				severity: "medium",
				message:
					'Message with <img src=x onerror=alert(1)> & "quotes" \u2028 \u2029 <!-- x',
				location: { file: "src/my file.ts", line: 3 },
				evidence: "</script><script>alert(2)</script>",
				references: ["javascript:alert(3)"],
				tags: ["cwe-79"],
				fingerprint: "bbbbbbbbbbbbbbbb",
			}),
		],
	},
	{
		auditor: "code.gitleaks",
		title: "Gitleaks",
		engine: "external",
		categories: ["security"],
		status: "failed",
		durationMs: 40,
		findings: [
			finding({
				ruleId: "code.gitleaks/aws-access-token",
				title: "DUPLICATE-ONLY-TITLE",
				auditor: "code.gitleaks",
				fingerprint: "eeeeeeeeeeeeeeee",
				duplicateOf: "aaaaaaaaaaaaaaaa",
			}),
		],
	},
	{
		auditor: "web.headers",
		title: "Security headers",
		engine: "builtin",
		categories: ["security", "best-practices"],
		status: "failed",
		durationMs: 30,
		findings: [
			finding({
				ruleId: "web.headers/csp-missing",
				title: "No Content-Security-Policy",
				severity: "high",
				location: { url: "https://example.com/", selector: "head" },
				evidence: undefined,
				confidence: "low",
				tags: ["cwe-693", "owasp-a05"],
				auditor: "web.headers",
				fingerprint: "cccccccccccccccc",
			}),
			finding({
				ruleId: "web.headers/server-banner",
				title: "Server banner",
				severity: "info",
				category: "best-practices",
				location: undefined,
				tags: [],
				auditor: "web.headers",
				fingerprint: "dddddddddddddddd",
			}),
		],
	},
	{
		auditor: "web.lighthouse",
		title: "Lighthouse",
		engine: "external",
		categories: ["performance"],
		status: "skipped",
		message: "lighthouse not found on PATH. Install: npm i -g lighthouse",
		durationMs: 0,
		findings: [],
	},
];

const report: Report = {
	schemaVersion: "1",
	tool: { name: "openaudit", version: "0.1.0" },
	target: {
		input: ".",
		type: "directory",
		root: "/work/my repo",
		kinds: ["codebase"],
		technologies: ["node", "typescript"],
	},
	startedAt: "2026-01-01T00:00:00.000Z",
	finishedAt: "2026-01-01T00:00:01.500Z",
	durationMs: 1500,
	summary: summarize(results),
	results,
	ai: {
		model: "claude-test",
		summary: "Rotate the <b>leaked</b> key first.",
		priorities: [
			{
				title: "Rotate keys",
				why: "A live key is in git.",
				fix: "Rotate and purge history.",
				fingerprints: ["aaaaaaaaaaaaaaaa"],
			},
		],
	},
};

const html = toHtml(report);
/** The page without the embedded JSON copy of the report. */
const markup = html.slice(0, html.indexOf('<script type="application/json"'));
const dataBlock =
	html.match(
		/<script type="application\/json" id="data-json"[^>]*>([\s\S]*?)<\/script>/,
	)?.[1] ?? "";

describe("html document", () => {
	test("is self-contained and accessible", () => {
		expect(html.startsWith("<!doctype html>")).toBe(true);
		expect(html).toContain('<html lang="en">');
		for (const landmark of ["<header", "<nav", '<main id="main"', "<footer"])
			expect(html).toContain(landmark);
		expect(html).toContain('<a class="skip" href="#main">');
		expect(html).toContain('<label for="security-q">Search</label>');
		expect(html).toContain('role="img" aria-label="Overall score');
		expect(html).toContain("prefers-color-scheme:dark");
		expect(html).toContain("@media print");
		expect(markup.match(/<h1[\s>]/g)).toHaveLength(1);
		// No external resources, no inline handlers. The one <link> is the
		// favicon, inlined as a data: URI.
		expect(html).not.toMatch(/<(img|iframe)\b/);
		const links = html.match(/<link\b[^>]*>/g) ?? [];
		expect(links).toHaveLength(1);
		expect(links[0]).toContain('rel="icon" href="data:image/svg+xml,');
		expect(html).not.toMatch(/\s(src)=["']https?:/);
		expect(markup).not.toMatch(/<[^>]*\son[a-z]+=/i);
		expect(html).toContain("default-src 'none'");
		// Ids are unique.
		const ids = [...markup.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]);
		expect(new Set(ids).size).toBe(ids.length);
	});

	test("CSP hashes match the inline style and script", () => {
		const csp = html.match(/content="(default-src[^"]+)"/)?.[1] ?? "";
		const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1] ?? "";
		const style = html.match(/<style>([\s\S]*?)<\/style>/)?.[1] ?? "";
		const hash = (s: string) =>
			new Bun.CryptoHasher("sha256").update(s).digest("base64");
		expect(script.length).toBeGreaterThan(100);
		expect(csp).toContain(`'sha256-${hash(script)}'`);
		expect(csp).toContain(`'sha256-${hash(style)}'`);
		expect(csp).not.toContain("unsafe-inline");
		// The inline script must at least parse.
		expect(() => new Function(script)).not.toThrow();
	});
});

describe("tabs", () => {
	const tabs = [...markup.matchAll(/<button[^>]*role="tab"[^>]*>/g)].map(
		(m) => m[0],
	);
	const panelIds = [
		"overview",
		...report.summary.categories.map((c) => c.category),
		"standards",
		"auditors",
	];

	test("one tab per panel, in a hidden tablist that JS reveals", () => {
		expect(markup).toContain('role="tablist"');
		expect(markup).toMatch(/<nav class="rail" id="tabbar"[^>]*hidden>/);
		expect(tabs.map((t) => t.match(/aria-controls="([^"]+)"/)?.[1])).toEqual(
			panelIds,
		);
		for (const id of panelIds) {
			expect(markup).toContain(`<section class="panel" id="${id}"`);
			expect(markup).toContain(`id="tab-${id}"`);
		}
	});

	test("first tab is selected and the only one in the tab order", () => {
		expect(tabs[0]).toContain('aria-selected="true"');
		expect(tabs[0]).toContain('tabindex="0"');
		for (const tab of tabs.slice(1)) {
			expect(tab).toContain('aria-selected="false"');
			expect(tab).toContain('tabindex="-1"');
		}
	});

	test("panels are server-rendered and reachable without JS", () => {
		// No panel starts hidden; a plain nav links to each one.
		expect(markup).not.toMatch(/<section class="panel"[^>]*hidden/);
		for (const id of panelIds) expect(markup).toContain(`<a href="#${id}">`);
		// Filters and buttons only appear once the script runs.
		expect(markup).toMatch(/<form class="filters"[^>]*data-js hidden>/);
	});

	test("the rail lists every category with its grade and score", () => {
		for (const c of report.summary.categories) {
			const tab = tabs.find((t) => t.includes(`aria-controls="${c.category}"`));
			expect(tab).toBeDefined();
			const start = markup.indexOf(`id="tab-${c.category}"`);
			const button = markup.slice(start, markup.indexOf("</button>", start));
			expect(button).toContain(`<span class="gm-${c.grade}">${c.grade}</span>`);
			expect(button).toContain(
				`<span class="ts" aria-hidden="true">${c.score}</span>`,
			);
			expect(button).toContain(`grade ${c.grade}, score ${c.score}`);
		}
		expect(markup).toContain('aria-orientation="vertical"');
		expect(markup).toMatch(/<p class="mini" aria-hidden="true">/);
	});

	test("motion has a reduced-motion path", () => {
		const style = html.match(/<style>([\s\S]*?)<\/style>/)?.[1] ?? "";
		const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1] ?? "";
		expect(style).toContain("@media (prefers-reduced-motion:reduce)");
		expect(script).toContain("prefers-reduced-motion: reduce");
		// Final states are in the markup; the script only animates towards them.
		expect(markup).toContain('stroke-dasharray="');
		expect(markup).toMatch(/<span data-count="\d+">\d+<\/span>/);
	});

	test("the script implements the WAI-ARIA tabs keyboard pattern", () => {
		const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1] ?? "";
		for (const key of ["ArrowRight", "ArrowLeft", "Home", "End"])
			expect(script).toContain(key);
		expect(script).toContain("aria-selected");
		expect(script).toContain('"tabpanel"');
		expect(script).toContain("history");
	});
});

describe("content", () => {
	test("overview shows grade, severities, categories and AI insights", () => {
		const { grade, score } = report.summary;
		expect(markup).toContain(`Grade ${grade}, score ${score} of 100`);
		expect(markup).toContain(
			`<span class="dial-grade gm-${grade}">${grade}</span>`,
		);
		// One dial segment per category, filled to its score.
		expect(markup.match(/<path class="seg a-[A-F]"/g)).toHaveLength(
			report.summary.categories.length,
		);
		expect(markup).toContain(
			"1 critical and 1 high severity findings need attention",
		);
		expect(markup).toContain('<a class="ch" href="#security"');
		expect(markup).toContain("AI insights");
		expect(markup).toContain("Rotate the &lt;b&gt;leaked&lt;/b&gt; key first.");
		expect(markup).toContain("Most severe findings");
	});

	test("coverage names categories whose auditors were skipped", () => {
		expect(markup).toContain("Performance was not examined");
		expect(markup).toContain("<code>web.lighthouse</code> skipped");
		expect(markup).toContain("Install: npm i -g lighthouse");
	});

	test("findings are grouped by rule with filters and a live count", () => {
		// Every rule here has one finding, so none is wrapped in a group.
		expect(markup).not.toContain('<li class="rule-item"');
		expect(markup.match(/<details class="finding">/g)).toHaveLength(4);
		expect(markup).toContain('data-sev="critical"');
		expect(markup).toContain('data-conf="low"');
		expect(markup).toContain('aria-live="polite"');
		expect(markup).toContain('name="confidence"');
		expect(markup).toContain('<option value="web.headers">');
		expect(markup).toContain("<code>head</code>");
	});

	test("a rule with several findings becomes one group", () => {
		const grouped: AuditorResult[] = [
			{
				...(results[0] as AuditorResult),
				findings: [
					finding({ location: { file: "a.ts", line: 1 }, fingerprint: "g1" }),
					finding({ location: { file: "b.ts", line: 2 }, fingerprint: "g2" }),
				],
			},
		];
		const out = toHtml({
			...report,
			results: grouped,
			summary: summarize(grouped),
		});
		expect(out.match(/<li class="rule-item">/g)).toHaveLength(1);
		expect(out).toContain('<span class="count" data-shown>2 findings</span>');
		// Children lead with their location and do not repeat the shared title.
		const body = out.slice(out.indexOf('<div class="rule-body">'));
		expect(body).not.toContain(
			'<span class="ft">AWS access key committed</span>',
		);
		expect(body).toContain('<span class="loc">a.ts:1</span>');
	});

	test("duplicates are neither listed nor counted; confirmations are shown", () => {
		expect(markup).not.toContain("DUPLICATE-ONLY-TITLE");
		expect(markup.match(/<li id="f-\d+"/g)).toHaveLength(4);
		expect(markup).toContain("Confirmed by code.gitleaks");
		// The gitleaks auditor row shows 0 findings plus the duplicate.
		expect(markup).toMatch(
			/<td class="n" data-label="Findings">0<span class="rid">\+1 duplicate</,
		);
		// Gitleaks can filter the finding it confirmed.
		expect(markup).toContain('data-auditors=" code.secrets code.gitleaks "');
	});

	test("diff mode and cloud targets are shown in the header", () => {
		const out = toHtml({
			...report,
			target: {
				...report.target,
				type: "cloud",
				cloud: "aws",
				kinds: ["cloud"],
			},
			diff: { base: "origin/main", changedFiles: 12 },
		});
		expect(out).toContain(
			"<dt>Changes since</dt><dd>origin/main (12 files)</dd>",
		);
		expect(out).toContain("<dt>Cloud</dt><dd>aws</dd>");
		expect(out).toContain("Changes since <code>origin/main</code>, 12 files");
	});

	test("suppressions are disclosed", () => {
		const out = toHtml(report, {
			suppressed: [
				{
					source: "openaudit.config.json",
					rules: 3,
					paths: 1,
					fingerprints: 0,
				},
			],
		});
		expect(out).toContain(
			"4 findings suppressed by openaudit.config.json (3 by rule, 1 by path)",
		);
	});
});

describe("escaping", () => {
	test("report strings are escaped in markup", () => {
		expect(markup).not.toContain("<script>alert");
		expect(markup).not.toContain("</script><script>alert(2)");
		expect(markup).not.toContain("<img src=x");
		expect(markup).toContain(
			"&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;",
		);
		expect(markup).not.toContain('href="javascript:');
		// Exactly one executable script element: ours.
		expect(html.match(/<script>/g)).toHaveLength(1);
		// Plus five inert data blocks: JSON, SARIF, Markdown, CSV and the AI prompt.
		expect(html.match(/<script\b/g)).toHaveLength(6);
		expect(html.match(/<script type="application\/json"/g)).toHaveLength(5);
	});

	test("the embedded data cannot break out and round-trips", () => {
		for (const block of html.matchAll(
			/<script type="application\/json"[^>]*>([\s\S]*?)<\/script>/g,
		))
			expect(block[1]).not.toMatch(/[<>&\u2028\u2029]/);
		// Identical apart from the local path, which becomes the folder name.
		expect(JSON.parse(dataBlock)).toEqual(
			canonicalize({
				...report,
				target: { ...report.target, input: "my repo", root: "my repo" },
			}),
		);
	});
});

describe("compliance mapping", () => {
	test("reference data is well-formed", () => {
		expect(OWASP_TOP10_2021.map((c) => c.id)).toEqual([
			"A01",
			"A02",
			"A03",
			"A04",
			"A05",
			"A06",
			"A07",
			"A08",
			"A09",
			"A10",
		]);
		expect(CWE_TOP25_2024.map((c) => c.rank)).toEqual(
			Array.from({ length: 25 }, (_, i) => i + 1),
		);
		expect(new Set(CWE_TOP25_2024.map((c) => c.cwe)).size).toBe(25);
		expect(CWE_TOP25_2024[0]).toMatchObject({ cwe: 79 });
		expect(CWE_TO_OWASP_2021.get(79)).toBe("A03");
		expect(CWE_TO_OWASP_2021.get(918)).toBe("A10");
		expect(CWE_TO_OWASP_2021.get(798)).toBe("A07");
	});

	test("OWASP tags win; CWEs are the fallback", () => {
		expect(owaspMatchesOf(finding({ tags: ["cwe-79", "owasp-a05"] }))).toEqual([
			{ id: "A05" },
		]);
		expect(owaspMatchesOf(finding({ tags: ["cwe-89"] }))).toEqual([
			{ id: "A03", viaCwe: 89 },
		]);
		expect(
			owaspMatchesOf(finding({ tags: ["cwe-99999", "owasp-a42"] })),
		).toEqual([]);
	});

	test("groups non-duplicate findings under every control", () => {
		const findings = results.flatMap((r) => r.findings);
		const owasp = groupByOwasp(findings);
		expect(owasp).toHaveLength(10);
		const a07 = owasp.find((g) => g.category.id === "A07");
		// The gitleaks duplicate is not counted twice.
		expect(a07?.matches.map((m) => m.finding.fingerprint)).toEqual([
			"aaaaaaaaaaaaaaaa",
		]);
		const a03 = owasp.find((g) => g.category.id === "A03");
		expect(a03?.matches).toEqual([
			{ finding: findings[1] as Finding, viaCwe: 79 },
		]);
		const cwe = groupByCweTop25(findings);
		expect(cwe).toHaveLength(25);
		expect(
			cwe
				.find((g) => g.entry.cwe === 798)
				?.matches.map((m) => m.finding.ruleId),
		).toEqual(["code.secrets/aws-key"]);
		expect(cwe.find((g) => g.entry.cwe === 89)?.matches).toEqual([]);
	});

	test("the compliance tab lists every control, including empty ones", () => {
		expect(markup).toContain("is not the same as compliant");
		expect(markup.match(/<span class="cid">A\d\d<\/span>/g)).toHaveLength(10);
		expect(markup.match(/<span class="cid">#\d+<\/span>/g)).toHaveLength(25);
		expect(markup).toContain('<span class="nf">no findings</span>');
		expect(markup).toContain("mapped via CWE-79");
	});
});

describe("scale", () => {
	test("renders 2,000 findings quickly with delegated listeners", () => {
		const many: Finding[] = Array.from({ length: 2000 }, (_, i) =>
			finding({
				ruleId: `code.lint/rule-${i % 40}`,
				severity: (["critical", "high", "medium", "low", "info"] as const)[
					i % 5
				],
				category: i % 3 ? "maintainability" : "security",
				fingerprint: `fp-${i}`,
				location: { file: `src/f${i}.ts`, line: i },
			}),
		);
		const big: AuditorResult[] = [
			{
				auditor: "code.lint",
				title: "Lint",
				engine: "builtin",
				categories: ["security", "maintainability"],
				status: "failed",
				durationMs: 1,
				findings: many,
			},
		];
		const started = performance.now();
		const out = toHtml({ ...report, results: big, summary: summarize(big) });
		expect(performance.now() - started).toBeLessThan(2000);
		expect(out.match(/<li id="f-\d+"/g)).toHaveLength(2000);
		const script = out.match(/<script>([\s\S]*?)<\/script>/)?.[1] ?? "";
		// Listeners are attached a fixed number of times, never per row.
		expect(script.match(/addEventListener/g)?.length).toBeLessThan(25);
	});
});

describe("local paths", () => {
	const local: Report = {
		...report,
		target: {
			...report.target,
			input: "/home/me/work/my repo",
			root: "/home/me/work/my repo",
		},
	};
	const page = toHtml(local);
	const block = (id: string) =>
		JSON.parse(
			page.match(
				new RegExp(
					`<script type="application/json" id="data-${id}"[^>]*>([\\s\\S]*?)</script>`,
				),
			)?.[1] ?? "null",
		);

	test("the page and its embedded data name the folder, not the path", () => {
		expect(page).not.toContain("/home/me");
		expect(page).not.toContain("file:///home");
		expect(page).toContain("my repo");
	});

	test("no download format carries the local path", () => {
		for (const id of ["json", "sarif", "markdown", "csv"]) {
			const data = block(id);
			expect(data).not.toBeNull();
			expect(JSON.stringify(data)).not.toContain("/home/me");
		}
		// SARIF is built without a root, so paths stay relative.
		const run = block("sarif").runs[0];
		expect(run.originalUriBaseIds).toBeUndefined();
		expect(run.properties.target).toBe("my repo");
		expect(
			run.results[0].locations[0].physicalLocation.artifactLocation,
		).toEqual({ uri: "src/config.ts" });
	});
});

describe("downloads", () => {
	test("a menu button offers every format, rendered by the core reporters", () => {
		expect(markup).toContain(
			'aria-haspopup="menu" aria-expanded="false" aria-controls="dl-menu"',
		);
		expect(markup).toContain('<ul class="dl-menu" id="dl-menu" role="menu"');
		expect(markup.match(/role="menuitem"/g)).toHaveLength(5);
		// The HTML item saves the page itself, so it has no data block.
		expect(markup).toContain('data-page="openaudit-report.html"');
		const files = [
			...html.matchAll(/data-file="([^"]+)" data-type="([^"]+)"/g),
		].map((m) => `${m[1]} ${m[2]}`);
		expect(files).toEqual([
			"openaudit-report.json application/json",
			"openaudit-report.sarif application/sarif+json",
			"openaudit-report.md text/markdown",
			"openaudit-findings.csv text/csv",
		]);
		const md = JSON.parse(
			html.match(/id="data-markdown"[^>]*>([\s\S]*?)<\/script>/)?.[1] ?? "",
		);
		expect(md).toContain("AWS access key committed");
		const csv = JSON.parse(
			html.match(/id="data-csv"[^>]*>([\s\S]*?)<\/script>/)?.[1] ?? "",
		);
		expect(csv.split("\r\n")[0]).toBe(CSV_COLUMNS.join(","));
	});
});

describe("copy for AI", () => {
	test("a button copies the report with a plain-language prompt", () => {
		expect(markup).toContain('data-action="copy-ai"');
		expect(html).toContain('role="status" id="copy-status"');
		const prompt = JSON.parse(
			html.match(/id="data-ai"[^>]*>([\s\S]*?)<\/script>/)?.[1] ?? "",
		);
		expect(prompt).toStartWith("Here's an openaudit report for my repo.");
		expect(prompt).toContain("Assume I'm not a security expert.");
		expect(prompt).toContain("## openaudit: my repo");
		expect(prompt).toContain("AWS access key committed");
		expect(prompt).not.toContain("/home/me");
	});
});

describe("csv", () => {
	test("one escaped row per non-duplicate finding", () => {
		const csv = toCsv(report);
		const lines = csv.trimEnd().split("\r\n");
		expect(lines[0]).toBe(
			"severity,category,title,ruleId,auditor,file,line,url,selector,message,remediation,confidence,alsoReportedBy,fingerprint",
		);
		// 4 kept findings; the gitleaks duplicate is not a row.
		expect(csv).not.toContain("DUPLICATE-ONLY-TITLE");
		expect(lines[1]).toBe(
			"critical,security,AWS access key committed,code.secrets/aws-key,code.secrets,src/config.ts,12,,,An AWS access key is hard-coded.,Rotate the key and load it from the environment.,,code.gitleaks,aaaaaaaaaaaaaaaa",
		);
		expect(csv).toContain(
			'"Message with <img src=x onerror=alert(1)> & ""quotes"" \u2028 \u2029 <!-- x"',
		);
	});

	test("cells cannot become spreadsheet formulas", () => {
		expect(csvCell("=HYPERLINK(1)")).toBe("'=HYPERLINK(1)");
		expect(csvCell("+1")).toBe("'+1");
		expect(csvCell("-2")).toBe("'-2");
		expect(csvCell("@SUM(A1)")).toBe("'@SUM(A1)");
		expect(csvCell("a,b")).toBe('"a,b"');
		expect(csvCell('say "hi"')).toBe('"say ""hi"""');
		expect(csvCell("line\nbreak")).toBe('"line\nbreak"');
		expect(csvCell(undefined)).toBe("");
		expect(csvCell(12)).toBe("12");
		// Control characters and terminal escapes are stripped.
		expect(csvCell("ok\u001b[31m")).toBe("ok");
	});
});
