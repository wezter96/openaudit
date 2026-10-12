import { describe, expect, test } from "bun:test";

import {
	assetFindings,
	consoleFinding,
	performanceAuditor,
	scanPerformanceSource,
} from "../src/codebase/performance";
import { fixture, runAuditor } from "./helpers";

const KB = 1024;

describe("code.performance", () => {
	test("flags heavy deps, whole-library imports, sync I/O in handlers and console logging", async () => {
		const report = await runAuditor(
			performanceAuditor,
			fixture("codebase", "perf"),
		);
		const findings = report.results.flatMap((r) => r.findings);
		expect(
			findings
				.map(
					(f) =>
						`${f.ruleId.replace("code.performance/", "")} ${f.location?.file}:${f.location?.line}`,
				)
				.sort(),
		).toEqual([
			"console-logging src/util.ts:5",
			"full-library-import src/util.ts:1",
			"full-library-import src/util.ts:2",
			"heavy-dependency package.json:5",
			"heavy-dependency package.json:6",
			"heavy-dependency package.json:7",
			"sync-io-in-handler src/server.ts:8",
		]);
		// core-js is a devDependency only; jquery is flagged because React is present.
		expect(findings.some((f) => f.evidence?.includes("core-js"))).toBe(false);
		expect(
			findings.find((f) => f.ruleId.endsWith("console-logging"))?.severity,
		).toBe("info");
	});

	test("asset size thresholds", () => {
		const rules = (path: string, size: number) =>
			assetFindings(path, size).map((f) => `${f.ruleId}:${f.severity}`);
		expect(rules("public/hero.png", 400 * KB)).toEqual([
			"code.performance/large-image:low",
		]);
		expect(rules("public/hero.jpg", 2048 * KB)).toEqual([
			"code.performance/large-image:medium",
		]);
		expect(rules("public/thumb.png", 150 * KB)).toEqual([
			"code.performance/legacy-image-format:info",
		]);
		expect(rules("public/thumb.webp", 150 * KB)).toEqual([]);
		expect(rules("static/intro.mp4", 5 * 1024 * KB)).toEqual([
			"code.performance/large-video:low",
		]);
		expect(rules("assets/fonts/Inter.ttf", 100 * KB)).toEqual([
			"code.performance/heavy-font:info",
		]);
		expect(rules("assets/fonts/Inter.woff2", 250 * KB)).toEqual([
			"code.performance/heavy-font:low",
		]);
		expect(rules("assets/fonts/Inter.woff2", 50 * KB)).toEqual([]);
		// Outside web-served directories (e.g. design sources) is ignored.
		expect(rules("design/mockup.png", 5 * 1024 * KB)).toEqual([]);
	});

	test("console threshold is aggregated across files", () => {
		expect(
			consoleFinding([{ path: "a.ts", count: 3, firstLine: 1 }]),
		).toBeUndefined();
		const f = consoleFinding([
			{ path: "a.ts", count: 3, firstLine: 1 },
			{ path: "b.ts", count: 8, firstLine: 4 },
		]);
		expect(f?.location).toEqual({ file: "b.ts", line: 4 });
		expect(f?.title).toBe("11 console.log calls in production source");
	});

	test("top-level sync reads are not flagged", () => {
		const text =
			'import fs from "node:fs";\nconst c = fs.readFileSync("x");\napp.get("/", (q, r) => r.send(c));\n';
		expect(scanPerformanceSource({ path: "server.ts", text }).findings).toEqual(
			[],
		);
	});
});
