import { describe, expect, test } from "bun:test";
import { correlate } from "../src/correlate";
import type { AuditorResult, Finding } from "../src/model";
import { summarize } from "../src/scoring";

const finding = (auditor: string, over: Partial<Finding>): Finding => ({
	ruleId: `${auditor}/rule`,
	title: "t",
	severity: "high",
	category: "security",
	message: "m",
	auditor,
	fingerprint: `${auditor}-${over.location?.line ?? ""}-${(over.tags ?? []).join(",")}`,
	...over,
});

const result = (auditor: string, findings: Finding[]): AuditorResult => ({
	auditor,
	title: auditor,
	engine: "external",
	categories: ["security"],
	status: "failed",
	durationMs: 1,
	findings,
});

const secret = (auditor: string, severity: Finding["severity"] = "high") =>
	finding(auditor, {
		severity,
		tags: ["cwe-798", "secrets"],
		location: { file: "src/a.ts", line: 3 },
	});

describe("correlate", () => {
	test("merges one secret reported by three tools and scores it once", () => {
		const results = [
			result("code.secrets", [secret("code.secrets")]),
			result("code.gitleaks", [secret("code.gitleaks", "critical")]),
			result("code.trufflehog", [secret("code.trufflehog")]),
		];
		const out = correlate(results);
		const all = out.flatMap((r) => r.findings);
		const kept = all.filter((f) => f.duplicateOf === undefined);
		expect(kept).toHaveLength(1);
		expect(kept[0]?.auditor).toBe("code.gitleaks");
		expect(kept[0]?.alsoReportedBy).toEqual([
			"code.secrets",
			"code.trufflehog",
		]);
		expect(
			all.filter((f) => f.duplicateOf === kept[0]?.fingerprint),
		).toHaveLength(2);
		expect(summarize(out).counts).toMatchObject({ critical: 1, high: 0 });
	});

	test("merges an advisory across tools in the same directory only", () => {
		const adv = (auditor: string, file: string) =>
			finding(auditor, {
				tags: ["ghsa-vfj7-8cjw-p6xm", "cwe-1050"],
				location: { file },
			});
		const out = correlate([
			result("code.osv-scanner", [adv("code.osv-scanner", "bun.lock")]),
			result("code.bun-audit", [adv("code.bun-audit", "package.json")]),
			result("code.npm-audit", [
				adv("code.npm-audit", "apps/web/package-lock.json"),
			]),
		]);
		const kept = out.flatMap((r) => r.findings).filter((f) => !f.duplicateOf);
		expect(kept.map((f) => f.auditor).sort()).toEqual([
			"code.bun-audit",
			"code.npm-audit",
		]);
	});

	test("never merges two findings from the same auditor", () => {
		const a = finding("code.semgrep", {
			tags: ["cwe-79"],
			location: { file: "x.ts", line: 1 },
			fingerprint: "a",
		});
		const b = finding("code.semgrep", {
			tags: ["cwe-79"],
			location: { file: "x.ts", line: 1 },
			fingerprint: "b",
		});
		const out = correlate([result("code.semgrep", [a, b])]);
		expect(
			out[0]?.findings.every((f) => !f.duplicateOf && !f.alsoReportedBy),
		).toBe(true);
	});

	test("does not merge different lines or findings without a location", () => {
		const out = correlate([
			result("code.semgrep", [
				finding("code.semgrep", {
					tags: ["cwe-79"],
					location: { file: "x.ts", line: 1 },
				}),
			]),
			result("code.opengrep", [
				finding("code.opengrep", {
					tags: ["cwe-79"],
					location: { file: "x.ts", line: 2 },
				}),
			]),
			result("code.bandit", [finding("code.bandit", { tags: ["cwe-79"] })]),
			result("code.gosec", [finding("code.gosec", { tags: ["cwe-79"] })]),
		]);
		expect(out.flatMap((r) => r.findings).some((f) => f.duplicateOf)).toBe(
			false,
		);
	});

	test("is idempotent and recomputes after the kept finding is removed", () => {
		const first = correlate([
			result("code.secrets", [secret("code.secrets")]),
			result("code.gitleaks", [secret("code.gitleaks", "critical")]),
		]);
		expect(correlate(first)).toEqual(first);
		const withoutKept = first.map((r) =>
			r.auditor === "code.gitleaks" ? { ...r, findings: [] } : r,
		);
		const again = correlate(withoutKept).flatMap((r) => r.findings);
		expect(again).toHaveLength(1);
		expect(again[0]?.duplicateOf).toBeUndefined();
		expect(again[0]?.alsoReportedBy).toBeUndefined();
	});

	test("merges one lint rule reported by two linters at the same file and line", () => {
		const lint = (auditor: string, line: number, rule: string) =>
			finding(auditor, {
				severity: "low",
				category: "reliability",
				tags: [`eslint:${rule}`],
				location: { file: "src/a.tsx", line },
			});
		const out = correlate([
			result("code.oxlint", [
				lint("code.oxlint", 5, "react-hooks/rules-of-hooks"),
				lint("code.oxlint", 9, "no-debugger"),
			]),
			result("code.eslint", [
				lint("code.eslint", 5, "React-Hooks/rules-of-hooks"),
				lint("code.eslint", 10, "no-debugger"),
				lint("code.eslint", 9, "eqeqeq"),
			]),
		]);
		const all = out.flatMap((r) => r.findings);
		expect(all.filter((f) => f.duplicateOf)).toHaveLength(1);
		expect(all.find((f) => f.alsoReportedBy)?.location?.line).toBe(5);
	});

	test("merges accessibility issues by WCAG criterion, URL and selector", () => {
		const loc = { url: "https://x.test/", selector: "img.hero" };
		const out = correlate([
			result("webapp.browser", [
				finding("webapp.browser", {
					category: "accessibility",
					tags: ["wcag-1.1.1"],
					location: loc,
				}),
			]),
			result("web.pa11y", [
				finding("web.pa11y", {
					category: "accessibility",
					tags: ["wcag-1.1.1"],
					location: loc,
				}),
			]),
		]);
		expect(
			out.flatMap((r) => r.findings).filter((f) => f.duplicateOf),
		).toHaveLength(1);
	});
});
