import { describe, expect, test } from "bun:test";

import { auditWorkflow, githubActions } from "../src/infra/github-actions";
import { fixture, ruleIds, runAuditor } from "./helpers";
import { findingsOf, firstResult, must } from "./must";

describe("iac.github-actions", () => {
	test("flags insecure workflows", async () => {
		const report = await runAuditor(githubActions, fixture("infra", "gha-bad"));
		expect(firstResult(report).status).toBe("failed");
		expect(ruleIds(report)).toEqual([
			"iac.github-actions/action-not-pinned",
			"iac.github-actions/action-not-pinned",
			"iac.github-actions/action-not-pinned",
			"iac.github-actions/action-not-pinned",
			"iac.github-actions/permissions-missing",
			"iac.github-actions/permissions-write-all",
			"iac.github-actions/pr-target-checkout",
			"iac.github-actions/script-injection",
			"iac.github-actions/secret-echoed",
			"iac.github-actions/secret-xtrace",
			"iac.github-actions/security-step-continue-on-error",
			"iac.github-actions/self-hosted-runner-public",
			"iac.github-actions/unsecure-commands",
		]);
		const findings = findingsOf(report);
		const byRule = (id: string) =>
			findings.filter((f) => f.ruleId === `iac.github-actions/${id}`);
		const prTarget = must(
			byRule("pr-target-checkout")[0],
			"pr-target-checkout",
		);
		expect(prTarget.severity).toBe("critical");
		expect(must(prTarget.location, "its location").line).toBe(15);
		expect(
			must(byRule("script-injection")[0], "script-injection").location,
		).toEqual({
			file: ".github/workflows/pr.yml",
			line: 20,
		});
		const pins = byRule("action-not-pinned");
		const pinOf = (action: string) =>
			must(
				pins.find((f) => (f.evidence ?? "").includes(action)),
				`a pin finding for ${action}`,
			);
		expect(pinOf("actions/checkout").severity).toBe("low");
		expect(pinOf("some-org").severity).toBe("medium");
	});

	test("passes a hardened workflow", async () => {
		const report = await runAuditor(
			githubActions,
			fixture("infra", "gha-clean"),
		);
		expect(report.results[0]?.status).toBe("passed");
		expect(ruleIds(report)).toEqual([]);
	});

	test("audits a single workflow file target", async () => {
		const report = await runAuditor(
			githubActions,
			fixture("infra", "gha-bad", ".github", "workflows", "ci.yml"),
		);
		expect(ruleIds(report)).toEqual([
			"iac.github-actions/action-not-pinned",
			"iac.github-actions/permissions-missing",
		]);
	});

	test("skips when there are no workflows", async () => {
		const report = await runAuditor(
			githubActions,
			fixture("infra", "terraform-clean"),
		);
		expect(report.results[0]?.status).toBe("skipped");
	});

	test("detects injection in github-script and head_ref", () => {
		const findings = auditWorkflow(
			"wf.yml",
			[
				"on: pull_request",
				"permissions: {}",
				"jobs:",
				"  a:",
				"    runs-on: ubuntu-latest",
				"    steps:",
				// biome-ignore lint/suspicious/noTemplateCurlyInString: GitHub Actions expression syntax
				"      - run: git push origin ${{ github.head_ref }}",
				"      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea",
				"        with:",
				"          script: |",
				// biome-ignore lint/suspicious/noTemplateCurlyInString: GitHub Actions expression syntax
				"            console.log('${{ github.event.comment.body }}')",
			].join("\n"),
		);
		const injections = findings.filter(
			(f) => f.ruleId === "iac.github-actions/script-injection",
		);
		expect(injections.map((f) => f.location?.line)).toEqual([7, 11]);
		expect(
			findings.some((f) => f.ruleId.endsWith("/permissions-missing")),
		).toBe(false);
	});

	test("ignores local and SHA-pinned actions, flags reusable workflows", () => {
		const findings = auditWorkflow(
			"wf.yml",
			[
				"on: push",
				"permissions:",
				"  contents: read",
				"jobs:",
				"  a:",
				"    runs-on: ubuntu-latest",
				"    steps:",
				"      - uses: ./.github/actions/setup",
				"      - uses: docker://alpine:3.20",
				"  b:",
				"    uses: org/shared/.github/workflows/build.yml@v1",
			].join("\n"),
		);
		expect(findings.map((f) => [f.ruleId, f.location?.line])).toEqual([
			["iac.github-actions/action-not-pinned", 11],
		]);
	});
});
