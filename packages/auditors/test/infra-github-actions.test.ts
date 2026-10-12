import { describe, expect, test } from "bun:test";

import { auditWorkflow, githubActions } from "../src/infra/github-actions";
import { fixture, ruleIds, runAuditor } from "./helpers";

describe("iac.github-actions", () => {
	test("flags insecure workflows", async () => {
		const report = await runAuditor(githubActions, fixture("infra", "gha-bad"));
		expect(report.results[0]?.status).toBe("failed");
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
		const findings = report.results[0]?.findings ?? [];
		const byRule = (id: string) =>
			findings.filter((f) => f.ruleId === `iac.github-actions/${id}`);
		expect(byRule("pr-target-checkout")[0]?.severity).toBe("critical");
		expect(byRule("pr-target-checkout")[0]?.location?.line).toBe(15);
		expect(byRule("script-injection")[0]?.location).toEqual({
			file: ".github/workflows/pr.yml",
			line: 20,
		});
		const pins = byRule("action-not-pinned");
		expect(
			pins.find((f) => f.evidence?.includes("actions/checkout"))?.severity,
		).toBe("low");
		expect(pins.find((f) => f.evidence?.includes("some-org"))?.severity).toBe(
			"medium",
		);
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
