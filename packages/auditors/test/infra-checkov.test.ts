import { describe, expect, test } from "bun:test";

import { checkov, parseCheckovOutput } from "../src/infra/checkov";
import { fixture, runAuditor } from "./helpers";

const report = (checkType: string, failed: unknown[]) => ({
	check_type: checkType,
	results: { passed_checks: [], failed_checks: failed, skipped_checks: [] },
	summary: { passed: 3, failed: failed.length, skipped: 0 },
});

describe("iac.checkov", () => {
	test("parses multi-framework JSON output", () => {
		const stdout = JSON.stringify([
			report("terraform", [
				{
					check_id: "CKV_AWS_20",
					check_name:
						"S3 Bucket has an ACL defined which allows public READ access.",
					file_path: "/main.tf",
					file_line_range: [7, 10],
					resource: "aws_s3_bucket.site",
					guideline:
						"https://docs.prismacloud.io/en/policy-reference/aws-policies/s3-1-acl-read-permissions-everyone",
					severity: "HIGH",
				},
			]),
			report("kubernetes", [
				{
					check_id: "CKV_K8S_16",
					check_name: "Container should not be privileged",
					file_path: "/k8s/app.yaml",
					file_line_range: [1, 30],
					resource: "Deployment.default.web",
					guideline: null,
					severity: null,
				},
			]),
		]);
		const findings = parseCheckovOutput(`Some banner\n${stdout}`);
		expect(findings).toHaveLength(2);
		expect(findings[0]).toMatchObject({
			ruleId: "iac.checkov/ckv-aws-20",
			severity: "high",
			category: "security",
			location: { file: "main.tf", line: 7 },
			evidence: "aws_s3_bucket.site",
		});
		expect(findings[0]?.references).toHaveLength(1);
		expect(findings[1]).toMatchObject({
			ruleId: "iac.checkov/ckv-k8s-16",
			severity: "medium",
			location: { file: "k8s/app.yaml", line: 1 },
		});
	});

	test("handles a single report and an empty summary", () => {
		expect(
			parseCheckovOutput(
				JSON.stringify(
					report("dockerfile", [
						{
							check_id: "CKV_DOCKER_2",
							check_name:
								"Ensure that HEALTHCHECK instructions have been added",
							file_path: "/Dockerfile",
							file_line_range: [1, 5],
							resource: "/Dockerfile.",
						},
					]),
				),
			).map((f) => f.ruleId),
		).toEqual(["iac.checkov/ckv-docker-2"]);
		expect(
			parseCheckovOutput(
				'{"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0}',
			),
		).toEqual([]);
		expect(parseCheckovOutput("")).toEqual([]);
	});

	test("skips gracefully when checkov is not installed", async () => {
		if (Bun.which("checkov")) return;
		const result = await runAuditor(
			checkov,
			fixture("infra", "terraform-clean"),
		);
		expect(result.results[0]?.status).toBe("skipped");
		expect(result.results[0]?.message).toContain("checkov");
	});
});
