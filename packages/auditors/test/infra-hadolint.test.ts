import { describe, expect, test } from "bun:test";

import { hadolint, parseHadolintOutput } from "../src/infra/hadolint";
import { fixture, runAuditor } from "./helpers";

const SAMPLE = JSON.stringify([
	{
		code: "DL3008",
		column: 1,
		file: "Dockerfile",
		level: "warning",
		line: 6,
		message:
			"Pin versions in apt get install. Instead of `apt-get install <package>` use `apt-get install <package>=<version>`",
	},
	{
		code: "DL3002",
		column: 1,
		file: "Dockerfile",
		level: "warning",
		line: 9,
		message: "Last USER should not be root",
	},
	{
		code: "SC2086",
		column: 1,
		file: "app/Dockerfile",
		level: "info",
		line: 3,
		message: "Double quote to prevent globbing and word splitting.",
	},
	{
		code: "DL1000",
		column: 1,
		file: "Dockerfile",
		level: "error",
		line: 1,
		message: "unexpected end of input",
	},
]);

describe("container.hadolint", () => {
	test("parses hadolint JSON", () => {
		const findings = parseHadolintOutput(SAMPLE);
		expect(
			findings.map((f) => [f.ruleId, f.severity, f.category, f.location?.line]),
		).toEqual([
			["container.hadolint/dl3008", "low", "best-practices", 6],
			["container.hadolint/dl3002", "low", "security", 9],
			["container.hadolint/sc2086", "info", "best-practices", 3],
			["container.hadolint/dl1000", "medium", "best-practices", 1],
		]);
		expect(findings[0]?.title.length).toBeLessThan(100);
		expect(findings[2]?.references).toEqual([
			"https://www.shellcheck.net/wiki/SC2086",
		]);
		expect(findings[2]?.location?.file).toBe("app/Dockerfile");
		expect(parseHadolintOutput("")).toEqual([]);
	});

	test("skips when hadolint is not installed", async () => {
		if (Bun.which("hadolint")) return;
		const report = await runAuditor(hadolint, fixture("infra", "docker-bad"));
		expect(report.results[0]?.status).toBe("skipped");
		expect(report.results[0]?.message).toContain("hadolint not found");
	});
});
