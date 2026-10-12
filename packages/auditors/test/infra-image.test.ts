import { describe, expect, test } from "bun:test";

import {
	configFindings,
	image,
	parseDockerInspect,
	parseTrivyOutput,
} from "../src/infra/image";
import { fixture, runAuditor } from "./helpers";

const NOW = Date.parse("2026-10-01T00:00:00Z");

const TRIVY = JSON.stringify({
	SchemaVersion: 2,
	ArtifactName: "example/app:1.0",
	Metadata: {
		Size: 1_300_000_000,
		OS: { Family: "debian", Name: "10.13", EOSL: true },
		ImageConfig: {
			created: "2025-01-01T00:00:00Z",
			config: {
				User: "",
				ExposedPorts: { "22/tcp": {}, "8080/tcp": {} },
				Env: ["PATH=/usr/bin", "DB_PASSWORD=hunter2hunter2"],
			},
		},
	},
	Results: [
		{
			Target: "example/app:1.0 (debian 10.13)",
			Class: "os-pkgs",
			Vulnerabilities: [
				{
					VulnerabilityID: "CVE-2023-0001",
					PkgName: "openssl",
					InstalledVersion: "1.1.1n",
					FixedVersion: "1.1.1w",
					Severity: "CRITICAL",
					Title: "openssl: something bad",
					PrimaryURL: "https://avd.aquasec.com/nvd/cve-2023-0001",
					CweIDs: ["CWE-787"],
				},
				{
					VulnerabilityID: "CVE-2023-0002",
					PkgName: "openssl",
					InstalledVersion: "1.1.1n",
					Severity: "UNKNOWN",
				},
			],
		},
		{
			Target: "/app/.env",
			Class: "secret",
			Secrets: [
				{
					RuleID: "aws-access-key-id",
					Category: "AWS",
					Severity: "CRITICAL",
					Title: "AWS Access Key ID",
					StartLine: 3,
					Match: "AWS_ACCESS_KEY_ID=********************",
				},
			],
		},
	],
});

describe("container.image", () => {
	test("parses trivy JSON", () => {
		const { findings, config } = parseTrivyOutput("example/app:1.0", TRIVY);
		expect(findings.map((f) => [f.ruleId, f.severity])).toEqual([
			["container.image/os-eol", "high"],
			["container.image/vulnerability", "critical"],
			["container.image/vulnerability", "info"],
			["container.image/secret", "critical"],
		]);
		expect(findings[1]?.remediation).toContain("1.1.1w");
		expect(findings[1]?.tags).toEqual(["cve-2023-0001", "cwe-787"]);
		expect(findings[1]?.evidence).not.toBe(findings[2]?.evidence);
		expect(findings[3]?.location).toEqual({ file: "/app/.env", line: 3 });
		expect(config?.exposedPorts).toEqual(["22/tcp", "8080/tcp"]);
		expect(config?.size).toBe(1_300_000_000);
	});

	test("derives config findings", () => {
		const { config } = parseTrivyOutput("example/app:1.0", TRIVY);
		if (!config) throw new Error("expected config");
		const findings = configFindings("example/app:1.0", config, NOW);
		expect(findings.map((f) => [f.ruleId, f.severity])).toEqual([
			["container.image/runs-as-root", "medium"],
			["container.image/ssh-exposed", "medium"],
			["container.image/exposed-ports", "info"],
			["container.image/secret-in-env", "high"],
			["container.image/stale", "low"],
			["container.image/large", "low"],
		]);
		const secret = findings.find(
			(f) => f.ruleId === "container.image/secret-in-env",
		);
		expect(secret?.evidence).not.toContain("hunter2hunter2");
	});

	test("parses docker image inspect output", () => {
		const config = parseDockerInspect(
			JSON.stringify([
				{
					Id: "sha256:abc",
					Created: "1970-01-01T00:00:00Z",
					Size: 20_000_000,
					Config: { User: "65532", Env: ["PATH=/bin"], ExposedPorts: null },
				},
			]),
		);
		expect(config).toEqual({
			user: "65532",
			exposedPorts: [],
			env: ["PATH=/bin"],
			created: "1970-01-01T00:00:00Z",
			size: 20_000_000,
		});
		// Epoch timestamps (reproducible builds) are not reported as stale.
		if (config) expect(configFindings("distroless", config, NOW)).toEqual([]);
		expect(parseDockerInspect("not json")).toBeUndefined();
	});

	test("skips non-image targets", async () => {
		const report = await runAuditor(image, fixture("infra", "docker-bad"));
		expect(report.results[0]?.status).toBe("skipped");
		expect(report.results[0]?.message).toContain("image:<ref>");
	});
});
