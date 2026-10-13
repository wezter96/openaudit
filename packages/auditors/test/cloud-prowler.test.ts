import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import {
	type AuditOptions,
	type Auditor,
	Exec,
	type ExecResult,
	Http,
	type Report,
	runAudit,
	Workspaces,
} from "@openaudit/core";
import { Effect, Layer } from "effect";

import { cloudAuditors } from "../src/cloud";
import {
	parseProwlerReport,
	prowler,
	prowlerArgs,
	readProwlerSettings,
} from "../src/cloud/prowler";
import { fixture } from "./helpers";

// Reconstructed from Prowler's docs and source (the OCSF Detection Finding
// that `--output-formats json-ocsf` emits); Prowler itself was not installed.
const text = readFileSync(fixture("prowler", "aws.ocsf.json"), "utf8");
const json: unknown = JSON.parse(text);

const runWithExec = (
	auditor: Auditor,
	target: string,
	which: (bin: string) => string | undefined,
	run: (cmd: ReadonlyArray<string>) => Promise<ExecResult>,
	options: AuditOptions = {},
): Promise<Report> =>
	Effect.runPromise(
		runAudit({
			target,
			auditors: [auditor],
			options,
			selection: { only: [auditor.id] },
		}).pipe(
			Effect.provide(
				Layer.mergeAll(
					Workspaces.layer,
					Http.layer,
					Layer.succeed(Exec, {
						which: (bin: string) => Effect.succeed(which(bin)),
						run: (cmd: ReadonlyArray<string>) => Effect.promise(() => run(cmd)),
					}),
				),
			),
		),
	);

const have = (bin: string) =>
	bin === "prowler" ? "/usr/bin/prowler" : undefined;
const outDirOf = (cmd: ReadonlyArray<string>) =>
	cmd[cmd.indexOf("--output-directory") + 1] ?? "";

describe("parseProwlerReport", () => {
	test("maps only FAIL results, with severity, location and compliance tags", () => {
		const findings = parseProwlerReport(json);
		expect(findings.map((f) => `${f.ruleId} ${f.severity}`)).toEqual([
			"cloud.prowler/s3-bucket-public-access high",
			"cloud.prowler/iam-root-mfa-enabled critical",
			"cloud.prowler/ec2-securitygroup-allow-ingress-from-internet-to-tcp-port-22 medium",
			"cloud.prowler/cloudtrail-log-file-validation-enabled low",
			"cloud.prowler/account-maintain-current-contact-details info",
		]); // PASS, MANUAL and the muted ("Suppressed") FAIL are dropped
		const s3 = findings[0];
		expect(s3?.location).toEqual({
			url: "arn:aws:s3:::customer-uploads-prod",
			selector: "AwsS3Bucket",
		});
		expect(s3?.category).toBe("security");
		expect(s3?.evidence).toContain("customer-uploads-prod");
		expect(s3?.message).toContain("eu-west-1");
		expect(s3?.tags).toEqual([
			"prowler",
			"aws",
			"cis-1.4",
			"cis-2.0",
			"aws-foundational-security-best-practices",
			"pci-3.2.1",
		]);
		expect(s3?.references).toEqual([
			"https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html",
			"https://docs.aws.amazon.com/AmazonS3/latest/user-guide/block-public-access-account.html",
		]); // the CLI one-liner in remediation.references is not a URL
		expect(s3?.remediation).toContain("Public Access Block");
		expect(findings[3]?.tags).toEqual(["prowler", "aws"]);
	});

	test("uses the compliance category when a framework was requested", () => {
		const findings = parseProwlerReport(json, { compliance: true });
		expect(findings.every((f) => f.category === "compliance")).toBe(true);
	});

	test("tolerates junk", () => {
		expect(parseProwlerReport([])).toEqual([]);
		expect(parseProwlerReport({})).toEqual([]);
		expect(parseProwlerReport([null, 1, { status_code: "FAIL" }])).toEqual([]);
	});
});

describe("settings and arguments", () => {
	test("builds provider-specific arguments", () => {
		const s = readProwlerSettings({
			profile: "audit-ro",
			regions: ["eu-west-1", "us-east-1"],
			checks: ["iam_root_mfa_enabled"],
			compliance: "cis_2.0_aws",
		});
		const args = prowlerArgs("aws", s, "/out");
		expect(args.slice(0, 5)).toEqual([
			"aws",
			"--output-formats",
			"json-ocsf",
			"--output-directory",
			"/out",
		]);
		expect(args).toContain("--no-banner");
		expect(
			args.slice(args.indexOf("--status"), args.indexOf("--status") + 2),
		).toEqual(["--status", "FAIL"]);
		expect(args).toEqual(
			expect.arrayContaining([
				"--profile",
				"audit-ro",
				"--filter-region",
				"eu-west-1",
				"us-east-1",
				"--checks",
				"iam_root_mfa_enabled",
				"--compliance",
				"cis_2.0_aws",
			]),
		);
		const az = prowlerArgs(
			"azure",
			readProwlerSettings({ azureAuth: "sp-env", profile: "x" }),
			"/out",
		);
		expect(az).toContain("--sp-env-auth");
		expect(az).not.toContain("--profile"); // aws-only
		expect(
			prowlerArgs(
				"gcp",
				readProwlerSettings({ projectIds: ["my-project-123"] }),
				"/o",
			),
		).toEqual(expect.arrayContaining(["--project-ids", "my-project-123"]));
		expect(
			prowlerArgs(
				"kubernetes",
				readProwlerSettings({ context: "prod-eu" }),
				"/o",
			),
		).toEqual(expect.arrayContaining(["--context", "prod-eu"]));
	});

	test("rejects anything that could inject arguments", () => {
		for (const bad of [
			{ profile: "--output-directory=/etc" },
			{ profile: "a b" },
			{ profile: "a;rm -rf" },
			{ profile: ["x"] },
			{ regions: ["-f"] },
			{ regions: ["us-east-1 --checks"] },
			{ checks: ["x\n--foo"] },
			{ checks: ["--all"] },
			{ services: ["$(id)"] },
			{ compliance: "../../etc/passwd" },
			{ compliance: "-x" },
			{ azureAuth: "browser" },
			{ projectIds: ["--x"] },
			{ context: "-v" },
			{ checks: Array.from({ length: 51 }, () => "a") },
		])
			expect(() => readProwlerSettings(bad)).toThrow();
		expect(() => readProwlerSettings(undefined)).not.toThrow();
	});
});

describe("cloud.prowler run", () => {
	test("is opt-in, cloud-only and registered", () => {
		expect(prowler.defaultEnabled).toBe(false);
		expect(prowler.targets).toEqual(["cloud"]);
		expect(prowler.tool).toBe("prowler");
		expect(prowler.categories).toEqual(["security", "compliance"]);
		expect(cloudAuditors).toEqual([prowler]);
	});

	test("runs prowler for the target provider and parses the report (exit code 3)", async () => {
		let cmd: ReadonlyArray<string> = [];
		const report = await runWithExec(
			prowler,
			"cloud:aws",
			have,
			async (c) => {
				cmd = c;
				await writeFile(`${outDirOf(c)}/openaudit.ocsf.json`, text);
				return { code: 3, stdout: "", stderr: "" };
			},
			{ settings: { "cloud.prowler": { regions: ["eu-west-1"] } } },
		);
		expect(cmd[0]).toBe("/usr/bin/prowler");
		expect(cmd[1]).toBe("aws");
		expect(cmd).toContain("eu-west-1");
		expect(report.results[0]?.status).toBe("failed");
		expect(report.results[0]?.findings).toHaveLength(5);
		expect(JSON.stringify(report.results[0]?.findings)).not.toContain(
			"AWS_SECRET",
		);
	});

	test("skips without prowler, and fails on bad settings or no report", async () => {
		const none = await runWithExec(
			prowler,
			"cloud:gcp",
			() => undefined,
			() => Promise.reject(new Error("no")),
		);
		expect(none.results[0]?.status).toBe("skipped");
		expect(none.results[0]?.message).toContain("prowler");

		const bad = await runWithExec(
			prowler,
			"cloud:aws",
			have,
			() => Promise.reject(new Error("must not run")),
			{ settings: { "cloud.prowler": { profile: "--evil" } } },
		);
		expect(bad.results[0]?.status).toBe("error");
		expect(bad.results[0]?.message).toContain("invalid");

		const crash = await runWithExec(prowler, "cloud:aws", have, async () => ({
			code: 1,
			stdout: "",
			stderr: "Unable to locate credentials",
		}));
		expect(crash.results[0]?.status).toBe("error");
		expect(crash.results[0]?.message).toContain("Unable to locate credentials");
	});
});
