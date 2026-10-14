import { afterEach, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
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

import { infraAuditors } from "../src/infra";
import {
	CRDS_CATALOG,
	kubeconform,
	kubeconformDownloadFailures,
	kubeconformLocator,
	parseKubeconformReport,
} from "../src/infra/kubeconform";
import { parseTflintReport, tflint, tflintConfig } from "../src/infra/tflint";
import { fixture } from "./helpers";

const sampleText = (name: string) =>
	readFileSync(fixture("infra", "external", name), "utf8");
const sample = (name: string): unknown => JSON.parse(sampleText(name));

const summary = (
	findings: ReadonlyArray<{
		ruleId: string;
		severity: string;
		location?: { file?: string; line?: number };
	}>,
) =>
	findings.map(
		(f) =>
			`${f.ruleId} ${f.severity} ${f.location?.file}:${f.location?.line ?? "-"}`,
	);

const K8S = fixture("infra", "k8s-schema");
const TF = fixture("infra", "tflint");
const GHA = fixture("infra", "gha-bad");

const manifests = new Map(
	["deploy/app.yaml", "deploy/broken.yaml", "deploy/crds.yaml"].map((f) => [
		f,
		readFileSync(join(K8S, f), "utf8"),
	]),
);

describe("kubeconform parser", () => {
	test("recorded from kubeconform 0.8.0 with -strict and the CRDs-catalog", () => {
		const findings = parseKubeconformReport(
			sample("kubeconform.json"),
			"/repo",
			kubeconformLocator(manifests),
		);
		expect(summary(findings)).toEqual([
			"iac.kubeconform/wrong-type high deploy/app.yaml:13",
			"iac.kubeconform/unknown-field medium deploy/app.yaml:25",
			"iac.kubeconform/missing-required-field high deploy/app.yaml:31",
			"iac.kubeconform/duplicate-key medium deploy/app.yaml:38",
			"iac.kubeconform/invalid-yaml high deploy/broken.yaml:6",
			// Validated against the CRDs-catalog schema for cert-manager.
			"iac.kubeconform/unknown-field medium deploy/crds.yaml:11",
			"iac.kubeconform/missing-schema info deploy/crds.yaml:13",
		]);
		const [wrongType, unknown] = findings;
		expect(unknown?.message).toBe(
			"Deployment/web at /spec/template/spec/containers/0: additional properties 'imagePullPolicyy' not allowed",
		);
		expect(unknown?.category).toBe("reliability");
		expect(unknown?.evidence).toBe(
			"Deployment/web /spec/template/spec/containers/0/imagePullPolicyy",
		);
		expect(wrongType?.title).toBe("Field has the wrong type: Deployment/web");
		expect(wrongType?.tags).toEqual([
			"kubeconform",
			"kubernetes",
			"wrong-type",
		]);
		const missing = findings.at(-1);
		expect(missing?.category).toBe("best-practices");
		expect(missing?.message).toBe(
			"1 Widget resource (widgets.example.com/v1) not validated: no JSON schema found. Files: deploy/crds.yaml.",
		);
		for (const f of findings) {
			expect(f.remediation).toBeTruthy();
			expect(f.references?.length).toBeGreaterThan(0);
		}
	});

	test("without a locator findings keep the file only", () => {
		const findings = parseKubeconformReport(
			sample("kubeconform.json"),
			"/repo",
		);
		expect(findings).toHaveLength(7);
		expect(findings.every((f) => f.location?.line === undefined)).toBe(true);
		expect(findings[0]?.location?.file).toBe("deploy/app.yaml");
	});

	test("missing schemas are reported once per kind", () => {
		const resource = (filename: string, name: string) => ({
			filename,
			kind: "Widget",
			name,
			version: "widgets.example.com/v1",
			status: "statusError",
			msg: "could not find schema for Widget",
		});
		const findings = parseKubeconformReport(
			{
				resources: [
					resource("./a.yaml", "a"),
					resource("./b.yaml", "b"),
					resource("./b.yaml", "c"),
				],
			},
			"/repo",
		);
		expect(findings).toHaveLength(1);
		expect(findings[0]?.message).toContain("3 Widget resources");
		expect(findings[0]?.message).toContain("Files: a.yaml, b.yaml.");
	});

	test("schema download failures are not findings", () => {
		const offline = sample("kubeconform-offline.json");
		expect(parseKubeconformReport(offline, "/repo")).toEqual([]);
		expect(kubeconformDownloadFailures(offline)).toHaveLength(2);
		expect(kubeconformDownloadFailures(sample("kubeconform.json"))).toEqual([]);
	});

	test("tolerates unexpected shapes", () => {
		expect(parseKubeconformReport(null, "/repo")).toEqual([]);
		expect(
			parseKubeconformReport({ resources: [1, null, "x"] }, "/repo"),
		).toEqual([]);
		expect(kubeconformDownloadFailures(null)).toEqual([]);
	});
});

describe("tflint parser", () => {
	const source = (file: string) => {
		try {
			return readFileSync(join(TF, file), "utf8");
		} catch {
			return undefined;
		}
	};

	test("recorded from tflint 0.64.0 with the AWS ruleset", () => {
		const { findings, errors } = parseTflintReport(
			sample("tflint.json"),
			"/repo",
			source,
		);
		expect(errors).toEqual([]);
		expect(summary(findings)).toEqual([
			"iac.tflint/terraform-required-version low main.tf:1",
			"iac.tflint/terraform-required-providers low main.tf:3",
			"iac.tflint/terraform-typed-variables low main.tf:9",
			"iac.tflint/terraform-unused-declarations low main.tf:11",
			"iac.tflint/aws-instance-invalid-type high main.tf:18",
			"iac.tflint/terraform-deprecated-interpolation low main.tf:20",
			"iac.tflint/terraform-module-version medium main.tf:24",
		]);
		const invalid = findings[4];
		expect(invalid?.category).toBe("reliability");
		expect(invalid?.message).toBe(
			'"t9.mega" is an invalid value as instance_type',
		);
		expect(invalid?.location?.column).toBe(19);
		expect(invalid?.evidence).toBe('instance_type = "t9.mega"');
		expect(invalid?.tags).toEqual([
			"tflint",
			"terraform",
			"aws_instance_invalid_type",
			"aws",
		]);
		// The AWS ruleset leaves `link` empty; the ruleset's rule index stands in.
		expect(invalid?.references).toEqual([
			"https://github.com/terraform-linters/tflint-ruleset-aws/blob/master/docs/rules/README.md",
		]);
		const moduleVersion = findings[6];
		expect(moduleVersion?.category).toBe("supply-chain");
		expect(moduleVersion?.references).toEqual([
			"https://github.com/terraform-linters/tflint-ruleset-terraform/blob/v0.15.0/docs/rules/terraform_module_version.md",
		]);
		expect(moduleVersion?.remediation).toContain("version");
		expect(findings[0]?.category).toBe("best-practices");
	});

	test("recorded Google and Azure rulesets", () => {
		const google = parseTflintReport(sample("tflint-google.json"), "/repo");
		expect(summary(google.findings)).toContain(
			"iac.tflint/google-compute-instance-invalid-machine-type high modules/gcp/main.tf:3",
		);
		const azure = parseTflintReport(sample("tflint-azurerm.json"), "/repo");
		const size = azure.findings.find((f) => f.ruleId.includes("invalid-size"));
		expect(size?.ruleId).toBe(
			"iac.tflint/azurerm-linux-virtual-machine-invalid-size",
		);
		expect(size?.location).toEqual({
			file: "modules/azure/main.tf",
			line: 5,
			column: 27,
		});
		expect(size?.references?.[0]).toContain(
			"tflint-ruleset-azurerm/blob/v0.32.0",
		);
	});

	test("syntax errors with a range become findings", () => {
		const { findings, errors } = parseTflintReport(
			sample("tflint-syntax-error.json"),
			"/repo",
			source,
		);
		expect(errors).toEqual([]);
		expect(summary(findings)).toEqual([
			"iac.tflint/syntax-error high broken/main.tf:2",
		]);
		expect(findings[0]?.title).toBe(
			"Terraform syntax error: Invalid expression",
		);
		expect(findings[0]?.evidence).toBe("ami =");
	});

	test("errors without a range are tool failures", () => {
		const { findings, errors } = parseTflintReport(
			{
				issues: [],
				errors: [
					{ message: "Failed to initialize plugins", severity: "error" },
				],
			},
			"/repo",
		);
		expect(findings).toEqual([]);
		expect(errors).toEqual(["Failed to initialize plugins"]);
	});

	test("tolerates unexpected shapes", () => {
		expect(parseTflintReport(null, "/repo")).toEqual({
			findings: [],
			errors: [],
		});
		expect(
			parseTflintReport(
				{ issues: [1, null, { rule: {} }], errors: [2] },
				"/repo",
			).findings,
		).toEqual([]);
	});

	test("config enables only the bundled ruleset and named plugins", () => {
		const bare = tflintConfig("/tmp/x", []);
		expect(bare).toContain('plugin_dir       = "/tmp/x"');
		expect(bare).toContain('call_module_type = "none"');
		expect(bare).toContain('preset  = "recommended"');
		expect(bare.match(/^plugin "/gm)).toEqual(['plugin "']);
		expect(tflintConfig("/opt/p", ["aws", "google"])).toContain(
			'plugin "google" {',
		);
		// HCL template sequences in a path are escaped, not interpolated.
		// biome-ignore lint/suspicious/noTemplateCurlyInString: HCL interpolation syntax
		expect(tflintConfig("/a/${b}/%{c}", [])).toContain(
			'plugin_dir       = "/a/$${b}/%%{c}"',
		);
	});
});

/** Runs an auditor against `target` with a fake Exec service. */
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

const present = (bin: string) => `/usr/local/bin/${bin}`;
const unreachable = () => Promise.reject(new Error("unreachable"));

describe("kubeconform auditor", () => {
	test("metadata and registration", () => {
		expect(kubeconform.engine).toBe("external");
		expect(kubeconform.tool).toBe("kubeconform");
		expect(kubeconform.network).toBe(true);
		expect(kubeconform.defaultEnabled).toBeUndefined();
		expect(infraAuditors).toContain(kubeconform);
	});

	test("validates plain manifests strictly and skips Helm templates", async () => {
		let seen: ReadonlyArray<string> = [];
		const report = await runWithExec(kubeconform, K8S, present, async (cmd) => {
			seen = cmd;
			return { code: 1, stdout: sampleText("kubeconform.json"), stderr: "" };
		});
		expect(seen.slice(1, 5)).toEqual([
			"-output",
			"json",
			"-summary",
			"-strict",
		]);
		expect(seen).toContain(CRDS_CATALOG);
		expect(seen).not.toContain("-kubernetes-version");
		expect(seen.filter((a) => a.startsWith("./")).sort()).toEqual([
			"./deploy/app.yaml",
			"./deploy/broken.yaml",
			"./deploy/crds.yaml",
		]);
		expect(report.results[0]?.status).toBe("failed");
		const lines = report.results[0]?.findings.map(
			(f) => `${f.ruleId} ${f.location?.file}:${f.location?.line}`,
		);
		expect(lines).toContain("iac.kubeconform/wrong-type deploy/app.yaml:13");
		expect(lines).toContain("iac.kubeconform/duplicate-key deploy/app.yaml:38");
	});

	test("passes a valid kubernetesVersion setting and rejects others", async () => {
		let seen: ReadonlyArray<string> = [];
		const run = async (cmd: ReadonlyArray<string>) => {
			seen = cmd;
			return { code: 0, stdout: '{"resources":[],"summary":{}}', stderr: "" };
		};
		await runWithExec(kubeconform, K8S, present, run, {
			settings: { "iac.kubeconform": { kubernetesVersion: "1.31.0" } },
		});
		expect(seen[seen.indexOf("-kubernetes-version") + 1]).toBe("1.31.0");
		const bad = await runWithExec(kubeconform, K8S, present, unreachable, {
			settings: { "iac.kubeconform": { kubernetesVersion: "1.31; rm" } },
		});
		expect(bad.results[0]?.status).toBe("error");
	});

	test("fails when no schema could be downloaded", async () => {
		const report = await runWithExec(kubeconform, K8S, present, async () => ({
			code: 1,
			stdout: sampleText("kubeconform-offline.json"),
			stderr: "",
		}));
		expect(report.results[0]?.status).toBe("error");
		expect(report.results[0]?.message).toContain("could not download");
	});

	test("is skipped by --offline", async () => {
		const report = await runWithExec(kubeconform, K8S, present, unreachable, {
			offline: true,
		});
		expect(report.results[0]?.status).toBe("skipped");
	});

	test("skips with an install hint, or quietly without manifests", async () => {
		const missing = await runWithExec(
			kubeconform,
			K8S,
			() => undefined,
			unreachable,
		);
		expect(missing.results[0]?.status).toBe("skipped");
		expect(missing.results[0]?.message).toContain("not found on PATH");
		expect(missing.results[0]?.message).toContain("Install");
		const none = await runWithExec(
			kubeconform,
			GHA,
			() => undefined,
			unreachable,
		);
		expect(none.results[0]?.status).toBe("skipped");
		expect(none.results[0]?.message).toContain("No Kubernetes manifests");
	});
});

describe("tflint auditor", () => {
	const saved = process.env.OPENAUDIT_TFLINT_PLUGIN_DIR;
	afterEach(() => {
		if (saved === undefined) delete process.env.OPENAUDIT_TFLINT_PLUGIN_DIR;
		else process.env.OPENAUDIT_TFLINT_PLUGIN_DIR = saved;
	});

	const recorded: Record<string, string> = {
		".": "tflint.json",
		"modules/gcp": "tflint-google.json",
		"modules/azure": "tflint-azurerm.json",
		broken: "tflint-syntax-error.json",
	};

	/** Fake tflint: replays the recording for the --chdir directory and captures the config. */
	const fakeTflint =
		(calls: Array<{ cmd: ReadonlyArray<string>; config: string }>) =>
		async (cmd: ReadonlyArray<string>): Promise<ExecResult> => {
			const configPath =
				cmd.find((a) => a.startsWith("--config="))?.slice(9) ?? "";
			calls.push({ cmd, config: await readFile(configPath, "utf8") });
			const dir = cmd.find((a) => a.startsWith("--chdir=./"))?.slice(10) ?? "";
			const file = recorded[dir];
			return file
				? { code: 2, stdout: sampleText(file), stderr: "" }
				: { code: 0, stdout: '{"issues":[],"errors":[]}', stderr: "" };
		};

	test("metadata and registration", () => {
		expect(tflint.engine).toBe("external");
		expect(tflint.tool).toBe("tflint");
		expect(tflint.network).toBeUndefined();
		expect(tflint.defaultEnabled).toBeUndefined();
		expect(infraAuditors).toContain(tflint);
	});

	test("runs once per module with an openaudit config, never --init", async () => {
		process.env.OPENAUDIT_TFLINT_PLUGIN_DIR = join(
			tmpdir(),
			"openaudit-no-such-dir",
		);
		const calls: Array<{ cmd: ReadonlyArray<string>; config: string }> = [];
		const report = await runWithExec(tflint, TF, present, fakeTflint(calls));
		// Modules run concurrently, so calls arrive in any order.
		expect(
			calls.map((c) => c.cmd.find((a) => a.startsWith("--chdir="))).sort(),
		).toEqual([
			"--chdir=./.",
			"--chdir=./broken",
			"--chdir=./modules/azure",
			"--chdir=./modules/gcp",
		]);
		for (const { cmd, config } of calls) {
			expect(cmd).not.toContain("--init");
			expect(cmd).toContain("--call-module-type=none");
			expect(cmd).toContain("--format=json");
			const configPath = cmd.find((a) => a.startsWith("--config=")) ?? "";
			// Never the project's .tflint.hcl, and never inside the target.
			expect(configPath.startsWith(`--config=${TF}`)).toBe(false);
			expect(configPath.endsWith(".tflint.hcl")).toBe(false);
			// No cloud plugins installed: only the bundled Terraform ruleset.
			expect(config.match(/^plugin "(\w+)"/gm)).toEqual(['plugin "terraform"']);
			expect(config).not.toContain(".tflint.d");
		}
		const configPath = calls[0]?.cmd
			.find((a) => a.startsWith("--config="))
			?.slice(9);
		expect(await Bun.file(configPath ?? "").exists()).toBe(false);
		const findings = report.results[0]?.findings ?? [];
		expect(report.results[0]?.status).toBe("failed");
		expect(findings.map((f) => f.ruleId)).toContain("iac.tflint/syntax-error");
		expect(findings.map((f) => f.ruleId)).toContain(
			"iac.tflint/aws-instance-invalid-type",
		);
	});

	test("enables cloud rulesets installed in the trusted plugin dir", async () => {
		const dir = await mkdtemp(join(tmpdir(), "openaudit-tflint-plugins-"));
		try {
			for (const name of ["aws", "google"]) {
				await writeFile(join(dir, `tflint-ruleset-${name}`), "");
				await chmod(join(dir, `tflint-ruleset-${name}`), 0o755);
			}
			process.env.OPENAUDIT_TFLINT_PLUGIN_DIR = dir;
			const calls: Array<{ cmd: ReadonlyArray<string>; config: string }> = [];
			await runWithExec(tflint, TF, present, fakeTflint(calls));
			const config = calls[0]?.config ?? "";
			expect(config).toContain(`plugin_dir       = "${dir}"`);
			// azurerm is used by the code but not installed.
			expect(config.match(/^plugin "(\w+)"/gm)).toEqual([
				'plugin "terraform"',
				'plugin "aws"',
				'plugin "google"',
			]);
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	test("a range-less error fails the auditor", async () => {
		const report = await runWithExec(tflint, TF, present, async () => ({
			code: 1,
			stdout:
				'{"issues":[],"errors":[{"message":"Failed to initialize plugins; boom","severity":"error"}]}',
			stderr: "",
		}));
		expect(report.results[0]?.status).toBe("error");
		expect(report.results[0]?.message).toContain("boom");
	});

	test("skips with an install hint, or quietly without Terraform", async () => {
		const missing = await runWithExec(tflint, TF, () => undefined, unreachable);
		expect(missing.results[0]?.status).toBe("skipped");
		expect(missing.results[0]?.message).toContain("not found on PATH");
		expect(missing.results[0]?.message).toContain("Install");
		const none = await runWithExec(tflint, K8S, () => undefined, unreachable);
		expect(none.results[0]?.status).toBe("skipped");
		expect(none.results[0]?.message).toContain("No Terraform files");
	});
});
