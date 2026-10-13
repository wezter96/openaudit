import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
	type Auditor,
	Exec,
	type ExecResult,
	Http,
	type Report,
	runAudit,
	Workspaces,
} from "@openaudit/core";
import { Effect, Layer } from "effect";

import { actionlint, parseActionlintReport } from "../src/infra/actionlint";
import { dockle, parseDockleReport } from "../src/infra/dockle";
import { kics, parseKicsReport } from "../src/infra/kics";
import { kubeLinter, parseKubeLinterReport } from "../src/infra/kube-linter";
import { kubescape, parseKubescapeReport } from "../src/infra/kubescape";
import { parseZizmorReport, zizmor } from "../src/infra/zizmor";
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

describe("infra tool parsers", () => {
	test("zizmor (recorded)", () => {
		const findings = parseZizmorReport(sample("zizmor.json"), "/repo");
		expect(summary(findings)).toEqual([
			"iac.zizmor/artipacked medium .github/workflows/ci.yml:6",
			"iac.zizmor/excessive-permissions medium .github/workflows/ci.yml:3",
			"iac.zizmor/unpinned-uses high .github/workflows/ci.yml:6",
			"iac.zizmor/artipacked medium .github/workflows/pr.yml:13",
			"iac.zizmor/dangerous-triggers high .github/workflows/pr.yml:2",
			"iac.zizmor/template-injection high .github/workflows/pr.yml:20",
			"iac.zizmor/unpinned-uses high .github/workflows/pr.yml:13",
			"iac.zizmor/unpinned-uses high .github/workflows/pr.yml:16",
			"iac.zizmor/unpinned-uses high .github/workflows/pr.yml:29",
			"iac.zizmor/insecure-commands high .github/workflows/pr.yml:7",
		]);
		const [artipacked] = findings;
		expect(artipacked?.confidence).toBe("low");
		expect(artipacked?.category).toBe("security");
		expect(artipacked?.references).toEqual([
			"https://docs.zizmor.sh/audits/#artipacked",
		]);
		expect(artipacked?.remediation).toContain("persist-credentials: false");
		expect(findings[2]?.category).toBe("supply-chain");
		expect(findings[5]?.tags).toContain("cwe-94");
	});

	test("zizmor drops ignored findings", () => {
		const raw = sample("zizmor.json") as Array<Record<string, unknown>>;
		const ignored = raw.map((r) => ({ ...r, ignored: true }));
		expect(parseZizmorReport(ignored, "/repo")).toEqual([]);
	});

	test("actionlint (recorded)", () => {
		const findings = parseActionlintReport(sample("actionlint.json"), "/repo");
		expect(summary(findings)).toEqual([
			"iac.actionlint/expression high .github/workflows/pr.yml:18",
		]);
		expect(findings[0]?.category).toBe("security");
		expect(findings[0]?.location?.column).toBe(44);
		expect(findings[0]?.tags).toContain("cwe-94");
		expect(findings[0]?.title).not.toContain("see https");
	});

	test("actionlint classifies non-security kinds as reliability or hygiene", () => {
		const findings = parseActionlintReport(
			[
				{
					message: 'unexpected key "foo" for "job" section',
					filepath: "a.yml",
					line: 3,
					column: 5,
					kind: "syntax-check",
				},
				{
					message:
						"shellcheck reported issue in this script: SC2034:warning:1:1: x appears unused",
					filepath: "a.yml",
					line: 9,
					column: 9,
					kind: "shellcheck",
				},
			],
			"/repo",
		);
		expect(findings.map((f) => [f.ruleId, f.category, f.severity])).toEqual([
			["iac.actionlint/syntax-check", "reliability", "medium"],
			["iac.actionlint/shellcheck", "best-practices", "low"],
		]);
	});

	test("kube-linter (recorded)", () => {
		const findings = parseKubeLinterReport(sample("kube-linter.json"), "/repo");
		expect(findings).toHaveLength(12);
		const byRule = new Map(findings.map((f) => [f.ruleId, f]));
		const priv = byRule.get("iac.kube-linter/privileged-container");
		expect(priv?.severity).toBe("high");
		expect(priv?.category).toBe("security");
		expect(priv?.location?.file).toBe("app.yaml");
		expect(priv?.evidence).toBe("Deployment/web");
		expect(priv?.references).toEqual([
			"https://docs.kubelinter.io/#/generated/checks?id=privileged-container",
		]);
		expect(priv?.remediation).toBeTruthy();
		expect(byRule.get("iac.kube-linter/unset-cpu-requirements")?.category).toBe(
			"reliability",
		);
		expect(byRule.get("iac.kube-linter/latest-tag")?.category).toBe(
			"best-practices",
		);
		expect(parseKubeLinterReport({ Reports: null }, "/repo")).toEqual([]);
	});

	test("kics (reconstructed from documented schema)", () => {
		const findings = parseKicsReport(sample("kics.json"), "/repo");
		expect(summary(findings)).toEqual([
			"iac.kics/kubernetes-privilege-escalation-allowed high k8s/app.yaml:15",
			"iac.kics/dockerfile-missing-user-instruction high Dockerfile:1",
			"iac.kics/terraform-s3-bucket-acl-allows-read-to-any-authenticated-user high main.tf:8",
			"iac.kics/kubernetes-container-running-as-root medium k8s/app.yaml:15",
			"iac.kics/dockerfile-healthcheck-instruction-missing info Dockerfile:1",
		]);
		expect(findings[0]?.tags).toContain("cwe-269");
		expect(findings[0]?.references).toEqual([
			"https://kubernetes.io/docs/tasks/configure-pod-container/security-context/",
		]);
		expect(findings[1]?.category).toBe("best-practices");
	});

	test("kubescape (reconstructed from documented schema)", () => {
		const findings = parseKubescapeReport(sample("kubescape.json"), "/repo");
		expect(
			findings.map((f) => [f.ruleId, f.severity, f.category, f.location?.file]),
		).toEqual([
			["iac.kubescape/c-0057", "high", "security", "app.yaml"],
			["iac.kubescape/c-0013", "medium", "security", "app.yaml"],
			["iac.kubescape/c-0004", "high", "reliability", "app.yaml"],
		]);
		expect(findings[0]?.evidence).toBe(
			"spec.template.spec.containers[0].securityContext.privileged",
		);
		expect(findings[1]?.remediation).toContain("runAsNonRoot");
		expect(findings[0]?.references).toEqual([
			"https://hub.armosec.io/docs/c-0057",
		]);
	});

	test("dockle (README sample)", () => {
		const findings = parseDockleReport(
			sample("dockle.json"),
			"goodwithtech/test-image:v1",
		);
		// The README sample has 10 details, none of them SKIP/PASS.
		expect(findings).toHaveLength(10);
		const first = findings[0];
		expect(first?.ruleId).toBe("container.dockle/cis-di-0001");
		expect(first?.severity).toBe("medium");
		expect(first?.location?.file).toBe("goodwithtech/test-image:v1");
		expect(first?.references).toEqual([
			"https://github.com/goodwithtech/dockle/blob/master/CHECKPOINT.md#cis-di-0001",
		]);
		expect(
			findings.find((f) => f.ruleId.endsWith("cis-di-0005"))?.severity,
		).toBe("low");
		expect(
			findings.find((f) => f.ruleId.endsWith("cis-di-0009"))?.category,
		).toBe("best-practices");
		expect(findings.filter((f) => f.severity === "high")).toHaveLength(6);
		const noisy = parseDockleReport(
			{
				details: [
					{ code: "X", title: "t", level: "SKIP", alerts: ["a"] },
					{ code: "Y", title: "t", level: "PASS", alerts: [] },
				],
			},
			"img",
		);
		expect(noisy).toEqual([]);
	});

	test("parsers tolerate unexpected shapes", () => {
		for (const parse of [
			parseZizmorReport,
			parseActionlintReport,
			parseKubeLinterReport,
			parseKicsReport,
			parseKubescapeReport,
		]) {
			expect(parse(null, "/repo")).toEqual([]);
			expect(
				parse({ queries: "x", Reports: [1, null], results: [null] }, "/repo"),
			).toEqual([]);
		}
		expect(parseDockleReport(null, "img")).toEqual([]);
	});
});

/** Runs an auditor against `target` with a fake Exec service. */
const runWithExec = (
	auditor: Auditor,
	target: string,
	which: (bin: string) => string | undefined,
	run: (cmd: ReadonlyArray<string>) => Promise<ExecResult>,
): Promise<Report> =>
	Effect.runPromise(
		runAudit({
			target,
			auditors: [auditor],
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

const GHA = fixture("infra", "gha-bad");
const K8S = fixture("infra", "k8s-bad");
const TF = fixture("infra", "terraform-bad");
const DOCKER = fixture("infra", "docker-bad");

describe("infra tool auditors", () => {
	test("metadata", () => {
		for (const a of [zizmor, actionlint, kics, kubescape, kubeLinter, dockle]) {
			expect(a.engine).toBe("external");
			expect(a.tool).toBeTruthy();
		}
		expect(kubescape.network).toBe(true);
		expect(dockle.targets).toEqual(["container"]);
		expect(kubescape.defaultEnabled).toBe(false);
	});

	test("skip with an install hint when the tool is missing", async () => {
		const cases: Array<[Auditor, string]> = [
			[zizmor, GHA],
			[actionlint, GHA],
			[kics, TF],
			[kubescape, K8S],
			[kubeLinter, K8S],
			[dockle, "image:nginx:1.27"],
		];
		for (const [auditor, target] of cases) {
			const report = await runWithExec(
				auditor,
				target,
				() => undefined,
				unreachable,
			);
			expect(report.results[0]?.status).toBe("skipped");
			expect(report.results[0]?.message).toContain("not found on PATH");
			expect(report.results[0]?.message).toContain("Install");
		}
	});

	test("skip without nagging for an install when nothing is relevant", async () => {
		const cases: Array<[Auditor, string, string]> = [
			[zizmor, K8S, "No GitHub Actions workflows"],
			[actionlint, K8S, "No GitHub Actions workflows"],
			[kubeLinter, GHA, "No Kubernetes manifests"],
			[kubescape, GHA, "No Kubernetes manifests"],
			[dockle, DOCKER, "image:<ref>"],
		];
		for (const [auditor, target, message] of cases) {
			const report = await runWithExec(
				auditor,
				target,
				() => undefined,
				unreachable,
			);
			expect(`${auditor.id} ${report.results[0]?.status}`).toBe(
				`${auditor.id} skipped`,
			);
			expect(report.results[0]?.message).toContain(message);
			expect(report.results[0]?.message).not.toContain("Install");
		}
	});

	test("zizmor runs offline without a token and accepts exit 14", async () => {
		const saved = [process.env.GH_TOKEN, process.env.GITHUB_TOKEN];
		delete process.env.GH_TOKEN;
		delete process.env.GITHUB_TOKEN;
		try {
			let seen: ReadonlyArray<string> = [];
			const report = await runWithExec(zizmor, GHA, present, async (cmd) => {
				seen = cmd;
				return { code: 14, stdout: sampleText("zizmor.json"), stderr: "" };
			});
			expect(seen).toContain("--offline");
			expect(seen).toContain("./.github/workflows/ci.yml");
			expect(report.results[0]?.status).toBe("failed");
			expect(report.results[0]?.findings).toHaveLength(10);
		} finally {
			if (saved[0] !== undefined) process.env.GH_TOKEN = saved[0];
			if (saved[1] !== undefined) process.env.GITHUB_TOKEN = saved[1];
		}
	});

	test("zizmor drops --offline when a token is set", async () => {
		const saved = process.env.GH_TOKEN;
		process.env.GH_TOKEN = "not-a-real-token";
		try {
			let seen: ReadonlyArray<string> = [];
			await runWithExec(zizmor, GHA, present, async (cmd) => {
				seen = cmd;
				return { code: 0, stdout: "[]", stderr: "" };
			});
			expect(seen).not.toContain("--offline");
		} finally {
			if (saved === undefined) delete process.env.GH_TOKEN;
			else process.env.GH_TOKEN = saved;
		}
	});

	test("zizmor treats exit 1 as an error", async () => {
		const report = await runWithExec(zizmor, GHA, present, async () => ({
			code: 1,
			stdout: "",
			stderr: "error: boom",
		}));
		expect(report.results[0]?.status).toBe("error");
		expect(report.results[0]?.message).toContain("boom");
	});

	test("actionlint exit 1 means findings", async () => {
		const report = await runWithExec(actionlint, GHA, present, async (cmd) => {
			expect(cmd).toContain("{{json .}}");
			return { code: 1, stdout: sampleText("actionlint.json"), stderr: "" };
		});
		expect(report.results[0]?.status).toBe("failed");
		expect(report.results[0]?.findings).toHaveLength(1);
		const clean = await runWithExec(actionlint, GHA, present, async () => ({
			code: 0,
			stdout: "null\n",
			stderr: "",
		}));
		expect(clean.results[0]?.status).toBe("passed");
	});

	test("kube-linter exit 1 means findings", async () => {
		const report = await runWithExec(kubeLinter, K8S, present, async (cmd) => {
			expect(cmd.slice(1, 4)).toEqual(["lint", "--format", "json"]);
			return { code: 1, stdout: sampleText("kube-linter.json"), stderr: "" };
		});
		expect(report.results[0]?.findings).toHaveLength(12);
	});

	test("kics reads results.json from a temp output dir", async () => {
		let outDir = "";
		const report = await runWithExec(kics, TF, present, async (cmd) => {
			outDir = cmd[cmd.indexOf("-o") + 1] ?? "";
			expect(cmd).toContain("--disable-secrets");
			expect(outDir.startsWith(TF)).toBe(false);
			await writeFile(join(outDir, "results.json"), sampleText("kics.json"));
			return { code: 50, stdout: "", stderr: "" };
		});
		expect(report.results[0]?.findings).toHaveLength(5);
		expect(await Bun.file(join(outDir, "results.json")).exists()).toBe(false);
	});

	test("kubescape never submits results and reads its output file", async () => {
		const report = await runWithExec(kubescape, K8S, present, async (cmd) => {
			expect(cmd).toContain("--keep-local");
			const out = cmd[cmd.indexOf("--output") + 1] ?? "";
			await writeFile(out, sampleText("kubescape.json"));
			return { code: 0, stdout: "", stderr: "" };
		});
		expect(report.results[0]?.findings).toHaveLength(3);
	});

	test("dockle scans image targets only", async () => {
		const report = await runWithExec(
			dockle,
			"image:goodwithtech/test-image:v1",
			present,
			async (cmd) => {
				expect(cmd.slice(1, 5)).toEqual(["-f", "json", "--exit-code", "0"]);
				expect(cmd.at(-1)).toBe("goodwithtech/test-image:v1");
				return { code: 0, stdout: sampleText("dockle.json"), stderr: "" };
			},
		);
		expect(report.results[0]?.findings).toHaveLength(10);
	});
});
