import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
	type Auditor,
	Exec,
	type ExecResult,
	type FindingInput,
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
import { firstResult, must } from "./must";

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

const ending = (findings: ReadonlyArray<FindingInput>, suffix: string) =>
	must(
		findings.find((f) => f.ruleId.endsWith(suffix)),
		`a ${suffix} finding`,
	);

const fileOf = (f: FindingInput) =>
	must(f.location, `${f.ruleId} location`).file;

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
		const artipacked = must(findings[0], "the artipacked finding");
		expect(artipacked.confidence).toBe("low");
		expect(artipacked.category).toBe("security");
		expect(artipacked.references).toEqual([
			"https://docs.zizmor.sh/audits/#artipacked",
		]);
		expect(artipacked.remediation).toContain("persist-credentials: false");
		expect(must(findings[2], "finding 2").category).toBe("supply-chain");
		expect(must(findings[5], "finding 5").tags).toContain("cwe-94");
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
		const expression = must(findings[0], "the expression finding");
		expect(expression.category).toBe("security");
		expect(must(expression.location, "its location").column).toBe(44);
		expect(expression.tags).toContain("cwe-94");
		expect(expression.title).not.toContain("see https");
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
		const rule = (id: string) => must(byRule.get(`iac.kube-linter/${id}`), id);
		const priv = rule("privileged-container");
		expect(priv.severity).toBe("high");
		expect(priv.category).toBe("security");
		expect(fileOf(priv)).toBe("app.yaml");
		expect(priv.evidence).toBe("Deployment/web");
		expect(priv.references).toEqual([
			"https://docs.kubelinter.io/#/generated/checks?id=privileged-container",
		]);
		expect(priv.remediation).toBeTruthy();
		expect(rule("unset-cpu-requirements").category).toBe("reliability");
		expect(rule("latest-tag").category).toBe("best-practices");
		expect(parseKubeLinterReport({ Reports: null }, "/repo")).toEqual([]);
	});

	test("kics (recorded from kics 2.2.0)", () => {
		const findings = parseKicsReport(sample("kics.json"), "/repo");
		expect(findings).toHaveLength(89);
		expect(new Set(findings.map((f) => f.location?.file))).toEqual(
			new Set(["tf/main.tf", "k8s/app.yaml", "docker/Dockerfile"]),
		);
		const rds = ending(findings, "rds-db-instance-publicly-accessible");
		expect(rds.ruleId).toBe(
			"iac.kics/terraform-rds-db-instance-publicly-accessible",
		);
		expect(rds.severity).toBe("critical");
		expect(rds.category).toBe("security");
		expect(rds.location).toEqual({ file: "tf/main.tf", line: 35 });
		expect(rds.evidence).toBe("aws_db_instance[db].publicly_accessible");
		expect(rds.tags).toContain("cwe-668");
		// `remediation` is a before/after JSON string for replacement fixes.
		expect(rds.remediation).toBe("Change true to false.");
		expect(rds.references).toEqual([
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance#publicly_accessible",
		]);
		const noUser = ending(findings, "dockerfile-missing-user-instruction");
		expect(noUser.severity).toBe("high");
		expect(noUser.category).toBe("best-practices");
		expect(noUser.location).toEqual({ file: "docker/Dockerfile", line: 2 });
		expect(ending(findings, "dockerfile-add-instead-of-copy").category).toBe(
			"supply-chain",
		);
	});

	test("kubescape (recorded from kubescape 4.0.15)", () => {
		const findings = parseKubescapeReport(sample("kubescape.json"), "/repo");
		// The manifest lives in deploy/sub: Kubescape reports the directory as
		// `source.path` and only the basename as `source.relativePath`.
		expect(findings).toHaveLength(28);
		expect(new Set(findings.map((f) => f.location?.file))).toEqual(
			new Set(["deploy/sub/app.yaml"]),
		);
		const privileged = ending(findings, "c-0057");
		expect(privileged.severity).toBe("high");
		expect(privileged.category).toBe("security");
		expect(privileged.message).toBe(
			"Privileged container failed for Deployment/web.",
		);
		expect(privileged.references).toEqual([
			"https://hub.armosec.io/docs/c-0057",
		]);
		expect(privileged.remediation).toContain(
			"Suggested: remove spec.template.spec.containers[0]",
		);
		const memory = ending(findings, "c-0004");
		expect(memory.category).toBe("reliability");
		expect(memory.remediation).toContain(
			'resources.limits.memory to "YOUR_VALUE"',
		);
		expect(ending(findings, "c-0013").severity).toBe("medium");
		expect(ending(findings, "c-0076").severity).toBe("low");
		// Passed and skipped controls never become findings.
		expect(findings.every((f) => f.title.startsWith("C-"))).toBe(true);
	});

	test("dockle (README sample)", () => {
		const findings = parseDockleReport(
			sample("dockle.json"),
			"goodwithtech/test-image:v1",
		);
		// The README sample has 10 details, none of them SKIP/PASS.
		expect(findings).toHaveLength(10);
		const first = must(findings[0], "the first finding");
		expect(first.ruleId).toBe("container.dockle/cis-di-0001");
		expect(first.severity).toBe("medium");
		expect(fileOf(first)).toBe("goodwithtech/test-image:v1");
		expect(first.references).toEqual([
			"https://github.com/goodwithtech/dockle/blob/master/CHECKPOINT.md#cis-di-0001",
		]);
		expect(ending(findings, "cis-di-0005").severity).toBe("low");
		expect(ending(findings, "cis-di-0009").category).toBe("best-practices");
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

	test("dockle (recorded from dockle 0.4.15 against local images)", () => {
		const alpine = parseDockleReport(sample("dockle-alpine.json"), "alpine");
		expect(summary(alpine)).toEqual([
			"container.dockle/cis-di-0001 medium alpine:-",
			"container.dockle/cis-di-0005 low alpine:-",
			"container.dockle/cis-di-0006 low alpine:-",
		]);
		expect(must(alpine[2], "finding 2").category).toBe("reliability");
		const bun = parseDockleReport(sample("dockle-bun.json"), "oven/bun");
		// CIS-DI-0008 reports one alert per setuid/setgid file.
		const setuid = bun.filter((f) => f.ruleId.endsWith("cis-di-0008"));
		expect(setuid).toHaveLength(11);
		expect(must(setuid[0], "a setuid finding").evidence).toBe(
			"setgid file: grwxr-xr-x usr/sbin/unix_chkpwd",
		);
		expect(bun).toHaveLength(14);
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
			const result = firstResult(report);
			expect(result.status).toBe("skipped");
			expect(result.message).toContain("not found on PATH");
			expect(result.message).toContain("Install");
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
			const result = firstResult(report);
			expect(`${auditor.id} ${result.status}`).toBe(`${auditor.id} skipped`);
			expect(result.message).toContain(message);
			expect(result.message).not.toContain("Install");
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
			const result = firstResult(report);
			expect(result.status).toBe("failed");
			expect(result.findings).toHaveLength(10);
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
		const result = firstResult(report);
		expect(result.status).toBe("error");
		expect(result.message).toContain("boom");
	});

	test("actionlint exit 1 means findings", async () => {
		const report = await runWithExec(actionlint, GHA, present, async (cmd) => {
			expect(cmd).toContain("{{json .}}");
			return { code: 1, stdout: sampleText("actionlint.json"), stderr: "" };
		});
		const result = firstResult(report);
		expect(result.status).toBe("failed");
		expect(result.findings).toHaveLength(1);
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
			// Not a KICS 2.x flag: it makes the scan fail with "unknown flag".
			expect(cmd).not.toContain("--disable-full-descriptions");
			expect(outDir.startsWith(TF)).toBe(false);
			await writeFile(join(outDir, "results.json"), sampleText("kics.json"));
			return { code: 50, stdout: "", stderr: "" };
		});
		// 89 raw results; the engine collapses duplicate fingerprints.
		expect(report.results[0]?.findings).toHaveLength(84);
		expect(await Bun.file(join(outDir, "results.json")).exists()).toBe(false);
	});

	test("kubescape never submits results and reads its output file", async () => {
		const report = await runWithExec(kubescape, K8S, present, async (cmd) => {
			expect(cmd).toContain("--keep-local");
			const out = cmd[cmd.indexOf("--output") + 1] ?? "";
			await writeFile(out, sampleText("kubescape.json"));
			return { code: 0, stdout: "", stderr: "" };
		});
		expect(report.results[0]?.findings.length).toBeGreaterThan(20);
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
