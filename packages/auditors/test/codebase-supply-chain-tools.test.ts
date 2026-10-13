import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	type Auditor,
	Exec,
	type ExecOptions,
	type ExecResult,
	Http,
	type Report,
	runAudit,
	Workspaces,
} from "@openaudit/core";
import { Effect, Layer } from "effect";

import {
	bunAudit,
	cargoAudit,
	classifyLicenseExpression,
	githubRepoFromGitConfig,
	govulncheck,
	grype,
	npmAudit,
	parseBunAuditReport,
	parseCargoAuditReport,
	parseGovulncheckReport,
	parseGrypeReport,
	parseNpmAuditReport,
	parsePipAuditReport,
	parsePipfileLockPins,
	parsePnpmAuditReport,
	parsePoetryLockPins,
	parseRequirementsPins,
	parseScorecardReport,
	parseSyftLicenses,
	pipAudit,
	pnpmAudit,
	scorecard,
	scorecardSeverity,
	splitJsonStream,
	syftLicenses,
	validSbomPath,
} from "../src/codebase/supply-chain-tools";
import { fixture, runAuditor } from "./helpers";

const text = (name: string) =>
	readFileSync(fixture("codebase", "external", name), "utf8");
const sample = (name: string): unknown => JSON.parse(text(`${name}.json`));
const supply = (dir: string) => fixture("codebase", "supply", dir);

const summary = (
	findings: ReadonlyArray<{
		ruleId: string;
		severity: string;
		confidence?: string;
		location?: { file?: string; line?: number };
	}>,
) =>
	findings.map(
		(f) =>
			`${f.ruleId} ${f.severity}/${f.confidence} ${f.location?.file}:${f.location?.line ?? "-"}`,
	);

describe("govulncheck", () => {
	test("splits concatenated JSON objects", () => {
		expect(splitJsonStream('{"a":"}{"}\n{"b":{"c":1}} junk {"d":2}')).toEqual([
			{ a: "}{" },
			{ b: { c: 1 } },
			{ d: 2 },
		]);
	});

	test("reachable symbols are high confidence, import-only ones lower", () => {
		const findings = parseGovulncheckReport(text("govulncheck.json"), "/repo");
		expect(summary(findings)).toEqual([
			"code.govulncheck/vulnerable-dependency medium/high main.go:10",
			"code.govulncheck/vulnerable-dependency low/low go.mod:-",
			"code.govulncheck/vulnerable-dependency low/low go.mod:-",
			"code.govulncheck/vulnerable-dependency low/low go.mod:-",
		]);
		const [called, pkgOnly, moduleOnly] = findings;
		expect(called?.title).toBe(
			"golang.org/x/text@v0.3.5: Out-of-bounds read in golang.org/x/text/language",
		);
		expect(called?.remediation).toBe(
			"Upgrade golang.org/x/text to v0.3.7 or later.",
		);
		expect(called?.message).toContain("reachable");
		expect(called?.tags).toContain("cve-2021-38561");
		expect(called?.tags).toContain("reachable");
		expect(pkgOnly?.message).toContain(
			"imported but the vulnerable function is not called",
		);
		expect(moduleOnly?.message).toContain("not imported or called");
		expect(called?.references).toContain(
			"https://pkg.go.dev/vuln/GO-2021-0113",
		);
	});

	test("module-relative paths are prefixed with the module dir", () => {
		const [first] = parseGovulncheckReport(
			text("govulncheck.json"),
			"/repo",
			"svc",
		);
		expect(first?.location?.file).toBe("svc/main.go");
	});
});

describe("pip-audit", () => {
	test("parses recorded output and dedupes repeated advisories", () => {
		const findings = parsePipAuditReport(
			sample("pip-audit"),
			"/repo",
			"requirements.txt",
		);
		const ids = findings.map((f) => f.evidence);
		expect(new Set(ids).size).toBe(ids.length);
		expect(ids).toContain("requests@2.19.0 PYSEC-2018-28");
		const req = findings.find(
			(f) => f.evidence === "requests@2.19.0 PYSEC-2018-28",
		);
		expect(req?.ruleId).toBe("code.pip-audit/vulnerable-dependency");
		expect(req?.remediation).toBe("Upgrade requests to 2.20.0 or later.");
		expect(req?.tags).toEqual([
			"owasp-a06",
			"cve-2018-18074",
			"ghsa-x84v-xcm2-53pg",
		]);
		expect(req?.location?.file).toBe("requirements.txt");
		expect(req?.category).toBe("supply-chain");
	});

	test("only exact pins are audited, rewritten without markers or options", () => {
		const pinned = parseRequirementsPins(
			readFileSync(join(supply("py-pinned"), "requirements.txt"), "utf8"),
		);
		expect(pinned).toEqual({
			pins: ["requests==2.19.0", "django[argon2]==3.2.0"],
			unpinned: [],
		});
		const loose = parseRequirementsPins(
			"requests>=2\n-r base.txt\ngit+https://x/y.git\n-e .\n",
		);
		expect(loose.pins).toEqual([]);
		expect(loose.unpinned.length).toBe(4);
		expect(
			parsePoetryLockPins(
				readFileSync(join(supply("py-poetry"), "poetry.lock"), "utf8"),
			).pins,
		).toEqual(["requests==2.19.0", "django==3.2.0"]);
		expect(
			parsePipfileLockPins(
				JSON.stringify({
					default: { a: { version: "==1.0" }, b: { git: "x" } },
					develop: { c: { version: "==2.0" } },
				}),
			).pins,
		).toEqual(["a==1.0", "c==2.0"]);
	});
});

describe("cargo-audit", () => {
	test("vulnerabilities and warnings", () => {
		const findings = parseCargoAuditReport(
			sample("cargo-audit"),
			"/repo",
			"Cargo.lock",
		);
		expect(summary(findings)).toEqual([
			"code.cargo-audit/vulnerable-dependency medium/high Cargo.lock:-",
			"code.cargo-audit/unmaintained-dependency low/high Cargo.lock:-",
		]);
		expect(findings[0]?.title).toBe(
			"time@0.1.45: Potential segfault in the time crate",
		);
		expect(findings[0]?.remediation).toBe("Upgrade time to 0.2.23 or later.");
		expect(findings[0]?.tags).toEqual([
			"owasp-a06",
			"cve-2020-26235",
			"ghsa-wcg3-cvx6-7396",
		]);
		expect(findings[0]?.references?.[0]).toBe(
			"https://rustsec.org/advisories/RUSTSEC-2020-0071.html",
		);
	});
});

describe("npm / pnpm / bun audit", () => {
	const npmLock = {
		file: "package-lock.json",
		text: readFileSync(join(supply("npm"), "package-lock.json"), "utf8"),
	};

	test("npm v7+ report: one finding per advisory with lockfile versions", () => {
		const findings = parseNpmAuditReport(sample("npm-audit"), "/repo", npmLock);
		expect(findings.length).toBe(8);
		const cmd = findings.find(
			(f) => f.evidence === "lodash@4.17.15 GHSA-35jh-r3h4-6jhm",
		);
		expect(cmd?.severity).toBe("high");
		expect(cmd?.title).toBe("lodash@4.17.15: Command Injection in lodash");
		expect(cmd?.remediation).toBe("Upgrade lodash to 4.17.21 or later.");
		expect(cmd?.tags).toEqual([
			"owasp-a06",
			"ghsa-35jh-r3h4-6jhm",
			"cwe-77",
			"cwe-94",
		]);
		expect(cmd?.location?.file).toBe("package-lock.json");
		const ranges = findings.find((f) =>
			f.evidence?.endsWith("GHSA-f23m-r3pf-42rh"),
		);
		expect(ranges?.remediation).toContain("Upgrade lodash to 4.18.1");
	});

	test("pnpm report", () => {
		const findings = parsePnpmAuditReport(
			sample("pnpm-audit"),
			"/repo",
			"pnpm-lock.yaml",
		);
		expect(findings.length).toBe(8);
		const mini = findings.find(
			(f) => f.evidence === "minimist@1.2.0 GHSA-xvch-5gv4-984h",
		);
		expect(mini?.severity).toBe("critical");
		expect(mini?.remediation).toBe("Upgrade minimist to 1.2.6 or later.");
		expect(mini?.tags).toContain("cve-2021-44906");
	});

	test("bun report resolves versions from bun.lock", () => {
		const findings = parseBunAuditReport(sample("bun-audit"), "/repo", {
			file: "bun.lock",
			text: readFileSync(join(supply("bun"), "bun.lock"), "utf8"),
		});
		expect(findings.length).toBe(8);
		expect(
			findings.every((f) => /@(4\.17\.15|1\.2\.0) /.test(f.evidence ?? "")),
		).toBe(true);
		expect(findings.map((f) => f.location?.file)).toEqual(
			Array(8).fill("bun.lock"),
		);
	});
});

describe("grype", () => {
	test("matches become dependency findings", () => {
		const findings = parseGrypeReport(sample("grype"), "/repo");
		expect(findings.length).toBe(8);
		const lodash = findings.find(
			(f) => f.evidence === "lodash@4.17.15 GHSA-35jh-r3h4-6jhm",
		);
		expect(lodash?.severity).toBe("high");
		expect(lodash?.location?.file).toBe("package-lock.json");
		expect(lodash?.remediation).toBe("Upgrade lodash to 4.17.21 or later.");
		expect(lodash?.tags).toContain("cve-2021-23337");
		expect(lodash?.tags).toContain("cwe-94");
		expect(lodash?.confidence).toBe("high");
	});
});

describe("syft licences", () => {
	test("policy findings from the SBOM", () => {
		const findings = parseSyftLicenses(sample("syft"), "/repo");
		expect(
			findings.map((f) => `${f.ruleId} ${f.severity} ${f.evidence}`).sort(),
		).toEqual([
			"code.syft-licenses/missing-license info 1/5 packages without licence",
			"code.syft-licenses/strong-copyleft medium gpl-pkg@2.0.0 GPL-3.0-only",
			"code.syft-licenses/weak-copyleft low lgpl-pkg@3.0.0 LGPL-2.1-or-later",
			"code.syft-licenses/weak-copyleft low mpl-pkg@1.0.0 MPL-2.0",
		]);
		expect(findings.every((f) => f.category === "compliance")).toBe(true);
		expect(findings[0]?.remediation).toContain("distributed");
		const missing = findings.find((f) => f.ruleId.endsWith("missing-license"));
		expect(missing?.message).toContain("nolic-pkg@1.0.0");
	});

	test("SPDX expressions", () => {
		const c = classifyLicenseExpression;
		expect(c("MIT")).toBe("permissive");
		expect(c("GPL-3.0-only")).toBe("strong");
		expect(c("AGPL-3.0-or-later")).toBe("strong");
		expect(c("LGPL-2.1-only")).toBe("weak");
		expect(c("MIT OR GPL-2.0-only")).toBe("permissive");
		expect(c("MIT AND GPL-2.0-only")).toBe("strong");
		expect(c("(MIT OR Apache-2.0) AND MPL-2.0")).toBe("weak");
		expect(c("GPL-2.0-only WITH Classpath-exception-2.0")).toBe("strong");
		expect(c("GNU Lesser General Public License v3")).toBe("weak");
		expect(c("SSPL-1.0")).toBe("strong");
	});

	test("sbomOut validation", () => {
		expect(validSbomPath("out/sbom.cdx.json")).toBe("out/sbom.cdx.json");
		for (const bad of [
			"",
			"-o",
			"a\nb",
			"a,format=x",
			5,
			null,
			"x".repeat(2000),
		])
			expect(validSbomPath(bad)).toBeUndefined();
	});
});

describe("scorecard", () => {
	test("scores 0-9 become findings, -1 and 10 are skipped", () => {
		const findings = parseScorecardReport(sample("scorecard"));
		expect(findings.map((f) => `${f.ruleId} ${f.severity}`)).toEqual([
			"code.scorecard/pinned-dependencies medium",
			"code.scorecard/token-permissions high",
			"code.scorecard/security-policy info",
			"code.scorecard/fuzzing medium",
			"code.scorecard/license info",
		]);
		expect(findings[0]?.references).toEqual([
			"https://github.com/ossf/scorecard/blob/v5.1.1/docs/checks.md#pinned-dependencies",
		]);
		expect(findings[0]?.evidence).toContain("not pinned by hash");
	});

	test("severity scales risk by score", () => {
		expect(scorecardSeverity("critical", 0)).toBe("critical");
		expect(scorecardSeverity("critical", 5)).toBe("high");
		expect(scorecardSeverity("high", 5)).toBe("medium");
		expect(scorecardSeverity("high", 8)).toBe("low");
		expect(scorecardSeverity("low", 9)).toBe("info");
	});

	test("origin remote parsing", () => {
		const cfg = (url: string) =>
			`[core]\n\tbare = false\n[remote "origin"]\n\turl = ${url}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n`;
		for (const url of [
			"https://github.com/example/widgets.git",
			"git@github.com:example/widgets.git",
			"ssh://git@github.com/example/widgets",
			"https://user:token@github.com/example/widgets/",
		])
			expect(githubRepoFromGitConfig(cfg(url))).toEqual({
				owner: "example",
				repo: "widgets",
			});
		expect(
			githubRepoFromGitConfig(cfg("https://gitlab.com/a/b.git")),
		).toBeUndefined();
		expect(githubRepoFromGitConfig("[core]\n")).toBeUndefined();
	});
});

test("parsers tolerate unexpected shapes", () => {
	for (const parse of [
		(v: unknown) => parsePipAuditReport(v, "/repo"),
		(v: unknown) => parseCargoAuditReport(v, "/repo"),
		(v: unknown) => parseNpmAuditReport(v, "/repo"),
		(v: unknown) => parsePnpmAuditReport(v, "/repo"),
		(v: unknown) => parseBunAuditReport(v, "/repo"),
		(v: unknown) => parseGrypeReport(v, "/repo"),
		(v: unknown) => parseSyftLicenses(v, "/repo"),
		(v: unknown) => parseScorecardReport(v),
	]) {
		expect(parse(null)).toEqual([]);
		expect(
			parse({
				dependencies: "x",
				vulnerabilities: [1],
				advisories: 3,
				matches: [null],
				artifacts: [5],
				checks: [{}],
				warnings: { unmaintained: [1] },
			}),
		).toEqual([]);
	}
	expect(parseGovulncheckReport("not json {", "/repo")).toEqual([]);
});

/* ------------------------------ auditor runs ------------------------------ */

interface Call {
	cmd: ReadonlyArray<string>;
	options?: ExecOptions;
}

const runWithExec = (
	auditor: Auditor,
	target: string,
	which: (bin: string) => string | undefined,
	run: (
		cmd: ReadonlyArray<string>,
		options?: ExecOptions,
	) => Promise<ExecResult>,
	options: Parameters<typeof runAudit>[0]["options"] = {},
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
						run: (cmd, opts) => Effect.promise(() => run(cmd, opts)),
					}),
				),
			),
		),
	);

const present = (bin: string) => `/usr/local/bin/${bin}`;
const unreachable = () => Promise.reject(new Error("tool must not run"));

describe("skip paths", () => {
	const cases: Array<[Auditor, string]> = [
		[govulncheck, "go.mod"],
		[pipAudit, "requirements"],
		[cargoAudit, "Cargo.lock"],
		[npmAudit, "package-lock.json"],
		[pnpmAudit, "pnpm-lock.yaml"],
		[bunAudit, "bun.lock"],
	];

	test("nothing relevant: skipped before the tool is required", async () => {
		for (const [auditor, what] of cases) {
			const report = await runWithExec(
				auditor,
				supply("empty"),
				() => undefined,
				unreachable,
			);
			expect(report.results[0]?.status).toBe("skipped");
			expect(report.results[0]?.message).toContain(what);
			expect(report.results[0]?.message).not.toContain("not found on PATH");
		}
	});

	test("relevant target but tool missing: skipped with an install hint", async () => {
		const withTargets: Array<[Auditor, string]> = [
			[govulncheck, "go"],
			[pipAudit, "py-pinned"],
			[cargoAudit, "cargo"],
			[npmAudit, "npm"],
			[pnpmAudit, "pnpm"],
			[bunAudit, "bun"],
			[grype, "empty"],
			[syftLicenses, "empty"],
		];
		for (const [auditor, dir] of withTargets) {
			const report = await runWithExec(
				auditor,
				supply(dir),
				() => undefined,
				unreachable,
			);
			expect(report.results[0]?.status).toBe("skipped");
			expect(report.results[0]?.message).toContain("not found on PATH");
			expect(report.results[0]?.message).toContain("Install");
			expect(auditor.engine).toBe("external");
		}
	});

	test("unpinned requirements are not audited", async () => {
		const report = await runWithExec(
			pipAudit,
			supply("py-unpinned"),
			present,
			unreachable,
		);
		expect(report.results[0]?.status).toBe("skipped");
		expect(report.results[0]?.message).toContain("Not fully pinned");
	});
});

describe("auditor runs", () => {
	test("govulncheck runs in the module dir with a hardened environment", async () => {
		const calls: Call[] = [];
		const report = await runWithExec(
			govulncheck,
			supply("go"),
			present,
			async (cmd, options) => {
				calls.push({ cmd, options });
				return { code: 0, stdout: text("govulncheck.json"), stderr: "" };
			},
		);
		expect(calls[0]?.cmd).toEqual([
			"/usr/local/bin/govulncheck",
			"-format",
			"json",
			"./...",
		]);
		expect(calls[0]?.options?.cwd).toContain("supply/go");
		expect(calls[0]?.options?.env?.CGO_ENABLED).toBe("0");
		expect(report.results[0]?.findings.length).toBe(4);
		expect(govulncheck.defaultEnabled).toBe(false);
	});

	test("pip-audit audits a sanitised pin file, never the target's", async () => {
		const calls: Call[] = [];
		let pins = "";
		const report = await runWithExec(
			pipAudit,
			supply("py-pinned"),
			present,
			async (cmd, options) => {
				calls.push({ cmd, options });
				pins = await readFile(cmd[cmd.indexOf("-r") + 1] ?? "", "utf8");
				return { code: 1, stdout: text("pip-audit.json"), stderr: "" };
			},
		);
		expect(calls[0]?.cmd.slice(1)).toEqual([
			"-r",
			calls[0]?.cmd[2] ?? "",
			"--no-deps",
			"--disable-pip",
			"--format",
			"json",
			"--progress-spinner",
			"off",
		]);
		expect(calls[0]?.cmd[2]).not.toContain("py-pinned");
		expect(pins).toBe("requests==2.19.0\ndjango[argon2]==3.2.0\n");
		expect(report.results[0]?.findings[0]?.location?.file).toBe(
			"requirements.txt",
		);
	});

	test("pip-audit reads poetry.lock pins", async () => {
		let pins = "";
		const report = await runWithExec(
			pipAudit,
			supply("py-poetry"),
			present,
			async (cmd) => {
				pins = await readFile(cmd[cmd.indexOf("-r") + 1] ?? "", "utf8");
				return {
					code: 0,
					stdout: '{"dependencies":[],"fixes":[]}',
					stderr: "",
				};
			},
		);
		expect(pins).toBe("requests==2.19.0\ndjango==3.2.0\n");
		expect(report.results[0]?.status).toBe("passed");
	});

	test("cargo-audit reads only the lockfile", async () => {
		const calls: Call[] = [];
		const report = await runWithExec(
			cargoAudit,
			supply("cargo"),
			present,
			async (cmd, options) => {
				calls.push({ cmd, options });
				return { code: 1, stdout: text("cargo-audit.json"), stderr: "" };
			},
		);
		expect(calls[0]?.cmd.slice(1, 4)).toEqual(["audit", "--json", "-f"]);
		expect(calls[0]?.cmd[4]).toEndWith("supply/cargo/Cargo.lock");
		expect(report.results[0]?.findings.length).toBe(2);
		expect(report.results[0]?.findings[0]?.location?.file).toBe("Cargo.lock");
	});

	test("npm, pnpm and bun audits pin the registry and stay lockfile-only", async () => {
		const cases: Array<[Auditor, string, string, string[]]> = [
			[
				npmAudit,
				"npm",
				"npm-audit.json",
				["audit", "--json", "--package-lock-only"],
			],
			[
				pnpmAudit,
				"pnpm",
				"pnpm-audit.json",
				[
					"audit",
					"--json",
					"--config.ignore-pnpmfile=true",
					"--config.manage-package-manager-versions=false",
				],
			],
			[bunAudit, "bun", "bun-audit.json", ["audit", "--json"]],
		];
		for (const [auditor, dir, file, args] of cases) {
			const calls: Call[] = [];
			const report = await runWithExec(
				auditor,
				supply(dir),
				present,
				async (cmd, options) => {
					calls.push({ cmd, options });
					return { code: 1, stdout: text(file), stderr: "" };
				},
			);
			expect(calls[0]?.cmd.slice(1)).toEqual([
				...args,
				"--registry",
				"https://registry.npmjs.org/",
			]);
			expect(report.results[0]?.status).toBe("failed");
			expect(report.results[0]?.findings.length).toBe(8);
			expect(auditor.defaultEnabled).toBe(true);
			expect(auditor.network).toBe(true);
		}
	});

	test("audit error JSON is reported as an error", async () => {
		const report = await runWithExec(
			npmAudit,
			supply("npm"),
			present,
			async () => ({
				code: 1,
				stdout: JSON.stringify({
					error: { code: "ENOAUDIT", summary: "registry unreachable" },
				}),
				stderr: "",
			}),
		);
		expect(report.results[0]?.status).toBe("error");
		expect(report.results[0]?.message).toContain("registry unreachable");
	});

	test("grype scans from a scratch dir", async () => {
		const calls: Call[] = [];
		const report = await runWithExec(
			grype,
			supply("npm"),
			present,
			async (cmd, options) => {
				calls.push({ cmd, options });
				return { code: 0, stdout: text("grype.json"), stderr: "" };
			},
		);
		expect(calls[0]?.cmd[1]).toStartWith("dir:");
		expect(calls[0]?.cmd.slice(2)).toEqual(["-o", "json", "-q"]);
		expect(calls[0]?.options?.cwd).not.toContain("supply");
		expect(report.results[0]?.findings.length).toBe(8);
		expect(grype.defaultEnabled).toBe(false);
	});

	test("syft passes a validated CycloneDX path and rejects bad ones", async () => {
		const calls: Call[] = [];
		const run = async (cmd: ReadonlyArray<string>, options?: ExecOptions) => {
			calls.push({ cmd, options });
			return { code: 0, stdout: text("syft.json"), stderr: "" };
		};
		const ok = await runWithExec(syftLicenses, supply("npm"), present, run, {
			settings: { "code.syft-licenses": { sbomOut: "out/sbom.json" } },
		});
		expect(ok.results[0]?.findings.length).toBe(4);
		expect(calls[0]?.cmd.slice(1, 6)).toEqual([
			"scan",
			`dir:${supply("npm")}`,
			"-o",
			"syft-json",
			"-q",
		]);
		expect(calls[0]?.cmd.slice(6)).toEqual([
			"-o",
			`cyclonedx-json=${join(supply("npm"), "out/sbom.json")}`,
		]);
		calls.length = 0;
		const bad = await runWithExec(syftLicenses, supply("npm"), present, run, {
			settings: { "code.syft-licenses": { sbomOut: "a,b=c" } },
		});
		expect(bad.results[0]?.status).toBe("error");
		expect(calls.length).toBe(0);
	});

	describe("scorecard", () => {
		const withRepo = async (
			config: string | undefined,
			fn: (dir: string) => Promise<void>,
		) => {
			const dir = await mkdtemp(join(tmpdir(), "openaudit-scorecard-"));
			try {
				if (config !== undefined) {
					await mkdir(join(dir, ".git"));
					await writeFile(join(dir, ".git", "config"), config);
				}
				await writeFile(join(dir, "README.md"), "x");
				await fn(dir);
			} finally {
				await rm(dir, { recursive: true, force: true });
			}
		};
		const origin =
			'[remote "origin"]\n\turl = git@github.com:example/widgets.git\n';
		const saved = {
			a: process.env.GITHUB_AUTH_TOKEN,
			b: process.env.GITHUB_TOKEN,
		};
		const restore = () => {
			for (const [k, v] of [
				["GITHUB_AUTH_TOKEN", saved.a],
				["GITHUB_TOKEN", saved.b],
			] as const)
				if (v === undefined) delete process.env[k];
				else process.env[k] = v;
		};

		test("skips without a git remote or token", async () => {
			try {
				delete process.env.GITHUB_AUTH_TOKEN;
				delete process.env.GITHUB_TOKEN;
				await withRepo(undefined, async (dir) => {
					const r = await runWithExec(scorecard, dir, present, unreachable);
					expect(r.results[0]?.status).toBe("skipped");
					expect(r.results[0]?.message).toContain(".git/config");
				});
				await withRepo(
					'[remote "origin"]\n\turl = https://gitlab.com/a/b.git\n',
					async (dir) => {
						const r = await runWithExec(scorecard, dir, present, unreachable);
						expect(r.results[0]?.message).toContain("not a GitHub");
					},
				);
				await withRepo(origin, async (dir) => {
					const r = await runWithExec(scorecard, dir, present, unreachable);
					expect(r.results[0]?.status).toBe("skipped");
					expect(r.results[0]?.message).toContain("GITHUB_AUTH_TOKEN");
				});
			} finally {
				restore();
			}
		});

		test("runs against the origin repository", async () => {
			try {
				delete process.env.GITHUB_AUTH_TOKEN;
				process.env.GITHUB_TOKEN = "ghp_exampletoken";
				await withRepo(origin, async (dir) => {
					const calls: Call[] = [];
					const missing = await runWithExec(
						scorecard,
						dir,
						() => undefined,
						unreachable,
					);
					expect(missing.results[0]?.message).toContain("Install");
					const report = await runWithExec(
						scorecard,
						dir,
						present,
						async (cmd, options) => {
							calls.push({ cmd, options });
							return { code: 0, stdout: text("scorecard.json"), stderr: "" };
						},
					);
					expect(calls[0]?.cmd.slice(1)).toEqual([
						"--repo=github.com/example/widgets",
						"--format",
						"json",
					]);
					expect(calls[0]?.options?.env?.GITHUB_AUTH_TOKEN).toBe(
						"ghp_exampletoken",
					);
					expect(report.results[0]?.findings.length).toBe(5);
					expect(scorecard.defaultEnabled).toBe(true);
				});
			} finally {
				restore();
			}
		});
	});
});

describe("hostile project config", () => {
	// pnpm loads .pnpmfile.cjs even for `audit`; a project's pnpm-workspace.yaml
	// and .npmrc try to switch the protection back off.
	test.skipIf(!Bun.which("pnpm"))(
		"pnpm audit never runs the project's .pnpmfile.cjs",
		async () => {
			const root = await mkdtemp(join(tmpdir(), "openaudit-pnpmfile-"));
			await writeFile(
				join(root, "package.json"),
				'{"name":"t","version":"1.0.0","dependencies":{"minimist":"1.2.0"}}',
			);
			await writeFile(
				join(root, ".pnpmfile.cjs"),
				"require('fs').writeFileSync(__dirname + '/PWNED', 'x'); module.exports = { hooks: {} };\n",
			);
			await writeFile(
				join(root, "pnpm-workspace.yaml"),
				"ignorePnpmfile: false\npnpmfile: .pnpmfile.cjs\npackages: ['.']\n",
			);
			await writeFile(join(root, ".npmrc"), "ignore-pnpmfile=false\n");
			await writeFile(
				join(root, "pnpm-lock.yaml"),
				"lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      minimist:\n        specifier: 1.2.0\n        version: 1.2.0\n\npackages:\n\n  minimist@1.2.0:\n    resolution: {integrity: sha512-7Wl+Jz+IGWuSdgsQEJ4JunV0si/iMhg42MnQQG6h1R6TNeVenp4U9x5CC5v/gYqz/fENLQITAWXidNtVL0NNbw==}\n\nsnapshots:\n\n  minimist@1.2.0: {}\n",
			);
			// Offline or online, the hook must not have run.
			await runAuditor(pnpmAudit, root);
			expect(await Bun.file(join(root, "PWNED")).exists()).toBe(false);
			await rm(root, { recursive: true, force: true });
		},
		60_000,
	);
});
