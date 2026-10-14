import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
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

import {
	clippy,
	golangciLint,
	mypy,
	parseClippyReport,
	parseGolangciReport,
	parseMypyReport,
	parseRuffReport,
	parseShellcheckReport,
	parseStaticcheckReport,
	RUFF_DEFAULT_SELECT,
	ruff,
	shellcheck,
	staticcheck,
} from "../src/codebase/lint-langs";
import { fixture } from "./helpers";

const text = (name: string) =>
	readFileSync(fixture("lint-langs", name), "utf8");
const json = (name: string): unknown => JSON.parse(text(name));

const summary = (
	findings: ReadonlyArray<{
		ruleId: string;
		severity: string;
		category: string;
		location?: { file?: string; line?: number };
	}>,
) =>
	findings.map(
		(f) =>
			`${f.ruleId} ${f.severity}/${f.category} ${f.location?.file}:${f.location?.line ?? "-"}`,
	);

// Recorded: cargo clippy 0.1.98, ruff 0.17.0, mypy 2.4.0, staticcheck 2025.1.1,
// shellcheck 0.11.0. Reconstructed by hand: golangci-lint.json.

describe("clippy parser", () => {
	const findings = parseClippyReport(text("clippy.jsonl"), "/repo/rust");

	test("maps lint groups to severity and category", () => {
		const by = (id: string) =>
			findings.find((f) => f.ruleId === `code.clippy/${id}`);
		expect(by("eq-op")).toMatchObject({
			severity: "high",
			category: "reliability",
		});
		expect(by("never-loop")?.severity).toBe("high");
		expect(by("absurd-extreme-comparisons")?.severity).toBe("high");
		expect(by("iter-nth-zero")).toMatchObject({
			severity: "info",
			category: "maintainability",
		});
		expect(by("useless-vec")).toMatchObject({
			severity: "low",
			category: "performance",
		});
		expect(by("needless-bool")).toMatchObject({
			severity: "low",
			category: "maintainability",
		});
		expect(by("unused-variables")?.severity).toBe("info");
		expect(by("unused-comparisons")).toMatchObject({
			severity: "low",
			category: "reliability",
		});
	});

	test("locates, quotes the source and dedupes per target", () => {
		const eq = findings.find((f) => f.ruleId === "code.clippy/eq-op");
		expect(eq?.location).toEqual({
			file: "src/main.rs",
			line: 30,
			column: 8,
		});
		expect(eq?.evidence).toBe('if a == a { println!("same"); }');
		expect(
			findings.filter((f) => f.ruleId === "code.clippy/ptr-arg"),
		).toHaveLength(1);
		expect(findings.every((f) => f.references?.length !== undefined)).toBe(
			true,
		);
	});

	test("prefixes nested crates and ignores spans outside the workspace", () => {
		const [f] = parseClippyReport(
			text("clippy.jsonl"),
			"/repo/rust",
			"crates/a",
		);
		expect(f?.location?.file).toBe("crates/a/src/main.rs");
		const outside = text("clippy.jsonl").replaceAll(
			'"file_name":"src/main.rs"',
			'"file_name":"/home/u/.cargo/registry/x/src/lib.rs"',
		);
		expect(parseClippyReport(outside, "/repo/rust")).toEqual([]);
	});

	test("security lints are reported as security", () => {
		const line = JSON.stringify({
			reason: "compiler-message",
			message: {
				level: "warning",
				message: "calling `uninit_vec`",
				code: { code: "clippy::uninit_vec" },
				spans: [
					{
						is_primary: true,
						file_name: "src/lib.rs",
						line_start: 3,
						column_start: 5,
						text: [],
					},
				],
			},
		});
		const [f] = parseClippyReport(`${line}\n{broken\n`, "/repo");
		expect(f).toMatchObject({ category: "security", severity: "high" });
	});
});

describe("ruff parser", () => {
	const findings = parseRuffReport(json("ruff.json"), "/repo/py");
	const by = (id: string) => findings.find((f) => f.ruleId.includes(id));

	test("classifies rules by family", () => {
		expect(by("s602")).toMatchObject({
			ruleId: "code.ruff/s602-subprocess-popen-with-shell-equals-true",
			severity: "medium",
			category: "security",
		});
		expect(by("s101")?.severity).toBe("low");
		expect(by("b006")).toMatchObject({
			severity: "low",
			category: "reliability",
		});
		expect(by("f401")).toMatchObject({
			severity: "low",
			category: "maintainability",
		});
		expect(by("syntax-error")).toMatchObject({
			severity: "high",
			category: "reliability",
		});
	});

	test("paths are relative; fixes are tagged", () => {
		expect(by("f401")?.location).toEqual({
			file: "app.py",
			line: 1,
			column: 8,
		});
		expect(by("f401")?.tags).toContain("autofixable");
		expect(by("s105")?.tags).not.toContain("autofixable");
		expect(summary(findings)[0]).toContain("code.ruff/e401");
	});
});

describe("mypy parser", () => {
	const findings = parseMypyReport(text("mypy.jsonl"), "/repo/py");

	test("type errors are reliability, missing annotations hygiene", () => {
		expect(summary(findings)).toEqual([
			"code.mypy/no-untyped-def low/maintainability tests/test_app.py:1",
			"code.mypy/no-untyped-def low/maintainability app.py:5",
			"code.mypy/return-value medium/reliability app.py:20",
			"code.mypy/assignment medium/reliability app.py:22",
		]);
		// mypy columns are 0-based.
		expect(findings[2]?.location?.column).toBe(12);
		expect(findings[0]?.message).toContain('Use "-> None"');
	});

	test("notes and junk are ignored; unresolved imports are low confidence", () => {
		const out = parseMypyReport(
			[
				'{"file":"a.py","line":1,"column":0,"message":"x","code":null,"severity":"note"}',
				"Success: no issues found",
				'{"file":"a.py","line":2,"column":0,"message":"Cannot find implementation","code":"import-not-found","severity":"error"}',
			].join("\n"),
			"/repo",
		);
		expect(out).toHaveLength(1);
		expect(out[0]?.confidence).toBe("low");
	});
});

describe("staticcheck parser", () => {
	test("maps check families", () => {
		const findings = parseStaticcheckReport(
			text("staticcheck.jsonl"),
			"/repo/go",
		);
		expect(summary(findings)).toEqual([
			"code.staticcheck/st1005 info/maintainability main.go:9",
			"code.staticcheck/sa4018 medium/reliability main.go:13",
			"code.staticcheck/s1003 low/maintainability main.go:14",
			"code.staticcheck/sa4017 medium/reliability main.go:20",
			"code.staticcheck/sa4000 medium/reliability main.go:21",
			"code.staticcheck/s1038 low/maintainability main.go:22",
			"code.staticcheck/s1025 low/maintainability main.go:22",
		]);
		expect(findings[1]?.references).toEqual([
			"https://staticcheck.dev/docs/checks/#SA4018",
		]);
	});

	test("compile errors become a low-confidence finding with a location", () => {
		const [f] = parseStaticcheckReport(
			text("staticcheck-compile.jsonl"),
			"/repo/go",
			"svc",
		);
		expect(f).toMatchObject({
			ruleId: "code.staticcheck/compile-error",
			confidence: "low",
			location: { file: "svc/main.go", line: 12, column: 6 },
		});
		expect(f?.message).toContain("declared and not used");
	});

	test("compile errors without a position in the message use the reported location", () => {
		// Recorded from staticcheck 2026.2.1 on a module missing its go.sum.
		// Without a location, path suppressions (e.g. test fixtures) missed it.
		const [f] = parseStaticcheckReport(
			text("staticcheck-compile-nofile.jsonl"),
			"/repo/supply/go",
			"supply/go",
		);
		expect(f).toMatchObject({
			ruleId: "code.staticcheck/compile-error",
			location: { file: "supply/go/main.go", line: 3, column: 8 },
		});
		const [bare] = parseStaticcheckReport(
			'{"code":"compile","severity":"error","location":{"file":"","line":0,"column":0},"message":"go: cannot load module"}',
			"/repo/svc",
			"svc",
		);
		expect(bare?.location).toEqual({ file: "svc/go.mod" });
	});
});

describe("golangci-lint parser", () => {
	const findings = parseGolangciReport(json("golangci-lint.json"), "/repo");

	test("maps linters and drops files outside the module", () => {
		expect(summary(findings)).toEqual([
			"code.golangci-lint/errcheck medium/reliability main.go:20",
			"code.golangci-lint/gosec-g401 medium/security pkg/hash/hash.go:12",
			"code.golangci-lint/staticcheck-sa4000 medium/reliability main.go:21",
			"code.golangci-lint/revive low/maintainability pkg/run.go:3",
		]);
		expect(findings[0]?.evidence).toBe("f()");
	});
});

describe("shellcheck parser", () => {
	const findings = parseShellcheckReport(json("shellcheck.json"), "/repo");

	test("maps levels and security codes", () => {
		const by = (code: string) =>
			findings.filter((f) => f.ruleId === `code.shellcheck/${code}`);
		expect(by("sc2086")[0]).toMatchObject({
			severity: "low",
			category: "security",
		});
		expect(by("sc2115")[0]).toMatchObject({
			severity: "low",
			category: "security",
		});
		expect(by("sc2045")[0]).toMatchObject({
			severity: "medium",
			category: "reliability",
		});
		expect(by("sc2154")[0]?.severity).toBe("low");
		expect(by("sc1009")[0]?.severity).toBe("info");
		expect(findings[0]?.location?.file).toBe("broken");
	});

	test("dedupes identical locations", () => {
		const doc = {
			comments: [1, 2].map(() => ({
				file: "a.sh",
				line: 1,
				column: 1,
				level: "warning",
				code: 2164,
				message: "m",
			})),
		};
		expect(parseShellcheckReport(doc, "/repo")).toHaveLength(1);
	});
});

/* --------------------------------- auditors -------------------------------- */

const runWith = (
	auditor: Auditor,
	target: string,
	which: (bin: string) => string | undefined,
	run: (
		cmd: ReadonlyArray<string>,
		opts: { cwd?: string; env?: Record<string, string> },
	) => Promise<ExecResult>,
): Promise<Report> =>
	Effect.runPromise(
		runAudit({
			target,
			auditors: [auditor],
			options: {},
			selection: { only: [auditor.id] },
		}).pipe(
			Effect.provide(
				Layer.mergeAll(
					Workspaces.layer,
					Http.layer,
					Layer.succeed(Exec, {
						which: (bin: string) => Effect.succeed(which(bin)),
						run: (cmd: ReadonlyArray<string>, options) =>
							Effect.promise(() => run(cmd, options ?? {})),
					}),
				),
			),
		),
	);

const present = (bin: string) => `/usr/local/bin/${bin}`;
const unreachable = () => Promise.reject(new Error("unreachable"));

const withProject = async (
	files: Record<string, string>,
	fn: (dir: string) => Promise<void>,
) => {
	const dir = await mkdtemp(join(tmpdir(), "openaudit-lintlangs-"));
	try {
		for (const [name, body] of Object.entries(files)) {
			await mkdir(dirname(join(dir, name)), { recursive: true });
			await writeFile(join(dir, name), body);
		}
		await fn(dir);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
};

const ALL = [clippy, ruff, mypy, staticcheck, golangciLint, shellcheck];

describe("lint-langs auditors", () => {
	test("metadata", () => {
		for (const a of ALL) {
			expect(a.engine).toBe("external");
			expect(a.targets).toEqual(["codebase"]);
		}
		expect(ruff.defaultEnabled).toBe(true);
		expect(staticcheck.defaultEnabled).toBe(true);
		expect(shellcheck.defaultEnabled).toBe(true);
		for (const a of [clippy, mypy, golangciLint]) {
			expect(a.defaultEnabled).toBe(false);
			expect(a.description).toContain("NOT safe on untrusted code");
		}
		expect(clippy.description).toContain("build.rs");
		expect(ruff.description).toContain(RUFF_DEFAULT_SELECT);
	});

	test("irrelevant targets skip before the tool is required", async () => {
		await withProject({ "README.md": "hi" }, async (dir) => {
			for (const a of ALL) {
				const report = await runWith(a, dir, () => undefined, unreachable);
				expect(report.results[0]?.status).toBe("skipped");
				expect(report.results[0]?.message).not.toContain("PATH");
			}
		});
	});

	test("missing tools skip with an install hint", async () => {
		await withProject(
			{
				"Cargo.toml": "[package]\nname='a'\n",
				"Cargo.lock": "",
				"a.py": "x = 1\n",
				"go.mod": "module a\n",
				"run.sh": "#!/bin/sh\necho hi\n",
			},
			async (dir) => {
				for (const a of ALL) {
					const report = await runWith(a, dir, () => undefined, unreachable);
					expect(report.results[0]?.status).toBe("skipped");
					expect(report.results[0]?.message).toContain("not found on PATH");
					expect(report.results[0]?.message).toContain("Install");
				}
			},
		);
	});

	test("clippy needs a Cargo.lock and runs locked, offline, off-tree", async () => {
		await withProject(
			{ "Cargo.toml": "[package]\nname='a'\n" },
			async (dir) => {
				const report = await runWith(clippy, dir, present, unreachable);
				expect(report.results[0]?.status).toBe("skipped");
				expect(report.results[0]?.message).toContain("Cargo.lock");
			},
		);
		await withProject(
			{
				"Cargo.toml": "[package]\nname='a'\n",
				"Cargo.lock": "",
				"member/Cargo.toml": "[package]\nname='b'\n",
				"member/Cargo.lock": "",
			},
			async (dir) => {
				const cmds: Array<ReadonlyArray<string>> = [];
				const report = await runWith(clippy, dir, present, async (cmd, o) => {
					cmds.push(cmd);
					expect(o.cwd).toBe(dir);
					return { code: 101, stdout: text("clippy.jsonl"), stderr: "" };
				});
				// Nested member crate is covered by the workspace root run.
				expect(cmds).toHaveLength(1);
				for (const flag of [
					"--locked",
					"--offline",
					"--workspace",
					"--target-dir",
				])
					expect(cmds[0]).toContain(flag);
				const target = cmds[0]?.[cmds[0].indexOf("--target-dir") + 1] ?? "";
				expect(target.startsWith(dir)).toBe(false);
				expect(report.results[0]?.findings.length).toBeGreaterThan(5);
			},
		);
	});

	test("clippy surfaces resolution failures as errors", async () => {
		await withProject(
			{ "Cargo.toml": "[package]\n", "Cargo.lock": "" },
			async (dir) => {
				const report = await runWith(clippy, dir, present, async () => ({
					code: 101,
					stdout: "",
					stderr: "error: failed to download `serde`",
				}));
				expect(report.results[0]?.status).toBe("error");
				expect(report.results[0]?.message).toContain("failed to download");
			},
		);
	});

	test("ruff isolates itself unless the project configures ruff", async () => {
		await withProject({ "a.py": "x = 1\n" }, async (dir) => {
			let cmd: ReadonlyArray<string> = [];
			const report = await runWith(ruff, dir, present, async (c) => {
				cmd = c;
				return {
					code: 1,
					stdout: text("ruff.json").replaceAll("/repo/py", dir),
					stderr: "",
				};
			});
			expect(cmd).toContain("--isolated");
			expect(cmd).toContain("--no-cache");
			expect(cmd).toContain(RUFF_DEFAULT_SELECT);
			expect(cmd).toContain("json");
			expect(report.results[0]?.status).toBe("failed");
			expect(report.results[0]?.findings.length).toBeGreaterThan(10);
			expect(
				report.results[0]?.findings.some((f) => f.location?.file === "app.py"),
			).toBe(true);
		});
		await withProject(
			{
				"a.py": "x = 1\n",
				"pyproject.toml": "[tool.ruff.lint]\nselect=['E']\n",
			},
			async (dir) => {
				let cmd: ReadonlyArray<string> = [];
				await runWith(ruff, dir, present, async (c) => {
					cmd = c;
					return { code: 0, stdout: "[]", stderr: "" };
				});
				expect(cmd).not.toContain("--isolated");
				expect(cmd).not.toContain("--select");
			},
		);
	});

	test("ruff exit code 2 is an error", async () => {
		await withProject({ "a.py": "x = 1\n" }, async (dir) => {
			const report = await runWith(ruff, dir, present, async () => ({
				code: 2,
				stdout: "",
				stderr: "ruff failed",
			}));
			expect(report.results[0]?.status).toBe("error");
		});
	});

	test("mypy uses a throwaway cache and never installs stubs", async () => {
		await withProject({ "a.py": "x = 1\n" }, async (dir) => {
			let cmd: ReadonlyArray<string> = [];
			const report = await runWith(mypy, dir, present, async (c) => {
				cmd = c;
				return { code: 1, stdout: text("mypy.jsonl"), stderr: "" };
			});
			expect(cmd).toContain("--no-install-types");
			expect(cmd).toContain("--cache-dir");
			expect(cmd[cmd.indexOf("--cache-dir") + 1]?.startsWith(dir)).toBe(false);
			expect(report.results[0]?.findings).toHaveLength(4);
		});
	});

	test("staticcheck hardens the Go environment per module", async () => {
		await withProject(
			{ "go.mod": "module a\n", "svc/go.mod": "module b\n" },
			async (dir) => {
				const seen: Array<{ cwd?: string; env?: Record<string, string> }> = [];
				const report = await runWith(
					staticcheck,
					dir,
					present,
					async (_c, o) => {
						seen.push(o);
						return {
							code: 1,
							stdout: text("staticcheck.jsonl").replaceAll(
								"/repo/go",
								o.cwd ?? "",
							),
							stderr: "",
						};
					},
				);
				expect(seen.map((s) => s.cwd)).toEqual([dir, join(dir, "svc")]);
				expect(seen[0]?.env).toMatchObject({
					GOTOOLCHAIN: "local",
					CGO_ENABLED: "0",
				});
				const files = new Set(
					report.results[0]?.findings.map((f) => f.location?.file),
				);
				expect([...files].sort()).toEqual(["main.go", "svc/main.go"]);
				expect(report.results[0]?.findings).toHaveLength(14);
			},
		);
	});

	test("golangci-lint picks output flags by version", async () => {
		await withProject({ "go.mod": "module a\n" }, async (dir) => {
			for (const [version, flag] of [
				["golangci-lint has version 1.64.8 built", "--out-format"],
				["golangci-lint has version 2.1.6 built", "--output.json.path"],
			] as const) {
				let cmd: ReadonlyArray<string> = [];
				const report = await runWith(golangciLint, dir, present, async (c) => {
					if (c.includes("--version"))
						return { code: 0, stdout: version, stderr: "" };
					cmd = c;
					return { code: 1, stdout: text("golangci-lint.json"), stderr: "" };
				});
				expect(cmd).toContain(flag);
				expect(cmd).toContain("readonly");
				expect(report.results[0]?.findings).toHaveLength(4);
			}
		});
	});

	test("shellcheck ignores rc files and finds scripts by shebang", async () => {
		await withProject(
			{
				"deploy.sh": "#!/bin/bash\nrm -rf $1\n",
				"bin/tool": "#!/usr/bin/env bash\necho hi\n",
				"bin/other": "#!/usr/bin/env python3\nprint(1)\n",
				README: "# not a script\n",
				".shellcheckrc": "source-path=/etc\n",
			},
			async (dir) => {
				let cmd: ReadonlyArray<string> = [];
				let opts: { cwd?: string; env?: Record<string, string> } = {};
				const report = await runWith(shellcheck, dir, present, async (c, o) => {
					cmd = c;
					opts = o;
					return { code: 1, stdout: text("shellcheck.json"), stderr: "" };
				});
				expect(cmd).toContain("--norc");
				expect(cmd).toContain("json1");
				const files = cmd.filter((a) => a.startsWith(dir)).sort();
				expect(files).toEqual([join(dir, "bin/tool"), join(dir, "deploy.sh")]);
				expect(opts.cwd).toBe(tmpdir());
				expect(opts.cwd?.startsWith(dir)).toBe(false);
				expect(opts.env).toEqual({ SHELLCHECK_OPTS: "" });
				expect(report.results[0]?.findings.length).toBeGreaterThan(5);
			},
		);
	});
});
