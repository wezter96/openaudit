import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import {
	mkdir,
	mkdtemp,
	readdir,
	readFile,
	rm,
	symlink,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
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

import {
	PHPSTAN_DEFAULT_LEVEL,
	PMD_RULESETS,
	parsePhpstanReport,
	parsePmdReport,
	phpstan,
	phpstanLevel,
	phpstanNeon,
	pmd,
} from "../src/codebase/lint-langs";
import { fixture, runAuditor } from "./helpers";
import { must } from "./must";

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

// Recorded: PHPStan 2.3.1 (PHP 8.5) on fixtures/lint-langs/php, PMD 7.28.0
// (OpenJDK 21) on fixtures/lint-langs/java; absolute paths rewritten to /repo.

describe("phpstan parser", () => {
	const findings = parsePhpstanReport(json("phpstan.json"), "/repo/php");

	test("maps identifiers to rule ids, severity and category", () => {
		expect(summary(findings)).toEqual([
			"code.phpstan/argument-type medium/reliability index.php:6",
			"code.phpstan/arguments-count medium/reliability index.php:7",
			"code.phpstan/return-type medium/reliability src/Cart.php:23",
			"code.phpstan/method-not-found medium/reliability src/Cart.php:31",
			"code.phpstan/argument-type medium/reliability src/Cart.php:37",
			"code.phpstan/variable-undefined medium/reliability src/Cart.php:38",
			"code.phpstan/dead-code-unreachable low/maintainability src/Cart.php:44",
			"code.phpstan/class-not-found low/reliability src/Mailer.php:13",
			"code.phpstan/arguments-count medium/reliability src/Mailer.php:14",
		]);
	});

	test("links the identifier docs and keeps tips", () => {
		const arg = findings[0];
		expect(arg?.references).toEqual([
			"https://phpstan.org/error-identifiers/argument.type",
		]);
		expect(arg?.message).toContain("expects float, string given");
		expect(arg?.message).toContain("[argument.type]");
		expect(arg?.tags).toEqual(["php", "argument-type"]);
		expect(arg?.confidence).toBe("high");
		const missing = findings.find((f) => f.ruleId.endsWith("class-not-found"));
		// Dependencies are never loaded, so unknown symbols may be false positives.
		expect(missing?.confidence).toBe("low");
		expect(missing?.remediation).toContain("discovering-symbols");
	});

	test("parse errors are high severity", () => {
		const [f, ...rest] = parsePhpstanReport(
			json("phpstan-parse.json"),
			"/repo/php",
		);
		expect(rest).toEqual([]);
		expect(f).toMatchObject({
			ruleId: "code.phpstan/phpstan-parse",
			severity: "high",
			category: "reliability",
			location: { file: "broken.php", line: 3 },
		});
	});

	test("drops files outside the root, keeps errors without identifiers", () => {
		const out = parsePhpstanReport(
			{
				files: {
					"/elsewhere/a.php": {
						messages: [{ message: "x", line: 1, identifier: "return.type" }],
					},
					"/repo/b.php": { messages: [{ message: "Legacy error", line: 2 }] },
				},
				errors: ["Internal error: boom"],
			},
			"/repo",
		);
		expect(summary(out)).toEqual([
			"code.phpstan/error medium/reliability b.php:2",
		]);
		expect(parsePhpstanReport("nope", "/repo")).toEqual([]);
	});
});

describe("phpstan config", () => {
	test("level defaults to 5 and accepts 0-10 or max", () => {
		expect(PHPSTAN_DEFAULT_LEVEL).toBe(5);
		expect(phpstanLevel(undefined)).toBe("5");
		expect(phpstanLevel({ level: 8 })).toBe("8");
		expect(phpstanLevel({ level: 0 })).toBe("0");
		expect(phpstanLevel({ level: "max" })).toBe("max");
		for (const level of [11, -1, 2.5, "9; rm", "8", null])
			expect(phpstanLevel({ level })).toBe("5");
	});

	test("generated neon lists files only and escapes NEON specials", () => {
		const neon = phpstanNeon({
			level: "6",
			tmpDir: "/tmp/x/cache",
			paths: ["/repo/a b/x%rootDir%.php", '/repo/q"t.php'],
			scanDirectories: ["/repo/vendor"],
		});
		expect(neon).toContain("level: 6");
		expect(neon).toContain('- "/repo/a b/x%%rootDir%%.php"');
		expect(neon).toContain('- "/repo/q\\"t.php"');
		expect(neon).toContain('tmpDir: "/tmp/x/cache"');
		expect(neon).toContain('- "/repo/vendor"');
		for (const key of ["includes", "bootstrapFiles", "services"])
			expect(neon).not.toContain(key);
	});
});

describe("pmd parser", () => {
	const findings = parsePmdReport(json("pmd.json"), "/repo/java");
	const src = "src/main/java/com/example";

	test("maps PMD categories and priorities", () => {
		expect(summary(findings)).toEqual([
			`code.pmd/unused-private-field low/maintainability ${src}/Accounts.java:9`,
			`code.pmd/double-checked-locking high/reliability ${src}/Accounts.java:12`,
			`code.pmd/compare-objects-with-equals low/reliability ${src}/Accounts.java:24`,
			`code.pmd/use-equals-to-compare-strings low/reliability ${src}/Accounts.java:24`,
			`code.pmd/close-resource low/reliability ${src}/Accounts.java:29`,
			`code.pmd/empty-catch-block low/reliability ${src}/Accounts.java:31`,
			`code.pmd/loose-coupling low/maintainability ${src}/Accounts.java:44`,
			`code.pmd/for-loop-can-be-foreach low/maintainability ${src}/Accounts.java:46`,
			`code.pmd/hard-coded-crypto-key medium/security ${src}/Crypto.java:9`,
			`code.pmd/insecure-crypto-iv medium/security ${src}/Crypto.java:10`,
			`code.pmd/parse-error low/reliability ${src}/Broken.java:4`,
		]);
	});

	test("carries columns, docs, CWE tags and parse errors", () => {
		const ending = (suffix: string) =>
			must(
				findings.find((f) => f.ruleId.endsWith(suffix)),
				`a ${suffix} finding`,
			);
		const key = ending("hard-coded-crypto-key");
		expect(must(key.location, "its location").column).toBe(47);
		expect(key.references).toEqual([
			"https://docs.pmd-code.org/snapshot/pmd_rules_java_security.html#hardcodedcryptokey",
		]);
		expect(key.tags).toEqual(["java", "pmd-security", "cwe-321"]);
		expect(ending("insecure-crypto-iv").tags).toContain("cwe-329");
		const parse = must(findings.at(-1), "the parse error finding");
		expect(parse.confidence).toBe("low");
		expect(must(parse.location, "its location").column).toBe(23);
		expect(parse.message).not.toContain("/repo/");
		expect(parse.message).toContain('Encountered "{"');
	});

	test("priority 4-5 is info; unknown categories are maintainability", () => {
		const out = parsePmdReport(
			{
				files: [
					{
						filename: "/repo/A.java",
						violations: [
							{ beginline: 1, rule: "X", ruleset: "Code Style", priority: 4 },
							{ beginline: 2, rule: "Y", ruleset: "Custom", priority: 2 },
						],
					},
					{ filename: "/other/B.java", violations: [{ rule: "Z" }] },
				],
			},
			"/repo",
		);
		expect(summary(out)).toEqual([
			"code.pmd/x info/maintainability A.java:1",
			"code.pmd/y medium/maintainability A.java:2",
		]);
	});
});

/* --------------------------------- auditors -------------------------------- */

type RunOpts = { cwd?: string; env?: Record<string, string> };

const runWith = (
	auditor: Auditor,
	target: string,
	which: (bin: string) => string | undefined,
	run: (cmd: ReadonlyArray<string>, opts: RunOpts) => Promise<ExecResult>,
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
						run: (cmd: ReadonlyArray<string>, opts) =>
							Effect.promise(() => run(cmd, opts ?? {})),
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
	const dir = await mkdtemp(join(tmpdir(), "openaudit-phpjava-"));
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

/** The `-c` config PHPStan was given, read while the temp dir still exists. */
const configOf = (cmd: ReadonlyArray<string>) =>
	readFile(cmd[cmd.indexOf("-c") + 1] ?? "", "utf8");

const PHP_PROJECT = {
	"composer.json": '{"name":"x/y"}',
	"index.php": "<?php echo 1;\n",
	"src/Cart.php": "<?php class Cart {}\n",
	"phpstan.neon": "parameters:\n\tbootstrapFiles: [evil.php]\n",
	"node_modules/pkg/a.php": "<?php\n",
};

describe("php and java auditors", () => {
	test("metadata", () => {
		for (const a of [phpstan, pmd]) {
			expect(a.engine).toBe("external");
			expect(a.targets).toEqual(["codebase"]);
			expect(a.defaultEnabled).toBe(true);
		}
		expect(phpstan.tool).toBe("phpstan");
		expect(pmd.tool).toBe("pmd");
		expect(phpstan.description).toContain("bootstrapFiles");
		expect(phpstan.description).toContain("vendor/autoload.php");
		expect(pmd.description).toContain("--aux-classpath");
	});

	test("irrelevant targets skip before the tool is required", async () => {
		await withProject({ "README.md": "hi" }, async (dir) => {
			for (const a of [phpstan, pmd]) {
				const report = await runWith(a, dir, () => undefined, unreachable);
				expect(report.results[0]?.status).toBe("skipped");
				expect(report.results[0]?.message).not.toContain("PATH");
			}
		});
	});

	test("missing tools skip with an install hint", async () => {
		await withProject(
			{ "a.php": "<?php\n", "A.java": "class A {}\n" },
			async (dir) => {
				for (const a of [phpstan, pmd]) {
					const report = await runWith(a, dir, () => undefined, unreachable);
					expect(report.results[0]?.status).toBe("skipped");
					expect(report.results[0]?.message).toContain("not found on PATH");
					expect(report.results[0]?.message).toContain("Install");
				}
			},
		);
	});

	test("phpstan ignores project config and runs off-tree on listed files", async () => {
		await withProject(PHP_PROJECT, async (dir) => {
			let cmd: ReadonlyArray<string> = [];
			let opts: RunOpts = {};
			let neon = "";
			const report = await runWith(phpstan, dir, present, async (c, o) => {
				cmd = c;
				opts = o;
				neon = await configOf(c);
				return {
					code: 1,
					stdout: text("phpstan.json").replaceAll("/repo/php", dir),
					stderr: "",
				};
			});
			expect(cmd.slice(0, 2)).toEqual(["/usr/local/bin/phpstan", "analyse"]);
			for (const flag of [
				"--error-format=json",
				"--no-progress",
				"--no-interaction",
			])
				expect(cmd).toContain(flag);
			expect(cmd.some((a) => a.startsWith("--memory-limit="))).toBe(true);
			expect(cmd.some((a) => a.includes("autoload"))).toBe(false);
			// Never the project's phpstan.neon, and never from the target's cwd.
			expect(cmd.some((a) => a.startsWith(dir))).toBe(false);
			expect(opts.cwd?.startsWith(dir)).toBe(false);
			expect(cmd[cmd.indexOf("-c") + 1]?.startsWith(opts.cwd ?? "?")).toBe(
				true,
			);
			expect(neon).toContain(`level: ${PHPSTAN_DEFAULT_LEVEL}`);
			expect(neon).toContain(`"${join(dir, "index.php")}"`);
			expect(neon).toContain(`"${join(dir, "src/Cart.php")}"`);
			expect(neon).not.toContain("node_modules");
			expect(neon).not.toContain("scanDirectories");
			expect(neon).not.toContain("evil.php");
			expect(report.results[0]?.status).toBe("failed");
			expect(report.results[0]?.findings).toHaveLength(9);
			expect(
				report.results[0]?.findings.some(
					(f) => f.location?.file === "src/Cart.php",
				),
			).toBe(true);
		});
	});

	test("phpstan honours the level setting", async () => {
		await withProject(PHP_PROJECT, async (dir) => {
			let neon = "";
			await runWith(
				phpstan,
				dir,
				present,
				async (c) => {
					neon = await configOf(c);
					return { code: 0, stdout: '{"files":{},"errors":[]}', stderr: "" };
				},
				{ settings: { "code.phpstan": { level: "max" } } },
			);
			expect(neon).toContain("level: max");
		});
	});

	test("phpstan scans a real vendor dir statically, never a symlinked one", async () => {
		await withProject(
			{ ...PHP_PROJECT, "vendor/autoload.php": "<?php exit(1);\n" },
			async (dir) => {
				await mkdir(join(dir, "lib"));
				await writeFile(join(dir, "lib/composer.json"), "{}");
				await symlink(join(dir, "vendor"), join(dir, "lib/vendor"));
				let neon = "";
				await runWith(phpstan, dir, present, async (c) => {
					neon = await configOf(c);
					return { code: 0, stdout: '{"files":{},"errors":[]}', stderr: "" };
				});
				expect(neon).toContain("scanDirectories:");
				expect(neon).toContain(`"${join(dir, "vendor")}"`);
				expect(neon).not.toContain(join(dir, "lib/vendor"));
				expect(neon).not.toContain("vendor/autoload.php");
			},
		);
	});

	test("phpstan re-runs without files that do not parse", async () => {
		await withProject(
			{ ...PHP_PROJECT, "broken.php": "<?php\nfunction broken( {\n" },
			async (dir) => {
				const configs: string[] = [];
				const outputs = [text("phpstan-parse.json"), text("phpstan.json")].map(
					(s) => s.replaceAll("/repo/php", dir),
				);
				const report = await runWith(phpstan, dir, present, async (c) => {
					configs.push(await configOf(c));
					return { code: 1, stdout: outputs.shift() ?? "", stderr: "" };
				});
				expect(configs).toHaveLength(2);
				expect(configs[0]).toContain(join(dir, "broken.php"));
				expect(configs[1]).not.toContain(join(dir, "broken.php"));
				expect(configs[1]).toContain(join(dir, "index.php"));
				const ids = report.results[0]?.findings.map((f) => f.ruleId) ?? [];
				expect(ids).toContain("code.phpstan/phpstan-parse");
				expect(ids).toHaveLength(10);
			},
		);
	});

	test("phpstan failures are errors", async () => {
		await withProject(PHP_PROJECT, async (dir) => {
			for (const res of [
				{ code: 255, stdout: "", stderr: "PHP Fatal error: memory" },
				{ code: 1, stdout: "", stderr: "Invalid configuration" },
			]) {
				const report = await runWith(phpstan, dir, present, async () => res);
				expect(report.results[0]?.status).toBe("error");
				expect(report.results[0]?.message).toContain(res.stderr);
			}
		});
	});

	test("pmd runs built-in rulesets off-tree over a file list", async () => {
		await withProject(
			{
				"src/A.java": "class A {}\n",
				"src/B,1.java": "class B {}\n",
				"target/gen/C.java": "class C {}\n",
				"rulesets/java/quickstart.xml": "<ruleset/>\n",
				"pmd.xml": "<ruleset/>\n",
			},
			async (dir) => {
				let cmd: ReadonlyArray<string> = [];
				let opts: RunOpts = {};
				let list = "";
				const report = await runWith(pmd, dir, present, async (c, o) => {
					cmd = c;
					opts = o;
					list = await readFile(c[c.indexOf("--file-list") + 1] ?? "", "utf8");
					return {
						code: 5,
						stdout: text("pmd.json").replaceAll("/repo/java", dir),
						stderr: "",
					};
				});
				expect(cmd.slice(0, 2)).toEqual(["/usr/local/bin/pmd", "check"]);
				expect(cmd[cmd.indexOf("-R") + 1]).toBe(PMD_RULESETS);
				expect(PMD_RULESETS).toBe(
					"rulesets/java/quickstart.xml,category/java/security.xml",
				);
				for (const flag of ["--no-cache", "--no-progress", "json"])
					expect(cmd).toContain(flag);
				expect(cmd).not.toContain("--aux-classpath");
				// Ruleset paths resolve against the cwd first: never the target.
				expect(opts.cwd?.startsWith(dir)).toBe(false);
				expect(cmd.some((a) => a.startsWith(dir))).toBe(false);
				expect(list.trim().split("\n")).toEqual([join(dir, "src/A.java")]);
				expect(report.results[0]?.findings).toHaveLength(11);
			},
		);
	});

	test("pmd exit codes", async () => {
		await withProject({ "A.java": "class A {}\n" }, async (dir) => {
			const ok = await runWith(pmd, dir, present, async () => ({
				code: 0,
				stdout: '{"files":[],"processingErrors":[]}',
				stderr: "",
			}));
			expect(ok.results[0]?.status).toBe("passed");
			for (const code of [1, 2]) {
				const report = await runWith(pmd, dir, present, async () => ({
					code,
					stdout: "",
					stderr: "Cannot load ruleset",
				}));
				expect(report.results[0]?.status).toBe("error");
				expect(report.results[0]?.message).toContain("Cannot load ruleset");
			}
		});
	});
});

/* ------------------------------- live tools ------------------------------- */

describe.skipIf(!Bun.which("phpstan"))("phpstan (live)", () => {
	test("never runs the target's autoloader, bootstrap files or code", async () => {
		const markers = await mkdtemp(join(tmpdir(), "openaudit-markers-"));
		const touch = (name: string) =>
			`<?php file_put_contents(${JSON.stringify(join(markers, name))}, "x");\n`;
		try {
			await withProject(
				{
					"composer.json": '{"autoload":{"psr-4":{"App\\\\":"src/"}}}',
					"vendor/autoload.php": touch("autoload"),
					"build/boot.php": touch("bootstrap"),
					"phpstan.neon":
						"parameters:\n\tbootstrapFiles: [build/boot.php]\n\tpaths: [src]\n",
					"phpstan.neon.dist":
						"parameters:\n\tbootstrapFiles: [build/boot.php]\n",
					"src/A.php": `${touch("toplevel")}final class A { public function f(): int { return "x"; } }\n`,
				},
				async (dir) => {
					const report = await runAuditor(phpstan, dir);
					expect(report.results[0]?.status).toBe("failed");
					expect(report.results[0]?.findings.map((f) => f.ruleId)).toContain(
						"code.phpstan/return-type",
					);
				},
			);
			expect(await readdir(markers)).toEqual([]);
		} finally {
			await rm(markers, { recursive: true, force: true });
		}
	}, 120_000);
});

describe.skipIf(!Bun.which("pmd"))("pmd (live)", () => {
	test("analyses the Java fixture", async () => {
		const report = await runAuditor(pmd, fixture("lint-langs", "java"));
		const ids = report.results[0]?.findings.map((f) => f.ruleId) ?? [];
		expect(ids).toContain("code.pmd/hard-coded-crypto-key");
		expect(ids).toContain("code.pmd/parse-error");
	}, 120_000);
});
