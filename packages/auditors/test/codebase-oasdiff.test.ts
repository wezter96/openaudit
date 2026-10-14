import { afterAll, describe, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	realpathSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	type AuditOptions,
	Exec,
	type ExecOptions,
	type ExecResult,
	GIT_HARDENING_ENV,
	Http,
	type Report,
	runAudit,
	Workspaces,
} from "@openaudit/core";
import { Effect, Layer } from "effect";

import {
	oasdiff,
	operationLine,
	parseOasdiffOutput,
} from "../src/codebase/oasdiff";
import { fixture } from "./helpers";

const fx = (name: string) => fixture("api", "oasdiff", name);
const read = (name: string) => readFileSync(fx(name), "utf8");
const recordedYaml: unknown = JSON.parse(read("breaking-yaml.json"));
const recordedJson: unknown = JSON.parse(read("breaking-json.json"));

const tmps: string[] = [];
afterAll(() => {
	for (const d of tmps) rmSync(d, { recursive: true, force: true });
});
const scratch = (prefix: string) => {
	const dir = mkdtempSync(join(tmpdir(), prefix));
	tmps.push(dir);
	return dir;
};

/* -------------------------------------------------------------------------- */
/*                                   Parser                                   */
/* -------------------------------------------------------------------------- */

describe("oasdiff parser", () => {
	const yaml = parseOasdiffOutput(recordedYaml, {
		file: "api/openapi.yaml",
		text: read("revision.yaml"),
		revisionFile: "revision.yaml",
		base: "main",
	});

	test("maps recorded breaking changes to findings", () => {
		expect(yaml.map((f) => f.ruleId)).toEqual([
			"code.oasdiff/new-required-request-parameter",
			"code.oasdiff/request-parameter-became-required",
			"code.oasdiff/response-required-property-removed",
			"code.oasdiff/request-property-became-required",
			"code.oasdiff/request-property-max-length-set",
			"code.oasdiff/api-removed-without-deprecation",
			"code.oasdiff/request-parameter-type-changed",
			"code.oasdiff/response-required-property-removed",
		]);
		for (const f of yaml) {
			expect(f.severity).toBe("high");
			expect(f.category).toBe("reliability");
			expect(f.confidence).toBe("high");
			expect(f.tags).toEqual(["openapi", "breaking-change"]);
			expect(f.location?.file).toBe("api/openapi.yaml");
			expect(f.remediation).toBeTruthy();
			expect(f.references?.[0]).toContain("oasdiff");
		}
		const added = yaml[0];
		expect(added?.title).toBe(
			"added the new required `query` request parameter `owner`",
		);
		expect(added?.message).toContain("GET /pets");
		expect(added?.message).toContain("main");
		expect(added?.evidence).toBe(
			"GET /pets: added the new required `query` request parameter `owner`",
		);
		// The comment oasdiff attaches explains the check.
		expect(yaml[4]?.message).toContain("Setting a bound rejects values");
	});

	test("uses the revision line, else finds the operation in the new spec", () => {
		// From revisionSource.
		expect(yaml[0]?.location?.line).toBe(15);
		expect(yaml[3]?.location?.line).toBe(69);
		// No revisionSource: the operation's line in the new spec.
		expect(yaml[2]?.location?.line).toBe(7);
		expect(yaml[7]?.location?.line).toBe(40);
		// The removed DELETE no longer exists: its path's line.
		expect(yaml[5]?.location?.line).toBe(39);
	});

	test("findings stay distinct when one rule fires twice", () => {
		const evidence = yaml.map((f) => f.evidence);
		expect(new Set(evidence).size).toBe(evidence.length);
	});

	test("maps warn to medium and finds lines in JSON specs", () => {
		const json = parseOasdiffOutput(recordedJson, {
			file: "openapi.json",
			text: read("revision.json"),
			revisionFile: "revision.json",
			base: "origin/main",
		});
		expect(json.map((f) => [f.ruleId, f.severity, f.location?.line])).toEqual([
			["code.oasdiff/request-parameter-pattern-changed", "medium", 6],
			["code.oasdiff/request-parameter-removed", "medium", 6],
			["code.oasdiff/request-property-removed", "medium", 6],
		]);
		expect(json[0]?.confidence).toBe("medium");
	});

	test("maps info levels and tolerates unexpected shapes", () => {
		const ctx = { file: "o.yaml", text: "", revisionFile: "r", base: "m" };
		expect(parseOasdiffOutput(null, ctx)).toEqual([]);
		expect(parseOasdiffOutput([1, {}, { level: 3 }], ctx)).toEqual([]);
		const [info] = parseOasdiffOutput(
			[{ id: "Some_Check", text: "t", level: 1 }],
			ctx,
		);
		expect(info?.ruleId).toBe("code.oasdiff/some-check");
		expect(info?.severity).toBe("info");
		expect(info?.location).toEqual({ file: "o.yaml" });
	});
});

describe("operationLine", () => {
	const yaml =
		"openapi: 3.0.0\npaths:\n  /a:\n    get: {}\n  /a/{id}:\n    post: {}\n";
	test("finds a path's method, or the path itself", () => {
		expect(operationLine(yaml, "/a", "GET")).toBe(4);
		expect(operationLine(yaml, "/a", "POST")).toBe(3);
		expect(operationLine(yaml, "/a/{id}", "POST")).toBe(6);
		expect(operationLine(yaml, "/gone", "GET")).toBeUndefined();
		expect(operationLine(yaml, undefined, undefined)).toBeUndefined();
	});
});

/* -------------------------------------------------------------------------- */
/*                         Auditor with a fake Exec                           */
/* -------------------------------------------------------------------------- */

interface Call {
	readonly cmd: ReadonlyArray<string>;
	readonly options: ExecOptions | undefined;
	/** Files the oasdiff call would compare, read while the call ran. */
	readonly files?: ReadonlyArray<string>;
}

type Responder = (cmd: ReadonlyArray<string>) => Partial<ExecResult>;

const BASE_OID = "a".repeat(40);
const SHA = "b".repeat(40);

/** Fake git: merge-base, ls-tree and cat-file answers for one spec. */
const fakeGit =
	(opts: {
		baseText?: string;
		lsTree?: string;
		mergeBase?: Partial<ExecResult>;
	}) =>
	(cmd: ReadonlyArray<string>): Partial<ExecResult> | undefined => {
		const sub = cmd[3];
		if (sub === "merge-base") return opts.mergeBase ?? { stdout: `${SHA}\n` };
		if (sub === "ls-tree")
			return {
				stdout:
					opts.lsTree ??
					(opts.baseText === undefined
						? ""
						: `100644 blob ${BASE_OID}   ${opts.baseText.length}\topenapi.yaml\0`),
			};
		if (sub === "cat-file") return { stdout: opts.baseText ?? "" };
		return undefined;
	};

const runOasdiff = async (
	target: string,
	opts: {
		options?: AuditOptions;
		which?: (bin: string) => string | undefined;
		respond?: Responder;
		git?: ReturnType<typeof fakeGit>;
	} = {},
): Promise<{ report: Report; calls: Call[] }> => {
	const calls: Call[] = [];
	const report = await Effect.runPromise(
		runAudit({
			target,
			auditors: [oasdiff],
			options: opts.options ?? { diffBase: "main" },
			selection: { only: [oasdiff.id] },
		}).pipe(
			Effect.provide(
				Layer.mergeAll(
					Workspaces.layer,
					Http.layer,
					Layer.succeed(Exec, {
						which: (bin: string) =>
							Effect.succeed(opts.which ? opts.which(bin) : `/usr/bin/${bin}`),
						run: (cmd: ReadonlyArray<string>, options?: ExecOptions) =>
							Effect.sync((): ExecResult => {
								const isOasdiff = cmd[0] === "/usr/bin/oasdiff";
								calls.push({
									cmd,
									options,
									files:
										isOasdiff && options?.cwd
											? cmd
													.slice(2, 4)
													.map((f) =>
														readFileSync(
															join(options.cwd as string, f),
															"utf8",
														),
													)
											: undefined,
								});
								const res = (!isOasdiff && opts.git?.(cmd)) ||
									opts.respond?.(cmd) || { stdout: "[]" };
								return { code: 0, stdout: "", stderr: "", ...res };
							}),
					}),
				),
			),
		),
	);
	return { report, calls };
};

/** A target holding the revision spec as `openapi.yaml`. */
const specTarget = (text = read("revision.yaml")) => {
	const dir = scratch("openaudit-oasdiff-target-");
	writeFileSync(join(dir, "openapi.yaml"), text);
	return dir;
};

describe("code.oasdiff", () => {
	test("is on by default, offline, and wraps oasdiff", () => {
		expect(oasdiff.defaultEnabled).toBe(true);
		expect(oasdiff.network).toBeUndefined();
		expect(oasdiff.engine).toBe("external");
		expect(oasdiff.tool).toBe("oasdiff");
		expect(oasdiff.categories).toEqual(["reliability"]);
	});

	test("skips without --diff", async () => {
		const { report, calls } = await runOasdiff(specTarget(), { options: {} });
		expect(report.results[0]?.status).toBe("skipped");
		expect(report.results[0]?.message).toContain("Only runs with --diff <ref>");
		expect(calls).toEqual([]);
	});

	test("skips with an install hint when oasdiff is missing", async () => {
		const { report, calls } = await runOasdiff(specTarget(), {
			which: (bin) => (bin === "oasdiff" ? undefined : `/usr/bin/${bin}`),
		});
		expect(report.results[0]?.status).toBe("skipped");
		expect(report.results[0]?.message).toContain("oasdiff not found");
		expect(report.results[0]?.message).toContain("brew install oasdiff");
		expect(calls).toEqual([]);
	});

	test("passes with nothing to do when there is no OpenAPI spec", async () => {
		const dir = scratch("openaudit-oasdiff-empty-");
		writeFileSync(join(dir, "index.js"), "1;\n");
		const { report, calls } = await runOasdiff(dir);
		expect(report.results[0]?.status).toBe("passed");
		expect(calls).toEqual([]);
	});

	test("refuses a ref that could be read as an option", async () => {
		for (const ref of ["--output=/tmp/x", "-c", "main..HEAD", "a b"]) {
			const { report, calls } = await runOasdiff(specTarget(), {
				options: { diffBase: ref },
			});
			expect(report.results[0]?.status).toBe("error");
			expect(report.results[0]?.message).toContain("Invalid git ref");
			expect(calls).toEqual([]);
		}
	});

	test("hardens every git call and compares from a temp dir", async () => {
		const target = specTarget();
		const baseText = read("base.yaml");
		const { report, calls } = await runOasdiff(target, {
			git: fakeGit({ baseText }),
			respond: () => ({ stdout: read("breaking-yaml.json") }),
		});
		expect(report.results[0]?.status).toBe("failed");
		expect(report.results[0]?.findings.length).toBe(8);

		const [mergeBase, lsTree, catFile, run] = calls;
		expect(calls.length).toBe(4);
		const root = mergeBase?.cmd[2] as string;
		expect(realpathSync(root)).toBe(realpathSync(target));
		for (const c of [mergeBase, lsTree, catFile]) {
			expect(c?.cmd.slice(0, 3)).toEqual(["/usr/bin/git", "-C", root]);
			const env = c?.options?.env ?? {};
			for (const [k, v] of Object.entries(GIT_HARDENING_ENV))
				if (!k.startsWith("GIT_CONFIG_")) expect(env[k]).toBe(v);
			const pairs = Object.entries(env)
				.filter(([k]) => k.startsWith("GIT_CONFIG_KEY_"))
				.map(([k, key]) => [
					key,
					env[k.replace("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")],
				]);
			expect(pairs).toEqual(
				expect.arrayContaining([
					["core.fsmonitor", "false"],
					["core.hooksPath", "/dev/null"],
					["protocol.allow", "never"],
				]),
			);
			expect(Number(env.GIT_CONFIG_COUNT)).toBe(pairs.length);
			expect(env.GIT_CONFIG_GLOBAL).toBe("/dev/null");
			expect(env.GIT_NO_LAZY_FETCH).toBe("1");
			expect(c?.options?.cwd).not.toBe(root);
		}
		// The user's ref only ever follows --end-of-options.
		expect(mergeBase?.cmd.slice(3)).toEqual([
			"merge-base",
			"--end-of-options",
			"main",
			"HEAD",
		]);
		// Paths come after `--`; blobs are read by object id, so no
		// working-tree filter or textconv driver can run.
		expect(lsTree?.cmd.slice(3)).toEqual([
			"ls-tree",
			"-l",
			"-z",
			SHA,
			"--",
			"openapi.yaml",
		]);
		expect(catFile?.cmd.slice(3)).toEqual(["cat-file", "blob", BASE_OID]);

		// oasdiff: our empty config, no external refs, relative temp files.
		const cwd = run?.options?.cwd as string;
		expect(cwd).not.toBe(root);
		expect(run?.cmd).toEqual([
			"/usr/bin/oasdiff",
			"breaking",
			"0/base.yaml",
			"0/revision.yaml",
			"--format",
			"json",
			"--allow-external-refs=false",
			"--config",
			join(cwd, "oasdiff.yaml"),
		]);
		expect(run?.files).toEqual([baseText, read("revision.yaml")]);
		// The temp dir is gone afterwards.
		expect(existsSync(cwd)).toBe(false);
	});

	test("a spec that did not exist at the base is new: nothing to break", async () => {
		const { report, calls } = await runOasdiff(specTarget(), {
			git: fakeGit({}),
		});
		expect(report.results[0]?.status).toBe("passed");
		expect(calls.map((c) => c.cmd[3])).toEqual(["merge-base", "ls-tree"]);
	});

	test("an unchanged spec is not compared", async () => {
		const text = read("revision.yaml");
		const { report, calls } = await runOasdiff(specTarget(text), {
			git: fakeGit({ baseText: text }),
		});
		expect(report.results[0]?.status).toBe("passed");
		expect(calls.map((c) => c.cmd[3])).toEqual([
			"merge-base",
			"ls-tree",
			"cat-file",
		]);
	});

	test("a base entry that is not a small blob is not read", async () => {
		const big = await runOasdiff(specTarget(), {
			git: fakeGit({
				lsTree: `100644 blob ${BASE_OID} 99999999\topenapi.yaml\0`,
			}),
		});
		expect(big.calls.map((c) => c.cmd[3])).toEqual(["merge-base", "ls-tree"]);
		expect(big.report.results[0]?.findings[0]?.ruleId).toBe(
			"code.oasdiff/not-compared",
		);
		const tree = await runOasdiff(specTarget(), {
			git: fakeGit({
				lsTree: `040000 tree ${BASE_OID}       -\topenapi.yaml\0`,
			}),
		});
		expect(tree.calls.length).toBe(2);
		expect(tree.report.results[0]?.status).toBe("passed");
	});

	test("specs with external $refs are reported as not compared", async () => {
		const { report } = await runOasdiff(specTarget(), {
			git: fakeGit({ baseText: read("base.yaml") }),
			respond: () => ({
				code: 102,
				stderr:
					'Error: failed to load revision spec from "0/revision.yaml": encountered disallowed external reference: "http://127.0.0.1:8765/pet.yaml"\n',
			}),
		});
		const result = report.results[0];
		expect(result?.status).toBe("passed");
		const [f] = result?.findings ?? [];
		expect(f?.ruleId).toBe("code.oasdiff/not-compared");
		expect(f?.severity).toBe("info");
		expect(f?.location).toEqual({ file: "openapi.yaml" });
		expect(f?.message).toContain("external $ref");
	});

	test("an unloadable spec is reported, other failures are errors", async () => {
		const bad = await runOasdiff(specTarget(), {
			git: fakeGit({ baseText: "swagger: '2.0'\n" }),
			respond: () => ({
				code: 102,
				stderr: 'Error: failed to load base spec from "0/base.yaml": boom\n',
			}),
		});
		const f = bad.report.results[0]?.findings[0];
		expect(f?.ruleId).toBe("code.oasdiff/not-compared");
		expect(f?.message).toContain("openapi.yaml at main");
		expect(f?.message).not.toContain("0/base.yaml");

		const crash = await runOasdiff(specTarget(), {
			git: fakeGit({ baseText: read("base.yaml") }),
			respond: () => ({ code: 2, stderr: "panic" }),
		});
		expect(crash.report.results[0]?.status).toBe("error");

		const noBase = await runOasdiff(specTarget(), {
			git: fakeGit({
				mergeBase: { code: 128, stderr: "fatal: Not a valid object name" },
			}),
		});
		expect(noBase.report.results[0]?.status).toBe("error");
		expect(noBase.report.results[0]?.message).toContain("git merge-base");
	});
});

/* -------------------------------------------------------------------------- */
/*                    Real git: a hostile repo must not run code              */
/* -------------------------------------------------------------------------- */

const git = (cwd: string, args: string[]) =>
	execFileSync("git", args, {
		cwd,
		env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", HOME: cwd },
		stdio: ["ignore", "pipe", "pipe"],
	}).toString();

/**
 * A repo whose `main` has the base spec and whose `feature` branch changes it,
 * with a .git/config armed to run commands from git and oasdiff alike.
 */
const prRepo = () => {
	const root = scratch("openaudit-oasdiff-repo-");
	const repo = join(root, "repo");
	const markers = join(root, "markers");
	mkdirSync(join(repo, "api"), { recursive: true });
	mkdirSync(markers);
	const script = (name: string) => {
		const path = join(root, `${name}.sh`);
		writeFileSync(path, `#!/bin/sh\ntouch "${markers}/${name}"\ncat "$@"\n`);
		chmodSync(path, 0o755);
		return path;
	};
	const id = ["-c", "user.email=t@t", "-c", "user.name=t"];
	git(repo, ["init", "-q", "-b", "main"]);
	writeFileSync(join(repo, "api", "openapi.yaml"), read("base.yaml"));
	git(repo, ["add", "."]);
	git(repo, [...id, "commit", "-qm", "base"]);
	git(repo, ["checkout", "-qb", "feature"]);
	writeFileSync(join(repo, "api", "openapi.yaml"), read("revision.yaml"));
	writeFileSync(join(repo, "new-api.yaml"), read("revision.yaml"));
	git(repo, ["add", "."]);
	git(repo, [...id, "commit", "-qm", "feature"]);
	// Arm the traps only after committing, so setup itself cannot trip them.
	writeFileSync(join(repo, ".gitattributes"), "*.yaml diff=x filter=x\n");
	git(repo, ["config", "core.fsmonitor", script("fsmonitor")]);
	git(repo, ["config", "diff.x.textconv", script("textconv")]);
	git(repo, ["config", "filter.x.clean", script("clean")]);
	git(repo, ["config", "filter.x.smudge", script("smudge")]);
	git(repo, ["config", "core.pager", script("pager")]);
	mkdirSync(join(repo, ".git", "hooks"), { recursive: true });
	for (const hook of [
		"post-checkout",
		"pre-auto-gc",
		"reference-transaction",
	]) {
		const path = join(repo, ".git", "hooks", hook);
		writeFileSync(path, `#!/bin/sh\ntouch "${markers}/hook"\n`);
		chmodSync(path, 0o755);
	}
	// oasdiff reads `.oasdiff.yaml` from its cwd; this one would hide
	// everything if oasdiff ever ran inside the target.
	writeFileSync(
		join(repo, ".oasdiff.yaml"),
		"match-path: ^/nothing-matches$\n",
	);
	return { repo, markers };
};

const TRAPS = ["fsmonitor", "textconv", "clean", "smudge", "pager", "hook"];

/** Real git through the live Exec; oasdiff answered from a recording. */
const realGitFakeOasdiff = async (repo: string) => {
	const live = await Effect.runPromise(
		Effect.gen(function* () {
			return yield* Exec;
		}).pipe(Effect.provide(Exec.layer)),
	);
	const seen: string[][] = [];
	const report = await Effect.runPromise(
		runAudit({
			target: repo,
			auditors: [oasdiff],
			options: { diffBase: "main" },
			selection: { only: [oasdiff.id] },
		}).pipe(
			Effect.provide(
				Layer.mergeAll(
					Workspaces.layer,
					Http.layer,
					Layer.succeed(Exec, {
						which: (bin: string) =>
							bin === "oasdiff"
								? Effect.succeed("/fake/oasdiff")
								: live.which(bin),
						run: (cmd: ReadonlyArray<string>, options?: ExecOptions) => {
							if (cmd[0] !== "/fake/oasdiff") return live.run(cmd, options);
							return Effect.sync((): ExecResult => {
								const cwd = options?.cwd as string;
								seen.push(
									cmd
										.slice(2, 4)
										.map((f) => readFileSync(join(cwd, f), "utf8")),
								);
								return {
									code: 0,
									stdout: read("breaking-yaml.json"),
									stderr: "",
								};
							});
						},
					}),
				),
			),
		),
	);
	return { report, seen };
};

const oasdiffAvailable = Bun.which("oasdiff") !== null;

describe("git hardening (real git)", () => {
	test("the naive approach does execute the repository's commands", () => {
		const { repo, markers } = prRepo();
		git(repo, ["status"]);
		git(repo, ["log", "-p", "-1", "--", "api/openapi.yaml"]);
		expect(existsSync(join(markers, "fsmonitor"))).toBe(true);
		expect(existsSync(join(markers, "textconv"))).toBe(true);
	});

	test("reads the base spec from the merge base without running anything", async () => {
		const { repo, markers } = prRepo();
		const { report, seen } = await realGitFakeOasdiff(repo);
		const result = report.results[0];
		expect(result?.status).toBe("failed");
		// Only the changed spec is compared; the new one has no base.
		expect(seen).toEqual([[read("base.yaml"), read("revision.yaml")]]);
		expect([...new Set(result?.findings.map((f) => f.location?.file))]).toEqual(
			["api/openapi.yaml"],
		);
		for (const m of TRAPS) expect(existsSync(join(markers, m))).toBe(false);
	});

	test.skipIf(!oasdiffAvailable)(
		"the real oasdiff reports the breaking changes, ignoring project config",
		async () => {
			const { repo, markers } = prRepo();
			const report = await Effect.runPromise(
				runAudit({
					target: repo,
					auditors: [oasdiff],
					options: { diffBase: "main" },
					selection: { only: [oasdiff.id] },
				}).pipe(
					Effect.provide(
						Layer.mergeAll(Workspaces.layer, Http.layer, Exec.layer),
					),
				),
			);
			const findings = report.results[0]?.findings ?? [];
			expect(findings.map((f) => f.ruleId)).toEqual(
				expect.arrayContaining([
					"code.oasdiff/api-removed-without-deprecation",
					"code.oasdiff/new-required-request-parameter",
					"code.oasdiff/request-parameter-type-changed",
				]),
			);
			const added = findings.find(
				(f) => f.ruleId === "code.oasdiff/new-required-request-parameter",
			);
			expect(added?.location).toEqual({ file: "api/openapi.yaml", line: 15 });
			for (const m of TRAPS) expect(existsSync(join(markers, m))).toBe(false);
		},
	);

	test.skipIf(!oasdiffAvailable)(
		"the real oasdiff never fetches a remote $ref, even a JSON-escaped one",
		async () => {
			let requests = 0;
			const server = Bun.serve({
				port: 0,
				hostname: "127.0.0.1",
				fetch: () => {
					requests++;
					return new Response("type: object\n");
				},
			});
			try {
				const repo = scratch("openaudit-oasdiff-remote-");
				const id = ["-c", "user.email=t@t", "-c", "user.name=t"];
				git(repo, ["init", "-q", "-b", "main"]);
				const base = read("base.json");
				writeFileSync(join(repo, "plain.json"), base);
				writeFileSync(join(repo, "escaped.json"), base);
				git(repo, ["add", "."]);
				git(repo, [...id, "commit", "-qm", "base"]);
				const url = `http://127.0.0.1:${server.port}/schema.yaml`;
				const swap = (key: string) =>
					read("revision.json").replace(
						'"type": "object",',
						`"${key}": "${url}",`,
					);
				writeFileSync(join(repo, "plain.json"), swap("$ref"));
				writeFileSync(join(repo, "escaped.json"), swap("\\u0024ref"));
				git(repo, [...id, "commit", "-qam", "remote refs"]);

				const report = await Effect.runPromise(
					runAudit({
						target: repo,
						auditors: [oasdiff],
						options: { diffBase: "HEAD~1" },
						selection: { only: [oasdiff.id] },
					}).pipe(
						Effect.provide(
							Layer.mergeAll(Workspaces.layer, Http.layer, Exec.layer),
						),
					),
				);
				const findings = report.results[0]?.findings ?? [];
				expect(
					findings.map((f) => [f.ruleId, f.location?.file]).sort(),
				).toEqual([
					["code.oasdiff/not-compared", "escaped.json"],
					["code.oasdiff/not-compared", "plain.json"],
				]);
				expect(findings[0]?.message).toContain("external $refs");
				expect(requests).toBe(0);
			} finally {
				server.stop(true);
			}
		},
	);
});
