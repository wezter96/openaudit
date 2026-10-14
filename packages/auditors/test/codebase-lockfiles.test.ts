import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { cp, mkdtemp, readdir, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding, Report } from "@openaudit/core";

import {
	classifySource,
	displayUrl,
	escapesRoot,
	lockfiles,
} from "../src/codebase/lockfiles";
import { fixture, runAuditor } from "./helpers";

// Lockfiles and package-manager configs are stored as `*.fixture` so repository
// scanners do not treat them as real. They get their real names in a temp copy.
const restoreNames = async (dir: string): Promise<void> => {
	for (const entry of await readdir(dir, { withFileTypes: true })) {
		if (entry.isDirectory()) await restoreNames(join(dir, entry.name));
		else if (entry.name.endsWith(".fixture"))
			await rename(
				join(dir, entry.name),
				join(dir, entry.name.slice(0, -".fixture".length)),
			);
	}
};

let root = "";
let report: Report;

beforeAll(async () => {
	root = await mkdtemp(join(tmpdir(), "openaudit-lockfiles-"));
	await cp(fixture("codebase", "lockfiles"), root, { recursive: true });
	await restoreNames(root);
	report = await runAuditor(lockfiles, root);
});

afterAll(() => rm(root, { recursive: true, force: true }));

const findings = (r: Report = report): ReadonlyArray<Finding> =>
	r.results[0]?.findings ?? [];

/** `file rule severity` for every finding in `dir`, sorted. */
const summary = (dir: string, r: Report = report) =>
	findings(r)
		.filter((f) => f.location?.file?.startsWith(`${dir}/`))
		.map(
			(f) =>
				`${f.location?.file?.slice(dir.length + 1)}:${f.location?.line ?? "-"} ${f.ruleId.split("/")[1]} ${f.severity} ${f.evidence?.split(":")[0]}`,
		)
		.sort();

const find = (rule: string, file: string, evidence?: string) =>
	findings().find(
		(f) =>
			f.ruleId === `code.lockfiles/${rule}` &&
			f.location?.file === file &&
			(evidence === undefined || f.evidence?.startsWith(evidence)),
	);

describe("source classification", () => {
	test("registry, path, git and tarball sources", () => {
		expect(classifySource(undefined).kind).toBe("registry");
		expect(classifySource("npm:1.0.0").kind).toBe("registry");
		expect(classifySource("workspace:packages/a").kind).toBe("ignored");
		expect(classifySource("file:../x")).toEqual({
			kind: "path",
			path: "../x",
		});
		expect(
			classifySource(
				"git+ssh://git@github.com/a/b.git#98e8ff1da1a89f93d1397a24d7413ed15421c139",
			),
		).toMatchObject({ kind: "git", pinned: true, insecure: false });
		expect(classifySource("github:a/b#main")).toMatchObject({
			kind: "git",
			ref: "main",
			pinned: false,
		});
		expect(
			classifySource(
				"https://github.com/a/b.git#commit=98e8ff1da1a89f93d1397a24d7413ed15421c139",
			),
		).toMatchObject({ kind: "git", pinned: true });
		expect(classifySource("git://github.com/a/b.git#v1")).toMatchObject({
			kind: "git",
			insecure: true,
		});
		expect(
			classifySource("https://codeload.github.com/a/b/tar.gz/refs/tags/1.0"),
		).toMatchObject({ kind: "git", ref: "refs/tags/1.0", pinned: false });
		expect(
			classifySource("https://github.com/a/b/archive/refs/tags/1.0.tar.gz"),
		).toMatchObject({ kind: "git", ref: "refs/tags/1.0" });
		expect(
			classifySource("http://registry.npmjs.org/a/-/a-1.0.0.tgz"),
		).toMatchObject({
			kind: "tarball",
			host: "registry.npmjs.org",
			insecure: true,
		});
	});

	test("evidence URLs drop credentials and query strings", () => {
		expect(displayUrl("https://u:p4ss@h.example/x.tgz?token=1")).toBe(
			"https://h.example/x.tgz",
		);
		expect(displayUrl("git+https://u:t0k@github.com/a/b.git#v1@x")).toBe(
			"git+https://github.com/a/b.git#v1@x",
		);
		expect(displayUrl("git+ssh://git@github.com/a/b.git")).toBe(
			"git+ssh://github.com/a/b.git",
		);
	});

	test("paths that leave the repository", () => {
		expect(escapesRoot("", "./local")).toBe(false);
		expect(escapesRoot("apps/web", "../../packages/ui")).toBe(false);
		expect(escapesRoot("apps/web", "../../../elsewhere")).toBe(true);
		expect(escapesRoot("", "../sibling")).toBe(true);
		expect(escapesRoot("a", "b/../../..")).toBe(true);
		expect(escapesRoot("", "/etc/passwd")).toBe(true);
		expect(escapesRoot("", "C:\\Users\\x")).toBe(true);
		expect(escapesRoot("", "~/pkg")).toBe(true);
	});
});

describe("code.lockfiles", () => {
	test("npm package-lock.json", () => {
		expect(summary("npm")).toEqual([
			".npmrc:1 custom-registry info @corp",
			".npmrc:3 tls-verification-disabled medium strict-ssl=false",
			"package-lock.json:109 weak-integrity low old-pkg@1.0.0",
			"package-lock.json:118 unexpected-host medium private-pkg@1.0.0",
			"package-lock.json:21 path-outside-workspace medium outside",
			"package-lock.json:27 custom-registry-source low npm.corp.example",
			"package-lock.json:32 install-scripts info bufferutil, utf-8-validate",
			"package-lock.json:32 ungated-install-scripts low bufferutil, utf-8-validate",
			"package-lock.json:45 insecure-protocol high insecure-pkg@1.0.0",
			"package-lock.json:50 git-dependency low is-number@7.0.0",
			"package-lock.json:58 git-dependency low is-odd@3.0.1",
			"package-lock.json:83 unexpected-host medium mirror-pkg@1.0.0",
			"package-lock.json:94 missing-integrity low no-integrity@1.0.0",
			"package.json:11 lockfile-drift low ms",
		]);
	});

	test("credentials in resolved URLs never reach a finding", () => {
		const f = find("unexpected-host", "npm/package-lock.json", "private-pkg");
		const text = JSON.stringify(f);
		expect(text).not.toContain("s3cr3t");
		expect(text).not.toContain("abc123");
		expect(f?.evidence).toContain("npm.other.example/private-pkg");
	});

	test("npm runs every install script unless ignore-scripts is set", () => {
		const f = find("ungated-install-scripts", "npm/package-lock.json");
		expect(f?.message).toContain("ignore-scripts");
		expect(f?.tags).toContain("install-scripts");
	});

	test("lockfile drift lists missing and changed dependencies", () => {
		const f = find("lockfile-drift", "npm/package.json");
		expect(f?.message).toContain("left-pad");
		expect(f?.message).toContain('ms is "^2.1.3"');
	});

	// The fixture overrides ms, so its package.json range differs from the
	// recorded specifier without being drift.
	test("pnpm v9 lockfile with an onlyBuiltDependencies allow-list", () => {
		expect(summary("pnpm")).toEqual([
			"pnpm-lock.yaml:30 path-outside-workspace medium outside-link",
			"pnpm-lock.yaml:41 install-scripts info bufferutil",
			"pnpm-lock.yaml:49 git-dependency low is-number@7.0.0",
			"pnpm-lock.yaml:54 git-dependency medium is-odd@3.0.1",
			"pnpm-lock.yaml:69 missing-integrity low tarball-pkg@1.0.0",
			"pnpm-lock.yaml:69 unexpected-host medium tarball-pkg@1.0.0",
		]);
		expect(find("install-scripts", "pnpm/pnpm-lock.yaml")?.message).toContain(
			"onlyBuiltDependencies",
		);
	});

	test("pnpm v6 lockfile records requiresBuild", () => {
		expect(summary("pnpm8")).toEqual([
			"pnpm-lock.yaml:29 install-scripts info bufferutil, utf-8-validate",
			"pnpm-lock.yaml:29 ungated-install-scripts low bufferutil",
			"pnpm-lock.yaml:59 git-dependency medium is-odd@3.0.1",
			"pnpm-lock.yaml:73 git-dependency low is-number@7.0.0",
		]);
	});

	test("bun.lock with trustedDependencies and a scoped registry", () => {
		expect(summary("bun")).toEqual([
			"bun.lock:21 custom-registry-source low registry.corp.example",
			"bun.lock:23 missing-integrity low bare-pkg@1.0.0",
			"bun.lock:25 install-scripts info bufferutil",
			"bun.lock:27 insecure-protocol high http-pkg@1.0.0",
			"bun.lock:29 git-dependency low is-number",
			"bun.lock:31 git-dependency low is-odd",
			"bunfig.toml:5 custom-registry info @corp = https",
			"package.json:17 lockfile-drift low zod",
		]);
		expect(find("install-scripts", "bun/bun.lock")?.message).toContain(
			"trustedDependencies",
		);
	});

	test("yarn v1 lockfile", () => {
		expect(summary("yarn1")).toEqual([
			"package.json:13 lockfile-drift low chalk",
			"yarn.lock:12 insecure-protocol high insecure@1.0.0",
			"yarn.lock:22 git-dependency low is-number@7.0.0",
			"yarn.lock:26 git-dependency low is-odd@3.0.1",
			"yarn.lock:32 weak-integrity low legacy@1.0.0",
		]);
	});

	test("yarn berry lockfile and .yarnrc.yml", () => {
		expect(summary("berry")).toEqual([
			".yarnrc.yml:2 tls-verification-disabled medium enableStrictSsl",
			".yarnrc.yml:3 insecure-protocol high npmRegistryServer",
			".yarnrc.yml:6 custom-registry info npmScopes.corp.npmRegistryServer",
			"yarn.lock:48 missing-integrity low evil@1.0.0",
			"yarn.lock:48 unexpected-host medium evil@1.0.0",
			"yarn.lock:80 git-dependency low is-number@7.0.0",
			"yarn.lock:94 git-dependency low is-odd@3.0.1",
		]);
	});

	test("pip requirements index options", () => {
		expect(summary("python")).toEqual([
			"requirements.txt:2 insecure-protocol high --index-url http",
			"requirements.txt:3 extra-index-url medium --extra-index-url https",
			"requirements.txt:4 tls-verification-disabled medium --trusted-host pypi.internal.example",
		]);
	});

	test("composer repositories", () => {
		expect(summary("composer")).toEqual([
			"composer.json:11 git-dependency low vcs",
			"composer.json:15 insecure-protocol high composer",
			"composer.json:19 path-outside-workspace medium path",
			"composer.json:23 insecure-protocol medium secure-http",
		]);
	});

	test("findings carry remediation, references and supply-chain category", () => {
		for (const f of findings()) {
			expect(f.category).toBe("supply-chain");
			expect(f.remediation).toBeTruthy();
			expect(f.references?.length).toBeGreaterThan(0);
			expect(f.location?.file).toBeTruthy();
		}
	});

	test("skips a target without lockfiles", async () => {
		const empty = await mkdtemp(join(tmpdir(), "openaudit-lockfiles-empty-"));
		try {
			await writeFile(join(empty, "index.ts"), "export {};\n");
			const r = await runAuditor(lockfiles, empty);
			expect(r.results[0]?.status).toBe("skipped");
		} finally {
			await rm(empty, { recursive: true, force: true });
		}
	});

	test("hostile lines do not slow the parsers down", async () => {
		const hostile = await mkdtemp(join(tmpdir(), "openaudit-lockfiles-redos-"));
		try {
			const long = "a".repeat(200_000);
			await writeFile(
				join(hostile, "yarn.lock"),
				`${": ".repeat(100_000)}\n  ${long}\n"${"@".repeat(100_000)}":\n  resolved "${"#".repeat(100_000)}"\n`,
			);
			await writeFile(
				join(hostile, "requirements.txt"),
				`--extra-index-url ${" ".repeat(100_000)}x\n${"-i ".repeat(50_000)}\n`,
			);
			await writeFile(
				join(hostile, "pnpm-lock.yaml"),
				`lockfileVersion: '9.0'\npackages:\n  ${": ".repeat(100_000)}:\n`,
			);
			const start = performance.now();
			const r = await runAuditor(lockfiles, hostile);
			expect(performance.now() - start).toBeLessThan(2000);
			expect(r.results[0]?.status).not.toBe("error");
		} finally {
			await rm(hostile, { recursive: true, force: true });
		}
	});
});
