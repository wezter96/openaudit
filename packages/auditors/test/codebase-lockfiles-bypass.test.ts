import { describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Finding } from "@openaudit/core";

import { lockfiles, MAX_FINDINGS_PER_RULE } from "../src/codebase/lockfiles";
import { runAuditor } from "./helpers";

/*
 * Ways a hostile repository could hide a risky lockfile entry from
 * code.lockfiles. Every target file is attacker-controlled data.
 */

/** Runs code.lockfiles over a temp directory holding `files`. */
const audit = async (
	files: Record<string, string>,
): Promise<ReadonlyArray<Finding>> => {
	const root = await mkdtemp(join(tmpdir(), "openaudit-lockfiles-bypass-"));
	try {
		for (const [path, text] of Object.entries(files)) {
			await mkdir(dirname(join(root, path)), { recursive: true });
			await writeFile(join(root, path), text);
		}
		const report = await runAuditor(lockfiles, root);
		return report.results[0]?.findings ?? [];
	} finally {
		await rm(root, { recursive: true, force: true });
	}
};

/** `rule severity evidence-prefix` for each finding, sorted. */
const rules = (findings: ReadonlyArray<Finding>) =>
	findings
		.map(
			(f) =>
				`${f.ruleId.split("/")[1]} ${f.severity} ${f.evidence?.split(":")[0]}`,
		)
		.sort();

const SHA512 = `sha512-${"A".repeat(86)}==`;
const SHA = "98e8ff1da1a89f93d1397a24d7413ed15421c139";

const npmLock = (
	packages: Record<string, Record<string, unknown>>,
	extra: Record<string, unknown> = {},
) =>
	JSON.stringify(
		{
			name: "app",
			lockfileVersion: 3,
			...extra,
			packages: { "": { name: "app" }, ...packages },
		},
		null,
		2,
	);

const tarball = (url: string, integrity: string | undefined = SHA512) => ({
	version: "1.0.0",
	resolved: url,
	...(integrity ? { integrity } : {}),
});

describe("registry configs in the target", () => {
	test("a declared registry is reported, and its packages are still listed", async () => {
		const findings = await audit({
			".npmrc":
				"registry=https://evil.example/\n@corp:registry=https://npm.corp.example/\n",
			"package-lock.json": npmLock({
				"node_modules/a": tarball("https://evil.example/a/-/a-1.0.0.tgz"),
				"node_modules/@corp/x": tarball(
					"https://npm.corp.example/@corp/x/-/x-1.0.0.tgz",
				),
				// A scoped registry only serves its own scope.
				"node_modules/b": tarball("https://npm.corp.example/b/-/b-1.0.0.tgz"),
			}),
		});
		expect(rules(findings)).toEqual([
			"custom-registry info @corp",
			"custom-registry info registry=https",
			"custom-registry-source low evil.example",
			"custom-registry-source low npm.corp.example",
			"unexpected-host medium b@1.0.0",
		]);
		const source = findings.find(
			(f) =>
				f.ruleId === "code.lockfiles/custom-registry-source" &&
				f.evidence?.startsWith("evil.example"),
		);
		expect(source?.evidence).toContain("a@1.0.0");
		expect(source?.message).toContain(".npmrc:1");
	});

	test("packages without a resolved URL come from the configured registry", async () => {
		const findings = await audit({
			".npmrc": "registry=https://evil.example/\n",
			"package-lock.json": npmLock({
				"node_modules/a": { version: "1.0.0", integrity: SHA512 },
			}),
		});
		expect(rules(findings)).toContain(
			"custom-registry-source low evil.example",
		);
	});

	test("only configs the package manager reads are trusted", async () => {
		const findings = await audit({
			// npm reads the project's .npmrc, not one in a parent directory, and
			// never .yarnrc.yml.
			".npmrc": "registry=https://evil.example/\nignore-scripts=true\n",
			"app/.yarnrc.yml": "enableScripts: false\n",
			"app/package-lock.json": npmLock({
				"node_modules/a": {
					...tarball("https://evil.example/a/-/a-1.0.0.tgz"),
					hasInstallScript: true,
				},
			}),
		});
		const r = rules(findings);
		expect(r).toContain("unexpected-host medium a@1.0.0");
		expect(r).toContain("ungated-install-scripts low a");
	});
});

describe("URL parsing", () => {
	test("hosts are compared after parsing, schemes case-insensitively", async () => {
		const findings = await audit({
			"package-lock.json": npmLock({
				"node_modules/userinfo": tarball(
					"https://registry.npmjs.org@evil.example/userinfo/-/userinfo-1.0.0.tgz",
				),
				"node_modules/suffix": tarball(
					"https://registry.npmjs.org.evil.example/suffix/-/suffix-1.0.0.tgz",
				),
				"node_modules/upper": tarball(
					"HTTP://registry.npmjs.org/upper/-/upper-1.0.0.tgz",
				),
				"node_modules/relative": tarball(
					"//evil.example/relative/-/relative-1.0.0.tgz",
				),
				// A tarball dressed up as a commit-pinned git dependency.
				"node_modules/disguised": tarball(
					`https://evil.example/disguised.tgz?x=.git#${SHA}`,
				),
				"node_modules/unknown": tarball("weird-scheme:payload"),
				"node_modules/gitsh": {
					version: "1.0.0",
					resolved: `git+ssh://git@evil.example/x/gitsh.git#${SHA}`,
				},
			}),
		});
		expect(rules(findings)).toEqual([
			"git-dependency medium gitsh@1.0.0",
			"insecure-protocol high upper@1.0.0",
			"unexpected-host medium disguised@1.0.0",
			"unexpected-host medium relative@1.0.0",
			"unexpected-host medium suffix@1.0.0",
			"unexpected-host medium unknown@1.0.0",
			"unexpected-host medium userinfo@1.0.0",
		]);
		for (const f of findings)
			expect(JSON.stringify(f)).not.toContain("registry.npmjs.org@");
	});

	test("an integrity value that is not a hash counts as missing", async () => {
		const findings = await audit({
			"package-lock.json": npmLock({
				"node_modules/a": tarball(
					"https://registry.npmjs.org/a/-/a-1.0.0.tgz",
					"x",
				),
			}),
		});
		expect(rules(findings)).toEqual(["missing-integrity low a@1.0.0"]);
	});
});

describe("install-script allow-lists", () => {
	test("Bun's allow-list is read from package.json as well as bun.lock", async () => {
		const findings = await audit({
			"package.json": JSON.stringify({
				name: "app",
				dependencies: { a: "1.0.0", evil: "1.0.0" },
				trustedDependencies: ["a", "evil"],
			}),
			"bun.lock": `{
  "lockfileVersion": 1,
  "workspaces": { "": { "name": "app", "dependencies": { "a": "1.0.0", "evil": "1.0.0" } } },
  "trustedDependencies": ["a"],
  "packages": {
    "a": ["a@1.0.0", "", {}, "${SHA512}"],
    "evil": ["evil@1.0.0", "", {}, "${SHA512}"],
  }
}
`,
		});
		const info = findings.find(
			(f) => f.ruleId === "code.lockfiles/install-scripts",
		);
		expect(info?.evidence).toBe("a, evil");
	});

	test("a wildcard allow-list allows every package", async () => {
		const findings = await audit({
			"pnpm-workspace.yaml": "onlyBuiltDependencies:\n  - '*'\n",
			"pnpm-lock.yaml": `lockfileVersion: '6.0'

dependencies:
  a:
    specifier: 1.0.0
    version: 1.0.0

packages:

  /a@1.0.0:
    resolution: {integrity: ${SHA512}}
    requiresBuild: true
    dev: false
`,
		});
		expect(rules(findings)).toContain("ungated-install-scripts low a");
	});
});

describe("parser evasion", () => {
	test("classic yarn.lock quoting, escaping, tabs and CRLF", async () => {
		const findings = await audit({
			"yarn.lock": [
				"# yarn lockfile v1",
				"",
				"tabbed@^1.0.0:",
				'\tversion "1.0.0"',
				'\tresolved "http://evil.example/tabbed-1.0.0.tgz"',
				`\tintegrity ${SHA512}`,
				"",
				'"escaped@^1.0.0":',
				'  version "1.0.0"',
				'  resolved "\\u0068ttp://evil.example/escaped-1.0.0.tgz"',
				`  integrity ${SHA512}`,
				"",
				"colon@^1.0.0:",
				'  version "1.0.0"',
				'  resolved:"https://evil.example/colon-1.0.0.tgz"',
				`  integrity ${SHA512}`,
				"",
			].join("\r\n"),
		});
		expect(rules(findings)).toEqual([
			"insecure-protocol high escaped@1.0.0",
			"insecure-protocol high tabbed@1.0.0",
			"unexpected-host medium colon@1.0.0",
		]);
	});

	test("Yarn Berry entries in YAML flow style", async () => {
		const findings = await audit({
			"yarn.lock": `__metadata:
  version: 8
  cacheKey: 10c0

"evil@https://evil.example/evil-1.0.0.tgz": { version: 1.0.0, resolution: "evil@https://evil.example/evil-1.0.0.tgz", checksum: 10c0/abc, languageName: node, linkType: hard }
`,
		});
		expect(rules(findings)).toEqual(["unexpected-host medium evil@1.0.0"]);
	});

	test("npm 6 reads the legacy dependencies section of a v2 lockfile", async () => {
		const findings = await audit({
			"package-lock.json": npmLock(
				{
					"node_modules/a": tarball(
						"https://registry.npmjs.org/a/-/a-1.0.0.tgz",
					),
				},
				{
					lockfileVersion: 2,
					dependencies: {
						a: {
							version: "1.0.0",
							resolved: "http://evil.example/a/-/a-1.0.0.tgz",
							integrity: SHA512,
						},
					},
				},
			),
		});
		expect(rules(findings)).toEqual(["insecure-protocol high a@1.0.0"]);
	});

	test("an unparseable lockfile is reported, not skipped", async () => {
		const findings = await audit({
			"pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages:\n  a: [\n",
		});
		expect(rules(findings)).toEqual([
			"unparseable-lockfile low pnpm-lock.yaml",
		]);
	});

	test("pip line continuations and attached short options", async () => {
		const findings = await audit({
			"requirements.txt":
				"--extra-index-url \\\n    http://evil.example/simple\n-ihttp://evil.example/simple\nrequests==2.31.0\n",
		});
		expect(
			findings
				.map((f) => `${f.location?.line} ${f.ruleId.split("/")[1]}`)
				.sort(),
		).toEqual([
			"1 extra-index-url",
			"1 insecure-protocol",
			"3 insecure-protocol",
		]);
	});
});

describe("large lockfiles", () => {
	test("entries after the first few thousand are still checked", async () => {
		const packages: Record<string, Record<string, unknown>> = {};
		for (let i = 0; i < 6000; i++)
			packages[`node_modules/p${i}`] = tarball(
				`https://registry.npmjs.org/p${i}/-/p${i}-1.0.0.tgz`,
			);
		packages["node_modules/zz-last"] = tarball(
			"http://evil.example/zz-last-1.0.0.tgz",
		);
		const findings = await audit({ "package-lock.json": npmLock(packages) });
		expect(rules(findings)).toEqual(["insecure-protocol high zz-last@1.0.0"]);
	});

	test("findings per rule are capped, with the rest summarised", async () => {
		const packages: Record<string, Record<string, unknown>> = {};
		for (let i = 0; i < MAX_FINDINGS_PER_RULE + 20; i++)
			packages[`node_modules/p${i}`] = tarball(
				`http://registry.npmjs.org/p${i}/-/p${i}-1.0.0.tgz`,
			);
		const findings = await audit({ "package-lock.json": npmLock(packages) });
		const insecure = findings.filter(
			(f) => f.ruleId === "code.lockfiles/insecure-protocol",
		);
		expect(insecure.length).toBe(MAX_FINDINGS_PER_RULE + 1);
		const summary = insecure.find((f) => f.title.startsWith("20 more"));
		expect(summary?.severity).toBe("high");
		expect(summary?.message).toContain(`p${MAX_FINDINGS_PER_RULE}@`);
	});
});
