import { describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Finding } from "@openaudit/core";

import { escapesRoot, lockfiles } from "../src/codebase/lockfiles";
import { runAuditor } from "./helpers";

/*
 * Findings of a security review of code.lockfiles: trusted-source allow-lists
 * a hostile repository could satisfy, files and entries that were dropped
 * without a finding, inputs that slowed the parsers down, and secrets echoed
 * into findings. Every target file is attacker-controlled data.
 */

const audit = async (
	files: Record<string, string | Uint8Array>,
): Promise<ReadonlyArray<Finding>> => {
	const root = await mkdtemp(join(tmpdir(), "openaudit-lockfiles-review-"));
	try {
		for (const [path, data] of Object.entries(files)) {
			await mkdir(dirname(join(root, path)), { recursive: true });
			await writeFile(join(root, path), data);
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

const npmLock = (
	packages: Record<string, unknown>,
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

describe("trusted sources a repository cannot claim", () => {
	test("pnpm binary resolutions are only trusted for official runtime downloads", async () => {
		const findings = await audit({
			"pnpm-lock.yaml": `lockfileVersion: '9.0'

packages:

  node@runtime:22.0.0:
    resolution:
      type: binary
      archive: tarball
      url: https://nodejs.org/download/release/v22.0.0/node-v22.0.0-linux-x64.tar.gz
      integrity: ${SHA512}

  bun@runtime:1.2.0:
    resolution:
      type: binary
      archive: zip
      url: https://github.com/oven-sh/bun/releases/download/bun-v1.2.0/bun-linux-x64.zip
      integrity: ${SHA512}

  lodash@4.17.21:
    resolution:
      type: binary
      archive: tarball
      url: https://github.com/attacker/lodash/releases/download/v1/lodash.tgz
      integrity: ${SHA512}

  node@runtime:20.0.0:
    resolution:
      type: binary
      archive: tarball
      url: https://github.com/attacker/node/releases/download/v20/node.tar.gz
      integrity: ${SHA512}

snapshots:

  lodash@4.17.21: {}
`,
		});
		expect(rules(findings)).toEqual([
			"unexpected-host medium lodash@4.17.21",
			"unexpected-host medium node",
		]);
	});

	test("Yarn Berry downloads npm: packages from their __archiveUrl", async () => {
		const findings = await audit({
			"yarn.lock": `__metadata:
  version: 8
  cacheKey: 10c0

"a@npm:^1.0.0":
  version: 1.0.0
  resolution: "a@npm:1.0.0::__archiveUrl=https%3A%2F%2Fevil.example%2Fa-1.0.0.tgz"
  checksum: 10c0/abc
  languageName: node
  linkType: hard
`,
		});
		expect(rules(findings)).toEqual(["unexpected-host medium a@1.0.0"]);
		expect(findings[0]?.evidence).toContain("evil.example/a-1.0.0.tgz");
	});

	test("GitHub Packages is not the public registry: anyone can publish there", async () => {
		const findings = await audit({
			"package-lock.json": npmLock({
				"node_modules/lodash": {
					version: "4.17.21",
					resolved:
						"https://npm.pkg.github.com/download/@attacker/lodash/4.17.21/0123abcd",
					integrity: SHA512,
				},
			}),
		});
		expect(rules(findings)).toEqual(["unexpected-host medium lodash@4.17.21"]);
	});

	test("http: URLs are parsed like a URL parser does, not prefix-matched", async () => {
		const findings = await audit({
			"package-lock.json": npmLock({
				"node_modules/a": {
					version: "1.0.0",
					resolved: "HTTP:evil.example/a-1.0.0.tgz",
					integrity: SHA512,
				},
			}),
		});
		expect(rules(findings)).toEqual(["insecure-protocol high a@1.0.0"]);
	});

	test("a base directory that itself leaves the repository", () => {
		// Yarn Berry's locator and pnpm's importer keys set the base directory.
		expect(escapesRoot("../../..", "../x")).toBe(true);
		expect(escapesRoot("a/../..", "x")).toBe(true);
		expect(escapesRoot("a/b", "../x")).toBe(false);
		// URL-style path resolution (npm-package-arg) decodes dot segments.
		expect(escapesRoot("", "%2e%2e/x")).toBe(true);
		expect(escapesRoot("a", ".%2E/%2e%2E/x")).toBe(true);
	});

	test("Yarn Berry links relative to a workspace outside the repository", async () => {
		const findings = await audit({
			"yarn.lock": `__metadata:
  version: 8

"x@link:../outside::locator=app%40workspace%3A..%2F..%2F..":
  version: 0.0.0-use.local
  resolution: "x@link:../outside::locator=app%40workspace%3A..%2F..%2F.."
  languageName: node
  linkType: soft
`,
		});
		expect(rules(findings)).toEqual([
			"path-outside-workspace medium x@0.0.0-use.local",
		]);
	});

	test("pip: file URLs with a host are absolute, and Python's URL parser decides the host", async () => {
		const findings = await audit({
			"requirements.txt": [
				"local @ file://localhost/home/user/local",
				"good @ https://files.pythonhosted.org/packages/good-1.0-py3-none-any.whl",
				"bad @ https://files.pythonhosted.org\\@evil.example/bad-1.0-py3-none-any.whl",
				"--index-url https://pypi.org\\@evil.example/simple",
				"",
			].join("\n"),
		});
		expect(
			findings.map((f) => `${f.location?.line} ${f.ruleId.split("/")[1]}`),
		).toEqual([
			"1 path-outside-workspace",
			"3 unexpected-host",
			"4 custom-registry",
		]);
	});
});

describe("nothing is dropped without a finding", () => {
	test("a NUL byte in a comment does not hide a lockfile or config", async () => {
		const findings = await audit({
			"yarn.lock": `# yarn lockfile v1
# \u0000

a@^1.0.0:
  version "1.0.0"
  resolved "http://evil.example/a-1.0.0.tgz"
  integrity ${SHA512}
`,
			"app/.npmrc": "; \u0000\nstrict-ssl=false\n",
		});
		expect(rules(findings)).toEqual([
			"insecure-protocol high a@1.0.0",
			"tls-verification-disabled medium strict-ssl=false",
		]);
	});

	test("a UTF-16 lockfile is reported as unchecked", async () => {
		const text = npmLock({
			"node_modules/a": {
				version: "1.0.0",
				resolved: "http://evil.example/a-1.0.0.tgz",
			},
		});
		const utf16 = new Uint8Array(2 + text.length * 2);
		utf16.set([0xff, 0xfe]);
		for (let i = 0; i < text.length; i++) utf16[2 + i * 2] = text.charCodeAt(i);
		const findings = await audit({ "package-lock.json": utf16 });
		expect(rules(findings)).toEqual([
			"unparseable-lockfile medium package-lock.json",
		]);
		expect(findings[0]?.message).toContain("UTF-16");
	});

	test("npm 6 dependencies nested deeper than any budget are still checked", async () => {
		let deps: Record<string, unknown> = {
			evil: {
				version: "1.0.0",
				resolved: "http://evil.example/evil-1.0.0.tgz",
				integrity: SHA512,
			},
		};
		for (let i = 0; i < 100; i++)
			deps = {
				[`d${i}`]: {
					version: "1.0.0",
					resolved: `https://registry.npmjs.org/d${i}/-/d${i}-1.0.0.tgz`,
					integrity: SHA512,
					dependencies: deps,
				},
			};
		const findings = await audit({
			"package-lock.json": JSON.stringify({
				name: "app",
				lockfileVersion: 1,
				dependencies: deps,
			}),
		});
		expect(rules(findings)).toEqual(["insecure-protocol high evil@1.0.0"]);
	});

	test("a source field of the wrong type is reported, not read as the registry", async () => {
		const findings = await audit({
			"package-lock.json": npmLock({
				"node_modules/a": {
					version: "1.0.0",
					resolved: ["http://evil.example/a-1.0.0.tgz"],
					integrity: SHA512,
				},
				"node_modules/b": "http://evil.example/b-1.0.0.tgz",
			}),
			"bun/bun.lock": `{
  "lockfileVersion": 1,
  "workspaces": { "": { "name": "app" } },
  "packages": {
    "c": ["c@1.0.0", { "url": "http://evil.example/c-1.0.0.tgz" }, {}, "${SHA512}"],
  }
}
`,
			"pnpm/pnpm-lock.yaml": `lockfileVersion: '9.0'

packages:

  d@1.0.0:
    resolution: {tarball: [http://evil.example/d-1.0.0.tgz], integrity: ${SHA512}}

snapshots:

  d@1.0.0: {}
`,
		});
		expect(rules(findings)).toEqual([
			"unexpected-host medium a@1.0.0",
			"unexpected-host medium b",
			"unexpected-host medium c@1.0.0",
			"unexpected-host medium d@1.0.0",
		]);
	});

	test("a merge-conflict side that does not parse is reported", async () => {
		const findings = await audit({
			"package-lock.json": `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app" },
<<<<<<< HEAD
    "node_modules/a": { "version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz", "integrity": "${SHA512}" }
=======
    "node_modules/a": { "version": "1.0.0", "resolved": "http://evil.example/a-1.0.0.tgz", "integrity": "${SHA512}" },,
>>>>>>> evil
  }
}
`,
		});
		expect(rules(findings)).toEqual([
			"unparseable-lockfile medium package-lock.json",
		]);
	});

	test("an unrecognised lockfile format version is reported", async () => {
		const findings = await audit({
			"package-lock.json": npmLock({}, { lockfileVersion: 99 }),
		});
		expect(rules(findings)).toEqual([
			"unparseable-lockfile low package-lock.json",
		]);
		expect(findings[0]?.message).toContain("99");
	});

	test("registry configs that do not parse are reported", async () => {
		const findings = await audit({
			"a/.yarnrc.yml": 'npmRegistryServer: "https://evil.example"\n  bad: [\n',
			"b/bunfig.toml": '[install]\nregistry = "https://evil.example/\n',
			"c/pnpm-workspace.yaml": "packages: [\n",
			"d/package.json": '{ "name": "app", ',
			"e/composer.lock": "{ ",
		});
		expect(rules(findings)).toEqual([
			"unparseable-config low a/.yarnrc.yml",
			"unparseable-config low b/bunfig.toml",
			"unparseable-config low c/pnpm-workspace.yaml",
			"unparseable-config low d/package.json",
			"unparseable-lockfile medium e/composer.lock",
		]);
		for (const f of findings) expect(f.evidence).not.toContain("evil");
	});

	test("pip requirement includes outside the repository are reported", async () => {
		const findings = await audit({
			"requirements.txt": "-r ../../outside.txt\n",
		});
		expect(rules(findings)).toEqual([
			"path-outside-workspace medium requirement file",
		]);
	});
});

describe("resource bounds", () => {
	test("many classic yarn.lock entries of one package stay linear", async () => {
		const lines = ["# yarn lockfile v1", ""];
		for (let i = 0; i < 150_000; i++) lines.push(`a@${i}:`, '  version "1"');
		lines.push(
			"evil@^1.0.0:",
			'  version "1.0.0"',
			'  resolved "http://evil.example/evil-1.0.0.tgz"',
			`  integrity ${SHA512}`,
			"",
		);
		const start = performance.now();
		const findings = await audit({ "yarn.lock": lines.join("\n") });
		expect(performance.now() - start).toBeLessThan(8000);
		expect(rules(findings)).toContain("insecure-protocol high evil@1.0.0");
	});
});

describe("secrets never reach a finding", () => {
	test("credentials in package.json dependency specs are not echoed", async () => {
		const findings = await audit({
			"package.json": JSON.stringify({
				name: "app",
				dependencies: {
					private:
						"git+https://user:ghp_s3cr3tT0k3n@github.com/org/private.git",
					tarball: "https://npm.example/t.tgz?token=s3cr3tQuery",
				},
			}),
			"pnpm-lock.yaml": `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      tarball:
        specifier: https://npm.example/t.tgz?token=0ldS3cr3t
        version: https://npm.example/t.tgz

packages: {}
`,
		});
		const drift = findings.find(
			(f) => f.ruleId === "code.lockfiles/lockfile-drift",
		);
		expect(drift).toBeDefined();
		const text = JSON.stringify(findings);
		expect(text).not.toContain("s3cr3t");
		expect(text).not.toContain("S3cr3t");
		expect(text).not.toContain("ghp_");
	});
});
