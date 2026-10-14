import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { cp, mkdtemp, readdir, rename, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding, Report } from "@openaudit/core";

import {
	anyOf,
	licenses,
	MAX_LICENSE_DEPENDENCIES,
	npmLicense,
	pythonLicense,
} from "../src/codebase/licenses";
import { fixture, runAuditor } from "./helpers";

// Lockfiles are stored as `*.fixture`, and installed metadata under
// `_node_modules` / `_venv`, so neither git nor repository scanners treat them
// as real dependencies. They get their real names in a temp copy.
const RENAMES: Record<string, string> = {
	_node_modules: "node_modules",
	_venv: ".venv",
};
const restoreNames = async (dir: string): Promise<void> => {
	for (const entry of await readdir(dir, { withFileTypes: true })) {
		const real =
			RENAMES[entry.name] ??
			(entry.name.endsWith(".fixture")
				? entry.name.slice(0, -".fixture".length)
				: entry.name);
		if (real !== entry.name)
			await rename(join(dir, entry.name), join(dir, real));
		if (entry.isDirectory()) await restoreNames(join(dir, real));
	}
};

let root = "";

beforeAll(async () => {
	root = await mkdtemp(join(tmpdir(), "openaudit-licenses-"));
	await cp(fixture("codebase", "licenses"), root, { recursive: true });
	await restoreNames(root);
});

afterAll(() => rm(root, { recursive: true, force: true }));

const audit = (policy?: Record<string, unknown>) =>
	runAuditor(
		licenses,
		root,
		policy ? { settings: { "code.licenses": policy } } : {},
	);

const result = (report: Report) => {
	const r = report.results[0];
	if (!r) throw new Error("no result");
	return r;
};

/** `rule package@version` for each finding, sorted. */
const summary = (report: Report) =>
	result(report)
		.findings.map(
			(f) => `${f.ruleId.split("/")[1]} ${f.evidence?.split(":")[0]}`,
		)
		.sort();

const find = (report: Report, pkg: string): Finding | undefined =>
	result(report).findings.find((f) => f.evidence?.startsWith(`${pkg}:`));

describe("licence metadata", () => {
	test("npm package.json shapes", () => {
		expect(npmLicense({ license: "MIT" })).toBe("MIT");
		expect(npmLicense({ license: { type: "ISC", url: "x" } })).toBe("ISC");
		expect(
			npmLicense({ licenses: [{ type: "Apache 2.0" }, { type: "BSD-3" }] }),
		).toBe("Apache-2.0 OR BSD-3-Clause");
		expect(npmLicense({ license: "  " })).toBeUndefined();
		expect(npmLicense({})).toBeUndefined();
	});

	test("anyOf keeps unparseable alternatives as written", () => {
		expect(anyOf(["MIT"])).toBe("MIT");
		expect(anyOf(["MIT", "GPL-2.0 AND ISC"])).toBe(
			"MIT OR (GPL-2.0-only AND ISC)",
		);
		expect(anyOf(["MIT", "Custom terms"])).toBe("MIT, Custom terms");
		expect(anyOf([])).toBeUndefined();
	});

	test("Python METADATA", () => {
		expect(
			pythonLicense(
				"Metadata-Version: 2.4\nLicense-Expression: MIT OR Apache-2.0\nLicense: BSD\n\nbody",
			),
		).toBe("MIT OR Apache-2.0");
		expect(
			pythonLicense(
				"Name: x\nLicense: BSD-3-Clause\nClassifier: License :: OSI Approved :: MIT License\n",
			),
		).toBe("BSD-3-Clause");
		// A full licence text in `License` is skipped in favour of classifiers.
		expect(
			pythonLicense(
				"Name: x\nLicense: Copyright (c) Someone\n        Permission is hereby granted\nClassifier: License :: OSI Approved :: MIT License\nClassifier: License :: OSI Approved :: Apache Software License\n",
			),
		).toBe("MIT OR Apache-2.0");
		// A single classifier is kept as written; evaluation normalises it.
		expect(
			pythonLicense(
				"Name: x\nClassifier: License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)\n",
			),
		).toBe("GNU General Public License v2 or later (GPLv2+)");
		expect(pythonLicense("Name: x\nLicense: UNKNOWN\n")).toBeUndefined();
		// Classifiers in the body (after the blank line) are ignored.
		expect(
			pythonLicense("Name: x\n\nClassifier: License :: OSI Approved :: MIT"),
		).toBeUndefined();
	});
});

describe("code.licenses", () => {
	test("skips with configuration help when no policy is set", async () => {
		const r = result(await audit());
		expect(r.status).toBe("skipped");
		expect(r.message).toContain('options.settings["code.licenses"]');
		expect(r.message).toContain('"deny"');
	});

	test("skips a policy with nothing to check", async () => {
		const r = result(await audit({ unknown: "off" }));
		expect(r.status).toBe("skipped");
	});

	test("rejects invalid settings", async () => {
		for (const policy of [
			{ deny: "GPL-3.0" },
			{ deny: ["MIT OR GPL-3.0"] },
			{ unknown: "sometimes" },
			{ denied: ["GPL-*"] },
		]) {
			const r = result(await audit(policy));
			expect(r.status).toBe("error");
			expect(r.message).toContain('settings["code.licenses"]');
		}
	});

	test("deny list across npm, Composer and Python sources", async () => {
		const report = await audit({ deny: ["GPL-*", "AGPL-*"] });
		expect(result(report).status).toBe("failed");
		expect(summary(report)).toEqual([
			"denied-license @acme/internal@5.0.0",
			"denied-license acme/gpl-php@1.0.0",
			"denied-license gpl-lib@2.0.0",
			"denied-license gplpkg@1.0.0",
			"denied-license nested@2.2.2",
			"no-license-data 3/19 dependencies without licence data",
			"unknown-license blank@0.1.0",
			"unknown-license closed-lib@3.0.0",
		]);

		const gpl = find(report, "gpl-lib@2.0.0");
		expect(gpl).toMatchObject({
			severity: "high",
			category: "compliance",
			location: { file: "package-lock.json", line: 17 },
			evidence: "gpl-lib@2.0.0: GPL-3.0",
			tags: ["licence", "licence-policy"],
		});
		expect(gpl?.remediation).toContain("ignorePackages");

		// Nested installs are read from the package-lock install path.
		expect(find(report, "nested@2.2.2")?.message).toContain(
			"(from node_modules/wrapper/node_modules/nested/package.json)",
		);
		expect(find(report, "gplpkg@1.0.0")?.message).toContain(
			".venv/lib/python3.12/site-packages/gplpkg-1.0.0.dist-info/METADATA",
		);
		expect(find(report, "acme/gpl-php@1.0.0")?.location?.file).toBe(
			"composer.lock",
		);
		expect(find(report, "closed-lib@3.0.0")?.severity).toBe("low");

		const noData = result(report).findings.find((f) =>
			f.ruleId.endsWith("/no-license-data"),
		);
		expect(noData?.severity).toBe("info");
		for (const pkg of [
			"not-installed@1.0.0",
			"mystery@1.0.0",
			"github.com/example/gomod@1.2.3",
		])
			expect(noData?.message).toContain(pkg);
	});

	test("allow list flags everything else", async () => {
		const report = await audit({
			allow: ["MIT", "ISC", "Apache-2.0", "BSD-*"],
			unknown: "off",
		});
		expect(summary(report)).toEqual([
			"license-not-allowed @acme/internal@5.0.0",
			"license-not-allowed acme/gpl-php@1.0.0",
			"license-not-allowed gpl-lib@2.0.0",
			"license-not-allowed gplpkg@1.0.0",
			"license-not-allowed left-pad@1.3.0",
			"license-not-allowed mpl-lib@0.4.0",
			"license-not-allowed nested@2.2.2",
			"no-license-data 3/19 dependencies without licence data",
		]);
		expect(find(report, "mpl-lib@0.4.0")?.severity).toBe("medium");
		// `(MIT OR GPL-3.0-only)` passes through its MIT alternative, and the
		// legacy `licenses` array of legacy-pkg reads as Apache-2.0 OR BSD-3-Clause.
		expect(find(report, "dual-lib@1.1.0")).toBeUndefined();
		expect(find(report, "legacy-pkg@0.9.0")).toBeUndefined();
	});

	test("checks a bounded number of dependencies", async () => {
		const dir = await mkdtemp(join(tmpdir(), "openaudit-licenses-many-"));
		try {
			const count = MAX_LICENSE_DEPENDENCIES + 50;
			const packages: Record<string, unknown> = { "": { name: "many" } };
			for (let i = 0; i < count; i++)
				packages[`node_modules/p${i}`] = {
					version: "1.0.0",
					license: "GPL-3.0-only",
				};
			await Bun.write(
				join(dir, "package-lock.json"),
				JSON.stringify({ name: "many", lockfileVersion: 3, packages }),
			);
			const report = await runAuditor(licenses, dir, {
				settings: { "code.licenses": { deny: ["GPL-*"] } },
			});
			const findings = result(report).findings;
			expect(
				findings.filter((f) => f.ruleId === "code.licenses/denied-license"),
			).toHaveLength(MAX_LICENSE_DEPENDENCIES);
			expect(
				findings.find((f) => f.ruleId === "code.licenses/truncated")?.message,
			).toContain(`${count}`);
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	test("reads lockfiles larger than the 2 MB text limit", async () => {
		// Workspace.readText refuses files over 2 MB, and readTextFiles used to
		// swallow that, so a big package-lock.json was silently not checked.
		const dir = await mkdtemp(join(tmpdir(), "openaudit-licenses-big-"));
		try {
			const lock = JSON.stringify({
				name: "big",
				lockfileVersion: 3,
				packages: {
					"": { name: "big", description: "x".repeat(2_500_000) },
					"node_modules/gpl-lib": { version: "1.0.0", license: "GPL-3.0-only" },
				},
			});
			expect(lock.length).toBeGreaterThan(2 * 1024 * 1024);
			await Bun.write(join(dir, "package-lock.json"), lock);
			const report = await runAuditor(licenses, dir, {
				settings: { "code.licenses": { deny: ["GPL-*"] } },
			});
			expect(result(report).findings.map((f) => f.ruleId)).toContain(
				"code.licenses/denied-license",
			);
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	test("ignorePackages and the unknown severity", async () => {
		const report = await audit({
			deny: ["GPL-*", "AGPL-*"],
			unknown: "medium",
			ignorePackages: ["@acme/*", "GPL-LIB"],
		});
		expect(find(report, "@acme/internal@5.0.0")).toBeUndefined();
		expect(find(report, "gpl-lib@2.0.0")).toBeUndefined();
		expect(find(report, "closed-lib@3.0.0")?.severity).toBe("medium");
		expect(summary(report)).toContain(
			"no-license-data 3/17 dependencies without licence data",
		);
	});
});
