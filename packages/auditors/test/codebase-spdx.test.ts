import { describe, expect, test } from "bun:test";

import {
	compileLicensePolicy,
	evaluateLicense,
	formatLicenseExpression,
	normaliseLicenseId,
	parseLicense,
} from "../src/codebase/spdx";

const show = (raw: string) => {
	const expr = parseLicense(raw);
	return expr ? formatLicenseExpression(expr) : undefined;
};

describe("normaliseLicenseId", () => {
	test.each([
		["MIT", "MIT"],
		["mit", "MIT"],
		["MIT License", "MIT"],
		["Expat", "MIT"],
		["Apache 2.0", "Apache-2.0"],
		["apache-2", "Apache-2.0"],
		["Apache2", "Apache-2.0"],
		["Apache License, Version 2.0", "Apache-2.0"],
		["Apache Software License", "Apache-2.0"],
		["ASL 2.0", "Apache-2.0"],
		["BSD-3", "BSD-3-Clause"],
		["New BSD License", "BSD-3-Clause"],
		["Simplified BSD", "BSD-2-Clause"],
		["isc", "ISC"],
		["ISCL", "ISC"],
		["MPL 2.0", "MPL-2.0"],
		["Mozilla Public License 2.0", "MPL-2.0"],
		["CC0", "CC0-1.0"],
		["The Unlicense", "Unlicense"],
		["Python Software Foundation License", "PSF-2.0"],
		["Boost Software License 1.0", "BSL-1.0"],
	])("%s -> %s", (input, expected) => {
		expect(normaliseLicenseId(input)).toBe(expected);
	});

	test.each([
		["GPL-2.0", "GPL-2.0-only"],
		["GPL-2.0+", "GPL-2.0-or-later"],
		["gpl-3.0", "GPL-3.0-only"],
		["GPLv3", "GPL-3.0-only"],
		["GPL v2", "GPL-2.0-only"],
		["GPLv2+", "GPL-2.0-or-later"],
		["GPL-3.0-or-later", "GPL-3.0-or-later"],
		["LGPL-2.1", "LGPL-2.1-only"],
		["LGPLv3+", "LGPL-3.0-or-later"],
		["AGPL-3.0", "AGPL-3.0-only"],
		["AGPLv3", "AGPL-3.0-only"],
		["GNU General Public License v3", "GPL-3.0-only"],
		["GNU General Public License v2 or later", "GPL-2.0-or-later"],
		["GNU Affero General Public License v3", "AGPL-3.0-only"],
		["GNU Lesser General Public License v2.1", "LGPL-2.1-only"],
		["GNU Library or Lesser General Public License", "LGPL-2.0-or-later"],
		["GNU General Public License", "GPL-1.0-or-later"],
	])("GNU spelling %s -> %s", (input, expected) => {
		expect(normaliseLicenseId(input)).toBe(expected);
	});

	test("keeps unknown ids as written", () => {
		expect(normaliseLicenseId("BlueOak-1.0.0")).toBe("BlueOak-1.0.0");
		expect(normaliseLicenseId(" Zlib ")).toBe("Zlib");
	});
});

describe("parseLicense", () => {
	test("SPDX expressions", () => {
		expect(show("MIT")).toBe("MIT");
		expect(show("(MIT OR Apache-2.0)")).toBe("MIT OR Apache-2.0");
		expect(show("MIT AND (BSD-2-Clause OR ISC)")).toBe(
			"MIT AND (BSD-2-Clause OR ISC)",
		);
		// AND binds tighter than OR.
		expect(show("MIT OR ISC AND GPL-3.0")).toBe(
			"MIT OR (ISC AND GPL-3.0-only)",
		);
		expect(show("GPL-2.0-only WITH Classpath-exception-2.0")).toBe(
			"GPL-2.0-only WITH Classpath-exception-2.0",
		);
		expect(show("mit or apache-2.0")).toBe("MIT OR Apache-2.0");
		expect(show("Apache-1.0+")).toBe("Apache-1.0+");
	});

	test("free text and legacy separators", () => {
		expect(show("Apache License, Version 2.0")).toBe("Apache-2.0");
		expect(show("GNU General Public License v2 or later (GPLv2+)")).toBe(
			"GPL-2.0-or-later",
		);
		expect(show("Mozilla Public License 2.0 (MPL 2.0)")).toBe("MPL-2.0");
		expect(show("MIT/Apache-2.0")).toBe("MIT OR Apache-2.0");
		expect(show("MIT, Apache 2.0")).toBe("MIT OR Apache-2.0");
	});

	test("rejects malformed expressions", () => {
		expect(parseLicense("")).toBeUndefined();
		expect(parseLicense("   ")).toBeUndefined();
		expect(parseLicense("(MIT")).toBeUndefined();
		expect(parseLicense("MIT OR")).toBeUndefined();
		expect(parseLicense("AND MIT")).toBeUndefined();
		expect(parseLicense("MIT WITH")).toBeUndefined();
		expect(parseLicense("SEE LICENSE IN LICENSE.md")).toBeUndefined();
		expect(parseLicense("Some custom licence text")).toBeUndefined();
	});
});

describe("evaluateLicense", () => {
	const deny = compileLicensePolicy({ deny: ["GPL-*", "AGPL-3.0-only"] });
	const allow = compileLicensePolicy({
		allow: ["MIT", "Apache-2.0", "BSD-*", "ISC"],
	});
	const both = compileLicensePolicy({
		deny: ["GPL-*"],
		allow: ["MIT", "GPL-2.0-only WITH Classpath-exception-2.0"],
	});

	test("deny list", () => {
		expect(evaluateLicense("MIT", deny)).toEqual({
			status: "ok",
			culprits: [],
		});
		expect(evaluateLicense("GPL-3.0-only", deny)).toEqual({
			status: "denied",
			culprits: ["GPL-3.0-only"],
		});
		// Case-insensitive, and deprecated ids are normalised first.
		expect(evaluateLicense("gpl-2.0", deny).status).toBe("denied");
		expect(evaluateLicense("agpl-3.0", deny).status).toBe("denied");
		// A family glob does not match a different family.
		expect(evaluateLicense("LGPL-2.1-only", deny).status).toBe("ok");
		// Without an allow list anything not denied passes.
		expect(evaluateLicense("WTFPL", deny).status).toBe("ok");
	});

	test("allow list", () => {
		expect(evaluateLicense("BSD-3-Clause", allow).status).toBe("ok");
		expect(evaluateLicense("MPL-2.0", allow)).toEqual({
			status: "not-allowed",
			culprits: ["MPL-2.0"],
		});
		expect(evaluateLicense("MIT License", allow).status).toBe("ok");
	});

	test("OR passes when any alternative passes", () => {
		expect(evaluateLicense("MIT OR GPL-3.0-only", deny).status).toBe("ok");
		expect(evaluateLicense("(GPL-2.0 OR AGPL-3.0)", deny)).toEqual({
			status: "denied",
			culprits: ["GPL-2.0-only", "AGPL-3.0-only"],
		});
		expect(evaluateLicense("MPL-2.0 OR Apache-2.0", allow).status).toBe("ok");
	});

	test("AND needs every part to pass", () => {
		expect(evaluateLicense("MIT AND GPL-3.0-only", deny)).toEqual({
			status: "denied",
			culprits: ["GPL-3.0-only"],
		});
		expect(evaluateLicense("MIT AND ISC", allow).status).toBe("ok");
		expect(evaluateLicense("MIT AND (ISC OR GPL-3.0)", deny).status).toBe("ok");
		expect(evaluateLicense("MIT AND (MPL-2.0 OR CDDL-1.0)", allow)).toEqual({
			status: "not-allowed",
			culprits: ["MPL-2.0", "CDDL-1.0"],
		});
	});

	test("the worst status wins under AND, the best under OR", () => {
		expect(evaluateLicense("GPL-3.0 AND UNLICENSED", deny).status).toBe(
			"denied",
		);
		expect(evaluateLicense("GPL-3.0 OR UNLICENSED", deny).status).toBe(
			"unknown",
		);
		expect(evaluateLicense("MPL-2.0 OR UNLICENSED", allow).status).toBe(
			"unknown",
		);
	});

	test("WITH: an entry for the exact exception wins over the base licence", () => {
		expect(
			evaluateLicense("GPL-2.0-only WITH Classpath-exception-2.0", both).status,
		).toBe("ok");
		expect(evaluateLicense("GPL-2.0-only", both).status).toBe("denied");
		// Otherwise the base licence decides.
		expect(
			evaluateLicense("GPL-3.0-only WITH GCC-exception-3.1", deny),
		).toEqual({
			status: "denied",
			culprits: ["GPL-3.0-only WITH GCC-exception-3.1"],
		});
		expect(
			evaluateLicense("Apache-2.0 WITH LLVM-exception", allow).status,
		).toBe("ok");
	});

	test("or-later and + match entries for their base version", () => {
		const onlyDeny = compileLicensePolicy({ deny: ["GPL-2.0-only"] });
		expect(evaluateLicense("GPL-2.0-or-later", onlyDeny).status).toBe("denied");
		const onlyAllow = compileLicensePolicy({ allow: ["GPL-2.0"] });
		expect(evaluateLicense("GPL-2.0+", onlyAllow).status).toBe("ok");
		const apache = compileLicensePolicy({ allow: ["Apache-1.0"] });
		expect(evaluateLicense("Apache-1.0+", apache).status).toBe("ok");
	});

	test("missing, proprietary and unparseable licences are unknown", () => {
		for (const raw of [
			"",
			"UNLICENSED",
			"NOASSERTION",
			"NONE",
			"SEE LICENSE IN LICENSE.md",
			"LicenseRef-Proprietary",
			"(MIT",
		])
			expect(evaluateLicense(raw, deny).status).toBe("unknown");
		expect(evaluateLicense("SEE LICENSE IN LICENSE.md", deny).culprits).toEqual(
			["SEE LICENSE IN LICENSE.md"],
		);
	});

	test("a policy can name non-SPDX values explicitly", () => {
		const policy = compileLicensePolicy({
			allow: ["LicenseRef-Acme-Commercial"],
			deny: ["UNLICENSED"],
		});
		expect(evaluateLicense("LicenseRef-Acme-Commercial", policy).status).toBe(
			"ok",
		);
		expect(evaluateLicense("UNLICENSED", policy).status).toBe("denied");
	});

	test("allow-all with a deny list", () => {
		const policy = compileLicensePolicy({ allow: ["*"], deny: ["SSPL-*"] });
		expect(evaluateLicense("SSPL-1.0", policy).status).toBe("denied");
		expect(evaluateLicense("Anything-1.0", policy).status).toBe("ok");
	});

	test("rejects entries that are expressions", () => {
		expect(() => compileLicensePolicy({ deny: ["MIT OR GPL-3.0"] })).toThrow(
			/single licence id/,
		);
		expect(() => compileLicensePolicy({ allow: [""] })).toThrow(
			/single licence id/,
		);
	});
});
