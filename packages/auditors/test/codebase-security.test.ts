import { describe, expect, test } from "bun:test";

import { scanSecurity, security } from "../src/codebase/security";
import { nonCodeMask } from "../src/codebase/util";
import { fixture, runAuditor } from "./helpers";

const rulesIn = (
	findings: ReadonlyArray<{ ruleId: string; location?: { file?: string } }>,
	file: string,
) =>
	findings
		.filter((f) => f.location?.file === file)
		.map((f) => f.ruleId.replace("code.security/", ""))
		.sort();

describe("code.security", () => {
	test("flags vulnerable patterns across languages and skips safe code and tests", async () => {
		const report = await runAuditor(security, fixture("codebase", "security"));
		const findings = report.results.flatMap((r) => r.findings);
		expect(report.results[0]?.status).toBe("failed");

		expect(rulesIn(findings, "src/server.js")).toEqual([
			"cleartext-http-endpoint",
			"code-injection",
			"command-injection",
			"cors-wildcard-credentials",
			"insecure-random",
			"open-redirect",
			"path-traversal",
			"sql-injection",
			"tls-verification-disabled",
			"weak-hash",
			"weak-password-hash",
			"xss",
		]);
		expect(rulesIn(findings, "src/app.py")).toEqual([
			"command-injection",
			"debug-mode-enabled",
			"insecure-deserialization",
			"insecure-deserialization",
			"open-redirect",
			"sql-injection",
			"tls-verification-disabled",
		]);
		expect(rulesIn(findings, "src/main.go")).toEqual([
			"sql-injection",
			"tls-verification-disabled",
		]);
		expect(rulesIn(findings, "src/index.php")).toEqual([
			"insecure-deserialization",
			"path-traversal",
			"sql-injection",
		]);
		expect(rulesIn(findings, "src/safe.ts")).toEqual([]);
		expect(rulesIn(findings, "tests/server.test.js")).toEqual([]);
	});

	test("maps findings to CWE and OWASP with locations", () => {
		const [f] = scanSecurity({
			path: "a.js",
			text: "\nconst x = eval(input);\n",
		});
		expect(f?.ruleId).toBe("code.security/code-injection");
		expect(f?.location).toEqual({ file: "a.js", line: 2 });
		expect(f?.tags).toEqual(["cwe-95", "owasp-a03"]);
		expect(f?.references?.[0]).toBe(
			"https://cwe.mitre.org/data/definitions/95.html",
		);
	});

	test("ignores matches inside strings, comments and regex literals", () => {
		const text = [
			'const doc = "never call eval(x) here";',
			"const md = `",
			"  avoid rejectUnauthorized: false in prod",
			"`;",
			"/* InsecureSkipVerify: true */",
			"const re = /eval\\(/g;",
		].join("\n");
		expect(scanSecurity({ path: "a.ts", text })).toEqual([]);
	});

	test("yaml.load with SafeLoader on a continuation line is safe", () => {
		const text =
			"data = yaml.load(\n    stream,\n    Loader=yaml.SafeLoader,\n)\n";
		expect(scanSecurity({ path: "a.py", text })).toEqual([]);
	});

	test("string mask keeps template expressions as code", () => {
		const text = ["const s = `a $", "{eval(x)} b`;"].join("");
		const mask = nonCodeMask(text, "js");
		expect(mask[text.indexOf("eval")]).toBe(0);
		expect(mask[text.indexOf("a $")]).toBe(1);
	});

	test("evidence never contains credentials from the flagged line", () => {
		const password = ["Hk29x", "Lq7Zp"].join("");
		const text = `const rows = db.query("SELECT * FROM t WHERE id=" + id, "postgres://admin:${password}@db/app");`;
		const findings = scanSecurity({ path: "a.js", text });
		expect(findings.map((f) => f.ruleId)).toEqual([
			"code.security/sql-injection",
		]);
		expect(findings[0]?.evidence).not.toContain(password);
		expect(findings[0]?.evidence).toContain("postgres://admin:");
	});
});
