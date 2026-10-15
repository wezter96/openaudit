import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import {
	type Auditor,
	type AuditorStatus,
	Exec,
	type ExecResult,
	type FindingInput,
	Http,
	type Report,
	runAudit,
	Workspaces,
} from "@openaudit/core";
import { Effect, Layer } from "effect";

import { pa11y, parsePa11yReport } from "../src/web/pa11y";
import { parseTestsslReport, testssl } from "../src/web/testssl";
import { parseZapReport, ZAP_IMAGE, zapBaseline } from "../src/web/zap";
import { fixture } from "./helpers";
import { findingWith, firstResult, must } from "./must";

const sampleText = (name: string) =>
	readFileSync(fixture("web", "external", name), "utf8");
const sample = (name: string): unknown => JSON.parse(sampleText(name));

const runWithExec = (
	auditor: Auditor,
	target: string,
	which: (bin: string) => string | undefined,
	run: (cmd: ReadonlyArray<string>) => Promise<ExecResult>,
	options = {},
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
						run: (cmd: ReadonlyArray<string>) => Effect.promise(() => run(cmd)),
					}),
				),
			),
		),
	);

const ok = (stdout = ""): ExecResult => ({ code: 0, stdout, stderr: "" });
const unreachable = () => Promise.reject(new Error("unreachable"));

/** Findings keyed by rule id. */
const byRule = (findings: ReadonlyArray<FindingInput>) =>
	Object.fromEntries(findings.map((f) => [f.ruleId, f]));

/** The finding for `ruleId`, failing the test when there is none. */
const entry = (by: Record<string, FindingInput>, ruleId: string) =>
	must(by[ruleId], `a ${ruleId} finding`);

/** The report's single result has `status` and a message containing `part`. */
const expectResult = (report: Report, status: AuditorStatus, part: string) => {
	const result = firstResult(report);
	expect(result.status).toBe(status);
	expect(result.message).toContain(part);
};

/** A fake Docker whose ZAP scan writes the recorded report into its mount. */
const fakeZap =
	(onScan: (cmd: ReadonlyArray<string>) => void) =>
	async (c: ReadonlyArray<string>): Promise<ExecResult> => {
		if (c[1] === "info") return ok();
		onScan(c);
		const mount = c[c.indexOf("-v") + 1] ?? "";
		const dir = mount.split(":")[0] ?? "";
		await writeFile(`${dir}/report.json`, sampleText("zap-baseline.json"));
		return { code: 2, stdout: "", stderr: "" };
	};

/** Every finding has a remediation and none is an "ok" result. */
const expectActionable = (findings: ReadonlyArray<FindingInput>) => {
	for (const f of findings) {
		expect(f.remediation).toBeTruthy();
		expect(["ok", "info"].includes(f.severity) && f.severity !== "info").toBe(
			false,
		);
	}
};

describe("web.pa11y", () => {
	test("groups axe and HTML_CodeSniffer issues by rule", () => {
		const findings = parsePa11yReport(sample("pa11y.json"), "http://x/");
		const by = byRule(findings);

		const button = entry(by, "web.pa11y/axe-button-name");
		expect(button.severity).toBe("high"); // axe impact: critical
		expect(button.title).toBe("Buttons must have discernible text");
		expect(button.location).toEqual({
			url: "http://x/",
			selector: "html > body > form > button",
		});
		expect(button.references?.[0]).toContain("dequeuniversity.com/rules/axe");
		expect(button.tags).toContain("axe-impact-critical");
		expect(button.message).not.toContain("dequeuniversity");

		expect(entry(by, "web.pa11y/axe-document-title").severity).toBe("medium");
		expect(entry(by, "web.pa11y/axe-heading-order").severity).toBe("low");
		// Several elements of one rule collapse into one finding.
		const region = entry(by, "web.pa11y/axe-region");
		expect(region.evidence).toContain("elements");
		expect(
			findings.filter((f) => f.ruleId.endsWith("axe-region")),
		).toHaveLength(1);
		// axe could not decide: not a confirmed failure.
		expect(entry(by, "web.pa11y/axe-frame-tested").severity).toBe("low");

		const h37 = entry(by, "web.pa11y/htmlcs-1-1-1-h37");
		expect(h37.severity).toBe("medium");
		expect(h37.category).toBe("accessibility");
		expect(h37.tags).toEqual(["htmlcs", "wcag2aa", "wcag-1.1.1"]);
		expect(h37.references).toEqual([
			"https://www.w3.org/TR/WCAG20-TECHS/H37.html",
		]);
		// Notices are info.
		const notice = entry(by, "web.pa11y/htmlcs-1-1-1-g73-g74");
		expect(notice.severity).toBe("info");
		expect(notice.references).toEqual([
			"https://www.w3.org/TR/WCAG20-TECHS/G73.html",
			"https://www.w3.org/TR/WCAG20-TECHS/G74.html",
		]);
		expect(parsePa11yReport([])).toEqual([]);
		expect(parsePa11yReport("nope")).toEqual([]);
	});

	test("runs pa11y from a clean directory and accepts exit code 2", async () => {
		let cmd: ReadonlyArray<string> = [];
		const report = await runWithExec(
			pa11y,
			"http://127.0.0.1:9/",
			(bin) => `/usr/local/bin/${bin}`,
			async (c) => {
				cmd = c;
				return { code: 2, stdout: sampleText("pa11y.json"), stderr: "" };
			},
		);
		expect(cmd.slice(1, 3)).toEqual(["--reporter", "json"]);
		expect(cmd).toContain("--include-warnings");
		expect(cmd.at(-1)).toBe("http://127.0.0.1:9/");
		const result = firstResult(report);
		expect(result.status).toBe("failed");
		expect(result.findings.length).toBeGreaterThan(10);
	});

	test("reports tool failures and skips when pa11y is missing", async () => {
		const failed = await runWithExec(
			pa11y,
			"http://127.0.0.1:9/",
			(bin) => `/usr/local/bin/${bin}`,
			async () => ({
				code: 1,
				stdout: "",
				stderr: "net::ERR_CONNECTION_REFUSED",
			}),
		);
		expectResult(failed, "error", "ERR_CONNECTION_REFUSED");

		const skipped = await runWithExec(
			pa11y,
			"http://127.0.0.1:9/",
			() => undefined,
			unreachable,
		);
		expectResult(skipped, "skipped", "npm i -g pa11y");
		expect(pa11y.defaultEnabled).not.toBe(false);
	});
});

describe("web.zap-baseline", () => {
	test("maps ZAP alerts to findings and restores the original host", () => {
		const findings = parseZapReport(sample("zap-baseline.json") as never, {
			from: "host.docker.internal",
			to: "127.0.0.1",
		});
		const csrf = findingWith(
			findings,
			"web.zap-baseline/10202-absence-of-anti-csrf-tokens",
		);
		expect(csrf.severity).toBe("medium");
		expect(csrf.confidence).toBe("low");
		expect(must(csrf.location, "its location").url).toBe(
			"http://127.0.0.1:8765/",
		);
		expect(csrf.evidence).toContain("<form");
		expect(csrf.tags).toEqual(["cwe-352", "wasc-9"]);
		expect(csrf.remediation).not.toContain("<p>");
		expect(csrf.references).toContain(
			"https://www.zaproxy.org/docs/alerts/10202/",
		);
		expect(JSON.stringify(findings)).not.toContain("host.docker.internal");

		const csp = findings.filter((f) => f.title.startsWith("Content Security"));
		expect(csp.length).toBe(3);
		expect(new Set(csp.map((f) => f.location?.url)).size).toBe(3);
		const info = must(
			findings.find((f) => f.title === "Storable and Cacheable Content"),
			"the cacheable content finding",
		);
		expect(info.severity).toBe("info");
		// Same pluginid, different alert names stay distinct rules.
		const rules = new Set(findings.map((f) => f.ruleId));
		expect(
			rules.has(
				"web.zap-baseline/90004-cross-origin-opener-policy-header-missing-or-invalid",
			),
		).toBe(true);
		expect(
			rules.has(
				"web.zap-baseline/90004-cross-origin-embedder-policy-header-missing-or-invalid",
			),
		).toBe(true);
		expect(parseZapReport({})).toEqual([]);
	});

	test("runs the pinned image through Docker with the host alias for localhost", async () => {
		let cmd: ReadonlyArray<string> = [];
		const report = await runWithExec(
			zapBaseline,
			"http://localhost:8765/",
			(bin) => (bin === "docker" ? "/usr/local/bin/docker" : undefined),
			fakeZap((c) => {
				cmd = c;
			}),
		);
		expect(cmd).toContain(ZAP_IMAGE);
		expect(cmd).toContain("--add-host=host.docker.internal:host-gateway");
		expect(cmd[cmd.indexOf("-t") + 1]).toBe(
			"http://host.docker.internal:8765/",
		);
		expect(cmd).toContain("-I");
		expect(cmd).not.toContain("zap-full-scan.py");
		const result = firstResult(report);
		expect(result.status).toBe("failed");
		const urls = result.findings.map((f) => f.location?.url ?? "");
		expect(urls.every((u) => u.startsWith("http://localhost:8765"))).toBe(true);
		expect(zapBaseline.defaultEnabled).toBe(false);
	});

	test("skips when the Docker daemon is down or nothing is installed", async () => {
		const down = await runWithExec(
			zapBaseline,
			"https://example.com/",
			(bin) => (bin === "docker" ? "/usr/local/bin/docker" : undefined),
			async () => ({ code: 1, stdout: "", stderr: "Cannot connect" }),
		);
		expectResult(down, "skipped", "daemon is not running");

		const none = await runWithExec(
			zapBaseline,
			"https://example.com/",
			() => undefined,
			unreachable,
		);
		expectResult(none, "skipped", "docker");
	});
});

describe("web.testssl", () => {
	test("keeps real TLS weaknesses and drops what web.tls covers", () => {
		const findings = parseTestsslReport(
			sample("testssl.json"),
			"https://tls-v1-0.badssl.com:1010/",
		);
		const by = byRule(findings);
		const logjam = entry(by, "web.testssl/logjam-common-primes");
		expect(logjam.severity).toBe("high");
		expect(logjam.tags).toEqual(["tls", "cwe-310", "cve-2015-4000"]);
		expect(logjam.references).toContain(
			"https://nvd.nist.gov/vuln/detail/CVE-2015-4000",
		);
		expect(entry(by, "web.testssl/beast").severity).toBe("medium");
		expect(entry(by, "web.testssl/breach").category).toBe("security");
		expect(
			entry(by, "web.testssl/cipherlist-obsoleted".replace(" ", "")).severity,
		).toBe("low");
		// Legacy TLS 1.0/1.1, wildcard trust, DNS CAA and local openssl notes are not reported.
		for (const id of [
			"tls1",
			"tls1-1",
			"cert-trust-wildcard",
			"dnscaarecord",
			"dns-caarecord",
			"engine-problem",
		])
			expect(by[`web.testssl/${id}`]).toBeUndefined();
		expectActionable(findings);
	});

	test("does not repeat the leaf certificate checks of web.tls", () => {
		const findings = parseTestsslReport(sample("testssl-expired.json"));
		const rules = findings.map((f) => f.ruleId);
		expect(rules).not.toContain("web.testssl/cert-expirationstatus");
		expect(rules).not.toContain("web.testssl/cert-chain-of-trust");
		expect(rules).toContain("web.testssl/intermediate-cert-expiration");
		expect(rules).toContain("web.testssl/ocsp-stapling");
		expect(
			must(
				findings.find((f) => f.ruleId.endsWith("ocsp-stapling")),
				"the OCSP stapling finding",
			).severity,
		).toBe("low");
		const [warning] = parseTestsslReport([
			{ id: "x", severity: "WARN", finding: "could not test" },
		]);
		expect(must(warning, "the warning finding").severity).toBe("info");
	});

	test("runs testssl.sh against host:port and reads its JSON file", async () => {
		let cmd: ReadonlyArray<string> = [];
		const report = await runWithExec(
			testssl,
			"https://tls-v1-0.badssl.com:1010/page",
			(bin) => (bin === "testssl" ? "/usr/local/bin/testssl" : undefined),
			async (c) => {
				cmd = c;
				await writeFile(
					c[c.indexOf("--jsonfile") + 1] ?? "",
					sampleText("testssl.json"),
				);
				return ok();
			},
		);
		expect(cmd[0]).toBe("/usr/local/bin/testssl");
		expect(cmd.at(-1)).toBe("tls-v1-0.badssl.com:1010");
		expect(cmd).toContain("--vulnerable");
		const out = cmd[cmd.indexOf("--jsonfile") + 1] ?? "";
		expect(await readFile(out).catch(() => null)).toBeNull(); // cleaned up
		expect(firstResult(report).status).toBe("failed");
		expect(testssl.defaultEnabled).toBe(false);
	});

	test("skips for http targets and when testssl is missing", async () => {
		const plain = await runWithExec(
			testssl,
			"http://example.com/",
			(bin) => `/usr/local/bin/${bin}`,
			unreachable,
		);
		expectResult(plain, "skipped", "https");

		const missing = await runWithExec(
			testssl,
			"https://example.com/",
			() => undefined,
			unreachable,
		);
		expectResult(missing, "skipped", "Install");
	});
});
