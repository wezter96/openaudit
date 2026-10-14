import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import {
	type Auditor,
	type AuditorResult,
	correlate,
	Exec,
	type ExecOptions,
	type ExecResult,
	type Finding,
	type FindingInput,
	Http,
	type Report,
	runAudit,
	Workspaces,
} from "@openaudit/core";
import { Effect, Layer } from "effect";

import { webAuditors } from "../src/web";
import { DEFAULT_COMMANDS, parseSslyzeReport, sslyze } from "../src/web/sslyze";
import { certificateFindings } from "../src/web/tls";
import { fixture } from "./helpers";

// Recorded on 2026-10-14 with sslyze 6.3.1 (uv tool install on Debian's
// python3 3.13), `--mozilla_config=disable --json_out=…`, then minified:
// - tls-v1-0, sha1-intermediate, conn-error: the default commands against
//   tls-v1-0.badssl.com:1010, sha1-intermediate.badssl.com and 127.0.0.1:1;
// - cert-*: `--certinfo` (some with `--slow_connection`) against the
//   badssl.com host of the same name;
// - null-ciphers, rc4-ciphers: `--slow_connection --tlsv1 --tlsv1_2` (TLS 1.2
//   timed out);
// - example-ciphers: `--sslv3 --tlsv1_2` against example.com.
const sampleText = (name: string) =>
	readFileSync(fixture("web", "external", `sslyze-${name}.json`), "utf8");
const sample = (name: string): Record<string, unknown> =>
	JSON.parse(sampleText(name));

/** A recorded report with one scan command's result replaced. */
const withResult = (
	name: string,
	key: string,
	result: Record<string, unknown>,
) => {
	const json = sample(name) as {
		server_scan_results: { scan_result: Record<string, unknown> }[];
	};
	const server = json.server_scan_results[0];
	if (server)
		server.scan_result[key] = {
			status: "COMPLETED",
			error_reason: null,
			error_trace: null,
			result,
		};
	return json;
};

const URL_1010 = "https://tls-v1-0.badssl.com:1010/";
// Recordings were made on 2026-10-14.
const NOW = Date.parse("2026-10-14T12:00:00Z");

const runWithExec = (
	auditor: Auditor,
	target: string,
	which: (bin: string) => string | undefined,
	run: (cmd: ReadonlyArray<string>, opts?: ExecOptions) => Promise<ExecResult>,
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
						run: (cmd: ReadonlyArray<string>, opts?: ExecOptions) =>
							Effect.promise(() => run(cmd, opts)),
					}),
				),
			),
		),
	);

const ok = (): ExecResult => ({ code: 0, stdout: "", stderr: "" });
const jsonOut = (cmd: ReadonlyArray<string>) =>
	cmd.find((a) => a.startsWith("--json_out="))?.slice("--json_out=".length) ??
	"";

describe("web.sslyze parser", () => {
	test("reports the protocol ceiling", () => {
		const scan = parseSslyzeReport(sample("tls-v1-0"), URL_1010, NOW);
		expect(scan.connectivityError).toBeUndefined();
		expect(scan.errors).toEqual([]);
		// Certificate valid everywhere; no cipher enumeration by default.
		expect(scan.findings.map((f) => f.ruleId)).toEqual([
			"web.sslyze/tls-1-2-not-supported",
		]);
		const f = scan.findings[0];
		expect(f?.severity).toBe("high");
		expect(f?.category).toBe("security");
		expect(f?.evidence).toBe("highest_tls_version_supported=TLS_1_0");
		// Shared with web.tls/weak-protocol: bare URL, so they merge.
		expect(f?.location).toEqual({ url: URL_1010 });
		expect(f?.tags).toEqual(["tls", "cwe-327", "owasp-a02"]);
		expect(f?.references).toContain(
			"https://wiki.mozilla.org/Security/Server_Side_TLS",
		);
		expect(f?.references).toContain(
			"https://cwe.mitre.org/data/definitions/327.html",
		);
		const tls13 = parseSslyzeReport(
			sample("cert-expired"),
			URL_1010,
			NOW,
		).findings.find((x) => x.ruleId === "web.sslyze/tls-1-3-not-supported");
		expect(tls13?.severity).toBe("low");
		// web.tls has no such check: located at the TLS endpoint.
		expect(tls13?.location).toEqual({
			url: URL_1010,
			selector: "tls:expired.badssl.com:443",
		});
	});

	test("maps certificate validity like web.tls, at the bare URL", () => {
		const rules = (name: string) =>
			parseSslyzeReport(sample(name), "https://x.badssl.com/", NOW)
				.findings.filter((f) => !f.ruleId.includes("tls-1-3"))
				.map((f) => [f.ruleId, f.severity]);
		expect(rules("cert-expired")).toEqual([
			["web.sslyze/certificate-expired", "critical"],
		]);
		expect(rules("cert-wrong-host")).toEqual([
			["web.sslyze/hostname-mismatch", "high"],
		]);
		expect(rules("cert-self-signed")).toEqual([
			["web.sslyze/certificate-self-signed", "high"],
		]);
		expect(rules("cert-untrusted-root")).toEqual([
			["web.sslyze/untrusted-chain", "high"],
		]);
		expect(rules("cert-incomplete-chain")).toEqual([
			["web.sslyze/untrusted-chain", "high"],
		]);

		const [expired] = parseSslyzeReport(
			sample("cert-expired"),
			"https://expired.badssl.com/",
			NOW,
		).findings.filter((f) => f.ruleId.endsWith("certificate-expired"));
		expect(expired?.location).toEqual({ url: "https://expired.badssl.com/" });
		expect(expired?.tags).toEqual(["tls", "cwe-295", "owasp-a02"]);
		expect(expired?.message).toContain("2015-04-12");
		expect(expired?.evidence).toBe(
			"CN=*.badssl.com,OU=PositiveSSL Wildcard,OU=Domain Control Validated; not_valid_after=2015-04-12",
		);
		const wrong = parseSslyzeReport(
			sample("cert-wrong-host"),
			"https://wrong.host.badssl.com/",
			NOW,
		).findings.find((f) => f.ruleId.endsWith("hostname-mismatch"));
		expect(wrong?.evidence).toBe(
			"CN=*.badssl.com; validation failed: leaf certificate has no matching subjectAltName",
		);
	});

	test("warns before the leaf expires", () => {
		// The recorded leaf is valid until 2026-12-28T20:02:55Z.
		const expiring = (now: number) =>
			parseSslyzeReport(sample("tls-v1-0"), URL_1010, now).findings.find(
				(f) => f.ruleId === "web.sslyze/certificate-expiring-soon",
			);
		expect(expiring(NOW)).toBeUndefined();
		expect(expiring(Date.parse("2026-12-10T00:00:00Z"))?.severity).toBe(
			"medium",
		);
		const soon = expiring(Date.parse("2026-12-25T00:00:00Z"));
		expect(soon?.severity).toBe("high");
		expect(soon?.message).toBe(
			"The certificate expires in 3 day(s), on 2026-12-28.",
		);
		expect(
			parseSslyzeReport(
				sample("tls-v1-0"),
				URL_1010,
				Date.parse("2026-09-01T00:00:00Z"),
			).findings.map((f) => f.ruleId),
		).toContain("web.sslyze/certificate-not-yet-valid");
	});

	test("flags SHA-1 signed intermediates", () => {
		const { findings } = parseSslyzeReport(
			sample("sha1-intermediate"),
			"https://sha1-intermediate.badssl.com/",
			NOW,
		);
		const by = Object.fromEntries(findings.map((f) => [f.ruleId, f]));
		expect(Object.keys(by).sort()).toEqual([
			"web.sslyze/certificate-expired",
			"web.sslyze/sha1-signature",
			"web.sslyze/tls-1-3-not-supported",
		]);
		const sha1 = by["web.sslyze/sha1-signature"];
		expect(sha1?.severity).toBe("medium");
		// The leaf is signed with SHA-256.
		expect(sha1?.evidence).toBe(
			"CN=COMODO SSL CA,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB (sha1)",
		);
		expect(sha1?.tags).toEqual(["tls", "cwe-328", "owasp-a02"]);
		for (const f of findings) expect(f.remediation).toBeTruthy();
	});

	test("classifies accepted cipher suites by their worst weakness", () => {
		const nul = parseSslyzeReport(
			sample("null-ciphers"),
			"https://null.badssl.com/",
			NOW,
		);
		const by = Object.fromEntries(nul.findings.map((f) => [f.ruleId, f]));
		const insecure = by["web.sslyze/insecure-cipher-suites"];
		expect(insecure?.severity).toBe("high");
		expect(insecure?.evidence).toStartWith("TLS 1.0: TLS_RSA_WITH_NULL_SHA");
		expect(insecure?.evidence).toContain("TLS_DH_anon_WITH_AES_128_CBC_SHA");
		// NULL/anon suites are not repeated as missing forward secrecy.
		expect(by["web.sslyze/no-forward-secrecy"]).toBeUndefined();
		// TLS 1.0 support is shared with web.tls: bare URL, so they merge.
		expect(by["web.sslyze/tls-1-0-enabled"]?.severity).toBe("medium");
		expect(by["web.sslyze/tls-1-0-enabled"]?.location).toEqual({
			url: "https://null.badssl.com/",
		});
		// The TLS 1.2 enumeration timed out on the recording: logged, not fatal.
		expect(nul.errors).toHaveLength(1);
		expect(nul.errors[0]).toStartWith(
			"tls_1_2_cipher_suites: CONNECTIVITY_ISSUE",
		);

		const rc4 = parseSslyzeReport(
			sample("rc4-ciphers"),
			"https://rc4.badssl.com/",
			NOW,
		);
		expect(
			rc4.findings.find((f) => f.ruleId === "web.sslyze/insecure-cipher-suites")
				?.evidence,
		).toBe("TLS 1.0: TLS_RSA_WITH_RC4_128_SHA, TLS_ECDHE_RSA_WITH_RC4_128_SHA");

		const example = parseSslyzeReport(
			sample("example-ciphers"),
			"https://example.com/",
			NOW,
		);
		expect(
			example.findings.map((f) => [f.ruleId, f.severity, f.evidence]),
		).toEqual([
			[
				"web.sslyze/no-forward-secrecy",
				"low",
				"TLS 1.2: TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_256_CBC_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA",
			],
		]);
	});

	test("maps 3DES and SSL 2.0 suites", () => {
		const suite = (name: string) => ({
			cipher_suite: { name, is_anonymous: false, key_size: 128 },
			ephemeral_key: null,
		});
		const report = withResult("example-ciphers", "tls_1_2_cipher_suites", {
			tls_version_used: "TLS_1_2",
			is_tls_version_supported: true,
			accepted_cipher_suites: [
				suite("TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
				suite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
			],
			rejected_cipher_suites: [],
		});
		const weak = parseSslyzeReport(
			report,
			"https://example.com/",
			NOW,
		).findings;
		expect(weak.map((f) => [f.ruleId, f.severity, f.evidence])).toEqual([
			[
				"web.sslyze/weak-cipher-suites",
				"medium",
				"TLS 1.2: TLS_RSA_WITH_3DES_EDE_CBC_SHA",
			],
		]);

		const ssl = withResult("tls-v1-0", "ssl_2_0_cipher_suites", {
			tls_version_used: "SSL_2_0",
			is_tls_version_supported: true,
			accepted_cipher_suites: [suite("SSL_CK_RC4_128_WITH_MD5")],
			rejected_cipher_suites: [],
		});
		const sslBy = Object.fromEntries(
			parseSslyzeReport(ssl, URL_1010, NOW).findings.map((f) => [f.ruleId, f]),
		);
		expect(sslBy["web.sslyze/sslv2-enabled"]?.severity).toBe("critical");
		// SSL 2.0 suites are covered by sslv2-enabled, not the cipher rules.
		expect(sslBy["web.sslyze/insecure-cipher-suites"]).toBeUndefined();
	});

	test("merges shared checks with web.tls and keeps the rest apart", () => {
		const url = "https://expired.badssl.com/";
		const asFinding = (auditor: string) => (f: FindingInput, i: number) =>
			({ ...f, auditor, fingerprint: `${auditor}-${i}` }) as Finding;
		const tlsFindings = certificateFindings(
			url,
			{
				protocol: "TLSv1",
				authorized: false,
				authorizationError: "CERT_HAS_EXPIRED",
				hostnameError: undefined,
				subject: "*.badssl.com",
				issuer: "COMODO",
				validFrom: new Date("2015-04-09T00:00:00Z"),
				validTo: new Date("2015-04-12T23:59:59Z"),
				selfSigned: false,
			},
			NOW,
		);
		const ssl = withResult("cert-expired", "ssl_2_0_cipher_suites", {
			tls_version_used: "SSL_2_0",
			is_tls_version_supported: true,
			accepted_cipher_suites: [
				{
					cipher_suite: {
						name: "SSL_CK_RC4_128_WITH_MD5",
						is_anonymous: false,
						key_size: 128,
					},
					ephemeral_key: null,
				},
			],
			rejected_cipher_suites: [],
		});
		const sslyzeFindings = parseSslyzeReport(ssl, url, NOW).findings;
		const [tlsResult, sslyzeResult] = correlate([
			{
				auditor: "web.tls",
				status: "failed",
				findings: tlsFindings.map(asFinding("web.tls")),
			},
			{
				auditor: "web.sslyze",
				status: "failed",
				findings: sslyzeFindings.map(asFinding("web.sslyze")),
			},
		] as unknown as AuditorResult[]);
		const tlsExpired = tlsResult?.findings.find(
			(f) => f.ruleId === "web.tls/certificate-expired",
		);
		const sslyzeExpired = sslyzeResult?.findings.find(
			(f) => f.ruleId === "web.sslyze/certificate-expired",
		);
		// Same issue, one kept and one marked duplicate.
		expect(
			[tlsExpired?.duplicateOf, sslyzeExpired?.duplicateOf].filter(Boolean),
		).toHaveLength(1);
		// Endpoint-scoped findings never merge with page-level ones.
		for (const f of sslyzeResult?.findings ?? [])
			if (!f.ruleId.endsWith("certificate-expired"))
				expect(f.duplicateOf).toBeUndefined();
		// A legacy protocol is not a certificate problem (cwe-327, not cwe-295).
		expect(
			tlsResult?.findings.find((f) => f.ruleId === "web.tls/weak-protocol")
				?.duplicateOf,
		).toBeUndefined();

		// ...but it is the same issue as sslyze's protocol ceiling.
		const legacyUrl = "https://tls-v1-0.badssl.com:1010/";
		const [legacyTls, legacySslyze] = correlate([
			{
				auditor: "web.tls",
				status: "failed",
				findings: certificateFindings(
					legacyUrl,
					{
						protocol: "TLSv1",
						authorized: true,
						authorizationError: undefined,
						hostnameError: undefined,
						subject: "*.badssl.com",
						issuer: "R3",
						validFrom: new Date("2026-09-29T20:02:56Z"),
						validTo: new Date("2026-12-28T20:02:55Z"),
						selfSigned: false,
					},
					NOW,
				).map(asFinding("web.tls")),
			},
			{
				auditor: "web.sslyze",
				status: "failed",
				findings: parseSslyzeReport(
					sample("tls-v1-0"),
					legacyUrl,
					NOW,
				).findings.map(asFinding("web.sslyze")),
			},
		] as unknown as AuditorResult[]);
		expect(legacyTls?.findings.map((f) => f.ruleId)).toEqual([
			"web.tls/weak-protocol",
		]);
		expect(legacySslyze?.findings[0]?.ruleId).toBe(
			"web.sslyze/tls-1-2-not-supported",
		);
		expect(
			[
				legacyTls?.findings[0]?.duplicateOf,
				legacySslyze?.findings[0]?.duplicateOf,
			].filter(Boolean),
		).toHaveLength(1);
	});

	test("maps known vulnerabilities with CVE tags that merge with testssl.sh", () => {
		const cases: [string, Record<string, unknown>, string, string, string][] = [
			[
				"heartbleed",
				{ is_vulnerable_to_heartbleed: true },
				"heartbleed",
				"critical",
				"cve-2014-0160",
			],
			[
				"openssl_ccs_injection",
				{ is_vulnerable_to_ccs_injection: true },
				"ccs-injection",
				"high",
				"cve-2014-0224",
			],
			[
				"session_renegotiation",
				{
					supports_secure_renegotiation: false,
					is_vulnerable_to_client_renegotiation_dos: false,
					client_renegotiations_success_count: 0,
				},
				"insecure-renegotiation",
				"high",
				"cve-2009-3555",
			],
			[
				"tls_compression",
				{ supports_compression: true },
				"compression-enabled",
				"medium",
				"cve-2012-4929",
			],
			[
				"robot",
				{ robot_result: "VULNERABLE_STRONG_ORACLE" },
				"robot",
				"high",
				"cve-2017-13099",
			],
		];
		for (const [key, result, rule, severity, cve] of cases) {
			const { findings } = parseSslyzeReport(
				withResult("tls-v1-0", key, result),
				URL_1010,
			);
			const f = findings.find((x) => x.ruleId === `web.sslyze/${rule}`);
			expect(f?.severity).toBe(severity as never);
			expect(f?.tags).toContain(cve);
			expect(f?.references?.[0]).toBe(
				`https://nvd.nist.gov/vuln/detail/${cve.toUpperCase()}`,
			);
		}

		const rest = parseSslyzeReport(
			withResult("tls-v1-0", "tls_fallback_scsv", {
				supports_fallback_scsv: false,
			}),
			URL_1010,
			NOW,
		).findings.map((f) => `${f.ruleId}:${f.severity}`);
		expect(rest).toContain("web.sslyze/no-fallback-scsv:low");
		const reneg = parseSslyzeReport(
			withResult("tls-v1-0", "session_renegotiation", {
				supports_secure_renegotiation: true,
				is_vulnerable_to_client_renegotiation_dos: true,
				client_renegotiations_success_count: 10,
			}),
			URL_1010,
			NOW,
		).findings.find((f) => f.ruleId === "web.sslyze/client-renegotiation");
		expect(reneg?.severity).toBe("medium");
		expect(reneg?.evidence).toBe("client_renegotiations_success_count=10");
		// A weak ROBOT oracle is medium; no oracle is not a finding.
		const weak = (robot: string) =>
			parseSslyzeReport(
				withResult("tls-v1-0", "robot", { robot_result: robot }),
				URL_1010,
				NOW,
			).findings.find((f) => f.ruleId === "web.sslyze/robot")?.severity;
		expect(weak("VULNERABLE_WEAK_ORACLE")).toBe("medium");
		expect(weak("NOT_VULNERABLE_NO_ORACLE")).toBeUndefined();
	});

	test("reports trust-store disagreement only when Mozilla trusts the chain", () => {
		const json = sample("tls-v1-0") as {
			server_scan_results: {
				scan_result: {
					certificate_info: {
						result: {
							certificate_deployments: {
								path_validation_results: {
									trust_store: { name: string };
									was_validation_successful: boolean;
									validation_error: string | null;
								}[];
							}[];
						};
					};
				};
			}[];
		};
		const dep =
			json.server_scan_results[0]?.scan_result.certificate_info.result
				.certificate_deployments[0];
		const stores = dep?.path_validation_results ?? [];
		expect(stores.map((s) => s.trust_store.name)).toContain("Mozilla");
		// The recorded chain validates everywhere.
		expect(stores.every((s) => s.was_validation_successful)).toBe(true);
		const apple = stores.find((s) => s.trust_store.name === "Apple");
		if (apple) {
			apple.was_validation_successful = false;
			apple.validation_error = "validation failed: untrusted root";
		}
		const f = parseSslyzeReport(json, URL_1010, NOW).findings.find(
			(x) => x.ruleId === "web.sslyze/untrusted-in-some-stores",
		);
		expect(f?.severity).toBe("medium");
		expect(f?.evidence).toBe("Apple: validation failed: untrusted root");

		const mozilla = stores.find((s) => s.trust_store.name === "Mozilla");
		if (mozilla) mozilla.was_validation_successful = false;
		expect(
			parseSslyzeReport(json, URL_1010, NOW).findings.map((x) => x.ruleId),
		).not.toContain("web.sslyze/untrusted-in-some-stores");
	});

	test("returns the connectivity error when no handshake succeeds", () => {
		const scan = parseSslyzeReport(sample("conn-error"), "https://x/");
		expect(scan.findings).toEqual([]);
		expect(scan.connectivityError).toBe(
			'sslyze.errors.ServerRejectedConnection: 127.0.0.1:1 -> "Server rejected the connection".',
		);
		expect(parseSslyzeReport({}, "https://x/").connectivityError).toBe(
			"sslyze returned no scan result",
		);
	});
});

describe("web.sslyze auditor", () => {
	test("runs by default on the target's host:port from a temp dir", async () => {
		let cmd: ReadonlyArray<string> = [];
		let cwd: string | undefined;
		const report = await runWithExec(
			sslyze,
			"https://expired.badssl.com:1010/some/page?q=1",
			(bin) => (bin === "sslyze" ? "/opt/uv/bin/sslyze" : undefined),
			async (c, opts) => {
				cmd = c;
				cwd = opts?.cwd;
				await writeFile(jsonOut(c), sampleText("cert-expired"));
				return ok();
			},
		);
		expect(cmd[0]).toBe("/opt/uv/bin/sslyze");
		expect(cmd.at(-1)).toBe("expired.badssl.com:1010");
		expect(cmd).toContain("--mozilla_config=disable");
		expect(
			cmd.filter((a) => /^--[a-z0-9_]+$/.test(a) && a !== "--quiet"),
		).toEqual(DEFAULT_COMMANDS.map((c) => `--${c}`));
		// Cipher suite enumeration and ROBOT are opt-in.
		for (const heavy of ["--tlsv1_2", "--sslv3", "--robot", "--http_headers"])
			expect(cmd).not.toContain(heavy);
		expect(cwd?.startsWith(tmpdir())).toBe(true);
		expect(jsonOut(cmd).startsWith(cwd ?? "?")).toBe(true);
		expect(await stat(cwd ?? "").catch(() => null)).toBeNull(); // cleaned up
		expect(await readFile(jsonOut(cmd)).catch(() => null)).toBeNull();

		const result = report.results[0];
		expect(result?.status).toBe("failed"); // has findings
		expect(result?.findings.map((f) => f.ruleId).sort()).toEqual([
			"web.sslyze/certificate-expired",
			"web.sslyze/tls-1-3-not-supported",
		]);
		// The finding points at the target as given, not at sslyze's view of it.
		expect(result?.findings[0]?.location?.url).toBe(
			"https://expired.badssl.com:1010/some/page?q=1",
		);
		expect(sslyze.defaultEnabled).not.toBe(false);
		expect(sslyze.engine).toBe("external");
		expect(sslyze.network).toBeUndefined();
		expect(webAuditors).toContain(sslyze);
	});

	test("defaults to port 443 and honours settings commands", async () => {
		let cmd: ReadonlyArray<string> = [];
		await runWithExec(
			sslyze,
			"https://rc4.badssl.com/",
			() => "/usr/bin/sslyze",
			async (c) => {
				cmd = c;
				await writeFile(jsonOut(c), sampleText("rc4-ciphers"));
				return ok();
			},
			{
				settings: {
					"web.sslyze": { commands: ["tlsv1", "tlsv1_2", "--evil", "rm"] },
				},
			},
		);
		expect(cmd.at(-1)).toBe("rc4.badssl.com:443");
		expect(cmd).toContain("--tlsv1");
		expect(cmd).toContain("--tlsv1_2");
		expect(cmd).not.toContain("--certinfo");
		expect(cmd.join(" ")).not.toContain("evil");
		expect(cmd.join(" ")).not.toContain("rm");
	});

	test("fails when sslyze cannot connect or writes no report", async () => {
		const refused = await runWithExec(
			sslyze,
			"https://127.0.0.1:1/",
			() => "/usr/bin/sslyze",
			async (c) => {
				await writeFile(jsonOut(c), sampleText("conn-error"));
				return ok();
			},
		);
		expect(refused.results[0]?.status).toBe("error");
		expect(refused.results[0]?.message).toContain(
			"could not connect to 127.0.0.1:1",
		);

		const broken = await runWithExec(
			sslyze,
			"https://example.com/",
			() => "/usr/bin/sslyze",
			async () => ({ code: 2, stdout: "", stderr: "usage: sslyze" }),
		);
		expect(broken.results[0]?.status).toBe("error");
		expect(broken.results[0]?.message).toContain("code 2");
	});

	test("skips http targets and a missing sslyze", async () => {
		const plain = await runWithExec(
			sslyze,
			"http://example.com/",
			(bin) => `/usr/bin/${bin}`,
			() => Promise.reject(new Error("unreachable")),
		);
		expect(plain.results[0]?.status).toBe("skipped");
		expect(plain.results[0]?.message).toContain("https");

		const missing = await runWithExec(
			sslyze,
			"https://example.com/",
			() => undefined,
			() => Promise.reject(new Error("unreachable")),
		);
		expect(missing.results[0]?.status).toBe("skipped");
		expect(missing.results[0]?.message).toContain("uv tool install sslyze");
	});
});
