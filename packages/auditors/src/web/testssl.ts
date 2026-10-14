import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	AuditorError,
	defineAuditor,
	type FindingInput,
	requireUrl,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, cweTags, str } from "../tool";
import { parseUrl, truncate } from "./util";

export interface TestsslEntry {
	readonly id?: string;
	readonly severity?: string;
	readonly finding?: string;
	readonly cve?: string;
	readonly cwe?: string;
}

const DOCS = "https://testssl.sh/";

// OK and INFO entries are dropped; WARN (testssl could not decide) is info.
const SEVERITY: Record<string, Severity> = {
	CRITICAL: "critical",
	HIGH: "high",
	MEDIUM: "medium",
	LOW: "low",
	WARN: "info",
};

/**
 * Covered by the built-in web.tls auditor (legacy TLS 1.0/1.1, leaf
 * certificate expiry, trust and hostname), or not about TLS at all.
 */
const SKIPPED = new Set([
	"TLS1",
	"TLS1_1",
	"cert_expirationStatus",
	"cert_notAfter",
	"cert_chain_of_trust",
	"cert_trust",
	"cert_trust_wildcard",
	"cert_commonName",
	"cert_subjectAltName",
	"DNS_CAArecord",
	"engine_problem",
]);

const INFO: Record<string, { title: string; fix: string }> = {
	SSLv2: {
		title: "SSLv2 is offered",
		fix: "Disable SSLv2 on the server.",
	},
	SSLv3: {
		title: "SSLv3 is offered",
		fix: "Disable SSLv3 on the server (POODLE).",
	},
	TLS1_2: {
		title: "TLS 1.2 is not offered",
		fix: "Enable TLS 1.2 and TLS 1.3 on the server.",
	},
	TLS1_3: {
		title: "TLS 1.3 is not offered",
		fix: "Enable TLS 1.3 on the server.",
	},
	cipherlist_NULL: {
		title: "NULL ciphers are offered",
		fix: "Remove NULL ciphers from the server's cipher list.",
	},
	cipherlist_aNULL: {
		title: "Anonymous (aNULL) ciphers are offered",
		fix: "Remove anonymous ciphers from the server's cipher list.",
	},
	cipherlist_EXPORT: {
		title: "Export-grade ciphers are offered",
		fix: "Remove EXPORT ciphers from the server's cipher list.",
	},
	cipherlist_LOW: {
		title: "Weak (LOW) ciphers are offered",
		fix: "Remove ciphers with 64-bit or smaller keys (e.g. DES).",
	},
	cipherlist_3DES_IDEA: {
		title: "3DES/IDEA ciphers are offered",
		fix: "Remove 3DES and IDEA ciphers (SWEET32).",
	},
	cipherlist_OBSOLETED: {
		title: "Obsolete ciphers are offered",
		fix: "Remove obsolete ciphers and prefer AEAD suites with forward secrecy.",
	},
	cipherlist_STRONG_FS: {
		title: "No strong forward-secret ciphers",
		fix: "Offer ECDHE/DHE with AES-GCM or ChaCha20-Poly1305.",
	},
	OCSP_stapling: {
		title: "OCSP stapling is not offered",
		fix: "Enable OCSP stapling so clients need not contact the CA.",
	},
	BREACH: {
		title: "HTTP compression enables BREACH",
		fix: "Disable HTTP compression for responses that reflect secrets, or mask CSRF tokens per request.",
	},
	BEAST: {
		title: "Vulnerable to BEAST",
		fix: "Disable TLS 1.0 and prefer TLS 1.2+ with AEAD ciphers.",
	},
	LUCKY13: {
		title: "Potentially vulnerable to LUCKY13",
		fix: "Prefer AEAD (GCM/ChaCha20) ciphers over CBC suites.",
	},
	LOGJAM: {
		title: "Vulnerable to Logjam",
		fix: "Use 2048-bit or larger unique DH groups, or ECDHE only.",
	},
	heartbleed: {
		title: "Vulnerable to Heartbleed",
		fix: "Upgrade OpenSSL and rotate keys and credentials.",
	},
	CCS: {
		title: "Vulnerable to CCS injection",
		fix: "Upgrade OpenSSL.",
	},
	ROBOT: {
		title: "Vulnerable to ROBOT",
		fix: "Disable RSA key exchange or update the TLS stack.",
	},
	POODLE_SSL: {
		title: "Vulnerable to POODLE",
		fix: "Disable SSLv3.",
	},
	SWEET32: {
		title: "Vulnerable to SWEET32",
		fix: "Disable 64-bit block ciphers (3DES, IDEA).",
	},
	FREAK: {
		title: "Vulnerable to FREAK",
		fix: "Disable EXPORT ciphers.",
	},
	DROWN: {
		title: "Vulnerable to DROWN",
		fix: "Disable SSLv2 everywhere the key is used.",
	},
	secure_renego: {
		title: "Insecure TLS renegotiation",
		fix: "Upgrade the TLS stack to support RFC 5746 secure renegotiation.",
	},
	secure_client_renego: {
		title: "Client-initiated renegotiation is allowed",
		fix: "Disable client-initiated renegotiation.",
	},
	CRIME_TLS: {
		title: "TLS compression enables CRIME",
		fix: "Disable TLS-level compression.",
	},
	fallback_SCSV: {
		title: "TLS_FALLBACK_SCSV is not supported",
		fix: "Upgrade the TLS stack to support TLS_FALLBACK_SCSV.",
	},
	ticketbleed: {
		title: "Vulnerable to Ticketbleed",
		fix: "Update the F5 BIG-IP firmware or disable session tickets.",
	},
};

const idKey = (id: string) => id.replace(/\s*<#\d+>$/, "");
const infoFor = (id: string) =>
	INFO[id] ?? INFO[id.replace(/[-_](common|prime|CBC).*$/i, "")];

const kebab = (s: string) =>
	s
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, "-")
		.replace(/^-+|-+$/g, "");

/** Maps a testssl.sh flat JSON report to findings. Exported for tests. */
export const parseTestsslReport = (
	json: unknown,
	url?: string,
): FindingInput[] => {
	const findings: FindingInput[] = [];
	const seen = new Set<string>();
	for (const raw of arr(json)) {
		const entry = raw as TestsslEntry;
		const id = str(entry.id);
		const severity = SEVERITY[(entry.severity ?? "").toUpperCase()];
		if (!id || !severity) continue;
		const key = idKey(id);
		// Intermediate certificate entries other than expiry are informational.
		if (SKIPPED.has(key) || /^intermediate_cert_(?!expiration)/.test(key))
			continue;
		const finding = (entry.finding ?? "").replace(/\s+/g, " ").trim();
		// testssl repeats some ids per protocol/IP; one finding per id and text.
		const dedupe = `${id}|${finding}`;
		if (seen.has(dedupe)) continue;
		seen.add(dedupe);
		const info = infoFor(key);
		const cves = (entry.cve ?? "").match(/CVE-\d{4}-\d+/gi) ?? [];
		findings.push({
			ruleId: `web.testssl/${kebab(key)}`,
			title: info?.title ?? truncate(`${key}: ${finding}`, 90),
			severity,
			category: "security",
			message: `testssl.sh reports ${key}: ${truncate(finding || "see testssl.sh output", 200)}`,
			location: { url },
			evidence: finding ? truncate(finding, 200) : undefined,
			remediation:
				info?.fix ??
				"Review the TLS configuration against the Mozilla server-side TLS guidelines.",
			references: [
				...cves.map(
					(c) => `https://nvd.nist.gov/vuln/detail/${c.toUpperCase()}`,
				),
				"https://wiki.mozilla.org/Security/Server_Side_TLS",
				DOCS,
			],
			tags: [
				"tls",
				...cweTags(entry.cwe ? [entry.cwe] : []),
				...cves.map((c) => c.toLowerCase()),
			],
		});
	}
	return findings;
};

/** Deep TLS scan with testssl.sh (protocols, ciphers, known vulnerabilities, server defaults). */
export const testssl = defineAuditor({
	id: "web.testssl",
	title: "testssl.sh deep TLS scan",
	description:
		"Runs testssl.sh against an https target: protocols, cipher categories, server defaults and known TLS vulnerabilities (BEAST, LOGJAM, ROBOT, Heartbleed, ...). Opens hundreds of TLS handshakes to the target and takes minutes, so it is opt-in. Complements web.tls, whose expiry/trust/legacy-protocol checks it does not repeat. Custom headers are not used (no HTTP requests are made except a compression probe).",
	categories: ["security"],
	targets: ["url", "webapp"],
	engine: "external",
	tool: "testssl.sh",
	defaultEnabled: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const url = yield* requireUrl(ctx);
			const parsed = yield* parseUrl(url);
			if (parsed.protocol !== "https:")
				return yield* skip("testssl.sh only applies to https targets");
			const bin =
				(yield* ctx.exec.which("testssl.sh")) ??
				(yield* ctx.exec.which("testssl"));
			if (!bin)
				return yield* skip(
					"testssl.sh not found on PATH. Install: brew install testssl (https://testssl.sh/).",
				);
			const dir = yield* Effect.promise(() =>
				mkdtemp(join(tmpdir(), "openaudit-testssl-")),
			);
			const out = join(dir, "report.json");
			const hostPort = `${parsed.hostname}:${parsed.port || "443"}`;
			return yield* Effect.gen(function* () {
				const res = yield* ctx.exec.run(
					[
						bin,
						"--protocols",
						"--server-defaults",
						"--vulnerable",
						"--std",
						"--jsonfile",
						out,
						"--quiet",
						"--warnings",
						"off",
						"--color",
						"0",
						"--ip",
						"one",
						hostPort,
					],
					{ cwd: dir, timeoutMs: 15 * 60_000 },
				);
				const text = yield* Effect.promise(() =>
					readFile(out, "utf8").catch(() => ""),
				);
				// Exit codes 240+ are testssl.sh fatal errors.
				if (!text.trim() || res.code >= 240)
					return yield* Effect.fail(
						new AuditorError({
							message: `testssl.sh exited with code ${res.code} and no report: ${truncate((res.stderr || res.stdout).trim(), 300)}`,
						}),
					);
				const json = yield* Effect.try({
					try: () => JSON.parse(text) as unknown,
					catch: (cause) =>
						new AuditorError({
							message: "testssl.sh produced invalid JSON output",
							cause,
						}),
				});
				return parseTestsslReport(json, url);
			}).pipe(
				Effect.ensuring(
					Effect.promise(() => rm(dir, { recursive: true, force: true })),
				),
			);
		}),
});
