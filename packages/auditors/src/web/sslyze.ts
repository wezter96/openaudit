import { readFile } from "node:fs/promises";
import { join } from "node:path";
import {
	type AuditContext,
	AuditorError,
	defineAuditor,
	type FindingInput,
	requireUrl,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { isRecord } from "../codebase/util";
import { arr, num, parseJson, str, withTempDir } from "../tool";
import { parseUrl, truncate } from "./util";

const ID = "web.sslyze";
const MOZILLA_TLS = "https://wiki.mozilla.org/Security/Server_Side_TLS";
const DOCS =
	"https://nabla-c0d3.github.io/sslyze/documentation/available-scan-commands.html";
const DAY = 86_400_000;

/**
 * sslyze scan commands (CLI flags without the dashes) this wrapper reads, with
 * the TLS connections each opened against example.com and badssl.com hosts
 * (sslyze 6.3.1, on top of ~2 for the connectivity check). Cipher suite
 * enumeration tries every suite OpenSSL knows, one handshake each, so it is
 * opt-in, as is ROBOT, which sends malformed RSA key exchanges.
 */
export const SSLYZE_COMMANDS = [
	"certinfo", // ~4
	"sslv2", // ~7
	"heartbleed", // ~1
	"openssl_ccs", // ~1
	"reneg", // ~2
	"fallback", // ~1
	"compression", // ~1
	"tlsv1_3", // ~5
	"robot", // ~20
	"sslv3", // ~120
	"tlsv1", // ~125
	"tlsv1_1", // ~130
	"tlsv1_2", // ~175
] as const;

export type SslyzeCommand = (typeof SSLYZE_COMMANDS)[number];

/** 20–35 TLS connections, about a second against a responsive host. */
export const DEFAULT_COMMANDS: ReadonlyArray<SslyzeCommand> = [
	"certinfo",
	"sslv2",
	"heartbleed",
	"openssl_ccs",
	"reneg",
	"fallback",
	"compression",
];

/**
 * Setting `settings["web.sslyze"].commands`: the scan commands to run instead
 * of the defaults, e.g. the defaults plus `"sslv3", "tlsv1", "tlsv1_1",
 * "tlsv1_2", "robot"` for cipher suite enumeration and ROBOT. Unknown names
 * are ignored.
 */
export const commandsOf = (ctx: AuditContext): ReadonlyArray<SslyzeCommand> => {
	const value = ctx.options.settings?.[ID]?.commands;
	if (!Array.isArray(value)) return DEFAULT_COMMANDS;
	const picked = SSLYZE_COMMANDS.filter((c) => value.includes(c));
	return picked.length > 0 ? picked : DEFAULT_COMMANDS;
};

interface Rule {
	readonly severity: Severity;
	readonly title: string;
	readonly message: string;
	readonly fix: string;
	readonly cwe: number;
	readonly cves?: ReadonlyArray<string>;
	/**
	 * Repeats a web.tls check: located at the bare URL with web.tls's CWE so
	 * correlation merges the two reports.
	 */
	readonly shared?: boolean;
}

const RULES = {
	"certificate-expired": {
		severity: "critical",
		title: "TLS certificate has expired",
		message:
			"The certificate has expired; browsers show a full-page warning and clients refuse to connect.",
		fix: "Renew the certificate and automate renewal (e.g. ACME/Let's Encrypt).",
		cwe: 295,
		shared: true,
	},
	"certificate-expiring-soon": {
		severity: "medium",
		title: "TLS certificate expires soon",
		message: "The certificate expires within 30 days.",
		fix: "Renew the certificate now and automate renewal with monitoring.",
		cwe: 295,
		shared: true,
	},
	"certificate-not-yet-valid": {
		severity: "high",
		title: "TLS certificate is not yet valid",
		message: "The certificate's validity period has not started.",
		fix: "Check the server clock and the certificate validity period.",
		cwe: 295,
		shared: true,
	},
	"certificate-self-signed": {
		severity: "high",
		title: "TLS certificate is self-signed",
		message:
			"The certificate is not issued by a trusted CA, so browsers warn and users learn to click through warnings (enabling MITM).",
		fix: "Use a certificate from a publicly trusted CA (e.g. Let's Encrypt).",
		cwe: 295,
		shared: true,
	},
	"hostname-mismatch": {
		severity: "high",
		title: "TLS certificate does not match the hostname",
		message: "The certificate's subjectAltName does not cover this host.",
		fix: "Issue a certificate whose subjectAltName covers this hostname.",
		cwe: 295,
		shared: true,
	},
	"untrusted-chain": {
		severity: "high",
		title: "TLS certificate chain is not trusted",
		message:
			"The chain does not validate against Mozilla's trust store (missing intermediates, unknown root or invalid certificate).",
		fix: "Serve the full chain (leaf + intermediates) from a publicly trusted CA.",
		cwe: 295,
		shared: true,
	},
	"tls-1-0-enabled": {
		severity: "medium",
		title: "Server still accepts TLS 1.0",
		message:
			"TLS 1.0 is deprecated (RFC 8996) and enables downgrade attacks for old clients.",
		fix: "Disable TLS 1.0 and 1.1; allow only TLS 1.2 and 1.3.",
		cwe: 327,
		shared: true,
	},
	"tls-1-1-enabled": {
		severity: "medium",
		title: "Server still accepts TLS 1.1",
		message:
			"TLS 1.1 is deprecated (RFC 8996) and enables downgrade attacks for old clients.",
		fix: "Disable TLS 1.0 and 1.1; allow only TLS 1.2 and 1.3.",
		cwe: 327,
		shared: true,
	},
	"sslv2-enabled": {
		severity: "critical",
		title: "SSL 2.0 is enabled",
		message:
			"The server accepts SSL 2.0 handshakes. SSL 2.0 is broken (RFC 6176) and lets attackers decrypt TLS sessions that share the key (DROWN).",
		fix: "Disable SSL 2.0 on every server that uses this certificate's key.",
		cwe: 327,
	},
	"sslv3-enabled": {
		severity: "high",
		title: "SSL 3.0 is enabled",
		message:
			"The server accepts SSL 3.0 handshakes. SSL 3.0 is deprecated (RFC 7568) and its CBC padding is broken (POODLE).",
		fix: "Disable SSL 3.0; support TLS 1.2 and 1.3 only.",
		cwe: 327,
	},
	"tls-1-2-not-supported": {
		severity: "high",
		title: "TLS 1.2 is not supported",
		message:
			"The server's highest protocol is older than TLS 1.2, so every client connects over a deprecated protocol (RFC 8996).",
		fix: "Enable TLS 1.2 and TLS 1.3.",
		cwe: 327,
		// web.tls/weak-protocol: the best protocol a client can negotiate is legacy.
		shared: true,
	},
	"tls-1-3-not-supported": {
		severity: "low",
		title: "TLS 1.3 is not supported",
		message:
			"The server's highest protocol is TLS 1.2. TLS 1.3 removes legacy algorithms and needs fewer round trips.",
		fix: "Enable TLS 1.3 alongside TLS 1.2.",
		cwe: 327,
	},
	"insecure-cipher-suites": {
		severity: "high",
		title: "Insecure cipher suites are accepted",
		message:
			"The server accepts NULL, anonymous, EXPORT, RC4, RC2, DES or MD5 cipher suites, which give no or easily broken encryption or authentication.",
		fix: "Remove these suites; offer only AEAD suites with ECDHE key exchange (Mozilla intermediate configuration).",
		cwe: 327,
	},
	"weak-cipher-suites": {
		severity: "medium",
		title: "64-bit block cipher suites are accepted",
		message:
			"The server accepts 3DES or IDEA suites, whose 64-bit blocks allow plaintext recovery from long-lived connections (SWEET32).",
		fix: "Remove 3DES and IDEA suites from the server's cipher list.",
		cwe: 327,
	},
	"no-forward-secrecy": {
		severity: "low",
		title: "Cipher suites without forward secrecy are accepted",
		message:
			"The server accepts suites with static RSA or DH key exchange, so a later key compromise decrypts recorded traffic.",
		fix: "Prefer ECDHE (or DHE) key exchange and drop static RSA suites.",
		cwe: 326,
	},
	heartbleed: {
		severity: "critical",
		title: "Vulnerable to Heartbleed",
		message:
			"The server returns memory beyond a heartbeat request, leaking private keys, session cookies and passwords.",
		fix: "Upgrade OpenSSL, then replace the private key, revoke the certificate and rotate credentials.",
		cwe: 125,
		cves: ["CVE-2014-0160"],
	},
	"ccs-injection": {
		severity: "high",
		title: "Vulnerable to OpenSSL CCS injection",
		message:
			"The server accepts an early ChangeCipherSpec, letting a network attacker force weak keys and decrypt or modify traffic.",
		fix: "Upgrade OpenSSL.",
		cwe: 326,
		cves: ["CVE-2014-0224"],
	},
	"insecure-renegotiation": {
		severity: "high",
		title: "Insecure TLS renegotiation",
		message:
			"The server does not support secure renegotiation (RFC 5746), so an attacker can splice their own request into a victim's session.",
		fix: "Upgrade the TLS stack so it supports RFC 5746 secure renegotiation.",
		cwe: 310,
		cves: ["CVE-2009-3555"],
	},
	"client-renegotiation": {
		severity: "medium",
		title: "Client-initiated renegotiation is allowed",
		message:
			"Clients may renegotiate repeatedly on one connection, which costs the server far more CPU than the client (denial of service).",
		fix: "Disable client-initiated renegotiation.",
		cwe: 400,
	},
	"no-fallback-scsv": {
		severity: "low",
		title: "TLS_FALLBACK_SCSV is not supported",
		message:
			"The server ignores the downgrade signal (RFC 7507), so clients that retry with older protocols can be forced onto a weaker one.",
		fix: "Upgrade the TLS stack, or disable protocols older than TLS 1.2 so there is nothing to fall back to.",
		cwe: 757,
	},
	"compression-enabled": {
		severity: "medium",
		title: "TLS compression is enabled",
		message:
			"Compressing before encryption leaks secrets such as session cookies through response sizes (CRIME).",
		fix: "Disable TLS-level compression.",
		cwe: 310,
		cves: ["CVE-2012-4929"],
	},
	robot: {
		severity: "high",
		title: "Vulnerable to ROBOT",
		message:
			"The server's RSA key exchange acts as a Bleichenbacher padding oracle, letting an attacker decrypt recorded sessions or sign with the server key.",
		fix: "Disable RSA key exchange suites or update the TLS stack.",
		cwe: 203,
		cves: ["CVE-2017-13099"],
	},
	"md5-signature": {
		severity: "high",
		title: "Certificate chain signed with MD5",
		message:
			"A certificate the server sends is signed with MD5, which allows forged certificates through hash collisions.",
		fix: "Reissue the certificate (and use intermediates) signed with SHA-256 or better.",
		cwe: 328,
	},
	"sha1-signature": {
		severity: "medium",
		title: "Certificate chain signed with SHA-1",
		message:
			"A certificate the server sends is signed with SHA-1. Browsers reject SHA-1 signatures, and SHA-1 collisions are practical.",
		fix: "Reissue the certificate and serve intermediates signed with SHA-256 or better.",
		cwe: 328,
	},
	"weak-certificate-key": {
		severity: "high",
		title: "Certificate uses a weak key",
		message:
			"A certificate's public key is shorter than 2048-bit RSA/DSA or 224-bit ECC, which is within reach of factoring or discrete-log attacks.",
		fix: "Reissue the certificate with an RSA 2048+ or ECDSA P-256 key.",
		cwe: 326,
	},
	"chain-order-invalid": {
		severity: "low",
		title: "Certificate chain is sent out of order",
		message:
			"The server does not send its certificates leaf first, each followed by its issuer (as TLS 1.2 requires, RFC 5246 §7.4.2), which strict clients reject.",
		fix: "Serve the chain in order: leaf, then each intermediate.",
		cwe: 295,
	},
	"must-staple-not-stapled": {
		severity: "high",
		title: "OCSP Must-Staple certificate without a stapled response",
		message:
			"The certificate requires OCSP stapling (TLS Feature extension), but the server sent no OCSP response, so browsers that enforce Must-Staple refuse the connection.",
		fix: "Enable OCSP stapling on the server, or reissue the certificate without Must-Staple.",
		cwe: 295,
	},
	"legacy-symantec-anchor": {
		severity: "high",
		title: "Certificate chains to a distrusted Symantec root",
		message:
			"The chain is anchored at a legacy Symantec root that browsers have distrusted.",
		fix: "Replace the certificate with one from a currently trusted CA.",
		cwe: 295,
	},
	"untrusted-in-some-stores": {
		severity: "medium",
		title: "Certificate is not trusted by every platform",
		message:
			"The chain validates against Mozilla's trust store but not against others (Apple, Android, Java or Windows), so some clients reject it.",
		fix: "Serve the full chain from a CA trusted on all platforms you support.",
		cwe: 295,
	},
} satisfies Record<string, Rule>;

type RuleId = keyof typeof RULES;

const PROTOCOLS: ReadonlyArray<readonly [string, string]> = [
	["ssl_2_0_cipher_suites", "SSL 2.0"],
	["ssl_3_0_cipher_suites", "SSL 3.0"],
	["tls_1_0_cipher_suites", "TLS 1.0"],
	["tls_1_1_cipher_suites", "TLS 1.1"],
	["tls_1_2_cipher_suites", "TLS 1.2"],
];

/** NULL, anonymous, EXPORT, RC4, RC2, single DES and MD5-MAC suites. */
const INSECURE_CIPHER =
	/(^|_)NULL(_|$)|_anon_|EXPORT|_RC4_|_RC2_|(^|_)DES(40)?_CBC_|_MD5$/;
/** 64-bit block ciphers (SWEET32). */
const WEAK_CIPHER = /3DES|_IDEA_/;
/** Static RSA/DH/PSK key exchange: no forward secrecy. */
const NO_FS_CIPHER = /^TLS_(RSA|PSK|RSA_PSK|DH_(RSA|DSS)|ECDH_(RSA|ECDSA))_/;

/** What sslyze reported for the scanned endpoint. Exported for tests. */
export interface SslyzeScan {
	readonly findings: FindingInput[];
	/** Scan commands that errored (timeouts, unexpected server behaviour). */
	readonly errors: string[];
	/** Set when sslyze could not complete a TLS handshake at all. */
	readonly connectivityError?: string;
}

const lastLine = (trace: unknown) =>
	(str(trace) ?? "").trim().split("\n").at(-1) ?? "";

const nameOf = (v: unknown) =>
	isRecord(v) ? (str(v.rfc4514_string) ?? "?") : "?";

const dateOf = (v: unknown) => {
	const t = Date.parse(str(v) ?? "");
	return Number.isNaN(t) ? undefined : t;
};

const day = (t: number) => new Date(t).toISOString().slice(0, 10);

const recordOr = (v: unknown): Record<string, unknown> =>
	isRecord(v) ? v : {};

type ScanRecord = Record<string, unknown>;

interface Hit {
	readonly evidence: Set<string>;
	readonly severity?: Severity;
	readonly message?: string;
}

type HitOverride = Pick<Hit, "severity" | "message">;

/** Scan results being read, plus the errors and evidence collected so far. */
interface ScanState {
	readonly scans: ScanRecord;
	readonly errors: string[];
	/** Evidence per rule, collected across protocols and certificate deployments. */
	readonly hits: Map<RuleId, Hit>;
}

/** The result of one scan command, recording an error when it failed. */
const resultOf = (state: ScanState, key: string): ScanRecord | undefined => {
	const attempt = state.scans[key];
	if (!isRecord(attempt) || attempt.status === "NOT_SCHEDULED")
		return undefined;
	if (attempt.status !== "COMPLETED" || !isRecord(attempt.result)) {
		state.errors.push(
			`${key}: ${str(attempt.error_reason) ?? "error"} ${lastLine(attempt.error_trace)}`.trim(),
		);
		return undefined;
	}
	return attempt.result;
};

const hit = (
	state: ScanState,
	rule: RuleId,
	evidence: string,
	override: HitOverride = {},
) => {
	const entry = state.hits.get(rule) ?? { evidence: new Set<string>() };
	entry.evidence.add(evidence);
	state.hits.set(rule, { ...entry, ...override });
};

/* ------------------------------ protocols ------------------------------ */

const VERSION_RULES: ReadonlyArray<readonly [string, RuleId]> = [
	["SSL 2.0", "sslv2-enabled"],
	["SSL 3.0", "sslv3-enabled"],
	["TLS 1.0", "tls-1-0-enabled"],
	["TLS 1.1", "tls-1-1-enabled"],
];

const suiteName = (accepted: unknown): string[] => {
	const name =
		isRecord(accepted) && isRecord(accepted.cipher_suite)
			? str(accepted.cipher_suite.name)
			: undefined;
	return name ? [name] : [];
};

/** Accepted cipher suite names per supported protocol label. */
const acceptedSuites = (state: ScanState): Map<string, string[]> => {
	const accepted = new Map<string, string[]>();
	for (const [key, label] of PROTOCOLS) {
		const res = resultOf(state, key);
		if (!res) continue;
		const names = arr(res.accepted_cipher_suites).flatMap(suiteName);
		if (res.is_tls_version_supported === true && names.length > 0)
			accepted.set(label, names);
	}
	return accepted;
};

const versionChecks = (state: ScanState, accepted: Map<string, string[]>) => {
	for (const [label, rule] of VERSION_RULES) {
		const names = accepted.get(label);
		if (names) hit(state, rule, `${label} cipher suites: ${names.join(", ")}`);
	}
};

const highestVersionCheck = (state: ScanState, server: ScanRecord) => {
	const highest = str(
		recordOr(server.connectivity_result).highest_tls_version_supported,
	);
	if (highest === "TLS_1_2")
		hit(
			state,
			"tls-1-3-not-supported",
			`highest_tls_version_supported=${highest}`,
		);
	else if (highest && /^(SSL_[23]_0|TLS_1_[01])$/.test(highest))
		hit(
			state,
			"tls-1-2-not-supported",
			`highest_tls_version_supported=${highest}`,
		);
};

// Each suite counts once, under the worst class it falls in.
const classOf = (name: string): RuleId | undefined =>
	INSECURE_CIPHER.test(name)
		? "insecure-cipher-suites"
		: WEAK_CIPHER.test(name)
			? "weak-cipher-suites"
			: NO_FS_CIPHER.test(name)
				? "no-forward-secrecy"
				: undefined;

const cipherChecks = (state: ScanState, accepted: Map<string, string[]>) => {
	for (const [label, names] of accepted) {
		// SSL 2.0 as a whole is already critical.
		if (label === "SSL 2.0") continue;
		const byClass = Map.groupBy(names, classOf);
		for (const [rule, suites] of byClass)
			if (rule) hit(state, rule, `${label}: ${suites.join(", ")}`);
	}
};

const protocolChecks = (state: ScanState, server: ScanRecord) => {
	const accepted = acceptedSuites(state);
	versionChecks(state, accepted);
	highestVersionCheck(state, server);
	cipherChecks(state, accepted);
};

/* ---------------------------- vulnerabilities --------------------------- */

/** A scan result field whose value alone flags a rule. */
interface FlagCheck {
	readonly scan: string;
	readonly field: string;
	readonly flagged: boolean;
	readonly rule: RuleId;
}

const flagCheck = (state: ScanState, check: FlagCheck) => {
	if (resultOf(state, check.scan)?.[check.field] === check.flagged)
		hit(state, check.rule, `${check.field}=${check.flagged}`);
};

const renegotiationChecks = (state: ScanState) => {
	const reneg = resultOf(state, "session_renegotiation");
	if (reneg?.supports_secure_renegotiation === false)
		hit(state, "insecure-renegotiation", "supports_secure_renegotiation=false");
	if (reneg?.is_vulnerable_to_client_renegotiation_dos === true)
		hit(
			state,
			"client-renegotiation",
			`client_renegotiations_success_count=${num(reneg.client_renegotiations_success_count) ?? "?"}`,
		);
};

const robotCheck = (state: ScanState) => {
	const robot = str(resultOf(state, "robot")?.robot_result);
	if (
		robot === "VULNERABLE_STRONG_ORACLE" ||
		robot === "VULNERABLE_WEAK_ORACLE"
	)
		hit(state, "robot", `robot_result=${robot}`, {
			severity: robot === "VULNERABLE_STRONG_ORACLE" ? "high" : "medium",
		});
};

const vulnerabilityChecks = (state: ScanState) => {
	flagCheck(state, {
		scan: "heartbleed",
		field: "is_vulnerable_to_heartbleed",
		flagged: true,
		rule: "heartbleed",
	});
	flagCheck(state, {
		scan: "openssl_ccs_injection",
		field: "is_vulnerable_to_ccs_injection",
		flagged: true,
		rule: "ccs-injection",
	});
	renegotiationChecks(state);
	flagCheck(state, {
		scan: "tls_fallback_scsv",
		field: "supports_fallback_scsv",
		flagged: false,
		rule: "no-fallback-scsv",
	});
	flagCheck(state, {
		scan: "tls_compression",
		field: "supports_compression",
		flagged: true,
		rule: "compression-enabled",
	});
	robotCheck(state);
};

/* ----------------------------- certificates ----------------------------- */

interface Leaf {
	readonly cert: ScanRecord | undefined;
	readonly name: string;
	readonly notAfter: number | undefined;
	readonly notBefore: number | undefined;
	readonly expired: boolean;
	readonly notYet: boolean;
}

const leafOf = (chain: ScanRecord[], now: number): Leaf => {
	const cert = chain[0];
	const notAfter = dateOf(cert?.not_valid_after);
	const notBefore = dateOf(cert?.not_valid_before);
	return {
		cert,
		name: nameOf(cert?.subject),
		notAfter,
		notBefore,
		expired: notAfter !== undefined && notAfter < now,
		notYet: notBefore !== undefined && notBefore > now,
	};
};

const expiringSoon = (
	state: ScanState,
	leaf: Leaf,
	notAfter: number,
	now: number,
) => {
	const days = Math.floor((notAfter - now) / DAY);
	hit(
		state,
		"certificate-expiring-soon",
		`${leaf.name}; not_valid_after=${day(notAfter)}`,
		{
			severity: days < 7 ? "high" : "medium",
			message: `The certificate expires in ${days} day(s), on ${day(notAfter)}.`,
		},
	);
};

const validityChecks = (state: ScanState, leaf: Leaf, now: number) => {
	const { notAfter, notBefore } = leaf;
	if (leaf.expired && notAfter !== undefined)
		hit(
			state,
			"certificate-expired",
			`${leaf.name}; not_valid_after=${day(notAfter)}`,
			{
				message: `The certificate expired on ${day(notAfter)}; browsers show a full-page warning and clients refuse to connect.`,
			},
		);
	else if (notAfter !== undefined && notAfter - now < 30 * DAY)
		expiringSoon(state, leaf, notAfter, now);
	if (leaf.notYet && notBefore !== undefined)
		hit(
			state,
			"certificate-not-yet-valid",
			`${leaf.name}; not_valid_before=${day(notBefore)}`,
		);
};

const storeName = (v: ScanRecord) =>
	isRecord(v.trust_store) ? (str(v.trust_store.name) ?? "?") : "?";

// Drops the "(encountered processing <Certificate(...)>)" suffix.
const validationError = (v: ScanRecord | undefined) =>
	(str(v?.validation_error) ?? "validation failed").replace(
		/\s*\(encountered processing [\s\S]*$/,
		"",
	);

const selfIssued = (cert: ScanRecord) =>
	nameOf(cert.subject) === nameOf(cert.issuer);

const outOfValidity = (leaf: Leaf) => leaf.expired || leaf.notYet;

// Mozilla's store is what web.tls (Node) uses; other platforms may differ.
const otherStoreChecks = (state: ScanState, validations: ScanRecord[]) => {
	for (const v of validations)
		if (v.was_validation_successful === false)
			hit(
				state,
				"untrusted-in-some-stores",
				`${storeName(v)}: ${truncate(validationError(v), 120)}`,
			);
};

const mozillaFailureCheck = (
	state: ScanState,
	chain: ScanRecord[],
	leaf: Leaf,
	error: string,
) => {
	if (/no matching subjectAltName/i.test(error))
		hit(state, "hostname-mismatch", `${leaf.name}; ${truncate(error, 160)}`);
	else if (chain.length === 1 && chain.every(selfIssued))
		hit(
			state,
			"certificate-self-signed",
			`${leaf.name}; issuer=${nameOf(leaf.cert?.issuer)}`,
		);
	// An expired leaf already explains "not valid at validation time".
	else if (
		!(outOfValidity(leaf) && /not valid at validation time/i.test(error))
	)
		hit(state, "untrusted-chain", `Mozilla: ${truncate(error, 200)}`);
};

const trustChecks = (
	state: ScanState,
	dep: ScanRecord,
	chain: ScanRecord[],
	leaf: Leaf,
) => {
	const validations = arr(dep.path_validation_results).filter(isRecord);
	const mozilla = validations.find((v) => storeName(v) === "Mozilla");
	if (mozilla?.was_validation_successful === true)
		otherStoreChecks(state, validations);
	else if (mozilla)
		mozillaFailureCheck(state, chain, leaf, validationError(mozilla));
};

const signatureCheck = (state: ScanState, cert: ScanRecord) => {
	// A self-signed root's own signature is never checked by clients.
	if (selfIssued(cert)) return;
	const hash = isRecord(cert.signature_hash_algorithm)
		? str(cert.signature_hash_algorithm.name)
		: undefined;
	if (hash === "md5" || hash === "sha1")
		hit(state, `${hash}-signature`, `${nameOf(cert.subject)} (${hash})`);
};

const minKeySize = (algorithm: string) =>
	algorithm.startsWith("RSA") || algorithm.startsWith("DSA")
		? 2048
		: algorithm.startsWith("EllipticCurve")
			? 224
			: 0;

const keySizeCheck = (state: ScanState, cert: ScanRecord) => {
	const key = recordOr(cert.public_key);
	const size = num(key.key_size);
	const algorithm = str(key.algorithm) ?? "";
	if (size !== undefined && size < minKeySize(algorithm))
		hit(
			state,
			"weak-certificate-key",
			`${nameOf(cert.subject)}: ${algorithm} ${size} bits`,
		);
};

const mustStapleMissing = (dep: ScanRecord) =>
	dep.leaf_certificate_has_must_staple_extension === true &&
	dep.ocsp_response === null;

const deploymentFlagChecks = (
	state: ScanState,
	dep: ScanRecord,
	leaf: Leaf,
) => {
	if (dep.received_chain_has_valid_order === false)
		hit(state, "chain-order-invalid", "received_chain_has_valid_order=false");
	if (mustStapleMissing(dep))
		hit(state, "must-staple-not-stapled", `${leaf.name}; ocsp_response=null`);
	if (dep.verified_chain_has_legacy_symantec_anchor === true)
		hit(
			state,
			"legacy-symantec-anchor",
			"verified_chain_has_legacy_symantec_anchor=true",
		);
};

const deploymentChecks = (state: ScanState, dep: ScanRecord, now: number) => {
	const chain = arr(dep.received_certificate_chain).filter(isRecord);
	const leaf = leafOf(chain, now);
	validityChecks(state, leaf, now);
	trustChecks(state, dep, chain, leaf);
	for (const cert of chain) {
		signatureCheck(state, cert);
		keySizeCheck(state, cert);
	}
	deploymentFlagChecks(state, dep, leaf);
};

// The deployment served without SNI only matters to ancient clients.
const certificateChecks = (state: ScanState, now: number) => {
	const deployments = arr(
		resultOf(state, "certificate_info")?.certificate_deployments,
	).filter(isRecord);
	for (const dep of deployments) deploymentChecks(state, dep, now);
};

/* -------------------------------- findings ------------------------------- */

interface Endpoint {
	readonly url: string;
	/** `host:port` of the scanned TLS endpoint. */
	readonly hostPort: string;
}

const endpointOf = (server: ScanRecord, url: string): Endpoint => {
	const loc = recordOr(server.server_location);
	return {
		url,
		hostPort: `${str(loc.hostname) ?? "?"}:${num(loc.port) ?? "?"}`,
	};
};

const toFinding = (id: RuleId, h: Hit, endpoint: Endpoint): FindingInput => {
	const rule: Rule = RULES[id];
	const cves = rule.cves ?? [];
	const { url } = endpoint;
	return {
		ruleId: `${ID}/${id}`,
		title: rule.title,
		severity: h.severity ?? rule.severity,
		category: "security",
		message: h.message ?? rule.message,
		location: rule.shared
			? { url }
			: { url, selector: `tls:${endpoint.hostPort}` },
		evidence: truncate([...h.evidence].join("; "), 500),
		remediation: rule.fix,
		references: [
			...cves.map((c) => `https://nvd.nist.gov/vuln/detail/${c}`),
			MOZILLA_TLS,
			`https://cwe.mitre.org/data/definitions/${rule.cwe}.html`,
			DOCS,
		],
		tags: [
			"tls",
			`cwe-${rule.cwe}`,
			"owasp-a02",
			...cves.map((c) => c.toLowerCase()),
		],
	};
};

const unreachable = (connectivityError: string): SslyzeScan => ({
	findings: [],
	errors: [],
	connectivityError,
});

/**
 * Maps a sslyze 6.x `--json_out` document to findings. Exported for tests.
 *
 * Certificate validity, TLS 1.0/1.1 support and a pre-TLS 1.2 ceiling repeat
 * checks of the built-in web.tls auditor (`shared` rules): they sit at the
 * bare target URL with web.tls's CWE, so correlation merges the two reports.
 * Everything else points at the TLS endpoint (`selector: "tls:host:port"`), so
 * its CWE tags never merge with unrelated page-level findings at the same URL;
 * CVE tags still merge with testssl.sh.
 */
export const parseSslyzeReport = (
	json: unknown,
	url: string,
	now = Date.now(),
): SslyzeScan => {
	const server = arr(isRecord(json) ? json.server_scan_results : undefined)[0];
	if (!isRecord(server)) return unreachable("sslyze returned no scan result");
	if (server.scan_status !== "COMPLETED")
		return unreachable(
			lastLine(server.connectivity_error_trace) ||
				`scan status ${String(server.scan_status)}`,
		);
	const state: ScanState = {
		scans: recordOr(server.scan_result),
		errors: [],
		hits: new Map(),
	};
	protocolChecks(state, server);
	vulnerabilityChecks(state);
	certificateChecks(state, now);
	const endpoint = endpointOf(server, url);
	const findings = [...state.hits].map(([id, h]) => toFinding(id, h, endpoint));
	return { findings, errors: state.errors };
};

/** Lightweight TLS scan with sslyze: protocols, known vulnerabilities and certificate health. */
export const sslyze = defineAuditor({
	id: ID,
	title: "sslyze TLS scan",
	description:
		'Runs sslyze against the https target\'s own host and port: certificate validity, expiry, hostname and trust (Mozilla, Apple, Android, Java and Windows stores), SHA-1/MD5 signatures, weak keys, chain order and Must-Staple, plus SSL 2.0, Heartbleed, CCS injection, renegotiation, TLS_FALLBACK_SCSV, compression and the highest supported protocol. About 20–35 TLS handshakes and no HTTP requests. Cipher suite enumeration (sslv3, tlsv1, tlsv1_1, tlsv1_2: 120–175 handshakes each) and ROBOT are opt-in through settings["web.sslyze"].commands. Findings that repeat web.tls checks merge with them.',
	categories: ["security"],
	targets: ["url"],
	engine: "external",
	tool: "sslyze",
	run: (ctx) =>
		Effect.gen(function* () {
			const url = yield* requireUrl(ctx);
			const parsed = yield* parseUrl(url);
			if (parsed.protocol !== "https:")
				return yield* skip("sslyze only applies to https targets");
			const bin = yield* ctx.exec.which("sslyze");
			if (!bin)
				return yield* skip(
					"sslyze not found on PATH. Install: uv tool install sslyze (or pipx install sslyze); https://github.com/nabla-c0d3/sslyze",
				);
			// Only the target's own endpoint, never a redirect to another host.
			const hostPort = `${parsed.hostname}:${parsed.port || "443"}`;
			const commands = commandsOf(ctx);
			const scan = yield* withTempDir("openaudit-sslyze-", (dir) =>
				Effect.gen(function* () {
					const out = join(dir, "report.json");
					const res = yield* ctx.exec.run(
						[
							bin,
							"--quiet",
							"--mozilla_config=disable",
							...commands.map((c) => `--${c}`),
							`--json_out=${out}`,
							hostPort,
						],
						{ cwd: dir, timeoutMs: 4 * 60_000 },
					);
					const text = yield* Effect.promise(() =>
						readFile(out, "utf8").catch(() => ""),
					);
					if (!text.trim())
						return yield* Effect.fail(
							new AuditorError({
								message: `sslyze exited with code ${res.code} and no report: ${truncate((res.stderr || res.stdout).trim(), 300)}`,
							}),
						);
					return parseSslyzeReport(yield* parseJson(text, "sslyze"), url);
				}),
			);
			if (scan.connectivityError)
				return yield* Effect.fail(
					new AuditorError({
						message: `sslyze could not connect to ${hostPort}: ${truncate(scan.connectivityError, 300)}`,
					}),
				);
			for (const e of scan.errors)
				yield* ctx.log(`web.sslyze: ${truncate(e, 300)}`);
			return scan.findings;
		}),
});
