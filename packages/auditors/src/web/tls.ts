import * as tls from "node:tls";
import {
	type AuditContext,
	type AuditorError,
	defineAuditor,
	type FindingInput,
	requireUrl,
	type Severity,
	type SkipAudit,
} from "@openaudit/core";
import { Effect, type Result } from "effect";

import { snippetOf } from "./dom";
import {
	type Crawl,
	crawl,
	fetchCached,
	isLoopback,
	type Page,
	type Resource,
	resourcesOf,
} from "./page";

const MDN_MIXED =
	"https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content";
const DAY = 86_400_000;

export interface TlsInfo {
	readonly protocol: string | null;
	readonly authorized: boolean;
	readonly authorizationError: string | undefined;
	readonly hostnameError: string | undefined;
	readonly subject: string | undefined;
	readonly issuer: string | undefined;
	readonly validFrom: Date | undefined;
	readonly validTo: Date | undefined;
	readonly selfSigned: boolean;
}

const nameOf = (o: unknown): string | undefined => {
	if (!o || typeof o !== "object") return undefined;
	const rec = o as Record<string, unknown>;
	const cn = rec.CN ?? rec.O;
	return Array.isArray(cn)
		? String(cn[0])
		: cn === undefined
			? undefined
			: String(cn);
};

const hostnameErrorOf = (
	host: string,
	cert: tls.PeerCertificate,
): string | undefined => {
	try {
		return tls.checkServerIdentity(host, cert)?.message;
	} catch (e) {
		return e instanceof Error ? e.message : String(e);
	}
};

/** OpenSSL's verification error code, e.g. `CERT_HAS_EXPIRED`. */
const authErrorCode = (authError: unknown): string | undefined => {
	if (authError === null || authError === undefined) return undefined;
	if (typeof authError === "string") return authError;
	return (authError as Error & { code?: string }).code ?? String(authError);
};

const dateOf = (value: string | undefined) =>
	value ? new Date(value) : undefined;

/** Issuer and subject are the same name. */
const selfIssued = (cert: tls.PeerCertificate | undefined) =>
	cert?.issuer !== undefined &&
	cert?.subject !== undefined &&
	JSON.stringify(cert.issuer) === JSON.stringify(cert.subject);

/** What the server presented on a completed handshake. */
const tlsInfoOf = (socket: tls.TLSSocket, host: string): TlsInfo => {
	const cert = socket.getPeerCertificate();
	const hostnameError = hostnameErrorOf(host, cert);
	const errorCode = authErrorCode(socket.authorizationError);
	return {
		protocol: socket.getProtocol(),
		authorized: socket.authorized,
		authorizationError: errorCode,
		hostnameError,
		subject: nameOf(cert?.subject),
		issuer: nameOf(cert?.issuer),
		validFrom: dateOf(cert?.valid_from),
		validTo: dateOf(cert?.valid_to),
		selfSigned:
			/SELF_SIGNED/.test(errorCode ?? "") ||
			(selfIssued(cert) && !socket.authorized),
	};
};

/** Connects with TLS (without rejecting bad certificates) and reports what was presented. */
export const inspectTls = (
	host: string,
	port: number,
	options: {
		timeoutMs?: number;
		minVersion?: tls.SecureVersion;
		maxVersion?: tls.SecureVersion;
		/** Address to dial instead of resolving `host`; SNI and name checks still use `host`. */
		connectHost?: string;
	} = {},
): Effect.Effect<TlsInfo, Error> =>
	Effect.callback<TlsInfo, Error>((resume) => {
		// rejectUnauthorized is off for inspection only; see below.
		// nosemgrep: problem-based-packs.insecure-transport.js-node.bypass-tls-verification.bypass-tls-verification
		const socket = tls.connect({
			host: options.connectHost ?? host,
			port,
			servername: /^[\d.]+$|:/.test(host) ? undefined : host,
			// Inspection only: we must complete the handshake to report on a bad
			// certificate, which is then verified explicitly below
			// (`authorizationError`, `checkServerIdentity`). No application data is
			// sent over this socket.
			rejectUnauthorized: false, // openaudit-ignore: handshake-only certificate inspection
			minVersion: options.minVersion,
			maxVersion: options.maxVersion,
		});
		const timer = setTimeout(() => {
			socket.destroy();
			resume(
				Effect.fail(new Error(`TLS handshake with ${host}:${port} timed out`)),
			);
		}, options.timeoutMs ?? 10_000);
		socket.once("secureConnect", () => {
			clearTimeout(timer);
			const info = tlsInfoOf(socket, host);
			socket.end();
			resume(Effect.succeed(info));
		});
		socket.once("error", (err) => {
			clearTimeout(timer);
			socket.destroy();
			resume(Effect.fail(err));
		});
		return Effect.sync(() => {
			clearTimeout(timer);
			socket.destroy();
		});
	});

/** TLS 1.1 and older, as Node's `getProtocol()` names them. */
const LEGACY_PROTOCOL = /^(SSLv|TLSv1(\.[01])?$)/;

/** One certificate or protocol problem, before the shared finding fields. */
interface CertProblem {
	readonly rule: string;
	readonly severity: Severity;
	readonly title: string;
	readonly message: string;
	readonly remediation: string;
	readonly cwe?: string;
}

const day = (date: Date) => date.toISOString().slice(0, 10);

const isExpired = (info: TlsInfo, now: number) =>
	info.validTo !== undefined && info.validTo.getTime() < now;

const expiryProblem = (info: TlsInfo, now: number): CertProblem | undefined => {
	if (isExpired(info, now))
		return {
			rule: "certificate-expired",
			severity: "critical",
			title: "TLS certificate has expired",
			message: `The certificate expired on ${info.validTo?.toISOString().slice(0, 10)}; browsers show a full-page warning and clients refuse to connect.`,
			remediation:
				"Renew the certificate and automate renewal (e.g. ACME/Let's Encrypt).",
		};
	if (!info.validTo) return undefined;
	const days = Math.floor((info.validTo.getTime() - now) / DAY);
	if (days < 30)
		return {
			rule: "certificate-expiring",
			severity: days < 7 ? "high" : "medium",
			title: "TLS certificate expires soon",
			message: `The certificate expires in ${days} day(s), on ${day(info.validTo)}.`,
			remediation:
				"Renew the certificate now and automate renewal with monitoring.",
		};
	return undefined;
};

const notYetValidProblem = (
	info: TlsInfo,
	now: number,
): CertProblem | undefined => {
	if (info.validFrom && info.validFrom.getTime() > now)
		return {
			rule: "certificate-not-yet-valid",
			severity: "high",
			title: "TLS certificate is not yet valid",
			message: `The certificate is only valid from ${info.validFrom.toISOString()}.`,
			remediation: "Check the server clock and certificate validity period.",
		};
	return undefined;
};

const hostnameMismatch = (info: TlsInfo) =>
	info.hostnameError ||
	info.authorizationError === "ERR_TLS_CERT_ALTNAME_INVALID";

const untrustedProblem = (info: TlsInfo): CertProblem | undefined => {
	const code = info.authorizationError;
	if (info.authorized || !code) return undefined;
	const incomplete = code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE";
	return {
		rule: incomplete ? "certificate-chain-incomplete" : "certificate-untrusted",
		severity: incomplete ? "medium" : "high",
		title: incomplete
			? "TLS certificate chain is incomplete"
			: "TLS certificate is not trusted",
		message: `Certificate verification failed: ${code}.`,
		remediation:
			"Serve the full chain (leaf + intermediates) from a publicly trusted CA.",
	};
};

const trustProblem = (info: TlsInfo, now: number): CertProblem | undefined => {
	if (info.selfSigned)
		return {
			rule: "certificate-self-signed",
			severity: "high",
			title: "TLS certificate is self-signed",
			message:
				"The certificate is not issued by a trusted CA, so browsers warn and users learn to click through warnings (enabling MITM).",
			remediation:
				"Use a certificate from a publicly trusted CA (e.g. Let's Encrypt).",
		};
	if (hostnameMismatch(info))
		return {
			rule: "certificate-hostname-mismatch",
			severity: "high",
			title: "TLS certificate does not match the hostname",
			message: `The certificate is not valid for this host: ${info.hostnameError ?? info.authorizationError}.`,
			remediation:
				"Issue a certificate whose subjectAltName covers this hostname.",
		};
	return isExpired(info, now) ? undefined : untrustedProblem(info);
};

const protocolProblem = (info: TlsInfo): CertProblem | undefined => {
	if (info.protocol && LEGACY_PROTOCOL.test(info.protocol))
		return {
			rule: "weak-protocol",
			severity: "high",
			title: `Server negotiated ${info.protocol}`,
			message: `The connection used ${info.protocol}, which is deprecated (RFC 8996) and vulnerable to known attacks.`,
			remediation:
				"Disable SSLv3, TLS 1.0 and TLS 1.1; support TLS 1.2 and 1.3 only.",
			cwe: "cwe-327",
		};
	return undefined;
};

/** Findings for a TLS handshake result. Exported for tests. */
export const certificateFindings = (
	url: string,
	info: TlsInfo,
	now = Date.now(),
): FindingInput[] => {
	const location = { url };
	const evidence = `subject=${info.subject ?? "?"}; issuer=${info.issuer ?? "?"}; valid_to=${info.validTo?.toISOString() ?? "?"}; protocol=${info.protocol ?? "?"}`;
	const refs = [
		"https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
	];
	const problems = [
		expiryProblem(info, now),
		notYetValidProblem(info, now),
		trustProblem(info, now),
		protocolProblem(info),
	].filter((p) => p !== undefined);
	return problems.map(
		(p): FindingInput => ({
			ruleId: `web.tls/${p.rule}`,
			title: p.title,
			severity: p.severity,
			category: "security",
			message: p.message,
			location,
			evidence,
			remediation: p.remediation,
			references: refs,
			tags: [p.cwe ?? "cwe-295", "owasp-a02"],
		}),
	);
};

/** Resource kinds whose mixed content browsers block. */
const ACTIVE_KINDS = ["script", "stylesheet", "iframe", "object", "font"];

const mixedContentText = (
	res: Resource,
): Pick<FindingInput, "ruleId" | "title" | "severity" | "message"> => {
	if (res.kind === "form")
		return {
			ruleId: "web.tls/insecure-form-action",
			title: "Form submits over plain HTTP",
			severity: "high",
			message: `A form on this HTTPS page posts to ${res.url}, sending its data unencrypted.`,
		};
	const active = ACTIVE_KINDS.includes(res.kind);
	return {
		ruleId: `web.tls/mixed-content-${active ? "active" : "passive"}`,
		title: `Mixed content: ${res.kind} loaded over HTTP`,
		severity: active ? "high" : "low",
		message: active
			? `This HTTPS page loads a ${res.kind} from ${res.url}. Browsers block active mixed content, breaking the page; where allowed, a network attacker can inject code.`
			: `This HTTPS page loads ${res.url} over HTTP. Browsers auto-upgrade or warn, and an attacker can swap the content.`,
	};
};

/** http:// subresources on an https page. Exported for tests. */
export const mixedContentFindings = (page: Page): FindingInput[] => {
	if (!page.url.startsWith("https:")) return [];
	return resourcesOf(page)
		.filter((res) => res.url.startsWith("http:"))
		.map((res): FindingInput => {
			const { ruleId, title, severity, message } = mixedContentText(res);
			return {
				ruleId,
				title,
				severity,
				category: "security",
				message,
				location: { url: page.url },
				evidence: snippetOf(res.el),
				remediation:
					"Reference the resource over https:// (or a protocol-relative/relative URL served over HTTPS).",
				references: [MDN_MIXED],
				tags: ["cwe-319"],
			};
		});
};

const checkRedirect = (ctx: AuditContext, url: URL) =>
	Effect.gen(function* () {
		// https://host:8443 has no known HTTP counterpart; http://host:8443 would
		// speak plain HTTP to the TLS port.
		if (url.port !== "") return [];
		const httpUrl = new URL(url.toString());
		httpUrl.protocol = "http:";
		const res = yield* fetchCached(ctx, httpUrl.toString(), {
			redirect: "manual",
			timeoutMs: 8_000,
			maxBytes: 4096,
		}).pipe(Effect.option);
		if (res._tag === "None") return [];
		const loc = res.value.headers.get("location") ?? "";
		const redirects = res.value.status >= 300 && res.value.status < 400;
		if (redirects && /^https:/i.test(new URL(loc, httpUrl).toString()))
			return [];
		return [
			{
				ruleId: "web.tls/http-not-redirected",
				title: "HTTP is not redirected to HTTPS",
				severity: "medium",
				category: "security",
				message: redirects
					? `${httpUrl} redirects to ${loc}, which is not HTTPS.`
					: `${httpUrl} answers with status ${res.value.status} instead of redirecting to HTTPS, so visitors typing the bare domain stay on an unencrypted connection.`,
				location: { url: httpUrl.toString() },
				evidence: `${res.value.status}${loc ? ` location: ${loc}` : ""}`,
				remediation:
					"Permanently redirect (301/308) every http:// request to its https:// equivalent and enable HSTS.",
				references: ["https://web.dev/articles/redirect-http-https"],
				tags: ["cwe-319"],
			} satisfies FindingInput,
		];
	});

/**
 * Setting `settings["web.tls"].connectHost`: a pre-validated IP address the TLS
 * probe connects to instead of resolving the target hostname (SNI and
 * certificate name checks still use the hostname). Lets callers such as the
 * public HTTP API pin the address they already vetted against SSRF.
 */
const connectHostOf = (ctx: AuditContext): string | undefined => {
	const value = ctx.options.settings?.["web.tls"]?.connectHost;
	return typeof value === "string" && value.length > 0 ? value : undefined;
};

const noHttpsFinding = (location: string): FindingInput => ({
	ruleId: "web.tls/no-https",
	title: "Site is served over plain HTTP",
	severity: "high",
	category: "security",
	message:
		"The target is served without TLS, so everything (including cookies and form data) travels in clear text and can be modified in transit.",
	location: { url: location },
	remediation:
		"Serve the site over HTTPS with a trusted certificate and redirect HTTP to HTTPS.",
	references: ["https://web.dev/articles/why-https-matters"],
	tags: ["cwe-319", "owasp-a02"],
});

type Crawled = Result.Result<Crawl, AuditorError | SkipAudit>;

const plainHttpFindings = (crawled: Crawled, url: URL) =>
	Effect.gen(function* () {
		if (crawled._tag === "Failure") return yield* crawled.failure;
		if (isLoopback(url.toString())) return [];
		return [noHttpsFinding(crawled.success.start.url)];
	});

/**
 * The TLS probe dials a raw socket outside ctx.http, so its host and port
 * come only from the target URL, never from a redirect to another host.
 * Its findings are located at that URL: TLS is per host and port, not
 * per page, and wrappers such as web.sslyze locate theirs there too.
 */
const tlsUrlOf = (target: URL, url: URL) =>
	target.protocol === "https:"
		? target
		: target.hostname === url.hostname
			? url
			: undefined;

/** Where the TLS probe connects. */
interface Probe {
	readonly hostname: string;
	readonly port: number;
	readonly connectHost: string | undefined;
}

const handshake = ({ hostname, port, connectHost }: Probe) =>
	inspectTls(hostname, port, { connectHost }).pipe(
		// Clients default to TLS 1.2+, so a legacy-only server needs a retry.
		Effect.catch(() =>
			inspectTls(hostname, port, {
				connectHost,
				minVersion: "TLSv1",
				timeoutMs: 5_000,
			}),
		),
		Effect.option,
	);

// Does the server still accept TLS 1.0/1.1? Clients default to 1.2+, so ask explicitly.
const legacyProtocolFindings = (
	{ hostname, port, connectHost }: Probe,
	location: string,
) =>
	Effect.gen(function* () {
		const legacy = yield* inspectTls(hostname, port, {
			connectHost,
			minVersion: "TLSv1",
			maxVersion: "TLSv1.1",
			timeoutMs: 5_000,
		}).pipe(Effect.option);
		if (legacy._tag === "None") return [];
		const { protocol } = legacy.value;
		if (!protocol || !/^TLSv1(\.1)?$/.test(protocol)) return [];
		return [
			{
				ruleId: "web.tls/legacy-protocol-supported",
				title: `Server still accepts ${protocol}`,
				severity: "medium",
				category: "security",
				message: `The server completed a ${protocol} handshake. TLS 1.0/1.1 are deprecated (RFC 8996) and enable downgrade attacks for old clients.`,
				location: { url: location },
				evidence: `protocol=${protocol}`,
				remediation: "Disable TLS 1.0 and 1.1; allow only TLS 1.2 and 1.3.",
				references: ["https://datatracker.ietf.org/doc/html/rfc8996"],
				tags: ["cwe-327"],
			} satisfies FindingInput,
		];
	});

/** HTTP redirect, certificate and protocol findings for the TLS endpoint. */
const endpointFindings = (ctx: AuditContext, tlsUrl: URL) =>
	Effect.gen(function* () {
		const location = tlsUrl.toString();
		const findings: FindingInput[] = [...(yield* checkRedirect(ctx, tlsUrl))];
		const probe: Probe = {
			hostname: tlsUrl.hostname,
			port: Number(tlsUrl.port || 443),
			connectHost: connectHostOf(ctx),
		};
		const info = yield* handshake(probe);
		if (info._tag === "None") {
			yield* ctx.log(`web.tls: TLS handshake with ${tlsUrl.host} failed`);
			return findings;
		}
		findings.push(...certificateFindings(location, info.value));
		if (!LEGACY_PROTOCOL.test(info.value.protocol ?? ""))
			findings.push(...(yield* legacyProtocolFindings(probe, location)));
		return findings;
	});

/** Adds mixed content findings from the crawl, or explains why there are none. */
const withMixedContent = (
	ctx: AuditContext,
	crawled: Crawled,
	findings: FindingInput[],
) =>
	Effect.gen(function* () {
		if (crawled._tag === "Failure") {
			// Nothing to show for the run: surface why the page was unreachable.
			if (findings.length === 0) return yield* crawled.failure;
			yield* ctx.log(
				`web.tls: mixed content not checked, the page fetch failed: ${crawled.failure.message}`,
			);
			return findings;
		}
		for (const page of crawled.success.pages)
			findings.push(...mixedContentFindings(page));
		return findings;
	});

/** HTTPS enforcement, certificate health, protocol versions and mixed content. */
export const tlsAuditor = defineAuditor({
	id: "web.tls",
	title: "TLS / HTTPS",
	description:
		"Checks HTTP→HTTPS redirects, certificate validity, expiry, hostname and trust, legacy TLS versions and mixed content.",
	categories: ["security"],
	targets: ["url"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const target = new URL(yield* requireUrl(ctx));
			// A bad certificate or a legacy-only server makes the page fetch fail,
			// and those are the hosts the TLS checks matter most for, so they run
			// on their own handshake whether or not the crawl succeeds.
			const crawled = yield* Effect.result(crawl(ctx));
			const url =
				crawled._tag === "Success"
					? new URL(crawled.success.start.url)
					: target;
			if (url.protocol === "http:")
				return yield* plainHttpFindings(crawled, url);
			const tlsUrl = tlsUrlOf(target, url);
			const findings =
				isLoopback(url.toString()) || !tlsUrl
					? []
					: yield* endpointFindings(ctx, tlsUrl);
			return yield* withMixedContent(ctx, crawled, findings);
		}),
});
