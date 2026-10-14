import * as tls from "node:tls";
import {
	type AuditContext,
	defineAuditor,
	type FindingInput,
	requireUrl,
	type Severity,
} from "@openaudit/core";
import { Effect } from "effect";

import { snippetOf } from "./dom";
import { crawl, fetchCached, isLoopback, type Page, resourcesOf } from "./page";

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
			const cert = socket.getPeerCertificate();
			let hostnameError: string | undefined;
			try {
				const err = tls.checkServerIdentity(host, cert);
				hostnameError = err?.message;
			} catch (e) {
				hostnameError = e instanceof Error ? e.message : String(e);
			}
			const authError = socket.authorizationError;
			const errorCode =
				authError === null || authError === undefined
					? undefined
					: typeof authError === "string"
						? authError
						: ((authError as Error & { code?: string }).code ??
							String(authError));
			const subject = nameOf(cert?.subject);
			const issuer = nameOf(cert?.issuer);
			const info: TlsInfo = {
				protocol: socket.getProtocol(),
				authorized: socket.authorized,
				authorizationError: errorCode,
				hostnameError,
				subject,
				issuer,
				validFrom: cert?.valid_from ? new Date(cert.valid_from) : undefined,
				validTo: cert?.valid_to ? new Date(cert.valid_to) : undefined,
				selfSigned:
					/SELF_SIGNED/.test(errorCode ?? "") ||
					(cert?.issuer !== undefined &&
						cert?.subject !== undefined &&
						JSON.stringify(cert.issuer) === JSON.stringify(cert.subject) &&
						!socket.authorized),
			};
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

/** Findings for a TLS handshake result. Exported for tests. */
export const certificateFindings = (
	url: string,
	info: TlsInfo,
	now = Date.now(),
): FindingInput[] => {
	const findings: FindingInput[] = [];
	const location = { url };
	const evidence = `subject=${info.subject ?? "?"}; issuer=${info.issuer ?? "?"}; valid_to=${info.validTo?.toISOString() ?? "?"}; protocol=${info.protocol ?? "?"}`;
	const refs = [
		"https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
	];
	const add = (
		rule: string,
		severity: Severity,
		title: string,
		message: string,
		remediation: string,
		cwe = "cwe-295",
	) =>
		findings.push({
			ruleId: `web.tls/${rule}`,
			title,
			severity,
			category: "security",
			message,
			location,
			evidence,
			remediation,
			references: refs,
			tags: [cwe, "owasp-a02"],
		});

	const expired = info.validTo !== undefined && info.validTo.getTime() < now;
	if (expired)
		add(
			"certificate-expired",
			"critical",
			"TLS certificate has expired",
			`The certificate expired on ${info.validTo?.toISOString().slice(0, 10)}; browsers show a full-page warning and clients refuse to connect.`,
			"Renew the certificate and automate renewal (e.g. ACME/Let's Encrypt).",
		);
	else if (info.validTo) {
		const days = Math.floor((info.validTo.getTime() - now) / DAY);
		if (days < 30)
			add(
				"certificate-expiring",
				days < 7 ? "high" : "medium",
				"TLS certificate expires soon",
				`The certificate expires in ${days} day(s), on ${info.validTo.toISOString().slice(0, 10)}.`,
				"Renew the certificate now and automate renewal with monitoring.",
			);
	}
	if (info.validFrom && info.validFrom.getTime() > now)
		add(
			"certificate-not-yet-valid",
			"high",
			"TLS certificate is not yet valid",
			`The certificate is only valid from ${info.validFrom.toISOString()}.`,
			"Check the server clock and certificate validity period.",
		);

	if (info.selfSigned)
		add(
			"certificate-self-signed",
			"high",
			"TLS certificate is self-signed",
			"The certificate is not issued by a trusted CA, so browsers warn and users learn to click through warnings (enabling MITM).",
			"Use a certificate from a publicly trusted CA (e.g. Let's Encrypt).",
		);
	else if (
		info.hostnameError ||
		info.authorizationError === "ERR_TLS_CERT_ALTNAME_INVALID"
	)
		add(
			"certificate-hostname-mismatch",
			"high",
			"TLS certificate does not match the hostname",
			`The certificate is not valid for this host: ${info.hostnameError ?? info.authorizationError}.`,
			"Issue a certificate whose subjectAltName covers this hostname.",
		);
	else if (!info.authorized && info.authorizationError && !expired)
		add(
			info.authorizationError === "UNABLE_TO_VERIFY_LEAF_SIGNATURE"
				? "certificate-chain-incomplete"
				: "certificate-untrusted",
			info.authorizationError === "UNABLE_TO_VERIFY_LEAF_SIGNATURE"
				? "medium"
				: "high",
			info.authorizationError === "UNABLE_TO_VERIFY_LEAF_SIGNATURE"
				? "TLS certificate chain is incomplete"
				: "TLS certificate is not trusted",
			`Certificate verification failed: ${info.authorizationError}.`,
			"Serve the full chain (leaf + intermediates) from a publicly trusted CA.",
		);

	if (info.protocol && /^(SSLv|TLSv1(\.[01])?$)/.test(info.protocol))
		add(
			"weak-protocol",
			"high",
			`Server negotiated ${info.protocol}`,
			`The connection used ${info.protocol}, which is deprecated (RFC 8996) and vulnerable to known attacks.`,
			"Disable SSLv3, TLS 1.0 and TLS 1.1; support TLS 1.2 and 1.3 only.",
			"cwe-327",
		);
	return findings;
};

/** http:// subresources on an https page. Exported for tests. */
export const mixedContentFindings = (page: Page): FindingInput[] => {
	if (!page.url.startsWith("https:")) return [];
	const findings: FindingInput[] = [];
	for (const res of resourcesOf(page)) {
		if (!res.url.startsWith("http:")) continue;
		const active = [
			"script",
			"stylesheet",
			"iframe",
			"object",
			"font",
		].includes(res.kind);
		const form = res.kind === "form";
		findings.push({
			ruleId: form
				? "web.tls/insecure-form-action"
				: `web.tls/mixed-content-${active ? "active" : "passive"}`,
			title: form
				? "Form submits over plain HTTP"
				: active
					? `Mixed content: ${res.kind} loaded over HTTP`
					: `Mixed content: ${res.kind} loaded over HTTP`,
			severity: active || form ? "high" : "low",
			category: "security",
			message: form
				? `A form on this HTTPS page posts to ${res.url}, sending its data unencrypted.`
				: active
					? `This HTTPS page loads a ${res.kind} from ${res.url}. Browsers block active mixed content, breaking the page; where allowed, a network attacker can inject code.`
					: `This HTTPS page loads ${res.url} over HTTP. Browsers auto-upgrade or warn, and an attacker can swap the content.`,
			location: { url: page.url },
			evidence: snippetOf(res.el),
			remediation:
				"Reference the resource over https:// (or a protocol-relative/relative URL served over HTTPS).",
			references: [MDN_MIXED],
			tags: ["cwe-319"],
		});
	}
	return findings;
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
			const site = crawled._tag === "Success" ? crawled.success : undefined;
			const url = site ? new URL(site.start.url) : target;
			const findings: FindingInput[] = [];
			const loopback = isLoopback(url.toString());

			if (url.protocol === "http:") {
				if (crawled._tag === "Failure") return yield* crawled.failure;
				if (!loopback)
					findings.push({
						ruleId: "web.tls/no-https",
						title: "Site is served over plain HTTP",
						severity: "high",
						category: "security",
						message:
							"The target is served without TLS, so everything (including cookies and form data) travels in clear text and can be modified in transit.",
						location: { url: site?.start.url ?? url.toString() },
						remediation:
							"Serve the site over HTTPS with a trusted certificate and redirect HTTP to HTTPS.",
						references: ["https://web.dev/articles/why-https-matters"],
						tags: ["cwe-319", "owasp-a02"],
					});
				return findings;
			}

			// The TLS probe dials a raw socket outside ctx.http, so its host and port
			// come only from the target URL, never from a redirect to another host.
			// Its findings are located at that URL: TLS is per host and port, not
			// per page, and wrappers such as web.sslyze locate theirs there too.
			const tlsUrl =
				target.protocol === "https:"
					? target
					: target.hostname === url.hostname
						? url
						: undefined;
			if (!loopback && tlsUrl) {
				const location = tlsUrl.toString();
				findings.push(...(yield* checkRedirect(ctx, tlsUrl)));
				const port = Number(tlsUrl.port || 443);
				const connectHost = connectHostOf(ctx);
				const info = yield* inspectTls(tlsUrl.hostname, port, {
					connectHost,
				}).pipe(
					// Clients default to TLS 1.2+, so a legacy-only server needs a retry.
					Effect.catch(() =>
						inspectTls(tlsUrl.hostname, port, {
							connectHost,
							minVersion: "TLSv1",
							timeoutMs: 5_000,
						}),
					),
					Effect.option,
				);
				if (info._tag === "Some")
					findings.push(...certificateFindings(location, info.value));
				else
					yield* ctx.log(`web.tls: TLS handshake with ${tlsUrl.host} failed`);
				// Does the server still accept TLS 1.0/1.1? Clients default to 1.2+, so ask explicitly.
				if (
					info._tag === "Some" &&
					!/^(SSLv|TLSv1(\.[01])?$)/.test(info.value.protocol ?? "")
				) {
					const legacy = yield* inspectTls(tlsUrl.hostname, port, {
						connectHost,
						minVersion: "TLSv1",
						maxVersion: "TLSv1.1",
						timeoutMs: 5_000,
					}).pipe(Effect.option);
					if (
						legacy._tag === "Some" &&
						legacy.value.protocol &&
						/^TLSv1(\.1)?$/.test(legacy.value.protocol)
					)
						findings.push({
							ruleId: "web.tls/legacy-protocol-supported",
							title: `Server still accepts ${legacy.value.protocol}`,
							severity: "medium",
							category: "security",
							message: `The server completed a ${legacy.value.protocol} handshake. TLS 1.0/1.1 are deprecated (RFC 8996) and enable downgrade attacks for old clients.`,
							location: { url: location },
							evidence: `protocol=${legacy.value.protocol}`,
							remediation:
								"Disable TLS 1.0 and 1.1; allow only TLS 1.2 and 1.3.",
							references: ["https://datatracker.ietf.org/doc/html/rfc8996"],
							tags: ["cwe-327"],
						});
				}
			}

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
		}),
});
