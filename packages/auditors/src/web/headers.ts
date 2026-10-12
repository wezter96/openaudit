import {
	defineAuditor,
	type FindingInput,
	type Severity,
} from "@openaudit/core";
import { Effect } from "effect";

import { attr, findFirst } from "./dom";
import { fetchCached, startPage } from "./page";
import { cookieEvidence, maxAgeOf, parseCsp, parseSetCookie } from "./util";

const MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers";
const OWASP_HEADERS =
	"https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html";

/** One year, as recommended by OWASP and the HSTS preload list. */
const HSTS_MIN_AGE = 31_536_000;
/** Origin used to test whether CORS reflects arbitrary origins. */
const PROBE_ORIGIN = "https://openaudit-cors-check.invalid";
const SESSION_COOKIE = /sess|sid|auth|token|jwt|login|remember|csrf|xsrf/i;

/** HTTP response security headers, CORS and cookie flags of the target document. */
export const headers = defineAuditor({
	id: "web.headers",
	title: "Security headers",
	description:
		"Checks CSP, HSTS, framing, MIME sniffing, referrer and permissions policies, cross-origin isolation, version disclosure, CORS and cookie flags on the target URL.",
	categories: ["security", "best-practices", "privacy"],
	targets: ["url"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const page = yield* startPage(ctx);
			const h = page.response.headers;
			const url = page.url;
			const https = url.startsWith("https:");
			const location = { url };
			const findings: FindingInput[] = [];
			const add = (
				rule: string,
				severity: Severity,
				f: Omit<
					FindingInput,
					"ruleId" | "severity" | "category" | "location"
				> & {
					category?: FindingInput["category"];
				},
			) =>
				findings.push({
					ruleId: `web.headers/${rule}`,
					severity,
					category: f.category ?? "security",
					location,
					...f,
				});

			/* ------------------------------- CSP -------------------------------- */
			const cspHeader = h.get("content-security-policy");
			const cspMeta = page.isHtml
				? attr(
						findFirst(
							page.doc,
							"meta",
							(m) =>
								(m.attrs["http-equiv"] ?? "").toLowerCase() ===
								"content-security-policy",
						) ?? page.doc,
						"content",
					)
				: undefined;
			const cspText = cspHeader ?? cspMeta;
			const csp = cspText ? parseCsp(cspText) : undefined;
			const xfo = h.get("x-frame-options");

			if (!csp) {
				if (page.isHtml)
					add("csp-missing", "medium", {
						title: "Content-Security-Policy is missing",
						message:
							"The page sets no Content-Security-Policy, so any injected script runs with full privileges. CSP is the main defence-in-depth control against XSS.",
						remediation:
							"Send a Content-Security-Policy header. Start with a strict, nonce- or hash-based policy, e.g. `default-src 'self'; script-src 'self' 'nonce-…'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'`, deploying it as Content-Security-Policy-Report-Only first.",
						references: [
							`${MDN}/Content-Security-Policy`,
							"https://web.dev/articles/strict-csp",
						],
						tags: ["cwe-693", "owasp-a05"],
					});
			} else {
				const scriptSrc = csp.get("script-src") ?? csp.get("default-src");
				const evidence = `content-security-policy: ${cspText}`.slice(0, 200);
				if (scriptSrc) {
					const hasNonceOrHash = scriptSrc.some((s) =>
						/^'(nonce-|sha(256|384|512)-)/.test(s),
					);
					const strictDynamic = scriptSrc.includes("'strict-dynamic'");
					if (scriptSrc.includes("'unsafe-inline'") && !hasNonceOrHash)
						add("csp-unsafe-inline", "medium", {
							title: "CSP allows inline scripts",
							message:
								"script-src contains 'unsafe-inline' without a nonce or hash, which lets injected inline scripts execute and largely defeats CSP's XSS protection.",
							evidence,
							remediation:
								"Remove 'unsafe-inline' from script-src and allow required inline scripts with nonces or hashes.",
							references: [`${MDN}/Content-Security-Policy/script-src`],
							tags: ["cwe-79", "owasp-a05"],
						});
					if (scriptSrc.includes("'unsafe-eval'"))
						add("csp-unsafe-eval", "medium", {
							title: "CSP allows eval()",
							message:
								"script-src contains 'unsafe-eval', allowing string-to-code APIs such as eval() and new Function() that turn data into script.",
							evidence,
							remediation:
								"Remove 'unsafe-eval' and refactor code (or dependencies) that relies on eval-like APIs.",
							references: [`${MDN}/Content-Security-Policy/script-src`],
							tags: ["cwe-95", "owasp-a05"],
						});
					const wildcard = strictDynamic
						? []
						: scriptSrc.filter((s) =>
								["*", "http:", "https:", "data:"].includes(s),
							);
					if (wildcard.length > 0)
						add("csp-wildcard-source", "medium", {
							title: "CSP allows scripts from any host",
							message: `script-src allows ${wildcard.join(", ")}, so an attacker can load script from a host they control.`,
							evidence,
							remediation:
								"Replace scheme and wildcard sources with explicit hosts, or use nonces with 'strict-dynamic'.",
							references: ["https://csp-evaluator.withgoogle.com/"],
							tags: ["cwe-79"],
						});
				}
				if (
					!csp.has("object-src") &&
					!(csp.get("default-src") ?? []).includes("'none'")
				)
					add("csp-object-src-missing", "low", {
						title: "CSP does not restrict plugins",
						message:
							"The policy has no object-src directive (and default-src is not 'none'), so <object>/<embed> plugin content is not restricted.",
						evidence,
						remediation: "Add `object-src 'none'` to the policy.",
						references: [`${MDN}/Content-Security-Policy/object-src`],
						tags: ["cwe-693"],
					});
				if (!csp.has("frame-ancestors") && xfo)
					add("csp-frame-ancestors-missing", "info", {
						title: "CSP has no frame-ancestors directive",
						message: cspHeader
							? "Framing is controlled only by the legacy X-Frame-Options header. frame-ancestors is the standard replacement and supports allow-lists."
							: "The policy is delivered via <meta>, where frame-ancestors is ignored; framing relies on X-Frame-Options.",
						evidence,
						remediation:
							"Add `frame-ancestors 'self'` (or 'none') to a Content-Security-Policy response header.",
						references: [`${MDN}/Content-Security-Policy/frame-ancestors`],
					});
			}

			/* ---------------------------- clickjacking --------------------------- */
			const frameAncestors = cspHeader
				? parseCsp(cspHeader).get("frame-ancestors")
				: undefined;
			if (
				page.isHtml &&
				!frameAncestors &&
				!/^(deny|sameorigin)$/i.test(xfo?.trim() ?? "")
			)
				add("clickjacking", "medium", {
					title: "Page can be framed by any site",
					message:
						"Neither CSP frame-ancestors nor a valid X-Frame-Options header is set, so other sites can embed this page in an iframe for clickjacking.",
					evidence: xfo ? `x-frame-options: ${xfo}` : undefined,
					remediation:
						"Send `Content-Security-Policy: frame-ancestors 'self'` (and optionally `X-Frame-Options: SAMEORIGIN` for old browsers).",
					references: [
						`${MDN}/X-Frame-Options`,
						"https://owasp.org/www-community/attacks/Clickjacking",
					],
					tags: ["cwe-1021", "owasp-a05"],
				});

			/* ------------------------------- HSTS -------------------------------- */
			if (https) {
				const hsts = h.get("strict-transport-security");
				if (!hsts)
					add("hsts-missing", "medium", {
						title: "Strict-Transport-Security is missing",
						message:
							"Without HSTS, browsers may connect over plain HTTP first, allowing SSL-stripping on hostile networks.",
						remediation:
							"Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` once every subdomain serves HTTPS.",
						references: [`${MDN}/Strict-Transport-Security`, OWASP_HEADERS],
						tags: ["cwe-319", "owasp-a02"],
					});
				else {
					const age = maxAgeOf(hsts) ?? 0;
					if (age < HSTS_MIN_AGE)
						add("hsts-short-max-age", "low", {
							title: "HSTS max-age is short",
							message: `HSTS max-age is ${age} seconds (${Math.round(age / 86400)} days); at least one year is recommended so the protection does not lapse between visits.`,
							evidence: `strict-transport-security: ${hsts}`,
							remediation: "Raise max-age to 31536000 (one year) or more.",
							references: [`${MDN}/Strict-Transport-Security`],
							tags: ["cwe-319"],
						});
					if (!/includesubdomains/i.test(hsts))
						add("hsts-no-subdomains", "low", {
							title: "HSTS does not cover subdomains",
							message:
								"HSTS lacks includeSubDomains, so subdomains (and cookies scoped to the parent domain) can still be reached over HTTP.",
							evidence: `strict-transport-security: ${hsts}`,
							remediation:
								"Add includeSubDomains once all subdomains support HTTPS.",
							references: [`${MDN}/Strict-Transport-Security`],
							tags: ["cwe-319"],
						});
				}
			}

			/* --------------------------- other headers --------------------------- */
			if (
				(h.get("x-content-type-options") ?? "").trim().toLowerCase() !==
				"nosniff"
			)
				add("x-content-type-options-missing", "low", {
					title: "X-Content-Type-Options is not nosniff",
					message:
						"Without `X-Content-Type-Options: nosniff`, browsers may MIME-sniff responses and execute uploaded or user-controlled content as script or HTML.",
					remediation:
						"Send `X-Content-Type-Options: nosniff` on all responses.",
					references: [`${MDN}/X-Content-Type-Options`],
					tags: ["cwe-693"],
				});

			const referrer = h.get("referrer-policy")?.toLowerCase();
			if (!referrer && page.isHtml)
				add("referrer-policy-missing", "low", {
					title: "Referrer-Policy is missing",
					category: "privacy",
					message:
						"No Referrer-Policy is set; older browsers send full URLs (including paths and query strings) to third parties.",
					remediation:
						"Send `Referrer-Policy: strict-origin-when-cross-origin` (or stricter).",
					references: [`${MDN}/Referrer-Policy`],
				});
			else if (
				referrer &&
				/unsafe-url|no-referrer-when-downgrade/.test(referrer)
			)
				add("referrer-policy-unsafe", "medium", {
					title: "Referrer-Policy leaks full URLs",
					category: "privacy",
					message: `Referrer-Policy \`${referrer}\` sends the full URL, including path and query parameters, to other origins.`,
					evidence: `referrer-policy: ${referrer}`,
					remediation:
						"Use `strict-origin-when-cross-origin` or `no-referrer`.",
					references: [`${MDN}/Referrer-Policy`],
					tags: ["cwe-200"],
				});

			if (page.isHtml && !h.get("permissions-policy"))
				add("permissions-policy-missing", "low", {
					title: "Permissions-Policy is missing",
					category: "best-practices",
					message:
						"No Permissions-Policy limits powerful browser features (camera, microphone, geolocation…) for this page and embedded third-party frames.",
					remediation:
						"Send a Permissions-Policy disabling features you do not use, e.g. `camera=(), microphone=(), geolocation=()`.",
					references: [`${MDN}/Permissions-Policy`],
				});

			if (page.isHtml && !h.get("cross-origin-opener-policy"))
				add("coop-missing", "low", {
					title: "Cross-Origin-Opener-Policy is missing",
					message:
						"Without COOP, cross-origin windows opened by or opening this page share a browsing context group, enabling XS-Leaks and limiting process isolation.",
					remediation:
						"Send `Cross-Origin-Opener-Policy: same-origin` (or `same-origin-allow-popups` if you rely on OAuth/payment popups).",
					references: [
						`${MDN}/Cross-Origin-Opener-Policy`,
						"https://xsleaks.dev/",
					],
				});
			if (!h.get("cross-origin-resource-policy"))
				add("corp-missing", "info", {
					title: "Cross-Origin-Resource-Policy is missing",
					message:
						"No CORP header; other origins can embed this response, which helps side-channel (Spectre-style) attacks on sensitive resources.",
					remediation:
						"Send `Cross-Origin-Resource-Policy: same-origin` on sensitive responses.",
					references: [`${MDN}/Cross-Origin-Resource-Policy`],
				});

			/* ------------------------- version disclosure ------------------------ */
			for (const name of [
				"server",
				"x-powered-by",
				"x-aspnet-version",
				"x-aspnetmvc-version",
				"x-generator",
			]) {
				const value = h.get(name);
				if (!value) continue;
				const versioned = /\d+\.\d+/.test(value);
				if (name === "server" && !versioned) continue;
				add("version-disclosure", "low", {
					title: `${name} header discloses software${versioned ? " version" : ""}`,
					category: "security",
					message: `The \`${name}\` header reveals \`${value}\`, helping attackers pick known exploits for that stack.`,
					evidence: `${name}: ${value}`,
					remediation:
						name === "server"
							? "Configure the server to omit version numbers (e.g. `server_tokens off` in nginx, `ServerTokens Prod` in Apache)."
							: `Remove the \`${name}\` header (e.g. \`app.disable("x-powered-by")\` in Express).`,
					references: [OWASP_HEADERS],
					tags: ["cwe-200"],
					confidence: "high",
				});
			}

			/* -------------------------------- CORS ------------------------------- */
			const acao = h.get("access-control-allow-origin");
			const acac =
				h.get("access-control-allow-credentials")?.toLowerCase() === "true";
			if (acao?.trim() === "*" && acac)
				add("cors-wildcard-credentials", "medium", {
					title: "CORS allows any origin with credentials",
					message:
						"Access-Control-Allow-Origin is `*` while Access-Control-Allow-Credentials is true. Browsers reject this combination, but it signals a CORS configuration that may reflect origins elsewhere.",
					evidence: `access-control-allow-origin: ${acao}; access-control-allow-credentials: true`,
					remediation:
						"Allow-list trusted origins explicitly and only send credentials for those.",
					references: [`${MDN}/Access-Control-Allow-Origin`],
					tags: ["cwe-942"],
				});
			const probe = yield* fetchCached(ctx, url, {
				headers: { origin: PROBE_ORIGIN },
				maxBytes: 1,
			}).pipe(Effect.option);
			if (probe._tag === "Some") {
				const reflected = probe.value.headers.get(
					"access-control-allow-origin",
				);
				const creds =
					probe.value.headers
						.get("access-control-allow-credentials")
						?.toLowerCase() === "true";
				if (reflected === PROBE_ORIGIN)
					add("cors-origin-reflected", creds ? "high" : "low", {
						title: creds
							? "CORS reflects any origin with credentials"
							: "CORS reflects any origin",
						message: creds
							? "The server echoes an arbitrary Origin in Access-Control-Allow-Origin and allows credentials, so any website can read authenticated responses on behalf of a logged-in visitor."
							: "The server echoes an arbitrary Origin in Access-Control-Allow-Origin. Without credentials the impact is limited to public data, but the policy is overly broad.",
						evidence: `origin: ${PROBE_ORIGIN} → access-control-allow-origin: ${reflected}${creds ? "; access-control-allow-credentials: true" : ""}`,
						remediation:
							"Validate the Origin against an allow-list instead of reflecting it.",
						references: [
							"https://portswigger.net/web-security/cors",
							`${MDN}/Access-Control-Allow-Origin`,
						],
						tags: ["cwe-942", "owasp-a05"],
					});
			}

			/* ------------------------------ cookies ------------------------------ */
			for (const raw of page.response.cookies) {
				const c = parseSetCookie(raw);
				if (!c.name) continue;
				const evidence = cookieEvidence(c);
				const sensitive = SESSION_COOKIE.test(c.name);
				const sameSite = c.attrs.get("samesite")?.toLowerCase();
				const cookieLoc = { url, selector: `cookie:${c.name}` };
				const push = (
					rule: string,
					severity: Severity,
					title: string,
					message: string,
					remediation: string,
				) =>
					findings.push({
						ruleId: `web.headers/${rule}`,
						title,
						severity,
						category: "security",
						message,
						location: cookieLoc,
						evidence,
						remediation,
						references: [
							`${MDN}/Set-Cookie`,
							"https://owasp.org/www-community/controls/SecureCookieAttribute",
						],
						tags: ["cwe-614"],
					});
				if (https && !c.attrs.has("secure"))
					push(
						"cookie-not-secure",
						sensitive ? "medium" : "low",
						`Cookie ${c.name} lacks Secure`,
						`Cookie \`${c.name}\` is set without the Secure attribute, so it can be sent over plain HTTP and intercepted.`,
						"Add the Secure attribute to every cookie on HTTPS sites.",
					);
				if (!c.attrs.has("httponly"))
					push(
						"cookie-not-httponly",
						sensitive ? "medium" : "low",
						`Cookie ${c.name} lacks HttpOnly`,
						`Cookie \`${c.name}\` is readable from JavaScript, so an XSS bug can steal it.${sensitive ? " Its name suggests it carries a session or token." : ""}`,
						"Add HttpOnly unless client-side script genuinely needs to read the cookie.",
					);
				if (!sameSite)
					push(
						"cookie-no-samesite",
						"low",
						`Cookie ${c.name} lacks SameSite`,
						`Cookie \`${c.name}\` has no SameSite attribute; behaviour then depends on browser defaults and cross-site requests may carry it (CSRF).`,
						"Set SameSite=Lax (or Strict) explicitly; use SameSite=None; Secure only for cookies that must be sent cross-site.",
					);
				else if (sameSite === "none" && !c.attrs.has("secure"))
					push(
						"cookie-samesite-none-insecure",
						"medium",
						`Cookie ${c.name} is SameSite=None without Secure`,
						`Cookie \`${c.name}\` uses SameSite=None without Secure; modern browsers reject it and older ones send it on every cross-site request.`,
						"Add Secure, or use SameSite=Lax.",
					);
			}

			return findings;
		}),
});
