import { Resolver as NodeResolver } from "node:dns/promises";
import {
	type AuditContext,
	AuditorError,
	defineAuditor,
	type FindingInput,
	type HttpResponse,
	requireUrl,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { truncate } from "./util";

/* -------------------------------------------------------------------------- */
/*                                  Resolver                                  */
/* -------------------------------------------------------------------------- */

export interface MxRecord {
	readonly exchange: string;
	readonly priority: number;
}

/**
 * DNS access, injectable so tests never touch the network. Every method
 * resolves to an empty result for NXDOMAIN / NODATA and rejects for anything
 * else (timeouts, SERVFAIL), so callers can tell "no record" from "unknown".
 */
export interface Resolver {
	/** TXT records, each with its character-strings concatenated. */
	readonly resolveTxt: (name: string) => Promise<ReadonlyArray<string>>;
	readonly resolveMx: (name: string) => Promise<ReadonlyArray<MxRecord>>;
	/** Number of CAA records at exactly `name`. */
	readonly resolveCaa: (name: string) => Promise<number>;
	/** The immediate CNAME target, if `name` is an alias. */
	readonly resolveCname: (name: string) => Promise<string | undefined>;
	/** False only for NXDOMAIN; true when the name has addresses or exists without them. */
	readonly nameExists: (name: string) => Promise<boolean>;
}

const EMPTY_CODES = new Set(["ENODATA", "ENOTFOUND", "NODATA", "NOTFOUND"]);

const isEmptyAnswer = (err: unknown): boolean => {
	const code = (err as { code?: unknown } | null)?.code;
	return typeof code === "string" && EMPTY_CODES.has(code.replace(/^DNS_/, ""));
};

/** Resolver backed by the system's configured DNS servers (via c-ares). */
export const systemResolver = (): Resolver => {
	const dns = new NodeResolver({ timeout: 4_000, tries: 2 });
	const empty =
		<A>(fallback: A) =>
		(err: unknown) => {
			if (isEmptyAnswer(err)) return fallback;
			throw err;
		};
	return {
		resolveTxt: (name) =>
			dns
				.resolveTxt(name)
				.then((rows) => rows.map((chunks) => chunks.join("")))
				.catch(empty([])),
		resolveMx: (name) => dns.resolveMx(name).catch(empty([])),
		resolveCaa: (name) =>
			dns
				.resolveCaa(name)
				.then((rows) => rows.length)
				.catch(empty(0)),
		resolveCname: (name) =>
			dns
				.resolveCname(name)
				.then((rows) => rows[0])
				.catch(empty(undefined)),
		nameExists: async (name) => {
			for (const family of [4, 6] as const) {
				try {
					const rows = await (family === 4
						? dns.resolve4(name)
						: dns.resolve6(name));
					if (rows.length > 0) return true;
				} catch (err) {
					const code = (err as { code?: string }).code ?? "";
					// ENODATA: the name exists, it just has no record of this type.
					if (code.endsWith("NODATA")) return true;
					if (!isEmptyAnswer(err)) throw err;
				}
			}
			return false;
		},
	};
};

/* -------------------------------------------------------------------------- */
/*                              Registrable domain                            */
/* -------------------------------------------------------------------------- */

/**
 * No public-suffix list is bundled. Instead: a short list of common two-label
 * public suffixes (`co.uk`, `com.au`, ...), otherwise the last two labels.
 * Uncommon multi-label suffixes (e.g. `k12.ca.us`) are therefore mis-split; the
 * DNS checks are then run against the suffix and will mostly report nothing.
 */
const TWO_LABEL_SUFFIXES = new Set(
	`co.uk org.uk me.uk ac.uk gov.uk ltd.uk plc.uk net.uk sch.uk
com.au net.au org.au edu.au gov.au co.nz org.nz net.nz govt.nz ac.nz
co.jp ne.jp or.jp ac.jp go.jp co.in net.in org.in gov.in ac.in
com.br net.br org.br gov.br com.cn net.cn org.cn gov.cn
com.mx com.ar com.co com.pe com.ve com.tr com.sg com.hk com.tw com.my com.ph com.vn
co.kr or.kr co.za org.za co.il co.id co.th co.ke com.ng com.pk com.bd com.eg com.sa
com.ua com.pl com.ru`.split(/\s+/),
);

/**
 * Hosting platforms whose subdomains belong to customers. The platform owns
 * the parent zone, so mail/CAA findings there are not the customer's to fix.
 */
const SHARED_SUFFIXES = [
	"github.io",
	"gitlab.io",
	"herokuapp.com",
	"vercel.app",
	"netlify.app",
	"pages.dev",
	"workers.dev",
	"azurewebsites.net",
	"cloudfront.net",
	"amazonaws.com",
	"appspot.com",
	"web.app",
	"firebaseapp.com",
	"onrender.com",
	"fly.dev",
	"railway.app",
	"surge.sh",
	"ngrok.io",
	"ngrok-free.app",
	"trycloudflare.com",
	"myshopify.com",
	"wordpress.com",
	"blogspot.com",
	"azurestaticapps.net",
	"cloudapp.azure.com",
	"trafficmanager.net",
	"readthedocs.io",
];

const isIp = (host: string) => /^[\d.]+$/.test(host) || host.includes(":");

export type DomainScope =
	| { readonly kind: "domain"; readonly host: string; readonly domain: string }
	| { readonly kind: "shared" | "none"; readonly host: string };

export const domainScope = (hostname: string): DomainScope => {
	const host = hostname
		.toLowerCase()
		.replace(/^\[|\]$/g, "")
		.replace(/\.$/, "");
	if (
		!host ||
		isIp(host) ||
		host === "localhost" ||
		host.endsWith(".localhost") ||
		host.endsWith(".local") ||
		host.endsWith(".internal") ||
		!host.includes(".")
	)
		return { kind: "none", host };
	if (SHARED_SUFFIXES.some((s) => host === s || host.endsWith(`.${s}`)))
		return { kind: "shared", host };
	const labels = host.split(".");
	const last2 = labels.slice(-2).join(".");
	const take = TWO_LABEL_SUFFIXES.has(last2) ? 3 : 2;
	if (labels.length < take) return { kind: "none", host };
	return { kind: "domain", host, domain: labels.slice(-take).join(".") };
};

/* -------------------------------------------------------------------------- */
/*                                  Parsers                                   */
/* -------------------------------------------------------------------------- */

const spfRecords = (txt: ReadonlyArray<string>) =>
	txt.filter((r) => /^\s*v=spf1(\s|$)/i.test(r));

const dmarcRecord = (txt: ReadonlyArray<string>) =>
	txt.find((r) => /^\s*v=DMARC1\s*(;|$)/i.test(r));

export const parseTags = (record: string): Map<string, string> => {
	const tags = new Map<string, string>();
	for (const part of record.split(";")) {
		const i = part.indexOf("=");
		if (i === -1) continue;
		const key = part.slice(0, i).trim().toLowerCase();
		if (key && !tags.has(key)) tags.set(key, part.slice(i + 1).trim());
	}
	return tags;
};

/** The `all` mechanism's qualifier in an SPF record, if there is one. */
export const spfAllQualifier = (record: string): string | undefined => {
	for (const term of record.trim().split(/\s+/).slice(1)) {
		const m = term.match(/^([+\-~?]?)all$/i);
		if (m) return m[1] || "+";
	}
	return undefined;
};

/** Mechanisms that cost a DNS lookup under RFC 7208 section 4.6.4. */
const SPF_LOOKUP = /^(a|mx|ptr)([:/]|$)|^exists:/i;

export interface SpfLookups {
	readonly count: number;
	/** False when the include tree was too large or unreadable to follow fully. */
	readonly complete: boolean;
}

const MAX_SPF_QUERIES = 15;

/** Counts SPF DNS-lookup mechanisms, recursing into include/redirect. */
export const countSpfLookups = async (
	resolver: Resolver,
	record: string,
): Promise<SpfLookups> => {
	let count = 0;
	let queries = 0;
	let complete = true;
	const seen = new Set<string>();
	const walk = async (rec: string): Promise<void> => {
		for (const raw of rec.trim().split(/\s+/).slice(1)) {
			const term = raw.replace(/^[+\-~?]/, "");
			const ref = term.match(/^(?:include:|redirect=)(\S+)$/i);
			if (ref?.[1]) {
				count++;
				const name = ref[1].toLowerCase();
				if (seen.has(name)) continue;
				seen.add(name);
				if (queries >= MAX_SPF_QUERIES) {
					complete = false;
					continue;
				}
				queries++;
				try {
					const child = spfRecords(await resolver.resolveTxt(name))[0];
					if (child) await walk(child);
				} catch {
					complete = false;
				}
			} else if (SPF_LOOKUP.test(term)) count++;
		}
	};
	await walk(record);
	return { count, complete };
};

/** Parses an MTA-STS policy file (`key: value` lines). */
export const parseMtaSts = (body: string): Map<string, string[]> => {
	const out = new Map<string, string[]>();
	for (const line of body.split(/\r?\n/)) {
		const m = line.match(/^\s*([A-Za-z_-]+)\s*:\s*(.*?)\s*$/);
		if (!m?.[1]) continue;
		const key = m[1].toLowerCase();
		out.set(key, [...(out.get(key) ?? []), m[2] ?? ""]);
	}
	return out;
};

/* -------------------------------------------------------------------------- */
/*                              Subdomain takeover                            */
/* -------------------------------------------------------------------------- */

interface TakeoverService {
	readonly name: string;
	/** CNAME targets (suffix match on the dot-separated name). */
	readonly suffixes: ReadonlyArray<string>;
	/** Unclaimed-resource page, per can-i-take-over-xyz. Absent: NXDOMAIN is the signal. */
	readonly fingerprint?: RegExp;
}

/**
 * Fingerprints follow https://github.com/EdOverflow/can-i-take-over-xyz.
 * CloudFront, Netlify and Fastly are left out on purpose: their "unknown
 * domain" pages also appear on healthy, merely misconfigured, setups and
 * those platforms verify domain ownership, so reporting them would be noise.
 */
const TAKEOVER_SERVICES: ReadonlyArray<TakeoverService> = [
	{
		name: "Heroku",
		suffixes: ["herokuapp.com", "herokudns.com"],
		fingerprint: /No such app/,
	},
	{
		name: "GitHub Pages",
		suffixes: ["github.io"],
		fingerprint: /There isn't a GitHub Pages site here\./,
	},
	{
		name: "AWS S3",
		suffixes: ["s3.amazonaws.com"],
		fingerprint: /The specified bucket does not exist/,
	},
	{
		name: "Shopify",
		suffixes: ["myshopify.com"],
		fingerprint: /Sorry, this shop is currently unavailable\./,
	},
	{
		name: "Surge.sh",
		suffixes: ["surge.sh"],
		fingerprint: /project not found/i,
	},
	{
		name: "Bitbucket",
		suffixes: ["bitbucket.io"],
		fingerprint: /Repository not found/,
	},
	{
		name: "Tumblr",
		suffixes: ["domains.tumblr.com"],
		fingerprint: /Whatever you were looking for doesn't currently exist/,
	},
	{
		name: "Pantheon",
		suffixes: ["pantheonsite.io"],
		fingerprint:
			/The gods are wise, but do not know of the site which you seek/,
	},
	{
		name: "Ghost",
		suffixes: ["ghost.io"],
		fingerprint:
			/The thing you were looking for is no longer here, or never was/,
	},
	// Azure resources are released with their DNS name, so a CNAME to a name
	// that no longer resolves is the whole signal.
	{
		name: "Azure App Service",
		suffixes: ["azurewebsites.net"],
	},
	{
		name: "Azure Cloud Services",
		suffixes: ["cloudapp.net", "cloudapp.azure.com"],
	},
	{
		name: "Azure Traffic Manager",
		suffixes: ["trafficmanager.net"],
	},
	{
		name: "Azure Blob Storage",
		suffixes: ["blob.core.windows.net"],
	},
];

const S3_HOST = /(^|\.)s3([.-][a-z0-9-]+)?\.amazonaws\.com$/i;

export const takeoverServiceFor = (
	target: string,
): TakeoverService | undefined => {
	const name = target.toLowerCase().replace(/\.$/, "");
	if (
		S3_HOST.test(name) ||
		/\.s3-website[.-][a-z0-9-]+\.amazonaws\.com$/.test(name)
	)
		return TAKEOVER_SERVICES.find((s) => s.name === "AWS S3");
	return TAKEOVER_SERVICES.find((s) =>
		s.suffixes.some((suffix) => name === suffix || name.endsWith(`.${suffix}`)),
	);
};

/** Does an HTTP response look like the service's "nothing here" page? */
export const matchesTakeoverFingerprint = (
	service: TakeoverService,
	res: Pick<HttpResponse, "status" | "body">,
): boolean =>
	service.fingerprint !== undefined &&
	res.status === 404 &&
	service.fingerprint.test(res.body);

/* -------------------------------------------------------------------------- */
/*                                  Auditor                                   */
/* -------------------------------------------------------------------------- */

const RFC = {
	spf: "https://www.rfc-editor.org/rfc/rfc7208",
	dmarc: "https://www.rfc-editor.org/rfc/rfc7489",
	caa: "https://www.rfc-editor.org/rfc/rfc8659",
	mtaSts: "https://www.rfc-editor.org/rfc/rfc8461",
	tlsRpt: "https://www.rfc-editor.org/rfc/rfc8460",
	nullMx: "https://www.rfc-editor.org/rfc/rfc7505",
	takeover: "https://github.com/EdOverflow/can-i-take-over-xyz",
};

/** Resolves to `undefined` when the lookup itself failed (unknown, not absent). */
const attempt = <A>(f: () => Promise<A>): Effect.Effect<A | undefined> =>
	Effect.promise(() => f().catch(() => undefined));

const MAX_CNAME_HOPS = 5;

export const makeDnsAuditor = (resolver: Resolver) =>
	defineAuditor({
		id: "web.dns",
		title: "DNS and email security",
		description:
			"Checks the target's registrable domain for SPF, DMARC, CAA, MTA-STS and TLS-RPT records, no-mail lockdown, and dangling CNAMEs to takeover-prone services. Lookups use the system resolver. DNSSEC is not checked: Node's resolver cannot validate signatures, so any verdict would be a guess.",
		categories: ["security", "best-practices"],
		targets: ["url"],
		engine: "builtin",
		// Queries go to the system resolver and a third-party policy host, not the target.
		network: true,
		run: (ctx: AuditContext) =>
			Effect.gen(function* () {
				const targetUrl = yield* requireUrl(ctx);
				const scope = domainScope(new URL(targetUrl).hostname);
				if (scope.kind === "none")
					return yield* skip(`${scope.host} is not a public DNS name`);
				const findings: FindingInput[] = [];
				const location = (name: string) => ({ url: `dns://${name}` });

				const add = (
					rule: string,
					severity: Severity,
					name: string,
					f: Omit<
						FindingInput,
						"ruleId" | "severity" | "category" | "location"
					> &
						Partial<Pick<FindingInput, "category">>,
				) =>
					findings.push({
						ruleId: `web.dns/${rule}`,
						severity,
						category: "security",
						location: location(name),
						...f,
					});

				/* ------------------------------ CNAME takeover ------------------------------ */
				yield* takeoverChecks(ctx, resolver, targetUrl, scope.host, add);

				if (scope.kind !== "domain") return findings;
				const domain = scope.domain;

				// Every lookup on a nonexistent domain answers "no records", which
				// would read as missing CAA, SPF and so on. Unknown (lookup failed)
				// is not proof of absence, so only a definite NXDOMAIN stops here.
				const exists = yield* attempt(() => resolver.nameExists(domain));
				if (exists === false)
					return yield* Effect.fail(
						new AuditorError({
							message: `${domain} does not exist in DNS (NXDOMAIN). Check the spelling of the target URL.`,
						}),
					);

				const [mx, txt, dmarcTxt, caaCount, mtaStsTxt, tlsRptTxt] =
					yield* Effect.all(
						[
							attempt(() => resolver.resolveMx(domain)),
							attempt(() => resolver.resolveTxt(domain)),
							attempt(() => resolver.resolveTxt(`_dmarc.${domain}`)),
							caaLookup(resolver, scope.host, domain),
							attempt(() => resolver.resolveTxt(`_mta-sts.${domain}`)),
							attempt(() => resolver.resolveTxt(`_smtp._tls.${domain}`)),
						],
						{ concurrency: 6 },
					);

				// A null MX (RFC 7505) is an explicit "this domain sends and receives no mail".
				const realMx = mx?.filter((r) => r.exchange.replace(/\.$/, "") !== "");
				const hasMail = realMx === undefined ? undefined : realMx.length > 0;
				const spf = txt ? spfRecords(txt) : undefined;
				const dmarc = dmarcTxt ? dmarcRecord(dmarcTxt) : undefined;
				const mailTags = ["email", "spoofing"];

				/* ----------------------------------- SPF ------------------------------------ */
				if (spf !== undefined) {
					if (spf.length === 0 && hasMail)
						add("spf-missing", "medium", domain, {
							title: "No SPF record",
							message: `${domain} receives mail (it has MX records) but publishes no SPF record, so receivers cannot tell which servers may send as this domain and spoofed mail is easier to deliver.`,
							remediation:
								'Publish a TXT record such as "v=spf1 include:<your-mail-provider> -all" listing every legitimate sender.',
							references: [RFC.spf],
							tags: mailTags,
						});
					if (spf.length > 1)
						add("spf-multiple-records", "low", domain, {
							title: "Multiple SPF records",
							message: `${domain} publishes ${spf.length} SPF records. RFC 7208 requires exactly one; receivers return a permanent error and ignore SPF entirely.`,
							evidence: truncate(spf.join(" | "), 200),
							remediation: "Merge the records into a single v=spf1 TXT record.",
							references: [RFC.spf],
							tags: mailTags,
						});
					const record = spf[0];
					if (record) {
						const q = spfAllQualifier(record);
						if (q === "+")
							add("spf-allow-all", "medium", domain, {
								title: "SPF allows every sender (+all)",
								message: `The SPF record ends in ${record.match(/(?:^|\s)[+]?all\b/i)?.[0].trim() ?? "+all"}, which authorises any server on the internet to send as ${domain}. It is equivalent to having no SPF.`,
								evidence: truncate(record, 200),
								remediation:
									"End the record with -all (or ~all while rolling out) after the legitimate senders.",
								references: [RFC.spf],
								tags: mailTags,
							});
						else if (q === "?")
							add("spf-neutral-all", "low", domain, {
								title: "SPF ends in ?all (neutral)",
								message:
									"The SPF record ends in ?all, which states no opinion on unlisted senders, so SPF gives receivers nothing to act on.",
								evidence: truncate(record, 200),
								remediation: "Use ~all or, once validated, -all.",
								references: [RFC.spf],
								tags: mailTags,
							});
						if (spf.length === 1) {
							const lookups = yield* Effect.promise(() =>
								countSpfLookups(resolver, record),
							);
							if (lookups.count > 10)
								add("spf-too-many-lookups", "low", domain, {
									title: `SPF needs about ${lookups.count} DNS lookups (limit 10)`,
									message: `Evaluating the SPF record takes ${lookups.complete ? "" : "at least "}${lookups.count} DNS-querying mechanisms (include, a, mx, ptr, exists, redirect). Above 10, receivers return a permanent error and SPF fails for all mail. The count is approximate: void lookups and nested mx expansion are not modelled.`,
									evidence: truncate(record, 200),
									remediation:
										"Flatten includes, drop unused providers, or use a flattening service.",
									references: [RFC.spf],
									tags: mailTags,
									confidence: "medium",
								});
						}
					}
				}

				/* ---------------------------------- no-mail ---------------------------------- */
				if (hasMail === false && spf !== undefined) {
					const locked = spf.some((r) => spfAllQualifier(r) === "-");
					const nullMx = mx?.some((r) => r.exchange.replace(/\.$/, "") === "");
					if (!locked || !nullMx)
						add("no-mail-not-locked-down", "low", domain, {
							title:
								"Domain sends no mail but is not locked down against spoofing",
							message: `${domain} has no MX records, yet ${[
								!locked ? 'no SPF "-all" record' : undefined,
								!nullMx ? "no null MX" : undefined,
							]
								.filter(Boolean)
								.join(" and ")} to say so, so attackers can spoof it freely.`,
							remediation:
								'If the domain sends and receives no mail, publish a null MX (priority 0, target ".") and the TXT record "v=spf1 -all", plus a DMARC policy of p=reject.',
							references: [RFC.nullMx, RFC.spf],
							tags: mailTags,
						});
				}

				/* ---------------------------------- DMARC ----------------------------------- */
				if (dmarcTxt !== undefined) {
					if (!dmarc) {
						if (hasMail !== undefined)
							add(
								"dmarc-missing",
								hasMail ? "medium" : "info",
								`_dmarc.${domain}`,
								{
									title: "No DMARC record",
									message: hasMail
										? `${domain} receives mail but publishes no DMARC policy, so receivers have no instruction to reject spoofed mail and you get no abuse reports.`
										: `${domain} publishes no DMARC policy. It sends no mail, but a p=reject policy stops others from spoofing it.`,
									remediation:
										'Publish a TXT record at _dmarc.<domain>, e.g. "v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>", then tighten to p=reject.',
									references: [RFC.dmarc],
									tags: mailTags,
								},
							);
					} else {
						const tags = parseTags(dmarc);
						const p = (tags.get("p") ?? "").toLowerCase();
						const name = `_dmarc.${domain}`;
						if (p === "none")
							add("dmarc-policy-none", "low", name, {
								title: "DMARC policy is p=none",
								message:
									"The DMARC policy is monitor-only: spoofed mail failing authentication is still delivered.",
								evidence: truncate(dmarc, 200),
								remediation:
									"Review the aggregate reports, then move to p=quarantine and p=reject.",
								references: [RFC.dmarc],
								tags: mailTags,
							});
						const pct = Number(tags.get("pct"));
						if (tags.has("pct") && Number.isFinite(pct) && pct < 100)
							add("dmarc-pct-partial", "low", name, {
								title: `DMARC applies to only ${pct}% of mail`,
								message: `pct=${pct} means the policy is enforced on a sample of failing mail, leaving the rest unprotected.`,
								evidence: truncate(dmarc, 200),
								remediation:
									"Raise pct to 100 (or remove it) once reports look clean.",
								references: [RFC.dmarc],
								tags: mailTags,
							});
						if (!tags.get("rua"))
							add("dmarc-no-rua", "info", name, {
								title: "DMARC has no aggregate report address (rua)",
								message:
									"Without rua= you receive no reports about who sends mail as your domain, which makes tightening the policy risky.",
								evidence: truncate(dmarc, 200),
								remediation:
									"Add rua=mailto:<address> to receive aggregate reports.",
								references: [RFC.dmarc],
								tags: mailTags,
							});
					}
				}

				/* ----------------------------------- CAA ------------------------------------ */
				if (caaCount === 0)
					add("caa-missing", "low", domain, {
						category: "best-practices",
						title: "No CAA record",
						message: `No CAA record is published for ${scope.host} or ${domain}, so any certificate authority may issue certificates for it.`,
						remediation:
							'Publish CAA records naming the CAs you use, e.g. `0 issue "letsencrypt.org"`.',
						references: [RFC.caa],
						tags: ["tls", "certificates"],
					});

				/* ------------------------- MTA-STS and TLS-RPT (mail domains) ------------------------- */
				if (hasMail) {
					const stsRecord = mtaStsTxt?.find((r) => /^\s*v=STSv1\b/i.test(r));
					if (mtaStsTxt !== undefined && !stsRecord)
						add("mta-sts-missing", "info", `_mta-sts.${domain}`, {
							category: "best-practices",
							title: "No MTA-STS policy",
							message: `${domain} receives mail but does not publish MTA-STS, so senders cannot be told to require TLS and a network attacker can downgrade SMTP to plaintext.`,
							remediation:
								'Publish "v=STSv1; id=<version>" at _mta-sts.<domain> and serve a policy at https://mta-sts.<domain>/.well-known/mta-sts.txt with mode: enforce.',
							references: [RFC.mtaSts],
							tags: ["email", "tls"],
						});
					if (stsRecord) {
						const url = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
						const res = yield* ctx
							.http(url, {
								redirect: "manual",
								timeoutMs: 8_000,
								maxBytes: 16 * 1024,
							})
							.pipe(Effect.option);
						if (res._tag === "None" || res.value.status !== 200)
							add("mta-sts-policy-unreachable", "low", url, {
								category: "best-practices",
								title: "MTA-STS policy file is not reachable",
								message: `${domain} advertises MTA-STS but ${url} ${res._tag === "None" ? "could not be fetched (DNS, TLS or connection error)" : `answered ${res.value.status}`}, so senders ignore the policy.`,
								evidence: stsRecord,
								remediation:
									"Serve the policy over HTTPS with a valid certificate for mta-sts.<domain>, with status 200 and no redirect.",
								references: [RFC.mtaSts],
								tags: ["email", "tls"],
							});
						else {
							const policy = parseMtaSts(res.value.body);
							const mode = policy.get("mode")?.[0]?.toLowerCase();
							if (mode !== "enforce")
								add("mta-sts-not-enforced", "low", url, {
									category: "best-practices",
									title: `MTA-STS mode is ${mode ?? "missing"}, not enforce`,
									message:
										"Only mode: enforce makes senders refuse to deliver over unencrypted or unauthenticated connections.",
									evidence: truncate(res.value.body.replace(/\s+/g, " "), 160),
									remediation:
										"Move to mode: enforce after reviewing TLS-RPT reports in testing mode.",
									references: [RFC.mtaSts],
									tags: ["email", "tls"],
								});
						}
					}
					if (
						tlsRptTxt !== undefined &&
						!tlsRptTxt.some((r) => /^\s*v=TLSRPTv1\b/i.test(r))
					)
						add("tls-rpt-missing", "info", `_smtp._tls.${domain}`, {
							category: "best-practices",
							title: "No TLS-RPT record",
							message:
								"Without a TLS-RPT record, sending providers cannot report TLS failures when delivering mail to this domain.",
							remediation:
								'Publish "v=TLSRPTv1; rua=mailto:<address>" at _smtp._tls.<domain>.',
							references: [RFC.tlsRpt],
							tags: ["email", "tls"],
						});
				}

				return findings;
			}),
	});

/** CAA applies to the closest name in the tree that has records, up to the registrable domain. */
const caaLookup = (resolver: Resolver, host: string, domain: string) =>
	Effect.promise(async (): Promise<number | undefined> => {
		const labels = host.split(".");
		const depth = domain.split(".").length;
		for (let i = 0; labels.length - i >= depth; i++) {
			try {
				const n = await resolver.resolveCaa(labels.slice(i).join("."));
				if (n > 0) return n;
			} catch {
				return undefined;
			}
		}
		return 0;
	});

type Add = (
	rule: string,
	severity: Severity,
	name: string,
	f: Omit<FindingInput, "ruleId" | "severity" | "category" | "location"> &
		Partial<Pick<FindingInput, "category">>,
) => unknown;

/** Follows the target host's CNAME chain and checks takeover-prone endpoints. */
const takeoverChecks = (
	ctx: AuditContext,
	resolver: Resolver,
	targetUrl: string,
	host: string,
	add: Add,
) =>
	Effect.gen(function* () {
		const chain: string[] = [];
		let current = host;
		for (let i = 0; i < MAX_CNAME_HOPS; i++) {
			const next = yield* attempt(() => resolver.resolveCname(current));
			if (!next) break;
			const name = next.toLowerCase().replace(/\.$/, "");
			if (chain.includes(name)) break;
			chain.push(name);
			current = name;
		}
		const hit = chain
			.map((name) => ({ name, service: takeoverServiceFor(name) }))
			.find((c) => c.service !== undefined);
		const service = hit?.service;
		if (!hit || !service) return;
		const evidence = `${host} → ${chain.join(" → ")}`;
		const finding = (why: string) =>
			add("dangling-cname", "high", host, {
				title: `Possible subdomain takeover via ${service.name}`,
				message: `${host} is a CNAME to ${hit.name} (${service.name}) ${why}. Anyone who registers that resource on ${service.name} can serve content on ${host}, including phishing pages and scripts that read its cookies.`,
				evidence,
				remediation: `Delete the DNS record for ${host} if it is no longer used, or re-create the ${service.name} resource it points to.`,
				references: [RFC.takeover],
				tags: ["subdomain-takeover", "dns", "cwe-923"],
				confidence: "medium",
			});

		if (!service.fingerprint) {
			// Only the last hop can be the released resource; earlier hops are other aliases.
			const exists = yield* attempt(() => resolver.nameExists(hit.name));
			if (exists === false) finding("which no longer resolves (NXDOMAIN)");
			return;
		}
		for (const url of [
			targetUrl,
			targetUrl.replace(/^https:/i, "http:"),
		].filter((u, i, all) => all.indexOf(u) === i)) {
			const res = yield* ctx
				.http(url, {
					redirect: "manual",
					timeoutMs: 8_000,
					maxBytes: 64 * 1024,
				})
				.pipe(Effect.option);
			if (
				res._tag === "Some" &&
				matchesTakeoverFingerprint(service, res.value)
			) {
				finding("and the service answers with its unclaimed-resource page");
				return;
			}
		}
	});

/** Default instance backed by the system resolver. */
export const dns = makeDnsAuditor(systemResolver());
