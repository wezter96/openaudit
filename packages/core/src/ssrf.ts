import { lookup as dnsLookup } from "node:dns/promises";
import { isIP } from "node:net";
import { Effect, Layer } from "effect";

import type { Auditor } from "./auditor";
import { AuditorError } from "./errors";
import {
	Http,
	type HttpRequest,
	type HttpResponse,
	USER_AGENT,
} from "./services";

/**
 * Server-side request forgery guard for the public `audit.url` endpoint.
 *
 * An audit service that fetches arbitrary user-supplied URLs is a textbook
 * SSRF target: without these checks anyone could make the server probe its own
 * loopback interface, the cloud metadata service (169.254.169.254) or the
 * private network it is deployed in.
 *
 * The guard:
 * - accepts only http/https URLs without embedded credentials,
 * - accepts only the default ports and 80/443/8080/8443,
 * - rejects internal-looking hostnames (`localhost`, `*.internal`, single labels),
 * - resolves the hostname and rejects it unless *every* address is public
 *   (IPv4 and IPv6, including IPv4-mapped/NAT64/6to4 embeddings).
 *
 * DNS rebinding: if we validated a name and then let `fetch` resolve it again,
 * a hostile DNS server with a zero TTL could answer with a public address for
 * the check and a private one for the connection. `resolvePublicUrl` therefore
 * returns the exact address it validated, and callers connect to that literal
 * IP (see `pinnedFetch` in audit.ts), keeping the hostname for the Host header
 * and for TLS SNI and certificate verification. Every redirect hop is resolved,
 * validated and pinned again before connecting.
 */

export type SsrfReason =
	| "invalid-url"
	| "protocol"
	| "credentials"
	| "port"
	| "hostname"
	| "private-address"
	| "dns";

export class SsrfError extends Error {
	readonly _tag = "SsrfError";
	constructor(
		readonly reason: SsrfReason,
		message: string,
	) {
		super(message);
		this.name = "SsrfError";
	}
}

export interface GuardOptions {
	/** Skip address/port/hostname checks (self-hosting against internal targets). */
	readonly allowPrivate?: boolean;
	/** Injectable resolver for tests; defaults to `dns.lookup(…, { all: true })`. */
	readonly lookup?: (hostname: string) => Promise<ReadonlyArray<string>>;
	/** Test hook to treat chosen resolved addresses as public. Never set in production. */
	readonly isPublicAddress?: (address: string) => boolean;
}

export interface ResolvedUrl {
	readonly url: URL;
	/**
	 * The validated address to connect to. Undefined only with `allowPrivate`,
	 * where no pinning is needed because nothing is being blocked.
	 */
	readonly address: string | undefined;
}

export const ALLOWED_PORTS: ReadonlySet<string> = new Set([
	"",
	"80",
	"443",
	"8080",
	"8443",
]);

const BLOCKED_HOST_SUFFIXES = [
	".localhost",
	".local",
	".internal",
	".intranet",
	".lan",
	".home.arpa",
	".arpa",
];

/** An IP address as written, possibly in brackets or with a zone id. */
type AddressText = string;
type Hostname = string;
type UrlText = string;
/** A CIDR range such as `10.0.0.0/8`. */
type Cidr = string;
/** An IPv4 address as an unsigned 32-bit integer. */
type IPv4Int = number;
type ByteCount = number;

/* ---------------------------------- IPv4 ---------------------------------- */

/** Strict dotted-quad parser. Returns the address as an unsigned 32-bit int. */
export const parseIPv4 = (input: AddressText): IPv4Int | undefined => {
	const parts = input.split(".");
	if (parts.length !== 4) return undefined;
	let n = 0;
	for (const part of parts) {
		if (!/^\d{1,3}$/.test(part)) return undefined;
		const octet = Number(part);
		if (octet > 255) return undefined;
		n = n * 256 + octet;
	}
	return n;
};

const v4 = (cidr: Cidr): readonly [IPv4Int, number] => {
	const [base = "", bits = "32"] = cidr.split("/");
	return [parseIPv4(base) ?? 0, Number(bits)];
};

/** IANA special-purpose IPv4 ranges that must never be fetched. */
const PRIVATE_V4 = [
	"0.0.0.0/8", // "this" network
	"10.0.0.0/8", // private
	"100.64.0.0/10", // carrier-grade NAT
	"127.0.0.0/8", // loopback
	"169.254.0.0/16", // link-local, incl. cloud metadata 169.254.169.254
	"172.16.0.0/12", // private
	"192.0.0.0/24", // IETF protocol assignments
	"192.0.2.0/24", // TEST-NET-1
	"192.31.196.0/24", // AS112
	"192.52.193.0/24", // AMT
	"192.88.99.0/24", // 6to4 relay anycast
	"192.168.0.0/16", // private
	"192.175.48.0/24", // AS112
	"198.18.0.0/15", // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24", // TEST-NET-3
	"224.0.0.0/4", // multicast
	"240.0.0.0/4", // reserved + broadcast
].map(v4);

const inV4 = (
	ip: IPv4Int,
	[base, bits]: readonly [IPv4Int, number],
): boolean => {
	if (bits === 0) return true;
	const size = 2 ** (32 - bits);
	return Math.floor(ip / size) === Math.floor(base / size);
};

export const isPrivateIPv4 = (ip: IPv4Int): boolean =>
	PRIVATE_V4.some((range) => inV4(ip, range));

/* ---------------------------------- IPv6 ---------------------------------- */

/** Lowercased, without brackets or a zone id; undefined unless it has a colon. */
const bareV6 = (input: AddressText): AddressText | undefined => {
	let s = input.trim().toLowerCase();
	if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
	const zone = s.indexOf("%");
	if (zone !== -1) s = s.slice(0, zone);
	return s.includes(":") ? s : undefined;
};

/** Rewrites an embedded IPv4 tail, e.g. ::ffff:127.0.0.1, as two hex groups. */
const withHexTail = (s: AddressText): AddressText | undefined => {
	const lastColon = s.lastIndexOf(":");
	const tail = s.slice(lastColon + 1);
	if (!tail.includes(".")) return s;
	const ip4 = parseIPv4(tail);
	if (ip4 === undefined) return undefined;
	const hi = ((ip4 >>> 16) & 0xffff).toString(16);
	const lo = (ip4 & 0xffff).toString(16);
	return `${s.slice(0, lastColon + 1)}${hi}:${lo}`;
};

/** The eight groups with `::` expanded, or undefined when there are not eight. */
const v6Groups = (s: AddressText): string[] | undefined => {
	const halves = s.split("::");
	if (halves.length > 2) return undefined;
	const head = halves[0] ? halves[0].split(":") : [];
	const rest = halves[1] ? halves[1].split(":") : [];
	const missing = 8 - head.length - rest.length;
	if (halves.length === 1 ? missing !== 0 : missing < 1) return undefined;
	return [...head, ...Array<string>(missing).fill("0"), ...rest];
};

const groupsToBigint = (groups: ReadonlyArray<string>): bigint | undefined => {
	let n = 0n;
	for (const g of groups) {
		if (!/^[0-9a-f]{1,4}$/.test(g)) return undefined;
		n = (n << 16n) | BigInt(Number.parseInt(g, 16));
	}
	return n;
};

/** Parses any textual IPv6 form (incl. `::`, embedded IPv4, zone ids) to a 128-bit bigint. */
export const parseIPv6 = (input: AddressText): bigint | undefined => {
	const bare = bareV6(input);
	if (bare === undefined) return undefined;
	const s = withHexTail(bare);
	if (s === undefined) return undefined;
	const groups = v6Groups(s);
	return groups ? groupsToBigint(groups) : undefined;
};

const v6 = (cidr: Cidr): readonly [bigint, number] => {
	const [base = "", bits = "128"] = cidr.split("/");
	return [parseIPv6(base) ?? 0n, Number(bits)];
};

const inV6 = (ip: bigint, [base, bits]: readonly [bigint, number]): boolean => {
	const shift = BigInt(128 - bits);
	return ip >> shift === base >> shift;
};

const GLOBAL_UNICAST = v6("2000::/3");
const MAPPED_V4 = v6("::ffff:0:0/96");
const NAT64 = v6("64:ff9b::/96");
const SIX_TO_FOUR = v6("2002::/16");

/** Ranges inside 2000::/3 that are still not publicly routable. */
const PRIVATE_V6_IN_GLOBAL = [
	"2001::/32", // Teredo (tunnels to arbitrary IPv4)
	"2001:2::/48", // benchmarking
	"2001:10::/28", // ORCHID
	"2001:20::/28", // ORCHIDv2
	"2001:db8::/32", // documentation
	"3fff::/20", // documentation
].map(v6);

const low32 = (ip: bigint): number => Number(ip & 0xffffffffn);

export const isPrivateIPv6 = (ip: bigint): boolean => {
	// IPv4-mapped (::ffff:a.b.c.d) and NAT64 (64:ff9b::a.b.c.d) embed an IPv4
	// address that is what the packet actually reaches.
	if (inV6(ip, MAPPED_V4) || inV6(ip, NAT64)) return isPrivateIPv4(low32(ip));
	if (inV6(ip, SIX_TO_FOUR))
		return isPrivateIPv4(Number((ip >> 80n) & 0xffffffffn));
	// Allow-list: only global unicast is public. This rejects ::, ::1,
	// IPv4-compatible ::/96, fc00::/7 (incl. fd00::/8), fe80::/10, fec0::/10,
	// ff00::/8 multicast and 100::/64 discard.
	if (!inV6(ip, GLOBAL_UNICAST)) return true;
	return PRIVATE_V6_IN_GLOBAL.some((range) => inV6(ip, range));
};

/** True for any address we must not connect to. Unparseable input counts as private. */
export const isPrivateAddress = (address: AddressText): boolean => {
	const family = isIP(address.replace(/^\[|\]$/g, "").split("%")[0] ?? "");
	if (family === 4) {
		const ip = parseIPv4(address);
		return ip === undefined || isPrivateIPv4(ip);
	}
	if (family === 6) {
		const ip = parseIPv6(address);
		return ip === undefined || isPrivateIPv6(ip);
	}
	return true;
};

/* --------------------------------- URLs ----------------------------------- */

const defaultLookup = async (hostname: Hostname) =>
	(await dnsLookup(hostname, { all: true, verbatim: true })).map(
		(r) => r.address,
	);

/** Hostname without IPv6 brackets or a trailing dot, lowercased. */
const normalizeHost = (hostname: Hostname) =>
	hostname
		.toLowerCase()
		.replace(/^\[|\]$/g, "")
		.replace(/\.$/, "");

const parseUrl = (input: UrlText): URL => {
	try {
		return new URL(input);
	} catch {
		throw new SsrfError(
			"invalid-url",
			"Enter a full URL such as https://example.com",
		);
	}
};

const WEB_PROTOCOLS = new Set(["http:", "https:"]);

const checkScheme = (url: URL): void => {
	if (!WEB_PROTOCOLS.has(url.protocol))
		throw new SsrfError("protocol", "Only http and https URLs can be audited");
	if (url.username || url.password)
		throw new SsrfError(
			"credentials",
			"URLs with embedded credentials are not accepted",
		);
};

const isInternalHostname = (host: Hostname): boolean =>
	host === "localhost" ||
	!host.includes(".") ||
	BLOCKED_HOST_SUFFIXES.some((suffix) => host.endsWith(suffix));

const checkHost = (host: Hostname): void => {
	if (isIP(host)) {
		if (isPrivateAddress(host))
			throw new SsrfError(
				"private-address",
				"Refusing to audit a private, loopback, link-local or reserved address",
			);
		return;
	}
	if (isInternalHostname(host))
		throw new SsrfError(
			"hostname",
			`Refusing to audit internal hostname "${host}"`,
		);
};

/**
 * Syntactic checks only (no DNS): protocol, credentials, port, hostname shape.
 * Returns the parsed URL.
 */
export const parsePublicUrl = (
	input: UrlText,
	options: GuardOptions = {},
): URL => {
	const url = parseUrl(input);
	checkScheme(url);
	if (options.allowPrivate) return url;
	if (!ALLOWED_PORTS.has(url.port))
		throw new SsrfError(
			"port",
			`Port ${url.port} is not allowed; use 80, 443, 8080 or 8443`,
		);
	checkHost(normalizeHost(url.hostname));
	return url;
};

/** IPv4 first: servers often lack IPv6 egress even when a host publishes AAAA. */
const pickAddress = (addresses: ReadonlyArray<string>): string =>
	addresses.find((a) => isIP(a) === 4) ?? (addresses[0] as string);

/**
 * Full check: syntax, then one DNS resolution. Every resolved address must be
 * public (so a name with one public and one private record is rejected), and
 * the address to connect to is returned so the caller can pin it.
 */
export const resolvePublicUrl = async (
	input: UrlText,
	options: GuardOptions = {},
): Promise<ResolvedUrl> => {
	const url = parsePublicUrl(input, options);
	if (options.allowPrivate) return { url, address: undefined };
	const host = normalizeHost(url.hostname);
	if (isIP(host)) return { url, address: host };

	let addresses: ReadonlyArray<string>;
	try {
		addresses = await (options.lookup ?? defaultLookup)(host);
	} catch {
		throw new SsrfError("dns", `Could not resolve ${host}`);
	}
	if (addresses.length === 0)
		throw new SsrfError("dns", `Could not resolve ${host}`);
	const isPublic =
		options.isPublicAddress ?? ((a: string) => !isPrivateAddress(a));
	if (!addresses.every(isPublic))
		throw new SsrfError(
			"private-address",
			`Refusing to audit ${host}: it resolves to a private, loopback, link-local or reserved address`,
		);
	return { url, address: pickAddress(addresses) };
};

/** `resolvePublicUrl` for callers that only need the verdict. */
export const assertPublicUrl = async (
	input: UrlText,
	options: GuardOptions = {},
): Promise<URL> => (await resolvePublicUrl(input, options)).url;

/* ------------------------------ Guarded HTTP ------------------------------ */

export interface GuardedFetchLimits {
	readonly requestTimeoutMs: number;
	readonly maxRedirects: number;
	readonly maxResponseBytes: number;
}

/** Sensible defaults for servers that guard URL targets. */
export const DEFAULT_GUARDED_LIMITS: GuardedFetchLimits = {
	requestTimeoutMs: 15_000,
	maxRedirects: 5,
	maxResponseBytes: 5 * 1024 * 1024,
};

/** The first `size` bytes of `chunks`, joined. */
const joinCapped = (
	chunks: ReadonlyArray<Uint8Array>,
	size: ByteCount,
): Uint8Array => {
	const buf = new Uint8Array(size);
	let offset = 0;
	for (const chunk of chunks) {
		const part = chunk.subarray(0, buf.byteLength - offset);
		buf.set(part, offset);
		offset += part.byteLength;
		if (offset >= buf.byteLength) break;
	}
	return buf;
};

const readLimited = async (
	res: Response,
	maxBytes: ByteCount,
): Promise<{ body: string; bytes: number }> => {
	if (!res.body) return { body: "", bytes: 0 };
	const reader = res.body.getReader();
	const chunks: Uint8Array[] = [];
	let bytes = 0;
	while (bytes < maxBytes) {
		const { done, value } = await reader.read();
		if (done) break;
		chunks.push(value);
		bytes += value.byteLength;
	}
	await reader.cancel().catch(() => {});
	const buf = joinCapped(chunks, Math.min(bytes, maxBytes));
	return { body: new TextDecoder().decode(buf), bytes };
};

const SENSITIVE_HEADERS = ["authorization", "cookie", "proxy-authorization"];

/** The URL to dial: the validated literal IP in place of the hostname. */
const pinnedUrl = (url: URL, address: AddressText): UrlText => {
	const pinned = new URL(url);
	pinned.hostname = address.includes(":") ? `[${address}]` : address;
	return pinned.toString();
};

/**
 * Fetch options that send the request to the pinned IP while the server still
 * sees the original hostname: `Host` header, TLS SNI, and certificate
 * verification against the hostname (Bun's `tls.serverName`; covered by the
 * "verifies certificates against the hostname" test).
 */
const pinnedInit = (
	url: URL,
	headers: Record<string, string>,
): RequestInit & { tls?: { serverName?: string } } => {
	const sansHost = Object.fromEntries(
		Object.entries(headers).filter(([k]) => k.toLowerCase() !== "host"),
	);
	const hostname = url.hostname.replace(/^\[|\]$/g, "");
	return {
		headers: { ...sansHost, host: url.host },
		// A pooled connection opened for another hostname on the same IP would
		// skip the certificate check for this one.
		keepalive: false,
		...(url.protocol === "https:" && !isIP(hostname)
			? { tls: { serverName: hostname } }
			: {}),
	};
};

/** Guard options plus an injectable `fetch`. */
type FetchGuard = GuardOptions & {
	/** Injectable for tests. */
	readonly fetch?: (url: string, init: RequestInit) => Promise<Response>;
};

export interface GuardedFetchOptions {
	readonly guard: FetchGuard;
	readonly limits: GuardedFetchLimits;
	/** Aborts the request, e.g. when the caller's effect is interrupted. */
	readonly signal?: AbortSignal;
}

/** What every hop of one guarded request shares. */
interface GuardedRequest {
	readonly guard: FetchGuard;
	readonly doFetch: (url: string, init: RequestInit) => Promise<Response>;
	readonly signal: AbortSignal;
	readonly maxRedirects: number;
}

/** Request state that changes as redirects are followed. */
interface GuardedHop {
	readonly current: UrlText;
	readonly method: string;
	readonly body: string | undefined;
	readonly headers: Record<string, string>;
}

/** Resolves, validates and pins one hop, then sends it. */
const sendHop = async (hop: GuardedHop, req: GuardedRequest) => {
	const { url, address } = await resolvePublicUrl(hop.current, req.guard);
	const current = url.toString();
	const res = await req.doFetch(
		address === undefined ? current : pinnedUrl(url, address),
		{
			method: hop.method,
			body: hop.body,
			redirect: "manual",
			signal: req.signal,
			...(address === undefined
				? { headers: hop.headers }
				: pinnedInit(url, hop.headers)),
		},
	);
	return { url, res };
};

/** Where a 3xx response points, unless the caller handles redirects. */
const redirectTarget = (
	res: Response,
	init: HttpRequest,
): string | undefined => {
	const location = res.headers.get("location");
	if (!location || init.redirect === "manual") return undefined;
	return res.status >= 300 && res.status < 400 ? location : undefined;
};

/** Per the fetch spec, 301/302 after POST and every 303 become GET. */
const becomesGet = (res: Response, hop: GuardedHop): boolean =>
	res.status === 303 ||
	(hop.method === "POST" && (res.status === 301 || res.status === 302));

const withoutSensitive = (
	headers: Record<string, string>,
): Record<string, string> =>
	Object.fromEntries(
		Object.entries(headers).filter(
			([k]) => !SENSITIVE_HEADERS.includes(k.toLowerCase()),
		),
	);

/** The next hop, from `url`, which answered with a redirect to `location`. */
const followHop = (
	hop: GuardedHop,
	res: Response,
	location: UrlText,
	url: URL,
): GuardedHop => {
	const next = new URL(location, url.toString());
	const get = becomesGet(res, hop);
	return {
		current: next.toString(),
		headers:
			next.origin === url.origin ? hop.headers : withoutSensitive(hop.headers),
		method: get ? "GET" : hop.method,
		body: get ? undefined : hop.body,
	};
};

const followGuarded = async (
	input: UrlText,
	init: HttpRequest,
	req: GuardedRequest,
): Promise<{ res: Response; url: UrlText; redirected: boolean }> => {
	let hop: GuardedHop = {
		current: input,
		method: init.method ?? "GET",
		body: init.body,
		headers: { "user-agent": USER_AGENT, ...init.headers },
	};
	for (let n = 0; ; n++) {
		const { url, res } = await sendHop(hop, req);
		const location = redirectTarget(res, init);
		if (!location) return { res, url: url.toString(), redirected: n > 0 };
		await res.body?.cancel().catch(() => {});
		if (n >= req.maxRedirects)
			throw new Error(`Too many redirects (>${req.maxRedirects})`);
		// Resolved, validated and pinned at the top of the next iteration.
		hop = followHop(hop, res, location, url);
	}
};

/**
 * `fetch` that only ever connects to addresses the SSRF guard validated.
 * Each hop (the initial URL and every redirect) is resolved once, every
 * resolved address is checked, and the connection goes to the checked literal
 * IP, so a DNS answer that changes between check and connect (rebinding) has
 * no effect. Redirects are followed manually for that reason.
 */
export const guardedFetch = async (
	input: UrlText,
	init: HttpRequest,
	{ guard, limits, signal }: GuardedFetchOptions,
): Promise<HttpResponse> => {
	const controller = new AbortController();
	signal?.addEventListener("abort", () => controller.abort());
	const timer = setTimeout(
		() => controller.abort(),
		Math.min(
			init.timeoutMs ?? limits.requestTimeoutMs,
			limits.requestTimeoutMs,
		),
	);
	const maxBytes = Math.min(
		init.maxBytes ?? limits.maxResponseBytes,
		limits.maxResponseBytes,
	);
	const started = performance.now();
	try {
		const final = await followGuarded(input, init, {
			guard,
			doFetch: guard.fetch ?? fetch,
			signal: controller.signal,
			maxRedirects: limits.maxRedirects,
		});
		const { res } = final;
		const ttfbMs = performance.now() - started;
		const read = await readLimited(res, maxBytes);
		return {
			url: final.url,
			status: res.status,
			headers: res.headers,
			cookies: res.headers.getSetCookie(),
			body: read.body,
			bytes: read.bytes,
			redirected: final.redirected,
			ttfbMs,
			totalMs: performance.now() - started,
		};
	} finally {
		clearTimeout(timer);
	}
};

export const guardedHttpLayer = (
	guard: GuardOptions,
	limits: GuardedFetchLimits,
) =>
	Layer.succeed(Http, {
		request: (url, init = {}) =>
			Effect.tryPromise({
				try: (signal) => guardedFetch(url, init, { guard, limits, signal }),
				catch: (cause) =>
					new AuditorError({
						message: `Request to ${url} failed: ${cause instanceof Error ? cause.message : String(cause)}`,
						cause,
					}),
			}),
	});

/**
 * Auditors that open network connections we cannot pin to a validated IP: a
 * real browser and Lighthouse resolve DNS themselves.
 */
const UNPINNABLE = new Set(["webapp.browser", "web.lighthouse"]);

/**
 * Deterministic `web.*` URL auditors whose traffic all goes through the
 * guarded `Http` service (or, for `web.tls`, a pinned `connectHost`).
 * External-tool wrappers are excluded: those binaries make their own requests.
 */
export const isPinnableUrlAuditor = (a: Auditor): boolean =>
	a.id.startsWith("web.") &&
	a.engine === "builtin" &&
	a.targets.includes("url") &&
	!UNPINNABLE.has(a.id);
