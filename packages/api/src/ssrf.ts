import { lookup as dnsLookup } from "node:dns/promises";
import { isIP } from "node:net";

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

/* ---------------------------------- IPv4 ---------------------------------- */

/** Strict dotted-quad parser. Returns the address as an unsigned 32-bit int. */
export const parseIPv4 = (input: string): number | undefined => {
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

const v4 = (cidr: string): readonly [number, number] => {
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

const inV4 = (ip: number, [base, bits]: readonly [number, number]): boolean => {
	if (bits === 0) return true;
	const size = 2 ** (32 - bits);
	return Math.floor(ip / size) === Math.floor(base / size);
};

export const isPrivateIPv4 = (ip: number): boolean =>
	PRIVATE_V4.some((range) => inV4(ip, range));

/* ---------------------------------- IPv6 ---------------------------------- */

/** Parses any textual IPv6 form (incl. `::`, embedded IPv4, zone ids) to a 128-bit bigint. */
export const parseIPv6 = (input: string): bigint | undefined => {
	let s = input.trim().toLowerCase();
	if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
	const zone = s.indexOf("%");
	if (zone !== -1) s = s.slice(0, zone);
	if (!s.includes(":")) return undefined;

	// Embedded IPv4 in the last 32 bits, e.g. ::ffff:127.0.0.1
	const lastColon = s.lastIndexOf(":");
	const tail = s.slice(lastColon + 1);
	if (tail.includes(".")) {
		const ip4 = parseIPv4(tail);
		if (ip4 === undefined) return undefined;
		const hi = ((ip4 >>> 16) & 0xffff).toString(16);
		const lo = (ip4 & 0xffff).toString(16);
		s = `${s.slice(0, lastColon + 1)}${hi}:${lo}`;
	}

	const halves = s.split("::");
	if (halves.length > 2) return undefined;
	const head = halves[0] ? halves[0].split(":") : [];
	const rest = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
	const missing = 8 - head.length - rest.length;
	if (halves.length === 1 ? missing !== 0 : missing < 1) return undefined;
	const groups = [...head, ...Array<string>(missing).fill("0"), ...rest];

	let n = 0n;
	for (const g of groups) {
		if (!/^[0-9a-f]{1,4}$/.test(g)) return undefined;
		n = (n << 16n) | BigInt(Number.parseInt(g, 16));
	}
	return n;
};

const v6 = (cidr: string): readonly [bigint, number] => {
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
export const isPrivateAddress = (address: string): boolean => {
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

const defaultLookup = async (hostname: string) =>
	(await dnsLookup(hostname, { all: true, verbatim: true })).map(
		(r) => r.address,
	);

/** Hostname without IPv6 brackets or a trailing dot, lowercased. */
const normalizeHost = (hostname: string) =>
	hostname
		.toLowerCase()
		.replace(/^\[|\]$/g, "")
		.replace(/\.$/, "");

/**
 * Syntactic checks only (no DNS): protocol, credentials, port, hostname shape.
 * Returns the parsed URL.
 */
export const parsePublicUrl = (
	input: string,
	options: GuardOptions = {},
): URL => {
	let url: URL;
	try {
		url = new URL(input);
	} catch {
		throw new SsrfError(
			"invalid-url",
			"Enter a full URL such as https://example.com",
		);
	}
	if (url.protocol !== "http:" && url.protocol !== "https:")
		throw new SsrfError("protocol", "Only http and https URLs can be audited");
	if (url.username || url.password)
		throw new SsrfError(
			"credentials",
			"URLs with embedded credentials are not accepted",
		);
	if (options.allowPrivate) return url;

	if (!ALLOWED_PORTS.has(url.port))
		throw new SsrfError(
			"port",
			`Port ${url.port} is not allowed; use 80, 443, 8080 or 8443`,
		);

	const host = normalizeHost(url.hostname);
	if (isIP(host)) {
		if (isPrivateAddress(host))
			throw new SsrfError(
				"private-address",
				"Refusing to audit a private, loopback, link-local or reserved address",
			);
		return url;
	}
	if (
		host === "localhost" ||
		!host.includes(".") ||
		BLOCKED_HOST_SUFFIXES.some((suffix) => host.endsWith(suffix))
	)
		throw new SsrfError(
			"hostname",
			`Refusing to audit internal hostname "${host}"`,
		);
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
	input: string,
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
	input: string,
	options: GuardOptions = {},
): Promise<URL> => (await resolvePublicUrl(input, options)).url;

/* ------------------------------ Rate limiting ----------------------------- */

export interface RateLimiter {
	/** Records a hit for `key`; `ok: false` when over the limit. */
	readonly hit: (key: string) => {
		readonly ok: boolean;
		readonly retryAfterMs: number;
	};
}

/**
 * Fixed-window in-memory limiter. Good enough for a single instance; use a
 * shared store (Redis, the edge) when running several replicas.
 *
 * Memory is bounded by evicting the oldest window rather than refusing new
 * keys: failing closed would let anyone with enough addresses (an IPv6 /64 has
 * billions) lock every other client out. Entries are kept in window-start
 * order (a reset window is moved to the end), so eviction is O(1). Pair it
 * with `clientKey` so IPv6 clients cannot rotate through addresses.
 */
export const createRateLimiter = (opts: {
	readonly limit: number;
	readonly windowMs: number;
	/** Upper bound on tracked keys so a flood of IPs cannot exhaust memory. */
	readonly maxKeys?: number;
	readonly now?: () => number;
}): RateLimiter => {
	const now = opts.now ?? Date.now;
	const maxKeys = opts.maxKeys ?? 10_000;
	const windows = new Map<string, { start: number; count: number }>();

	return {
		hit: (key) => {
			const t = now();
			let w = windows.get(key);
			if (!w || t - w.start >= opts.windowMs) {
				windows.delete(key);
				while (windows.size >= maxKeys) {
					const oldest = windows.keys().next().value;
					if (oldest === undefined) break;
					windows.delete(oldest);
				}
				w = { start: t, count: 0 };
				windows.set(key, w);
			}
			w.count++;
			return w.count <= opts.limit
				? { ok: true, retryAfterMs: 0 }
				: { ok: false, retryAfterMs: w.start + opts.windowMs - t };
		},
	};
};

/**
 * Rate-limit key for a client address: IPv6 clients are grouped by /64 (what a
 * single customer usually controls), IPv4 by full address.
 */
export const clientKey = (ip: string | undefined): string => {
	if (!ip) return "unknown";
	const v4mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
	if (v4mapped?.[1]) return v4mapped[1];
	if (!ip.includes(":")) return ip;
	const [head = "", tail = ""] = ip.toLowerCase().split("::");
	const left = head ? head.split(":") : [];
	const right = tail ? tail.split(":") : [];
	const groups = ip.includes("::")
		? [
				...left,
				...Array(Math.max(0, 8 - left.length - right.length)).fill("0"),
				...right,
			]
		: left;
	return `${groups
		.slice(0, 4)
		.map((g) => (Number.parseInt(g, 16) || 0).toString(16))
		.join(":")}::/64`;
};
