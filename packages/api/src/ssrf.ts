export {
	ALLOWED_PORTS,
	assertPublicUrl,
	type GuardOptions,
	isPrivateAddress,
	isPrivateIPv4,
	isPrivateIPv6,
	parseIPv4,
	parseIPv6,
	parsePublicUrl,
	type ResolvedUrl,
	resolvePublicUrl,
	SsrfError,
	type SsrfReason,
} from "@openaudit/core";

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
