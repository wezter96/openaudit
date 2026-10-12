import { describe, expect, test } from "bun:test";

import {
	assertPublicUrl,
	clientKey,
	createRateLimiter,
	isPrivateAddress,
	parseIPv6,
	parsePublicUrl,
	SsrfError,
} from "./ssrf";

const reasonOf = async (fn: () => unknown): Promise<string | undefined> => {
	try {
		await fn();
		return undefined;
	} catch (e) {
		return e instanceof SsrfError ? e.reason : `unexpected: ${String(e)}`;
	}
};

const resolvesTo =
	(...addresses: string[]) =>
	async () =>
		addresses;

describe("isPrivateAddress", () => {
	test.each([
		"127.0.0.1",
		"127.255.255.254",
		"10.1.2.3",
		"172.16.0.1",
		"172.31.255.255",
		"192.168.1.1",
		"169.254.169.254",
		"100.64.0.1",
		"100.127.255.255",
		"0.0.0.0",
		"224.0.0.1",
		"255.255.255.255",
		"198.18.0.1",
		"192.0.2.10",
		"::",
		"::1",
		"[::1]",
		"fe80::1",
		"fe80::1%en0",
		"fc00::1",
		"fd00::1",
		"fd12:3456:789a::1",
		"ff02::1",
		"::ffff:127.0.0.1",
		"::ffff:7f00:1",
		"::ffff:169.254.169.254",
		"::ffff:10.0.0.1",
		"::127.0.0.1",
		"64:ff9b::10.0.0.1",
		"2002:7f00:0001::1",
		"2001:db8::1",
		"2001:0:4136:e378::1",
		"not-an-ip",
	])("%s is private", (address) => {
		expect(isPrivateAddress(address)).toBe(true);
	});

	test.each([
		"1.1.1.1",
		"8.8.8.8",
		"93.184.216.34",
		"172.32.0.1",
		"100.128.0.1",
		"2606:4700:4700::1111",
		"2a00:1450:4001:80b::200e",
		"::ffff:8.8.8.8",
		"64:ff9b::8.8.8.8",
		"2002:0808:0808::1",
	])("%s is public", (address) => {
		expect(isPrivateAddress(address)).toBe(false);
	});
});

describe("parseIPv6", () => {
	test("expands shorthand and embedded IPv4", () => {
		expect(parseIPv6("::1")).toBe(1n);
		expect(parseIPv6("::ffff:127.0.0.1")).toBe(parseIPv6("::ffff:7f00:1"));
		expect(parseIPv6("1:2:3:4:5:6:7:8")).toBe(
			0x00010002000300040005000600070008n,
		);
	});
	test("rejects malformed input", () => {
		expect(parseIPv6("1::2::3")).toBeUndefined();
		expect(parseIPv6("1:2:3")).toBeUndefined();
		expect(parseIPv6("12345::")).toBeUndefined();
		expect(parseIPv6("1.2.3.4")).toBeUndefined();
	});
});

describe("parsePublicUrl", () => {
	test.each([
		["not a url", "invalid-url"],
		["ftp://example.com", "protocol"],
		["file:///etc/passwd", "protocol"],
		["gopher://example.com", "protocol"],
		["javascript:alert(1)", "protocol"],
		["https://user:pass@example.com", "credentials"],
		["https://example.com:22", "port"],
		["http://example.com:6379", "port"],
		["http://localhost", "hostname"],
		["http://LOCALHOST.", "hostname"],
		["http://app.localhost", "hostname"],
		["http://metadata.google.internal", "hostname"],
		["http://intranet", "hostname"],
		["http://127.0.0.1", "private-address"],
		["http://2130706433", "private-address"], // decimal 127.0.0.1
		["http://0x7f.0.0.1", "private-address"], // hex octet
		["http://0177.0.0.1", "private-address"], // octal octet
		["http://169.254.169.254/latest/meta-data/", "private-address"],
		["http://[::1]", "private-address"],
		["http://[::ffff:127.0.0.1]", "private-address"],
		["http://[fd00::1]", "private-address"],
		["http://0.0.0.0", "private-address"],
	])("%s → %s", async (input, reason) => {
		expect(await reasonOf(() => parsePublicUrl(input))).toBe(reason);
	});

	test.each([
		"https://example.com",
		"http://example.com/path?q=1",
		"https://example.com:443",
		"http://example.com:8080",
		"https://example.com:8443",
		"https://1.1.1.1",
	])("%s is accepted", (input) => {
		expect(() => parsePublicUrl(input)).not.toThrow();
	});

	test("allowPrivate skips network checks but not protocol/credentials", async () => {
		const opts = { allowPrivate: true };
		expect(() => parsePublicUrl("http://localhost:3000", opts)).not.toThrow();
		expect(await reasonOf(() => parsePublicUrl("file:///x", opts))).toBe(
			"protocol",
		);
		expect(
			await reasonOf(() => parsePublicUrl("http://a:b@localhost", opts)),
		).toBe("credentials");
	});
});

describe("assertPublicUrl", () => {
	test("accepts names that resolve only to public addresses", async () => {
		const url = await assertPublicUrl("https://example.com", {
			lookup: resolvesTo("93.184.216.34", "2606:2800:220:1::1"),
		});
		expect(url.hostname).toBe("example.com");
	});

	test("rejects names that resolve to a private address", async () => {
		expect(
			await reasonOf(() =>
				assertPublicUrl("https://evil.example", {
					lookup: resolvesTo("127.0.0.1"),
				}),
			),
		).toBe("private-address");
	});

	test("rejects when any of several records is private", async () => {
		expect(
			await reasonOf(() =>
				assertPublicUrl("https://mixed.example", {
					lookup: resolvesTo("93.184.216.34", "10.0.0.5"),
				}),
			),
		).toBe("private-address");
	});

	test("rejects IPv4-mapped IPv6 records pointing at metadata", async () => {
		expect(
			await reasonOf(() =>
				assertPublicUrl("https://rebind.example", {
					lookup: resolvesTo("::ffff:169.254.169.254"),
				}),
			),
		).toBe("private-address");
	});

	test("reports DNS failures", async () => {
		expect(
			await reasonOf(() =>
				assertPublicUrl("https://nx.example", {
					lookup: async () => {
						throw new Error("ENOTFOUND");
					},
				}),
			),
		).toBe("dns");
		expect(
			await reasonOf(() =>
				assertPublicUrl("https://empty.example", { lookup: resolvesTo() }),
			),
		).toBe("dns");
	});

	test("allowPrivate permits private targets without resolving", async () => {
		let called = false;
		await assertPublicUrl("http://localhost:3000", {
			allowPrivate: true,
			lookup: async () => {
				called = true;
				return ["127.0.0.1"];
			},
		});
		expect(called).toBe(false);
	});
});

describe("createRateLimiter", () => {
	test("limits per key within a window", () => {
		let t = 0;
		const rl = createRateLimiter({ limit: 2, windowMs: 1000, now: () => t });
		expect(rl.hit("a").ok).toBe(true);
		expect(rl.hit("a").ok).toBe(true);
		const third = rl.hit("a");
		expect(third.ok).toBe(false);
		expect(third.retryAfterMs).toBe(1000);
		expect(rl.hit("b").ok).toBe(true);
		t = 1000;
		expect(rl.hit("a").ok).toBe(true);
	});

	test("bounds memory by evicting the oldest window, never locking others out", () => {
		let t = 0;
		const rl = createRateLimiter({
			limit: 1,
			windowMs: 1000,
			maxKeys: 2,
			now: () => t,
		});
		expect(rl.hit("a").ok).toBe(true);
		t = 1;
		expect(rl.hit("b").ok).toBe(true);
		// Full: a new client is still served; the oldest window ("a") is evicted.
		t = 2;
		expect(rl.hit("c").ok).toBe(true);
		expect(rl.hit("c").ok).toBe(false);
		expect(rl.hit("b").ok).toBe(false);
	});

	test("stays fast under a flood of distinct keys", () => {
		const rl = createRateLimiter({ limit: 1, windowMs: 60_000, maxKeys: 1000 });
		const started = performance.now();
		for (let i = 0; i < 200_000; i++) rl.hit(`k${i}`);
		expect(rl.hit("fresh").ok).toBe(true);
		expect(performance.now() - started).toBeLessThan(1000);
	});
});

describe("clientKey", () => {
	test("groups IPv6 by /64 and unwraps mapped IPv4", () => {
		expect(clientKey("2001:db8:1:2:aaaa::1")).toBe("2001:db8:1:2::/64");
		expect(clientKey("2001:db8:1:2:ffff:ffff:ffff:ffff")).toBe(
			"2001:db8:1:2::/64",
		);
		expect(clientKey("2001:db8::1")).toBe("2001:db8:0:0::/64");
		expect(clientKey("::ffff:203.0.113.9")).toBe("203.0.113.9");
		expect(clientKey("203.0.113.9")).toBe("203.0.113.9");
		expect(clientKey(undefined)).toBe("unknown");
	});
});
