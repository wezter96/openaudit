import { describe, expect, test } from "bun:test";

import { ScanError } from "../src/errors";
import { assertPublicSite, parseSiteUrl, type Resolver } from "../src/site";

const resolvesTo =
	(...addresses: string[]): Resolver =>
	async () =>
		addresses;

describe("parseSiteUrl", () => {
	test("accepts a public https URL", () => {
		expect(parseSiteUrl("https://example.com/docs").toString()).toBe(
			"https://example.com/docs",
		);
		expect(parseSiteUrl("https://example.com:443/").port).toBe("");
	});

	test.each([
		"http://example.com",
		"https://example.com:8443",
		"https://user:pw@example.com",
		"https://localhost",
		"https://box.local",
		"https://db.internal",
		"https://nas.lan",
		"https://intranet",
		"https://8.8.8.8",
		"https://10.0.0.1",
		"https://[2606:4700::1111]",
		"ftp://example.com",
		"not a url",
	])("refuses %s", (input) => {
		expect(() => parseSiteUrl(input)).toThrow(ScanError);
	});
});

describe("assertPublicSite", () => {
	test("returns the URL when every address is public", async () => {
		await expect(
			assertPublicSite(
				"https://example.com",
				resolvesTo("93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"),
			),
		).resolves.toBe("https://example.com/");
	});

	test.each([
		["loopback", "127.0.0.1"],
		["private", "192.168.1.10"],
		["CGNAT / Tailscale", "100.101.102.103"],
		["link-local metadata", "169.254.169.254"],
		["ULA", "fd7a:115c:a1e0::1"],
		["IPv6 loopback", "::1"],
		["IPv4-mapped private", "::ffff:10.0.0.1"],
		["unspecified", "0.0.0.0"],
		["this-network", "0.1.2.3"],
		["IPv6 link-local", "fe80::1"],
		["IPv6 ULA fc00::/7", "fc00::1"],
		["NAT64 private", "64:ff9b::a00:1"],
		["6to4 private", "2002:a00:1::1"],
		["IPv4-mapped metadata", "::ffff:169.254.169.254"],
		["Teredo", "2001:0:4136:e378:8000:63bf:3fff:fdd2"],
	])("refuses a host that resolves to %s", async (_, address) => {
		await expect(
			assertPublicSite("https://example.com", resolvesTo(address)),
		).rejects.toThrow("private or reserved");
	});

	test("scans the checked hostname and path only", async () => {
		await expect(
			assertPublicSite(
				"https://Example.COM./docs?lang=en#top",
				resolvesTo("93.184.215.14"),
			),
		).resolves.toBe("https://example.com/docs?lang=en");
	});

	test("refuses a host with one public and one private address", async () => {
		await expect(
			assertPublicSite(
				"https://example.com",
				resolvesTo("93.184.215.14", "10.1.2.3"),
			),
		).rejects.toThrow("private or reserved");
	});

	test("refuses a host that does not resolve", async () => {
		await expect(
			assertPublicSite("https://example.com", async () => {
				throw new Error("ENOTFOUND");
			}),
		).rejects.toThrow("could not resolve example.com");
		await expect(
			assertPublicSite("https://example.com", resolvesTo()),
		).rejects.toThrow("could not resolve");
	});
});
