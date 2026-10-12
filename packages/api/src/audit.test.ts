import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { guardedFetch, urlAuditors } from "./audit";
import { SsrfError } from "./ssrf";

const PUBLIC_IP = "93.184.216.34";
const publicLookup = async () => [PUBLIC_IP];

interface Call {
	readonly url: string;
	readonly host: string | undefined;
	readonly serverName: string | undefined;
	readonly authorization: string | undefined;
}

/** Fake fetch routed by `Host` header + path, recording what was dialed. */
const fakeFetch = (routes: Record<string, () => Response>) => {
	const calls: Call[] = [];
	const fetch = async (url: string, init: RequestInit) => {
		const headers = init.headers as Record<string, string>;
		const tls = (init as { tls?: { serverName?: string } }).tls;
		calls.push({
			url,
			host: headers.host,
			serverName: tls?.serverName,
			authorization: headers.authorization,
		});
		const key = `${headers.host}${new URL(url).pathname}`;
		const route = routes[key];
		if (!route) throw new Error(`unexpected fetch ${key}`);
		return route();
	};
	return { calls, fetch };
};

const redirect = (status: number, location: string) => () =>
	new Response(null, { status, headers: { location } });

describe("guardedFetch pins connections to validated addresses", () => {
	test("dials the validated IP with the hostname as Host and TLS SNI", async () => {
		const { calls, fetch } = fakeFetch({
			"site.example/": () => new Response("hello"),
		});
		const res = await guardedFetch(
			"https://site.example/",
			{},
			{ lookup: publicLookup, fetch },
		);
		expect(res.url).toBe("https://site.example/");
		expect(res.body).toBe("hello");
		expect(calls).toEqual([
			{
				url: `https://${PUBLIC_IP}/`,
				host: "site.example",
				serverName: "site.example",
				authorization: undefined,
			},
		]);
	});

	test("a second DNS answer cannot redirect the connection (rebinding)", async () => {
		let lookups = 0;
		// Public on the first query, loopback on every later one.
		const rebinding = async () =>
			lookups++ === 0 ? [PUBLIC_IP] : ["127.0.0.1"];
		const { calls, fetch } = fakeFetch({
			"rebind.example/": () => new Response("ok"),
		});
		await guardedFetch(
			"http://rebind.example/",
			{},
			{ lookup: rebinding, fetch },
		);
		expect(lookups).toBe(1);
		expect(calls.map((c) => c.url)).toEqual([`http://${PUBLIC_IP}/`]);
	});

	test("rebinding on a redirect hop to the same host is refused", async () => {
		let lookups = 0;
		const rebinding = async () =>
			lookups++ === 0 ? [PUBLIC_IP] : ["127.0.0.1"];
		const { calls, fetch } = fakeFetch({
			"rebind.example/": redirect(302, "/admin"),
		});
		const err = await guardedFetch(
			"http://rebind.example/",
			{},
			{ lookup: rebinding, fetch },
		).catch((e) => e);
		expect(err).toBeInstanceOf(SsrfError);
		expect(lookups).toBe(2);
		expect(calls).toHaveLength(1);
	});

	test("keeps non-default ports in Host and IPv6 addresses bracketed", async () => {
		const { calls, fetch } = fakeFetch({
			"v6.example:8443/": () => new Response("ok"),
		});
		await guardedFetch(
			"https://v6.example:8443/",
			{},
			{ lookup: async () => ["2606:2800:220:1::1"], fetch },
		);
		expect(calls[0]?.url).toBe("https://[2606:2800:220:1::1]:8443/");
		expect(calls[0]?.host).toBe("v6.example:8443");
		expect(calls[0]?.serverName).toBe("v6.example");
	});

	test("ignores a Host header supplied by an auditor", async () => {
		const { calls, fetch } = fakeFetch({
			"site.example/": () => new Response("ok"),
		});
		await guardedFetch(
			"https://site.example/",
			{ headers: { Host: "169.254.169.254" } },
			{ lookup: publicLookup, fetch },
		);
		expect(calls[0]?.host).toBe("site.example");
	});

	test("follows public redirects, pinning each hop", async () => {
		const lookup = async (host: string) =>
			host === "cdn.example" ? ["198.41.0.4"] : [PUBLIC_IP];
		const { calls, fetch } = fakeFetch({
			"site.example/": redirect(301, "https://cdn.example/home"),
			"cdn.example/home": () => new Response("hello"),
		});
		const res = await guardedFetch(
			"http://site.example/",
			{},
			{ lookup, fetch },
		);
		expect(res.url).toBe("https://cdn.example/home");
		expect(res.redirected).toBe(true);
		expect(calls.map((c) => c.url)).toEqual([
			`http://${PUBLIC_IP}/`,
			"https://198.41.0.4/home",
		]);
	});

	test("refuses a redirect to cloud metadata before connecting", async () => {
		const { calls, fetch } = fakeFetch({
			"evil.example/": redirect(
				302,
				"http://169.254.169.254/latest/meta-data/",
			),
		});
		const err = await guardedFetch(
			"https://evil.example/",
			{},
			{ lookup: publicLookup, fetch },
		).catch((e) => e);
		expect(err).toBeInstanceOf(SsrfError);
		expect(calls).toHaveLength(1);
	});

	test("refuses a redirect to a name that resolves privately", async () => {
		const lookup = async (host: string) =>
			host === "internal.example" ? ["10.0.0.1"] : [PUBLIC_IP];
		const { calls, fetch } = fakeFetch({
			"evil.example/": redirect(307, "https://internal.example/"),
		});
		const err = await guardedFetch(
			"https://evil.example/",
			{},
			{ lookup, fetch },
		).catch((e) => e);
		expect(err).toBeInstanceOf(SsrfError);
		expect(calls).toHaveLength(1);
	});

	test("caps redirect chains", async () => {
		const { fetch } = fakeFetch(
			Object.fromEntries(
				Array.from({ length: 10 }, (_, i) => [
					`loop.example/${i}`,
					redirect(302, `/${i + 1}`),
				]),
			),
		);
		const err = await guardedFetch(
			"https://loop.example/0",
			{},
			{ lookup: publicLookup, fetch },
		).catch((e) => e);
		expect(String(err)).toContain("Too many redirects");
	});

	test("truncates large bodies", async () => {
		const { fetch } = fakeFetch({
			"big.example/": () => new Response("x".repeat(3 * 1024 * 1024)),
		});
		const res = await guardedFetch(
			"https://big.example/",
			{ maxBytes: 1024 },
			{ lookup: publicLookup, fetch },
		);
		expect(res.body.length).toBe(1024);
	});

	test("drops credentials on cross-origin redirects", async () => {
		const { calls, fetch } = fakeFetch({
			"a.example/": redirect(302, "https://b.example/"),
			"b.example/": () => new Response("ok"),
		});
		await guardedFetch(
			"https://a.example/",
			{ headers: { authorization: "Bearer secret" } },
			{ lookup: publicLookup, fetch },
		);
		expect(calls.map((c) => c.authorization)).toEqual([
			"Bearer secret",
			undefined,
		]);
	});
});

/*
 * End-to-end with Bun's real fetch: the hostname `good.test` does not exist in
 * DNS, so a successful request proves fetch dialed the pinned address instead
 * of resolving the name, and that SNI + certificate verification used the
 * hostname. Needs openssl and a free port 8443 (an allowed port); skipped
 * otherwise.
 */
const openssl = Bun.which("openssl");
let server: Server | undefined;
let ca = "";
let dir = "";
const seen: string[] = [];

beforeAll(async () => {
	if (!openssl) return;
	dir = mkdtempSync(join(tmpdir(), "openaudit-pin-"));
	const gen = Bun.spawnSync([
		openssl,
		"req",
		"-x509",
		"-newkey",
		"rsa:2048",
		"-nodes",
		"-days",
		"1",
		"-subj",
		"/CN=good.test",
		"-addext",
		"subjectAltName=DNS:good.test",
		"-keyout",
		join(dir, "key.pem"),
		"-out",
		join(dir, "cert.pem"),
	]);
	if (gen.exitCode !== 0) return;
	ca = readFileSync(join(dir, "cert.pem"), "utf8");
	const s = createServer(
		{ key: readFileSync(join(dir, "key.pem")), cert: ca },
		(req, res) => {
			const sni = (req.socket as { servername?: string }).servername;
			seen.push(`sni=${sni} host=${req.headers.host}`);
			res.end("pinned");
		},
	);
	await new Promise<void>((resolve) => {
		s.once("error", () => resolve());
		s.listen(8443, "127.0.0.1", () => {
			server = s;
			resolve();
		});
	});
});

afterAll(() => {
	server?.close();
	if (dir) rmSync(dir, { recursive: true, force: true });
});

describe("guardedFetch with Bun's fetch", () => {
	// Treat loopback as "public" so the local server stands in for a real host.
	const guard = () => ({
		lookup: async () => ["127.0.0.1"],
		isPublicAddress: (a: string) => a === "127.0.0.1",
		fetch: (url: string, init: RequestInit) =>
			fetch(url, {
				...init,
				tls: { ...(init as { tls?: object }).tls, ca },
			} as RequestInit),
	});

	test("connects to the pinned IP with SNI and Host set to the hostname", async () => {
		if (!server) return console.warn("skipped: no openssl or port 8443 busy");
		const res = await guardedFetch("https://good.test:8443/", {}, guard());
		expect(res.status).toBe(200);
		expect(res.body).toBe("pinned");
		expect(seen.at(-1)).toBe("sni=good.test host=good.test:8443");
	});

	test("verifies certificates against the hostname, not the IP", async () => {
		if (!server) return console.warn("skipped: no openssl or port 8443 busy");
		// Same IP and trusted CA, but the certificate does not cover evil.test.
		const err = await guardedFetch(
			"https://evil.test:8443/",
			{},
			guard(),
		).catch((e) => e);
		expect(String(err)).toMatch(/ALTNAME|certificate/i);
	});
});

describe("urlAuditors", () => {
	test("never selects auditors that cannot be pinned", () => {
		const ids = urlAuditors().map((a) => a.id);
		expect(ids).not.toContain("web.lighthouse");
		expect(ids).not.toContain("webapp.browser");
		expect(ids.every((id) => id.startsWith("web."))).toBe(true);
	});
});

/*
 * Canary: a real Bun.serve on 127.0.0.1:8080 (an allowed port, so only the
 * address check can stop the request) counts every hit. The resolver answers
 * with a public address first and loopback afterwards, as a rebinding DNS
 * server would. With ALLOW_PRIVATE_TARGETS off, no request may reach it.
 */
describe("DNS rebinding canary on loopback", () => {
	let canary: ReturnType<typeof Bun.serve> | undefined;
	let hits = 0;

	beforeAll(() => {
		try {
			canary = Bun.serve({
				hostname: "127.0.0.1",
				port: 8080,
				fetch: () => {
					hits++;
					return new Response("canary");
				},
			});
		} catch {
			canary = undefined;
		}
	});
	afterAll(() => canary?.stop(true));

	const rebindingLookup = () => {
		let n = 0;
		return async () => (n++ === 0 ? [PUBLIC_IP] : ["127.0.0.1"]);
	};
	/** Real fetch, except the public address answers with a same-host redirect (no network). */
	const fetchWithPublicRedirect =
		(location: string) => (url: string, init: RequestInit) =>
			new URL(url).hostname === PUBLIC_IP
				? Promise.resolve(
						new Response(null, { status: 302, headers: { location } }),
					)
				: fetch(url, init);

	test("control: the canary is reachable when loopback is allowed", async () => {
		if (!canary) return console.warn("skipped: port 8080 busy");
		hits = 0;
		const res = await guardedFetch(
			"http://canary.test:8080/",
			{},
			{
				lookup: async () => ["127.0.0.1"],
				isPublicAddress: () => true,
			},
		);
		expect(res.body).toBe("canary");
		expect(hits).toBe(1);
	});

	test("a name resolving to loopback never reaches it", async () => {
		if (!canary) return console.warn("skipped: port 8080 busy");
		hits = 0;
		const err = await guardedFetch(
			"http://rebind.test:8080/",
			{},
			{ lookup: async () => ["127.0.0.1"] },
		).catch((e) => e);
		expect(err).toBeInstanceOf(SsrfError);
		expect(hits).toBe(0);
	});

	test("public first, loopback second: the redirect hop is refused", async () => {
		if (!canary) return console.warn("skipped: port 8080 busy");
		hits = 0;
		const err = await guardedFetch(
			"http://rebind.test:8080/",
			{},
			{
				lookup: rebindingLookup(),
				fetch: fetchWithPublicRedirect("/admin"),
			},
		).catch((e) => e);
		expect(err).toBeInstanceOf(SsrfError);
		expect(hits).toBe(0);
	});

	test("public first, loopback second: a single request dials only the public IP", async () => {
		if (!canary) return console.warn("skipped: port 8080 busy");
		hits = 0;
		const dialed: string[] = [];
		const lookup = rebindingLookup();
		// Resolve once up front, as the router does, so the fetch's own hop sees loopback.
		await lookup();
		const err = await guardedFetch(
			"http://rebind.test:8080/",
			{},
			{
				lookup,
				fetch: (url, init) => {
					dialed.push(url);
					return fetch(url, init);
				},
			},
		).catch((e) => e);
		expect(err).toBeInstanceOf(SsrfError);
		expect(dialed).toEqual([]);
		expect(hits).toBe(0);
	});
});
