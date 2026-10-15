import { afterAll, beforeEach, describe, expect, test } from "bun:test";
import type { Registration } from "@openaudit/badge";
import { parseRepo, parseSite, slugOf } from "./input";
import {
	activeProject,
	at,
	github,
	type Harness,
	makeHarness,
	repoFile,
	T0,
} from "./test/harness";

const realFetch = globalThis.fetch;
afterAll(() => {
	globalThis.fetch = realFetch;
});

let h: Harness;
beforeEach(() => {
	at(T0);
	h = makeHarness(github("acme/widgets"));
});

const register = (body: unknown, ip?: string) =>
	h.call("POST", "/api/badges", { body, ...(ip ? { ip } : {}) });

describe("input", () => {
	test("repos", () => {
		expect(parseRepo("acme/widgets")).toBe("acme/widgets");
		expect(parseRepo("https://github.com/acme/widgets.git")).toBe(
			"acme/widgets",
		);
		expect(parseRepo("acme")).toBeUndefined();
		expect(parseRepo("acme/widgets/extra")).toBeUndefined();
		expect(parseRepo("acme/..")).toBeUndefined();
		expect(parseRepo("-acme/x")).toBeUndefined();
		expect(parseRepo("acme/<script>")).toBeUndefined();
		expect(slugOf("Acme/My.Widgets")).toBe("acme-my-widgets");
	});

	test("sites", () => {
		expect(parseSite("https://acme.dev/app?x=1#y")).toBe(
			"https://acme.dev/app",
		);
		expect(parseSite("https://acme.dev:443/")).toBe("https://acme.dev/");
		for (const bad of [
			"http://acme.dev/",
			"https://acme.dev:8443/",
			"https://user:pw@acme.dev/",
			"https://localhost/",
			"https://127.0.0.1/",
			"https://[::1]/",
			"https://printer.local/",
			"https://db.internal/",
			"https://nas.lan/",
			"https://intranet/",
			"https://2130706433/",
			"https://0x7f000001/",
			"https://017700000001/",
			"https://0x7f.1/",
			"https://127.1/",
			"https://[::ffff:127.0.0.1]/",
			"https://example.123/",
			"https://x.localhost/",
			"https://router.home.arpa/",
			"https://evil.com./",
			"javascript:alert(1)",
			"not a url",
		])
			expect(parseSite(bad)).toBeUndefined();
	});
});

describe("registration", () => {
	test("returns the code and a token, and stores only the token's hash", async () => {
		const res = await register({
			repo: "acme/widgets",
			site: "https://acme.dev",
		});
		expect(res.status).toBe(201);
		const body = (await res.json()) as Registration;
		expect(body.id).toBe("acme-widgets");
		expect(body.site).toBe("https://acme.dev/");
		expect(body.verification).toEqual({
			code: expect.stringMatching(/^openaudit-verify-[0-9a-f]{32}$/),
			repoFile: ".openaudit-badge",
			siteFile: "/.well-known/openaudit-badge.txt",
			dnsName: "_openaudit-badge.acme.dev",
		});
		expect(body.manageToken).toMatch(/^oam_/);
		const dump = JSON.stringify(
			h.d1.sqlite.query("SELECT * FROM projects, registrations").all(),
		);
		expect(dump).not.toContain(body.manageToken);
		expect(dump).not.toContain("203.0.113.7");
	});

	test("rejects bad input", async () => {
		expect((await register({ repo: "nope" })).status).toBe(422);
		const res = await register({
			repo: "acme/widgets",
			site: "https://localhost/",
		});
		expect(res.status).toBe(422);
		expect(((await res.json()) as { _tag: string })._tag).toBe("InvalidInput");
		expect((await register({ repo: 42 })).status).toBe(400);
	});

	test("checks the repo on GitHub", async () => {
		expect((await register({ repo: "acme/ghost" })).status).toBe(404);
		Object.assign(h.routes, github("acme/secret", { private: true }));
		expect((await register({ repo: "acme/secret" })).status).toBe(404);
		Object.assign(h.routes, github("acme/huge", { size: 600 * 1024 }));
		const huge = await register({ repo: "acme/huge" });
		expect(huge.status).toBe(422);
		expect(((await huge.json()) as { _tag: string })._tag).toBe("RepoTooLarge");
		h.routes["https://api.github.com/repos/acme/down"] = () =>
			new Response("rate limited", { status: 403 });
		expect((await register({ repo: "acme/down" })).status).toBe(503);
	});

	test("refuses a repo that is already registered, in any case", async () => {
		expect((await register({ repo: "acme/widgets" })).status).toBe(201);
		const again = await register({ repo: "ACME/Widgets" });
		expect(again.status).toBe(409);
	});

	test("gives colliding slugs a suffix", async () => {
		Object.assign(h.routes, github("acme-x/y"), github("acme/x-y"));
		const a = (await (await register({ repo: "acme-x/y" })).json()) as {
			id: string;
		};
		const b = (await (await register({ repo: "acme/x-y" })).json()) as {
			id: string;
		};
		expect([a.id, b.id]).toEqual(["acme-x-y", "acme-x-y-2"]);
	});

	test("limits sign-ups per IP per day", async () => {
		for (let i = 0; i < 5; i++) {
			Object.assign(h.routes, github(`acme/r${i}`));
			expect((await register({ repo: `acme/r${i}` })).status).toBe(201);
		}
		Object.assign(h.routes, github("acme/r5"));
		expect((await register({ repo: "acme/r5" })).status).toBe(429);
		expect((await register({ repo: "acme/r5" }, "198.51.100.1")).status).toBe(
			201,
		);
		at(T0 + 86_401);
		Object.assign(h.routes, github("acme/r6"));
		expect((await register({ repo: "acme/r6" })).status).toBe(201);
	});

	test("is full at 100 live projects", async () => {
		const insert = h.d1.sqlite.prepare(
			"INSERT INTO projects (id, repo, code, manage_hash, status, created_at) VALUES (?, ?, 'c', 'h', 'active', ?)",
		);
		for (let i = 0; i < 100; i++) insert.run(`p${i}`, `o/p${i}`, T0);
		const res = await register({ repo: "acme/widgets" });
		expect(res.status).toBe(503);
		expect(((await res.json()) as { _tag: string })._tag).toBe("Full");
	});

	test("sends no CORS headers, so other sites can't call it from a browser", async () => {
		const res = await register({ repo: "acme/widgets" });
		expect(res.headers.get("access-control-allow-origin")).toBeNull();
		expect(res.headers.get("access-control-allow-credentials")).toBeNull();
		const preflight = await h.call("OPTIONS", "/api/badges");
		expect(preflight.headers.get("access-control-allow-origin")).toBeNull();
	});

	test("refuses long URLs", async () => {
		const res = await h.call("GET", `/api/badges/${"a".repeat(600)}`);
		expect(res.status).toBe(414);
	});

	test("refuses oversized bodies", async () => {
		const res = await register({
			repo: "acme/widgets",
			site: "x".repeat(5_000),
		});
		expect(res.status).toBe(413);
	});
});

interface Signed {
	id: string;
	manageToken: string;
	verification: { code: string };
}

const signUp = async (body: unknown) =>
	(await (await register(body)).json()) as Signed;

const verifyAs = (reg: Signed, token = reg.manageToken) =>
	h.call("POST", `/api/badges/${reg.id}/verify`, { token });

describe("verification", () => {
	test("activates once the repo file has the code, and makes it due", async () => {
		const reg = await signUp({
			repo: "acme/widgets",
			site: "https://acme.dev",
		});
		expect(await (await verifyAs(reg)).json()).toEqual({
			status: "pending",
			repoVerified: false,
			siteVerified: false,
		});
		Object.assign(
			h.routes,
			repoFile("acme/widgets", `${reg.verification.code}\n`),
		);
		h.routes["https://acme.dev/.well-known/openaudit-badge.txt"] = () =>
			new Response(reg.verification.code);
		at(T0 + 11);
		expect(await (await verifyAs(reg)).json()).toEqual({
			status: "active",
			repoVerified: true,
			siteVerified: true,
		});
		const state = (await (
			await h.call("GET", `/api/badges/${reg.id}`)
		).json()) as { nextScanAt: number; status: string };
		expect(state).toMatchObject({ status: "active", nextScanAt: T0 + 11 });
	});

	test("only the manage token can ask for a check", async () => {
		const reg = await signUp({ repo: "acme/widgets" });
		Object.assign(h.routes, repoFile("acme/widgets", reg.verification.code));
		const anonymous = await h.call("POST", `/api/badges/${reg.id}/verify`);
		expect(anonymous.status).toBe(401);
		expect((await verifyAs(reg, "oam_guess")).status).toBe(401);
		expect(h.net.calls.some((u) => u.includes("raw.githubusercontent"))).toBe(
			false,
		);
		expect((await verifyAs(reg)).status).toBe(200);
	});

	test("accepts the site code from DNS, with the name encoded", async () => {
		const reg = await signUp({
			repo: "acme/widgets",
			site: "https://acme.dev",
		});
		h.routes[
			"https://cloudflare-dns.com/dns-query?name=_openaudit-badge.acme.dev&type=TXT"
		] = () =>
			Response.json({ Answer: [{ data: `"${reg.verification.code}"` }] });
		const body = await (await verifyAs(reg)).json();
		expect(body).toMatchObject({ siteVerified: true, repoVerified: false });
	});

	test("a redirect or an oversized file fails the site check", async () => {
		const reg = await signUp({
			repo: "acme/widgets",
			site: "https://acme.dev",
		});
		const file = "https://acme.dev/.well-known/openaudit-badge.txt";
		h.routes[file] = () =>
			new Response(null, {
				status: 302,
				headers: { location: "http://169.254.169.254/" },
			});
		expect(await (await verifyAs(reg)).json()).toMatchObject({
			siteVerified: false,
		});
		h.routes[file] = () =>
			new Response(`${"x".repeat(5000)}${reg.verification.code}`);
		at(T0 + 11);
		expect(await (await verifyAs(reg)).json()).toMatchObject({
			siteVerified: false,
		});
	});

	test("checks at most every 10 seconds", async () => {
		const reg = await signUp({ repo: "acme/widgets" });
		await verifyAs(reg);
		const before = h.net.calls.length;
		await verifyAs(reg);
		expect(h.net.calls.length).toBe(before);
	});

	test("unknown ids are 404", async () => {
		const verify = h.call("POST", "/api/badges/nope/verify", {
			token: "oam_x",
		});
		expect((await verify).status).toBe(404);
		expect((await h.call("GET", "/api/badges/nope")).status).toBe(404);
	});
});

describe("ownership", () => {
	test("codes have 128 bits and tokens 256", async () => {
		const reg = await signUp({ repo: "acme/widgets" });
		expect(reg.verification.code).toMatch(/^openaudit-verify-[0-9a-f]{32}$/);
		expect(reg.manageToken).toMatch(/^oam_[A-Za-z0-9_-]{43}$/);
	});

	test("a pending or active repo can't be taken over", async () => {
		await signUp({ repo: "acme/widgets" });
		expect(
			(await register({ repo: "acme/widgets" }, "198.51.100.9")).status,
		).toBe(409);
		const other = makeHarness(github("acme/widgets"));
		h = other;
		await activeProject(h);
		expect((await register({ repo: "Acme/Widgets" })).status).toBe(409);
	});

	test("a stale unverified sign-up can be replaced", async () => {
		const old = await signUp({ repo: "acme/widgets" });
		at(T0 + 7 * 86_400 + 1);
		const fresh = await signUp({ repo: "acme/widgets" });
		expect(fresh.id).toBe("acme-widgets");
		expect(fresh.verification.code).not.toBe(old.verification.code);
		expect(
			(await verifyAs({ ...fresh, manageToken: old.manageToken })).status,
		).toBe(401);
	});
});

describe("manage token", () => {
	test("rescan needs the token and runs once a day", async () => {
		const reg = await activeProject(h);
		const path = `/api/badges/${reg.id}/rescan`;
		expect((await h.call("POST", path)).status).toBe(401);
		expect((await h.call("POST", path, { token: "oam_wrong" })).status).toBe(
			401,
		);
		expect(
			(await h.call("POST", path, { token: reg.manageToken })).status,
		).toBe(202);
		expect(
			(await h.call("POST", path, { token: reg.manageToken })).status,
		).toBe(429);
		at(T0 + 86_400);
		expect(
			(await h.call("POST", path, { token: reg.manageToken })).status,
		).toBe(202);
	});

	test("remove deletes everything and leaves a removed badge", async () => {
		const reg = await activeProject(h);
		const path = `/api/badges/${reg.id}`;
		expect((await h.call("DELETE", path, { token: "oam_wrong" })).status).toBe(
			401,
		);
		expect(
			(await h.call("DELETE", path, { token: reg.manageToken })).status,
		).toBe(204);
		expect((await h.call("GET", path)).status).toBe(404);
		const svg = await (await h.call("GET", `/badge/${reg.id}.svg`)).text();
		expect(svg).toContain(">removed<");
		const row = h.d1.sqlite.query("SELECT * FROM projects").get() as Record<
			string,
			unknown
		>;
		expect(row).toMatchObject({
			status: "removed",
			code: "",
			manage_hash: "",
			site: null,
			ip_day: null,
		});
		const count = h.d1.sqlite.query("SELECT count(*) AS n FROM scans").get();
		expect(count).toEqual({ n: 0 });
		expect((await register({ repo: "acme/widgets" })).status).toBe(201);
	});
});
