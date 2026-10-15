import { afterAll, beforeEach, describe, expect, test } from "bun:test";
import worker from "../index";
import { sha256 } from "./crypto";
import {
	markRemoved,
	type ProjectRow,
	queueRescan,
	saveVerification,
} from "./store";
import {
	activeProject,
	at,
	github,
	type Harness,
	makeHarness,
	SCANNER_TOKEN,
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

const row = (id: string) =>
	h.d1.sqlite
		.query("SELECT * FROM projects WHERE id = ?")
		.get(id) as ProjectRow;

const asOwner = (method: string, path: string, token: string) =>
	h.call(method, path, { token });

describe("manage token", () => {
	test("an empty, malformed or stale hash never matches", async () => {
		const reg = await activeProject(h);
		const path = `/api/badges/${reg.id}/rescan`;
		for (const hash of ["", "not-a-hash", await sha256("")]) {
			h.d1.sqlite
				.query("UPDATE projects SET manage_hash = ? WHERE id = ?")
				.run(hash, reg.id);
			expect((await asOwner("POST", path, reg.manageToken)).status).toBe(401);
		}
		expect((await h.call("POST", path, { token: " " })).status).toBe(401);
	});

	test("a removed badge's old token does nothing, even after a new sign-up", async () => {
		const reg = await activeProject(h);
		expect(
			(await asOwner("DELETE", `/api/badges/${reg.id}`, reg.manageToken))
				.status,
		).toBe(204);
		for (const [method, path] of [
			["POST", `/api/badges/${reg.id}/verify`],
			["POST", `/api/badges/${reg.id}/rescan`],
			["DELETE", `/api/badges/${reg.id}`],
		] as const)
			expect((await asOwner(method, path, reg.manageToken)).status).toBe(404);
		await h.call("POST", "/api/badges", {
			body: { repo: "acme/widgets" },
			ip: "198.51.100.2",
		});
		for (const [method, path] of [
			["POST", `/api/badges/${reg.id}/verify`],
			["POST", `/api/badges/${reg.id}/rescan`],
			["DELETE", `/api/badges/${reg.id}`],
		] as const)
			expect((await asOwner(method, path, reg.manageToken)).status).toBe(401);
	});

	test("writes repeat the hash, so a token read before a replace can't act", async () => {
		const reg = await activeProject(h);
		const before = row(reg.id);
		h.d1.sqlite
			.query("UPDATE projects SET manage_hash = ? WHERE id = ?")
			.run("f".repeat(64), reg.id);
		expect(await queueRescan(h.env.BADGES, before, T0)).toBe(false);
		expect(
			await saveVerification(
				h.env.BADGES,
				before,
				{ repo: true, site: false },
				T0,
			),
		).toBe(false);
		expect(await markRemoved(h.env.BADGES, before)).toBe(false);
		expect(row(reg.id).status).toBe("active");
	});

	test("parallel rescans get one through", async () => {
		const reg = await activeProject(h);
		const path = `/api/badges/${reg.id}/rescan`;
		const results = await Promise.all(
			[1, 2, 3].map(() => asOwner("POST", path, reg.manageToken)),
		);
		expect(results.map((r) => r.status).sort()).toEqual([202, 429, 429]);
	});
});

describe("registration", () => {
	const register = (repo: string, ip: string, site?: string) =>
		h.call("POST", "/api/badges", {
			body: site ? { repo, site } : { repo },
			ip,
		});

	test("a fresh pending sign-up can't be replaced or have its site changed", async () => {
		const first = await register(
			"acme/widgets",
			"198.51.100.1",
			"https://acme.dev",
		);
		expect(first.status).toBe(201);
		const second = await register(
			"acme/widgets",
			"198.51.100.2",
			"https://evil.example",
		);
		expect(second.status).toBe(409);
		at(T0 + 6 * 86_400);
		expect((await register("acme/widgets", "198.51.100.3")).status).toBe(409);
		expect(row("acme-widgets").site).toBe("https://acme.dev/");
	});

	test("parallel sign-ups for one repo: one wins", async () => {
		const results = await Promise.all(
			["198.51.100.1", "198.51.100.2", "198.51.100.3"].map((ip) =>
				register("acme/widgets", ip),
			),
		);
		expect(results.map((r) => r.status).sort()).toEqual([201, 409, 409]);
		const count = h.d1.sqlite.query("SELECT count(*) AS n FROM projects").get();
		expect(count).toEqual({ n: 1 });
	});

	test("parallel sign-ups from one address stop at five", async () => {
		for (let i = 0; i < 8; i++) Object.assign(h.routes, github(`acme/r${i}`));
		const results = await Promise.all(
			[0, 1, 2, 3, 4, 5, 6, 7].map((i) =>
				register(`acme/r${i}`, "203.0.113.50"),
			),
		);
		expect(results.filter((r) => r.status === 201).length).toBe(5);
		expect(results.filter((r) => r.status === 429).length).toBe(3);
	});

	test("a request without a client address is refused", async () => {
		const res = await register("acme/widgets", "");
		expect(res.status).toBe(422);
		expect(h.net.calls).toEqual([]);
	});
});

describe("body and URL limits come first", () => {
	const trackedStream = (size: number) => {
		let pulled = 0;
		let bytes = size;
		const stream = new ReadableStream<Uint8Array>(
			{
				pull(controller) {
					pulled++;
					controller.enqueue(new Uint8Array(Math.min(bytes, 1024)).fill(32));
					bytes -= 1024;
					if (bytes <= 0) controller.close();
				},
			},
			{ highWaterMark: 0 },
		);
		return { stream, pulls: () => pulled };
	};

	const send = (
		path: string,
		body: ReadableStream,
		headers: Record<string, string>,
	) =>
		worker.fetch(
			new Request(`https://openaudit.se${path}`, {
				method: "POST",
				headers: { "cf-connecting-ip": "203.0.113.7", ...headers },
				body,
				duplex: "half",
			} as RequestInit),
			h.env,
		);

	test("an unauthenticated scanner upload is refused before a byte is read", async () => {
		const body = trackedStream(30 * 1024 * 1024);
		const res = await send("/api/scanner/jobs/x", body.stream, {
			"content-length": String(30 * 1024 * 1024),
		});
		expect(res.status).toBe(401);
		expect(body.pulls()).toBe(0);
		expect(h.d1.queries).toEqual([]);
	});

	test("an oversized form body is cut off while streaming, before D1", async () => {
		const body = trackedStream(64 * 1024);
		const res = await send("/api/badges", body.stream, {
			"content-type": "application/json",
		});
		expect(res.status).toBe(413);
		expect(body.pulls()).toBeLessThan(10);
		expect(h.d1.queries).toEqual([]);
	});

	test("a declared oversize or malformed length is refused unread", async () => {
		const big = trackedStream(1024);
		const res = await send("/api/badges", big.stream, {
			"content-length": "999999",
		});
		expect(res.status).toBe(413);
		expect(big.pulls()).toBe(0);
		const odd = trackedStream(10);
		expect(
			(await send("/api/badges", odd.stream, { "content-length": "1e3" }))
				.status,
		).toBe(400);
		expect(h.d1.queries).toEqual([]);
	});
});

describe("scanner jobs", () => {
	const claim = async () =>
		(await (
			await h.call("POST", "/api/scanner/claim", { token: SCANNER_TOKEN })
		).json()) as { job: { id: string } | null };

	const report = {
		status: "failed",
		error: "verification file missing",
	};

	test("parallel claims hand a project out once", async () => {
		await activeProject(h);
		const jobs = await Promise.all([claim(), claim(), claim()]);
		expect(jobs.filter((j) => j.job !== null).length).toBe(1);
	});

	test("a report after the lease is refused, even before a sweep", async () => {
		await activeProject(h);
		const { job } = await claim();
		at(T0 + 30 * 60 + 1);
		const res = await h.call("POST", `/api/scanner/jobs/${job?.id}`, {
			token: SCANNER_TOKEN,
			body: report,
		});
		expect(res.status).toBe(404);
	});

	test("a repeated report changes nothing and keeps the first one's files", async () => {
		const reg = await activeProject(h);
		const { job } = await claim();
		const ok = {
			status: "ok",
			codebase: {
				json: JSON.stringify({
					schemaVersion: "1",
					tool: { version: "0.3.0" },
					summary: {
						score: 90,
						grade: "A",
						counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
						categories: [],
						auditors: { passed: 1, failed: 0, skipped: 0, error: 0 },
					},
				}),
				html: "<p>first</p>",
			},
		};
		const path = `/api/scanner/jobs/${job?.id}`;
		expect(
			(await h.call("POST", path, { token: SCANNER_TOKEN, body: ok })).status,
		).toBe(204);
		expect(
			(await h.call("POST", path, { token: SCANNER_TOKEN, body: report }))
				.status,
		).toBe(404);
		expect(h.r2.objects.get(`${reg.id}/${job?.id}/codebase.html`)?.value).toBe(
			"<p>first</p>",
		);
	});
});
