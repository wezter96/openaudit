import { afterAll, beforeEach, describe, expect, test } from "bun:test";
import type { QuickState } from "@openaudit/badge";
import { QUICK_KEEP, QUICK_LEASE, QUICK_PER_IP, QUICK_QUEUE } from "./quick";
import {
	at,
	type Harness,
	makeHarness,
	reportJson,
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
	h = makeHarness();
});

const start = (site: string, ip?: string) =>
	h.call("POST", "/api/quick", { body: { site }, ip });

const startId = async (site: string, ip?: string) => {
	const res = await start(site, ip);
	expect(res.status).toBe(202);
	return ((await res.json()) as { id: string }).id;
};

const state = async (id: string) =>
	(await (await h.call("GET", `/api/quick/${id}`)).json()) as QuickState;

const claim = async () =>
	(
		(await (
			await h.call("POST", "/api/scanner/quick/claim", { token: SCANNER_TOKEN })
		).json()) as { job: { id: string; site: string } | null }
	).job;

const upload = (id: string, body: unknown) =>
	h.call("POST", `/api/scanner/quick/${id}`, { token: SCANNER_TOKEN, body });

const ok = {
	status: "ok",
	openauditVersion: "0.4.1",
	site: { json: reportJson(82, "B"), html: "<h1>site report</h1>" },
};

describe("quick audits", () => {
	test("queue, claim, report and read the report", async () => {
		const id = await startId("example.com");
		expect(await state(id)).toMatchObject({
			site: "https://example.com/",
			status: "queued",
			ahead: 0,
			summary: null,
		});
		const job = await claim();
		expect(job).toEqual({ id, site: "https://example.com/" });
		expect((await state(id)).status).toBe("running");
		expect((await upload(id, ok)).status).toBe(204);
		const done = await state(id);
		expect(done.status).toBe("ok");
		expect(done.summary?.score).toBe(82);
		const page = await h.call("GET", `/q/${id}`);
		expect(page.status).toBe(200);
		expect(await page.text()).toBe("<h1>site report</h1>");
		expect(page.headers.get("content-security-policy")).toContain("sandbox");
		expect(page.headers.get("x-robots-tag")).toContain("noindex");
	});

	test("refuses private, non-https and malformed sites", async () => {
		for (const site of [
			"http://example.com",
			"https://localhost",
			"https://10.0.0.1",
			"https://router.lan",
			"https://user:pw@example.com",
			"https://example.com:8443",
			"not a url",
		])
			expect((await start(site)).status).toBe(422);
	});

	test("reuses a queued or recent audit of the same site", async () => {
		const id = await startId("https://example.com");
		expect(await startId("https://example.com/")).toBe(id);
		await claim();
		await upload(id, ok);
		at(T0 + 30 * 60);
		expect(await startId("https://example.com")).toBe(id);
		at(T0 + 2 * 60 * 60);
		expect(await startId("https://example.com")).not.toBe(id);
	});

	test("limits each address per day", async () => {
		for (let n = 0; n < QUICK_PER_IP; n++) {
			const id = await startId(`https://site${n}.example`);
			await claim();
			await upload(id, ok);
		}
		expect((await start("https://another.example")).status).toBe(429);
		expect(
			(await start("https://another.example", "198.51.100.9")).status,
		).toBe(202);
	});

	test("refuses new audits while the queue is full", async () => {
		for (let n = 0; n < QUICK_QUEUE; n++)
			await startId(`https://q${n}.example`, `198.51.100.${n}`);
		expect((await start("https://late.example", "192.0.2.1")).status).toBe(503);
		const last = await startId("https://q0.example", "192.0.2.2");
		expect((await state(last)).status).toBe("queued");
	});

	test("reports queue position", async () => {
		await startId("https://a.example");
		at(T0 + 1);
		const b = await startId("https://b.example");
		expect((await state(b)).ahead).toBe(1);
	});

	test("a failed audit keeps its error, and a late report is refused", async () => {
		const id = await startId("https://example.com");
		await claim();
		expect(
			(await upload(id, { status: "failed", error: "could not resolve" }))
				.status,
		).toBe(204);
		expect(await state(id)).toMatchObject({
			status: "failed",
			error: "could not resolve",
		});
		expect((await upload(id, ok)).status).toBe(404);
		expect((await h.call("GET", `/q/${id}`)).status).toBe(404);
	});

	test("a lease runs out and the audit fails", async () => {
		const id = await startId("https://example.com");
		await claim();
		at(T0 + QUICK_LEASE + 1);
		expect(await claim()).toBeNull();
		expect(await state(id)).toMatchObject({
			status: "failed",
			error: "the audit timed out",
		});
		expect((await upload(id, ok)).status).toBe(404);
	});

	test("an ok report must carry a real openaudit report", async () => {
		const id = await startId("https://example.com");
		await claim();
		expect(
			(
				await upload(id, {
					status: "ok",
					site: { json: "{}", html: "<p>x</p>" },
				})
			).status,
		).toBe(422);
		expect(h.r2.objects.size).toBe(0);
	});

	test("the scanner routes need the scanner token", async () => {
		expect((await h.call("POST", "/api/scanner/quick/claim")).status).toBe(401);
	});

	test("old audits and their reports are deleted", async () => {
		const id = await startId("https://example.com");
		await claim();
		await upload(id, ok);
		expect(h.r2.objects.size).toBe(2);
		at(T0 + QUICK_KEEP + 1);
		await startId("https://other.example");
		expect(h.r2.objects.size).toBe(0);
		expect((await h.call("GET", `/api/quick/${id}`)).status).toBe(404);
	});
});
