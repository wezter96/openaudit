import { afterAll, describe, expect, test } from "bun:test";

import { makeScannerClient } from "../src/client";

const SCAN_ID = "0b6f2a1e-3c4d-4e5f-8a9b-0c1d2e3f4a5b";
const JOB = {
	id: SCAN_ID,
	projectId: "wezter96-openaudit",
	repo: "wezter96/openaudit",
	site: null,
	code: "c0de",
};

const seen: Array<{ path: string; auth: string | null; body: string }> = [];
let nextJob: typeof JOB | null = JOB;

const server = Bun.serve({
	port: 0,
	hostname: "localhost",
	fetch: async (req) => {
		const path = new URL(req.url).pathname;
		seen.push({
			path,
			auth: req.headers.get("authorization"),
			body: await req.text(),
		});
		if (req.headers.get("authorization") !== "Bearer tok")
			return Response.json(
				{ _tag: "Unauthorized", message: "no" },
				{ status: 401 },
			);
		if (path === "/api/scanner/claim") return Response.json({ job: nextJob });
		if (path === `/api/scanner/jobs/${SCAN_ID}`)
			return new Response(null, { status: 204 });
		return new Response("not found", { status: 404 });
	},
});
afterAll(() => server.stop(true));

const client = (token = "tok") =>
	makeScannerClient({
		apiUrl: `http://localhost:${server.port}`,
		token,
		openaudit: ["openaudit"],
	});

describe("makeScannerClient", () => {
	test("claims with the bearer token", async () => {
		nextJob = JOB;
		expect(await (await client()).claim()).toEqual(JOB);
		expect(seen.at(-1)).toMatchObject({
			path: "/api/scanner/claim",
			auth: "Bearer tok",
		});
		nextJob = null;
		expect(await (await client()).claim()).toBeNull();
	});

	test("reports a result to the scan's endpoint", async () => {
		await (await client()).report(SCAN_ID, {
			status: "failed",
			error: "verification file missing",
		});
		const last = seen.at(-1);
		expect(last?.path).toBe(`/api/scanner/jobs/${SCAN_ID}`);
		expect(JSON.parse(last?.body ?? "")).toEqual({
			status: "failed",
			error: "verification file missing",
		});
	});

	test("rejects when the token is wrong", async () => {
		await expect((await client("nope")).claim()).rejects.toBeDefined();
	});
});
