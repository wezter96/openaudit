import { afterAll, beforeEach, describe, expect, test } from "bun:test";
import type { ProjectState } from "@openaudit/badge";
import {
	activeProject,
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

interface Job {
	id: string;
	projectId: string;
	repo: string;
	site: string | null;
	code: string;
}

const claim = async (token = SCANNER_TOKEN) =>
	(await (await h.call("POST", "/api/scanner/claim", { token })).json()) as {
		job: Job | null;
	};

const upload = (id: string, body: unknown, token = SCANNER_TOKEN) =>
	h.call("POST", `/api/scanner/jobs/${id}`, { token, body });

const okReport = (score = 96, grade = "A") => ({
	status: "ok",
	commit: "0123456789abcdef0123456789abcdef01234567",
	openauditVersion: "0.3.0",
	codebase: { json: reportJson(score, grade), html: "<h1>report</h1>" },
});

/** Claims the due job and uploads a report for it. */
const scanOnce = async (body: unknown = okReport()) => {
	const { job } = await claim();
	if (!job) throw new Error("no job");
	expect((await upload(job.id, body)).status).toBe(204);
	return job;
};

describe("scanner auth", () => {
	test("refuses a missing or wrong token, and any token without the secret", async () => {
		expect((await h.call("POST", "/api/scanner/claim")).status).toBe(401);
		expect(
			(await h.call("POST", "/api/scanner/claim", { token: "nope" })).status,
		).toBe(401);
		const { SCANNER_TOKEN: _, ...withoutSecret } = h.env;
		const res = await (await import("../index")).default.fetch(
			new Request("https://openaudit.se/api/scanner/claim", {
				method: "POST",
				headers: { authorization: "Bearer " },
			}),
			withoutSecret,
		);
		expect(res.status).toBe(401);
	});
});

describe("claim and upload", () => {
	test("hands out the due project once, then nothing", async () => {
		expect(await claim()).toEqual({ job: null });
		const reg = await activeProject(h);
		const { job } = await claim();
		expect(job).toMatchObject({
			projectId: reg.id,
			repo: "acme/widgets",
			site: null,
			code: reg.verification.code,
		});
		expect(await claim()).toEqual({ job: null });
	});

	test("an expired lease fails the scan and frees the project", async () => {
		await activeProject(h);
		const first = (await claim()).job;
		at(T0 + 30 * 60 + 1);
		const second = (await claim()).job;
		expect(second?.id).not.toBe(first?.id);
		const row = h.d1.sqlite
			.query("SELECT status, error FROM scans WHERE id = ?")
			.get(first?.id ?? "") as { status: string; error: string };
		expect(row).toEqual({ status: "failed", error: "scan timed out" });
		expect((await upload(first?.id ?? "", okReport())).status).toBe(404);
	});

	test("a timed-out project waits an hour before it's claimable again", async () => {
		const reg = await activeProject(h);
		await claim();
		const expiry = T0 + 30 * 60 + 1;
		at(expiry);
		expect(await claim()).toEqual({ job: null });
		const row = h.d1.sqlite
			.query("SELECT next_scan_at FROM projects WHERE id = ?")
			.get(reg.id) as { next_scan_at: number };
		expect(row.next_scan_at).toBe(expiry + 3600);
		at(expiry + 3600);
		expect((await claim()).job?.projectId).toBe(reg.id);
	});

	test("an ok scan with a site note keeps the codebase score and shows the note", async () => {
		const reg = await activeProject(h);
		await scanOnce({
			...okReport(),
			error: "site: <script>timed out</script>",
		});
		const state = (await (
			await h.call("GET", `/api/badges/${reg.id}`)
		).json()) as ProjectState;
		expect(state.latest).toMatchObject({
			status: "ok",
			site: null,
			error: "site: <script>timed out</script>",
			codebase: { score: 96 },
		});
		const svg = await (await h.call("GET", `/badge/${reg.id}.svg`)).text();
		expect(svg).toContain(">96 A<");
		const html = await (await h.call("GET", `/v/${reg.id}`)).text();
		expect(html).toContain(
			"From this scan: site: &lt;script&gt;timed out&lt;/script&gt;",
		);
		expect(html).not.toContain("<script>timed");
	});

	test("an upload stores the reports and schedules the next scan", async () => {
		const reg = await activeProject(h);
		const job = await scanOnce();
		expect([...h.r2.objects.keys()].sort()).toEqual([
			`${reg.id}/${job.id}/codebase.html`,
			`${reg.id}/${job.id}/codebase.json`,
		]);
		expect(
			h.r2.objects.get(`${reg.id}/${job.id}/codebase.html`)?.contentType,
		).toBe("text/html; charset=utf-8");
		const state = (await (
			await h.call("GET", `/api/badges/${reg.id}`)
		).json()) as ProjectState;
		expect(state.nextScanAt).toBe(T0 + 7 * 86_400);
		expect(state.latest).toMatchObject({
			id: job.id,
			status: "ok",
			commit: "0123456789abcdef0123456789abcdef01234567",
			codebase: { score: 96, grade: "A", openauditVersion: "0.3.0" },
		});
		expect((await upload(job.id, okReport())).status).toBe(404);
	});

	test("rejects reports that aren't openaudit reports", async () => {
		await activeProject(h);
		const { job } = await claim();
		const bad = { status: "ok", codebase: { json: "{}", html: "" } };
		expect((await upload(job?.id ?? "", bad)).status).toBe(422);
		expect((await upload(job?.id ?? "", { status: "ok" })).status).toBe(422);
		const long = { status: "failed", error: "x".repeat(501) };
		expect((await upload(job?.id ?? "", long)).status).toBe(400);
		expect((await upload("not-a-uuid", okReport())).status).toBe(400);
	});

	test("a failed scan keeps the last good one as latest", async () => {
		const reg = await activeProject(h);
		const good = await scanOnce();
		at(T0 + 8 * 86_400);
		await scanOnce({ status: "failed", error: "verification file missing" });
		const state = (await (
			await h.call("GET", `/api/badges/${reg.id}`)
		).json()) as ProjectState;
		expect(state.latest?.id).toBe(good.id);
		expect(state.lastScan).toMatchObject({
			status: "failed",
			error: "verification file missing",
		});
		const svg = await (await h.call("GET", `/badge/${reg.id}.svg`)).text();
		expect(svg).toContain(">96 A<");
		expect(svg).toContain(">scan failed<");
	});

	test("keeps only the newest five scans and their reports", async () => {
		const reg = await activeProject(h);
		const jobs: Job[] = [];
		for (let i = 0; i < 7; i++) {
			at(T0 + i * 8 * 86_400);
			jobs.push(await scanOnce(okReport(90 + i)));
		}
		const ids = h.d1.sqlite.query("SELECT id FROM scans").all() as {
			id: string;
		}[];
		expect(ids.length).toBe(5);
		expect(h.r2.objects.size).toBe(10);
		expect(h.r2.objects.has(`${reg.id}/${jobs[0]?.id}/codebase.html`)).toBe(
			false,
		);
	});

	test("removing a badge deletes its scans and reports, and a new sign-up starts empty", async () => {
		const reg = await activeProject(h);
		await scanOnce();
		expect(h.r2.objects.size).toBe(2);
		const del = await h.call("DELETE", `/api/badges/${reg.id}`, {
			token: reg.manageToken,
		});
		expect(del.status).toBe(204);
		expect(h.r2.objects.size).toBe(0);
		expect((await h.call("GET", `/v/${reg.id}/report`)).status).toBe(404);
		const again = await activeProject(h);
		expect(again.id).toBe(reg.id);
		const state = (await (
			await h.call("GET", `/api/badges/${reg.id}`)
		).json()) as ProjectState;
		expect(state.latest).toBeUndefined();
	});

	test("refuses oversized uploads", async () => {
		await activeProject(h);
		const { job } = await claim();
		const res = await h.call("POST", `/api/scanner/jobs/${job?.id}`, {
			token: SCANNER_TOKEN,
			body: {
				status: "ok",
				codebase: { json: "x".repeat(26 * 1024 * 1024), html: "" },
			},
		});
		expect(res.status).toBe(413);
	});
});

describe("public pages", () => {
	test("badge and card SVGs", async () => {
		const reg = await activeProject(h);
		await scanOnce();
		const res = await h.call("GET", `/badge/${reg.id}.svg`);
		expect(res.status).toBe(200);
		expect(res.headers.get("content-type")).toBe(
			"image/svg+xml; charset=utf-8",
		);
		expect(res.headers.get("cache-control")).toBe("public, max-age=900");
		expect(res.headers.get("access-control-allow-origin")).toBe("*");
		expect(await res.text()).toContain(">15 Oct 2026<");
		const card = await h.call("GET", `/badge/${reg.id}/card.svg`);
		expect(await card.text()).toContain(">acme/widgets<");
		const head = await h.call("HEAD", `/badge/${reg.id}.svg`);
		expect(await head.text()).toBe("");
	});

	test("long URLs, other methods and unknown ids stay cheap", async () => {
		const long = await h.call("GET", `/v/acme-widgets?${"a".repeat(600)}`);
		expect(long.status).toBe(414);
		expect((await h.call("POST", "/v/acme-widgets")).status).toBe(405);
		h.net.calls.length = 0;
		await h.call("GET", "/v/nobody-here/report");
		expect(h.r2.objects.size).toBe(0);
		expect(h.net.calls).toEqual([]);
	});

	test("an unknown badge is a grey 404", async () => {
		const res = await h.call("GET", "/badge/nobody-here.svg");
		expect(res.status).toBe(404);
		expect(await res.text()).toContain(">not found<");
	});

	test("the verification page", async () => {
		const reg = await activeProject(h);
		await scanOnce();
		const res = await h.call("GET", `/v/${reg.id}`);
		expect(res.status).toBe(200);
		expect(res.headers.get("content-security-policy")).toMatch(
			/^default-src 'none'; style-src 'sha256-[A-Za-z0-9+/=]+'/,
		);
		const html = await res.text();
		expect(html).toContain("Verified and up to date");
		expect(html).toContain(`href="/v/${reg.id}/report"`);
		expect(html).not.toContain(reg.verification.code);
		expect((await h.call("GET", "/v/nobody-here")).status).toBe(404);
	});

	test("stored reports are sandboxed", async () => {
		const reg = await activeProject(h);
		const first = await scanOnce(okReport(80, "B"));
		at(T0 + 8 * 86_400);
		await scanOnce();
		const res = await h.call("GET", `/v/${reg.id}/report`);
		expect(res.status).toBe(200);
		expect(res.headers.get("content-security-policy")).toBe(
			"sandbox allow-scripts allow-downloads allow-popups",
		);
		expect(res.headers.get("x-content-type-options")).toBe("nosniff");
		expect(res.headers.get("cache-control")).toBe("public, max-age=300");
		expect(await res.text()).toBe("<h1>report</h1>");
		const old = await h.call("GET", `/v/${reg.id}/report?scan=${first.id}`);
		expect(old.status).toBe(200);
		expect((await h.call("GET", `/v/${reg.id}/site-report`)).status).toBe(404);
	});
});
