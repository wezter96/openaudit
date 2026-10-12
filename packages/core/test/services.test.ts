import { afterAll, describe, expect, test } from "bun:test";
import {
	mkdirSync,
	mkdtempSync,
	rmSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Effect } from "effect";

import { CoreLive, defineAuditor, Http, makeWorkspace, runAudit } from "../src";

const dir = mkdtempSync(join(tmpdir(), "openaudit-ws-"));
const outside = mkdtempSync(join(tmpdir(), "openaudit-outside-"));
writeFileSync(join(outside, "secret.txt"), "top secret");
mkdirSync(join(dir, "src"));
writeFileSync(join(dir, "src", "a.ts"), "export {}");
symlinkSync(join(outside, "secret.txt"), join(dir, "link.txt"));
afterAll(() => {
	rmSync(dir, { recursive: true, force: true });
	rmSync(outside, { recursive: true, force: true });
});

describe("Workspace", () => {
	const ws = makeWorkspace(dir);
	test("lists regular files and skips symlinks", async () => {
		expect(await Effect.runPromise(ws.files)).toEqual(["src/a.ts"]);
	});
	test("refuses paths that escape the root", async () => {
		const traversal = await Effect.runPromise(Effect.flip(ws.readText("../x")));
		expect(traversal._tag).toBe("AuditorError");
		const viaLink = await Effect.runPromise(
			Effect.flip(ws.readText("link.txt")),
		);
		expect(String(viaLink.cause)).toContain("outside workspace");
		expect(await Effect.runPromise(ws.exists("link.txt"))).toBe(false);
	});
});

describe("Http", () => {
	const seen: Record<string, string | null> = {};
	const other = Bun.serve({
		port: 0,
		fetch: (req) => {
			seen.other = req.headers.get("authorization");
			seen.otherKey = req.headers.get("x-api-key");
			return new Response("other");
		},
	});
	const target = Bun.serve({
		port: 0,
		fetch: (req) => {
			const path = new URL(req.url).pathname;
			if (path === "/away")
				return Response.redirect(`${other.url}landing`, 302);
			if (path === "/big") return new Response("x".repeat(100_000));
			seen.target = req.headers.get("authorization");
			return new Response("ok");
		},
	});
	afterAll(() => {
		other.stop(true);
		target.stop(true);
	});

	const request = (url: string, maxBytes?: number) =>
		Effect.runPromise(
			Effect.gen(function* () {
				const http = yield* Http;
				return yield* http.request(url, {
					headers: { authorization: "Bearer t", "x-api-key": "k" },
					maxBytes,
				});
			}).pipe(Effect.provide(CoreLive)),
		);

	test("drops credentials on cross-origin redirects", async () => {
		const res = await request(`${target.url}away`);
		expect(res.redirected).toBe(true);
		expect(res.body).toBe("other");
		expect(seen.other).toBeNull();
		expect(seen.otherKey).toBeNull();
	});

	test("caps buffered body size", async () => {
		const res = await request(`${target.url}big`, 1000);
		expect(res.body.length).toBe(1000);
	});

	test("engine only sends user headers to the exact target origin", async () => {
		const lookalike = `${target.url.origin}.evil.test/`;
		const sent: string[] = [];
		const probe = defineAuditor({
			id: "test.probe",
			title: "probe",
			description: "probe",
			categories: ["security"],
			targets: ["url"],
			engine: "builtin",
			run: (ctx) =>
				Effect.gen(function* () {
					yield* ctx.http(`${target.url}`);
					sent.push(String(seen.target));
					// Look-alike host must not receive the header; request may fail, that's fine.
					yield* Effect.ignore(ctx.http(lookalike, { timeoutMs: 500 }));
					return [];
				}),
		});
		await Effect.runPromise(
			runAudit({
				target: target.url.toString(),
				auditors: [probe],
				options: { headers: { authorization: "Bearer user" } },
			}).pipe(Effect.provide(CoreLive)),
		);
		expect(sent).toEqual(["Bearer user"]);
	});
});
