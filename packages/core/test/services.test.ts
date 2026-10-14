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

describe("gitignore", () => {
	const repo = mkdtempSync(join(tmpdir(), "openaudit-gitignore-"));
	const git = (...args: string[]) =>
		Bun.spawnSync(["git", ...args], {
			cwd: repo,
			env: {
				...process.env,
				GIT_AUTHOR_NAME: "t",
				GIT_AUTHOR_EMAIL: "t@example.com",
				GIT_COMMITTER_NAME: "t",
				GIT_COMMITTER_EMAIL: "t@example.com",
			},
		});
	mkdirSync(join(repo, "src"));
	mkdirSync(join(repo, "logs"));
	writeFileSync(join(repo, "src", "a.ts"), "export {}");
	writeFileSync(join(repo, "hidden.js"), "committed, then ignored");
	git("init", "-q");
	git("add", "src/a.ts", "hidden.js");
	git("commit", "-qm", "init");
	writeFileSync(join(repo, ".gitignore"), ".env\nlogs/\nhidden.js\n");
	writeFileSync(join(repo, ".env"), "KEY=abc");
	writeFileSync(join(repo, "logs", "a.log"), "x");
	afterAll(() => rmSync(repo, { recursive: true, force: true }));

	const ws = makeWorkspace(repo);
	test("lists tracked files and leaves out untracked ignored ones", async () => {
		expect([...(await Effect.runPromise(ws.files))].sort()).toEqual([
			".gitignore",
			"hidden.js",
			"src/a.ts",
		]);
		expect([...(await Effect.runPromise(ws.ignored))].sort()).toEqual([
			".env",
			"logs/",
		]);
	});

	test("an inherited GIT_DIR can't point the listing elsewhere", async () => {
		const saved = process.env.GIT_DIR;
		process.env.GIT_DIR = join(dir, "nowhere.git");
		try {
			const fresh = makeWorkspace(repo);
			expect(await Effect.runPromise(fresh.files)).toContain("src/a.ts");
		} finally {
			if (saved === undefined) delete process.env.GIT_DIR;
			else process.env.GIT_DIR = saved;
		}
	});

	const reporter = (id: string, keepIgnored?: boolean) =>
		defineAuditor({
			id,
			title: id,
			description: id,
			categories: ["security"],
			targets: ["codebase"],
			engine: "external",
			...(keepIgnored ? { keepIgnored } : {}),
			run: () =>
				Effect.succeed(
					[
						".env",
						"./logs/a.log",
						join(repo, ".env"),
						"hidden.js",
						"src/a.ts",
					].map((file, i) => ({
						ruleId: `${id}/r${i}`,
						title: "t",
						message: "m",
						severity: "high" as const,
						category: "security" as const,
						location: { file },
					})),
				),
		});

	test("findings in ignored files are dropped and counted", async () => {
		const report = await Effect.runPromise(
			runAudit({
				target: repo,
				auditors: [reporter("test.walker"), reporter("test.history", true)],
			}).pipe(Effect.provide(CoreLive)),
		);
		const files = (id: string) =>
			report.results
				.find((r) => r.auditor === id)
				?.findings.map((f) => f.location?.file);
		// Committed files stay even though .gitignore now matches them.
		expect(files("test.walker")).toEqual(["hidden.js", "src/a.ts"]);
		expect(files("test.history")).toHaveLength(5);
		expect(report.suppressed).toEqual([
			{ source: ".gitignore", rules: 0, paths: 3, fingerprints: 0 },
		]);
	});
});
