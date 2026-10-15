/** A Worker wired to fake bindings, plus helpers to call it. */
import { setSystemTime } from "bun:test";
import worker, { type Env } from "../../index";
import { fakeD1, fakeFetch, fakeR2, type Routes } from "./fakes";

export const SCANNER_TOKEN = "scanner-secret-token";
export const T0 = Date.UTC(2026, 9, 15, 12) / 1000;

export const at = (seconds: number) => setSystemTime(new Date(seconds * 1000));

export const github = (repo: string, extra: Record<string, unknown> = {}) => ({
	[`https://api.github.com/repos/${repo}`]: () =>
		Response.json({ full_name: repo, private: false, size: 1200, ...extra }),
});

export const repoFile = (repo: string, text: string) => ({
	[`https://raw.githubusercontent.com/${repo}/HEAD/.openaudit-badge`]: () =>
		new Response(text),
});

export const makeHarness = (routes: Routes = {}) => {
	const env: Env = {
		ASSETS: { fetch: async () => new Response("asset", { status: 404 }) },
		BADGES: fakeD1(),
		BADGE_REPORTS: fakeR2(),
		SCANNER_TOKEN,
	};
	const net = fakeFetch(routes);
	globalThis.fetch = net.fetch;
	const call = (
		method: string,
		path: string,
		options: { body?: unknown; token?: string; ip?: string } = {},
	) => {
		const headers = new Headers({
			"cf-connecting-ip": options.ip ?? "203.0.113.7",
		});
		if (options.token) headers.set("authorization", `Bearer ${options.token}`);
		if (options.body !== undefined)
			headers.set("content-type", "application/json");
		const body =
			options.body === undefined ? undefined : JSON.stringify(options.body);
		return worker.fetch(
			new Request(`https://openaudit.se${path}`, { method, headers, body }),
			env,
		);
	};
	return {
		env,
		net,
		routes,
		call,
		d1: env.BADGES as ReturnType<typeof fakeD1>,
		r2: env.BADGE_REPORTS as ReturnType<typeof fakeR2>,
	};
};

export type Harness = ReturnType<typeof makeHarness>;

export const reportJson = (score = 96, grade = "A") =>
	JSON.stringify({
		schemaVersion: "1",
		tool: { name: "openaudit", version: "0.3.0" },
		summary: {
			score,
			grade,
			counts: { critical: 0, high: 1, medium: 0, low: 2, info: 0 },
			categories: [{ category: "security", score, grade }],
			auditors: { passed: 20, failed: 3, skipped: 9, error: 0 },
		},
		results: [],
	});

/** Registers acme/widgets and verifies its repo, so it's due now. */
export const activeProject = async (h: Harness, repo = "acme/widgets") => {
	Object.assign(h.routes, github(repo));
	const res = await h.call("POST", "/api/badges", { body: { repo } });
	const reg = (await res.json()) as {
		id: string;
		manageToken: string;
		verification: { code: string };
	};
	Object.assign(h.routes, repoFile(repo, reg.verification.code));
	await h.call("POST", `/api/badges/${reg.id}/verify`);
	return reg;
};
