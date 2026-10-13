import { afterAll, describe, expect, test } from "bun:test";

import {
	isDefault404,
	reliability,
	wwwCounterpart,
} from "../src/web/reliability";
import { ruleIds, runAuditor } from "./helpers";
import { type Site, serve } from "./web-server";

const html = (body: string, init: ResponseInit = {}) =>
	new Response(body, {
		...init,
		headers: { "content-type": "text/html", ...init.headers },
	});
const page = (links: string[]) =>
	`<html><head><title>t</title></head><body>${links.map((l) => `<a href="${l}">x</a>`).join("")}</body></html>`;
const redirect = (to: string, status = 301) =>
	new Response(null, { status, headers: { location: to } });

const sites: Site[] = [];
const start = (...args: Parameters<typeof serve>) => {
	const site = serve(...args);
	sites.push(site);
	return site;
};
afterAll(() => {
	for (const s of sites) s.stop();
});

const notFound = () =>
	html(
		"<html><body><h1>We lost that page</h1><a href='/'>Home</a> and plenty of friendly help text</body></html>",
		{ status: 404 },
	);

describe("web.reliability helpers", () => {
	test("apex/www counterpart", () => {
		expect(wwwCounterpart("example.com")).toBe("www.example.com");
		expect(wwwCounterpart("www.example.com")).toBe("example.com");
		expect(wwwCounterpart("blog.example.com")).toBeUndefined();
		expect(wwwCounterpart("example.co.uk")).toBe("www.example.co.uk");
		expect(wwwCounterpart("127.0.0.1")).toBeUndefined();
	});

	test("default 404 detection", () => {
		expect(isDefault404({ body: "" })).toBe(true);
		expect(isDefault404({ body: "Cannot GET /zzz" })).toBe(true);
		expect(
			isDefault404({
				body: "<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>",
			}),
		).toBe(true);
		expect(
			isDefault404({
				body: "<html><body><h1>Oops</h1><p>That page does not exist. Try our search or visit the homepage.</p></body></html>",
			}),
		).toBe(false);
	});
});

describe("web.reliability on local sites", () => {
	test("a healthy site has no findings", async () => {
		const site = start(
			{ "/": () => html(page(["/about"])), "/about": () => html(page(["/"])) },
			notFound,
		);
		const report = await runAuditor(reliability, site.url);
		expect(ruleIds(report)).toEqual([]);
		expect(site.requests.every((r) => r.startsWith("GET"))).toBe(true);
	});

	test("5xx pages, 503 without Retry-After, and soft 404", async () => {
		const site = start(
			{
				"/": () => html(page(["/boom", "/maint", "/maint-ok"])),
				"/boom": () => html("error", { status: 500 }),
				"/maint": () => html("down", { status: 503 }),
				"/maint-ok": () =>
					html("down", { status: 503, headers: { "retry-after": "120" } }),
			},
			() => html(page([])),
		);
		const report = await runAuditor(reliability, site.url);
		const findings = report.results[0]?.findings ?? [];
		expect(ruleIds(report)).toEqual([
			"web.reliability/503-no-retry-after",
			"web.reliability/server-error",
			"web.reliability/server-error",
			"web.reliability/server-error",
			"web.reliability/soft-404",
		]);
		expect(
			findings.filter((f) => f.ruleId.endsWith("503-no-retry-after")),
		).toHaveLength(1);
		expect(findings.every((f) => f.category === "reliability")).toBe(true);
	});

	test("long redirect chain", async () => {
		const site = start(
			{
				"/": () => redirect("/a"),
				"/a": () => redirect("/b", 302),
				"/b": () => redirect("/c"),
				"/c": () => html(page([])),
			},
			notFound,
		);
		const report = await runAuditor(reliability, site.url);
		const f = report.results[0]?.findings.find(
			(x) => x.ruleId === "web.reliability/redirect-chain",
		);
		expect(f?.title).toBe("Redirect chain of 3 hops");
		expect(f?.evidence).toContain("/a");
	});

	test("two hops are fine; a loop is reported without crawling", async () => {
		const ok = start(
			{
				"/": () => redirect("/a"),
				"/a": () => redirect("/b"),
				"/b": () => html(page([])),
			},
			notFound,
		);
		expect(ruleIds(await runAuditor(reliability, ok.url))).toEqual([]);
		const loop = start(
			{ "/": () => redirect("/a"), "/a": () => redirect("/") },
			notFound,
		);
		const report = await runAuditor(reliability, loop.url);
		expect(ruleIds(report)).toEqual(["web.reliability/redirect-loop"]);
		expect(report.results[0]?.status).not.toBe("error");
	});

	test("unknown URLs that crash or fall back to defaults", async () => {
		const crash = start({ "/": () => html(page([])) }, () =>
			html("boom", { status: 500 }),
		);
		expect(ruleIds(await runAuditor(reliability, crash.url))).toEqual([
			"web.reliability/404-server-error",
		]);
		const plain = start({ "/": () => html(page([])) }, () =>
			html("Cannot GET /x", { status: 404 }),
		);
		expect(ruleIds(await runAuditor(reliability, plain.url))).toEqual([
			"web.reliability/default-404-page",
		]);
		const toHome = start({ "/": () => html(page([])) }, () => redirect("/"));
		expect(ruleIds(await runAuditor(reliability, toHome.url))).toEqual([
			"web.reliability/soft-404",
		]);
	});
});
