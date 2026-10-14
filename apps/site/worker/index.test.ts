import { describe, expect, test } from "bun:test";
import { markdownFor, prefersMarkdown } from "./agents";
import worker, { type Env } from "./index";

const HTML = { "content-type": "text/html; charset=utf-8" };
const files: Record<string, [string, Record<string, string>]> = {
	"/": ["<!doctype html><title>home</title>", HTML],
	"/docs/cli/": ["<!doctype html><title>cli</title>", HTML],
	"/index.md": ["# openaudit\n", { "content-type": "text/markdown" }],
	"/docs/cli/index.md": [
		"# CLI reference\n\nFlags.\n",
		{ "content-type": "text/markdown" },
	],
	"/report/openaudit-report.md": [
		"# Report\n",
		{ "content-type": "text/markdown" },
	],
	"/llms.txt": ["# openaudit\n", { "content-type": "text/plain" }],
	"/.well-known/api-catalog": [
		'{"linkset":[]}',
		{ "content-type": "application/octet-stream" },
	],
	"/.well-known/ai-catalog.json": [
		'{"specVersion":"1.0"}',
		{ "content-type": "application/json" },
	],
	"/.well-known/mcp/server-card.json": [
		'{"name":"se.openaudit/catalogue"}',
		{ "content-type": "application/json" },
	],
	"/.well-known/mcp/index.json": [
		'{"mcp_version":"x"}',
		{ "content-type": "application/json" },
	],
	"/favicon.svg": ["<svg/>", { "content-type": "image/svg+xml" }],
};
const env: Env = {
	ASSETS: {
		fetch: async (request) => {
			const path = new URL(request.url).pathname;
			const file = files[path];
			if (!file)
				return new Response("<!doctype html>404", {
					status: 404,
					headers: HTML,
				});
			return new Response(request.method === "HEAD" ? null : file[0], {
				headers: { ...file[1], "cross-origin-resource-policy": "same-origin" },
			});
		},
	},
};
const get = (
	path: string,
	headers: Record<string, string> = {},
	method = "GET",
) =>
	worker.fetch(
		new Request(`https://openaudit.se${path}`, { method, headers }),
		env,
	);

describe("content negotiation", () => {
	test("Accept preferences", () => {
		expect(prefersMarkdown("text/markdown")).toBe(true);
		expect(prefersMarkdown("text/markdown, text/html;q=0.9")).toBe(true);
		expect(prefersMarkdown("text/html, text/markdown")).toBe(true);
		expect(prefersMarkdown("text/html,application/xhtml+xml,*/*;q=0.8")).toBe(
			false,
		);
		expect(prefersMarkdown("text/markdown;q=0.5, */*")).toBe(false);
		expect(prefersMarkdown("text/markdown;q=0")).toBe(false);
		expect(prefersMarkdown(null)).toBe(false);
	});

	test("page paths map to their Markdown", () => {
		expect(markdownFor("/")).toBe("/index.md");
		expect(markdownFor("/docs/cli/")).toBe("/docs/cli/index.md");
		expect(markdownFor("/docs/cli")).toBe("/docs/cli/index.md");
		expect(markdownFor("/report/")).toBe("/report/openaudit-report.md");
		expect(markdownFor("/favicon.svg")).toBeUndefined();
	});

	test("HTML stays the default, with Link and Vary", async () => {
		const res = await get("/docs/cli/", { accept: "text/html" });
		expect(await res.text()).toContain("<title>cli</title>");
		expect(res.headers.get("vary")).toContain("Accept");
		const link = res.headers.get("link") ?? "";
		for (const rel of [
			'rel="api-catalog"',
			'rel="service-desc"',
			'rel="service-doc"',
			'rel="describedby"',
			'rel="ai-catalog"',
		])
			expect(link).toContain(rel);
		expect(link).toContain(
			'</docs/cli/index.md>; rel="alternate"; type="text/markdown"',
		);
	});

	test("Accept: text/markdown gets the page's Markdown", async () => {
		const res = await get("/docs/cli/", { accept: "text/markdown" });
		expect(res.status).toBe(200);
		expect(res.headers.get("content-type")).toBe(
			"text/markdown; charset=utf-8",
		);
		expect(res.headers.get("vary")).toBe("Accept");
		const body = await res.text();
		expect(body).toStartWith("# CLI reference");
		expect(res.headers.get("x-markdown-tokens")).toBe(
			String(Math.ceil(body.length / 4)),
		);
		const home = await get("/", { accept: "text/markdown" });
		expect(await home.text()).toBe("# openaudit\n");
		const head = await get("/", { accept: "text/markdown" }, "HEAD");
		expect(head.headers.get("x-markdown-tokens")).toBe("3");
		expect(await head.text()).toBe("");
	});

	test("a page without Markdown falls back to HTML; 404s get no alternate", async () => {
		const res = await get("/nowhere/", { accept: "text/markdown" });
		expect(res.status).toBe(404);
		expect(res.headers.get("link")).not.toContain("text/markdown");
	});
});

describe("agent files", () => {
	test("content types and CORS", async () => {
		const cases: Array<[string, string]> = [
			["/llms.txt", "text/plain; charset=utf-8"],
			[
				"/.well-known/api-catalog",
				'application/linkset+json; profile="https://www.rfc-editor.org/info/rfc9727"',
			],
			["/.well-known/ai-catalog.json", "application/json"],
			["/docs/cli/index.md", "text/markdown; charset=utf-8"],
		];
		for (const [path, type] of cases) {
			const res = await get(path);
			expect(res.headers.get("content-type")).toBe(type);
			expect(res.headers.get("access-control-allow-origin")).toBe("*");
			expect(res.headers.get("cross-origin-resource-policy")).toBe(
				"cross-origin",
			);
		}
		const pre = await get("/llms.txt", {}, "OPTIONS");
		expect(pre.status).toBe(204);
		expect(pre.headers.get("access-control-allow-origin")).toBe("*");
	});

	test("/.well-known/mcp and /mcp/server-card", async () => {
		const manifest = await get("/.well-known/mcp");
		expect(await manifest.json()).toEqual({ mcp_version: "x" });
		expect(manifest.headers.get("access-control-allow-origin")).toBe("*");
		const card = await get("/mcp/server-card");
		expect(card.headers.get("content-type")).toBe(
			"application/mcp-server-card+json",
		);
		expect((await card.json()).name).toBe("se.openaudit/catalogue");
	});

	test("other assets pass through untouched", async () => {
		const res = await get("/favicon.svg");
		expect(res.headers.get("content-type")).toBe("image/svg+xml");
		expect(res.headers.get("access-control-allow-origin")).toBeNull();
		expect(res.headers.get("link")).toBeNull();
	});
});

describe("routing", () => {
	test("www redirects to the apex", async () => {
		const res = await worker.fetch(
			new Request("https://www.openaudit.se/docs/?a=1"),
			env,
		);
		expect(res.status).toBe(301);
		expect(res.headers.get("location")).toBe("https://openaudit.se/docs/?a=1");
	});

	test("/mcp is the MCP endpoint", async () => {
		const res = await worker.fetch(
			new Request("https://openaudit.se/mcp", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
			}),
			env,
		);
		expect(await res.json()).toEqual({ jsonrpc: "2.0", id: 1, result: {} });
		expect((await get("/mcp")).status).toBe(405);
	});
});
