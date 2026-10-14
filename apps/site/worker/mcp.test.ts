import { describe, expect, test } from "bun:test";
import {
	type Assets,
	handleMcp,
	LIMITS,
	PROTOCOL_VERSIONS,
	SERVER_INFO,
	TOOLS,
	validate,
} from "./mcp";

const catalogue = {
	version: "0.0.0-test",
	auditors: [
		{
			id: "code.secrets",
			title: "Secrets in source",
			description: "Detects committed credentials.",
			engine: "builtin",
			tool: null,
			categories: ["security"],
			targets: ["codebase"],
			network: false,
			optIn: false,
			command: "bunx @openaudit/cli . --only code.secrets",
			url: "https://openaudit.se/auditors/code.secrets/",
		},
		{
			id: "web.a11y",
			title: "Accessibility markup",
			description: "Checks alt text and labels.",
			engine: "builtin",
			tool: null,
			categories: ["accessibility"],
			targets: ["url"],
			network: false,
			optIn: false,
			command: "bunx @openaudit/cli https://example.com --only web.a11y",
			url: "https://openaudit.se/auditors/web.a11y/",
		},
		{
			id: "agent.authz",
			title: "Authorization review",
			description: "An agent traces access control.",
			engine: "agentic",
			tool: null,
			categories: ["security"],
			targets: ["codebase"],
			network: true,
			optIn: true,
			command: "bunx @openaudit/cli . --only agent.authz",
			url: "https://openaudit.se/auditors/agent.authz/",
		},
	],
	playbooks: [
		{
			id: "agent.authz",
			title: "Authorization review",
			summary: "Trace who can reach what.",
			needs: ["code"],
			markdown: "# Authorization\n\n## Checklist\n\n- [ ] every route",
		},
	],
};
const docs = {
	version: "0.0.0-test",
	sections: [
		{
			page: "Configuration",
			heading: "Suppressions",
			url: "https://openaudit.se/docs/configuration/#suppressions",
			text: "Use a baseline or ignore.rules to suppress findings. A baseline keeps only new findings.",
		},
		{
			page: "CLI reference",
			heading: "Exit codes",
			url: "https://openaudit.se/docs/cli/#exit-codes",
			text: "Exit 1 when findings reach --fail-on.",
		},
	],
	install: {
		cli: "Run `bunx @openaudit/cli .`",
		mcp: "claude mcp add openaudit -- bunx @openaudit/cli mcp",
	},
};
const schema = {
	$schema: "http://json-schema.org/draft-07/schema#",
	type: "object",
};

const assets = (
	files: Record<string, unknown> = {},
): Assets & { hits: string[] } => {
	const all: Record<string, unknown> = {
		"/data/catalogue.json": catalogue,
		"/data/docs.json": docs,
		"/schema/config.json": schema,
		...files,
	};
	const hits: string[] = [];
	return {
		hits,
		fetch: async (request) => {
			const path = new URL(request.url).pathname;
			hits.push(path);
			return path in all
				? Response.json(all[path])
				: new Response("not found", { status: 404 });
		},
	};
};

const post = (body: unknown, headers: Record<string, string> = {}) =>
	new Request("https://openaudit.se/mcp", {
		method: "POST",
		headers: {
			"content-type": "application/json",
			accept: "application/json, text/event-stream",
			...headers,
		},
		body: typeof body === "string" ? body : JSON.stringify(body),
	});

// biome-ignore lint/suspicious/noExplicitAny: test replies are inspected loosely
const rpc = async (body: unknown, a: Assets = assets()): Promise<any> => {
	const res = await handleMcp(post(body), a);
	expect(res.headers.get("content-type")).toBe("application/json");
	return res.json();
};
const call = (name: string, args?: unknown, a?: Assets) =>
	rpc(
		{
			jsonrpc: "2.0",
			id: 1,
			method: "tools/call",
			params: { name, ...(args === undefined ? {} : { arguments: args }) },
		},
		a,
	);

describe("protocol", () => {
	test("initialize negotiates the version and describes the server", async () => {
		const r = await rpc({
			jsonrpc: "2.0",
			id: 1,
			method: "initialize",
			params: {
				protocolVersion: "2025-06-18",
				capabilities: {},
				clientInfo: { name: "t", version: "1" },
			},
		});
		expect(r.id).toBe(1);
		expect(r.result.protocolVersion).toBe("2025-06-18");
		expect(r.result.capabilities).toEqual({ tools: { listChanged: false } });
		expect(r.result.serverInfo.name).toBe(SERVER_INFO.name);
		expect(r.result.instructions).toContain("bunx @openaudit/cli mcp");
	});

	test("an unknown protocol version gets the newest", async () => {
		const r = await rpc({
			jsonrpc: "2.0",
			id: "a",
			method: "initialize",
			params: { protocolVersion: "1999-01-01" },
		});
		expect(r.result.protocolVersion).toBe(PROTOCOL_VERSIONS[0]);
	});

	test("notifications are accepted without a body", async () => {
		const res = await handleMcp(
			post({ jsonrpc: "2.0", method: "notifications/initialized" }),
			assets(),
		);
		expect(res.status).toBe(202);
		expect(await res.text()).toBe("");
	});

	test("ping and tools/list", async () => {
		expect(
			(await rpc({ jsonrpc: "2.0", id: 2, method: "ping" })).result,
		).toEqual({});
		const list = await rpc({ jsonrpc: "2.0", id: 3, method: "tools/list" });
		expect(list.result.tools.map((t: { name: string }) => t.name)).toEqual([
			"list_auditors",
			"get_auditor",
			"search_docs",
			"get_config_schema",
			"get_install_instructions",
		]);
		for (const t of list.result.tools) {
			expect(t.annotations.readOnlyHint).toBe(true);
			expect(t.inputSchema.type).toBe("object");
		}
	});

	test("unknown methods, bad envelopes and parse errors", async () => {
		expect(
			(await rpc({ jsonrpc: "2.0", id: 4, method: "resources/list" })).error
				.code,
		).toBe(-32601);
		expect(
			(await rpc({ jsonrpc: "1.0", id: 5, method: "ping" })).error.code,
		).toBe(-32600);
		expect(
			(await rpc({ jsonrpc: "2.0", id: null, method: "ping" })).error.code,
		).toBe(-32600);
		expect(
			(await rpc({ jsonrpc: "2.0", id: 6, method: "ping", params: [] })).error
				.code,
		).toBe(-32602);
		expect((await rpc("not json")).error.code).toBe(-32700);
		expect((await rpc(42)).error.code).toBe(-32600);
	});

	test("batches answer each request and skip notifications", async () => {
		const r = await rpc([
			{ jsonrpc: "2.0", id: 1, method: "ping" },
			{ jsonrpc: "2.0", method: "notifications/initialized" },
			{ jsonrpc: "2.0", id: 2, method: "nope" },
		]);
		expect(r.map((x: { id: number }) => x.id)).toEqual([1, 2]);
		expect(r[1].error.code).toBe(-32601);
	});
});

describe("limits and HTTP", () => {
	test("GET and DELETE are 405", async () => {
		for (const method of ["GET", "DELETE"]) {
			const res = await handleMcp(
				new Request("https://openaudit.se/mcp", { method }),
				assets(),
			);
			expect(res.status).toBe(405);
			expect(res.headers.get("allow")).toBe("POST, OPTIONS");
		}
	});

	test("preflight allows any origin", async () => {
		const res = await handleMcp(
			new Request("https://openaudit.se/mcp", { method: "OPTIONS" }),
			assets(),
		);
		expect(res.status).toBe(204);
		expect(res.headers.get("access-control-allow-origin")).toBe("*");
		expect(res.headers.get("access-control-allow-headers")).toContain(
			"Mcp-Protocol-Version",
		);
	});

	test("an oversize body is refused, by header and by content", async () => {
		const big = JSON.stringify({
			jsonrpc: "2.0",
			id: 1,
			method: "ping",
			params: { pad: "x".repeat(LIMITS.maxBodyBytes) },
		});
		expect((await handleMcp(post(big), assets())).status).toBe(413);
		// No Content-Length: the stream is cut off at the limit.
		const stream = new ReadableStream({
			start(c) {
				c.enqueue(new TextEncoder().encode(big));
				c.close();
			},
		});
		const res = await handleMcp(
			new Request("https://openaudit.se/mcp", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: stream,
				// @ts-expect-error: Bun needs duplex for a streamed body
				duplex: "half",
			}),
			assets(),
		);
		expect(res.status).toBe(413);
	});

	test("batches over the limit, empty batches and wrong content types", async () => {
		const many = Array.from({ length: LIMITS.maxBatch + 1 }, (_, i) => ({
			jsonrpc: "2.0",
			id: i,
			method: "ping",
		}));
		expect((await handleMcp(post(many), assets())).status).toBe(400);
		expect((await handleMcp(post([]), assets())).status).toBe(400);
		const res = await handleMcp(
			post("{}", { "content-type": "text/plain" }),
			assets(),
		);
		expect(res.status).toBe(415);
	});

	test("an unsupported MCP-Protocol-Version header is a 400", async () => {
		const res = await handleMcp(
			post(
				{ jsonrpc: "2.0", id: 1, method: "ping" },
				{ "mcp-protocol-version": "1999-01-01" },
			),
			assets(),
		);
		expect(res.status).toBe(400);
		const ok = await handleMcp(
			post(
				{ jsonrpc: "2.0", id: 1, method: "ping" },
				{ "mcp-protocol-version": "2025-06-18" },
			),
			assets(),
		);
		expect(ok.status).toBe(200);
	});

	test("replies are JSON and never reflect input as markup", async () => {
		const r = await call("<script>alert(1)</script>");
		expect(r.error.code).toBe(-32602);
		const res = await handleMcp(
			post({ jsonrpc: "2.0", id: 1, method: "<b>x</b>" }),
			assets(),
		);
		expect(res.headers.get("content-type")).toBe("application/json");
		expect(res.headers.get("x-content-type-options")).toBe("nosniff");
	});
});

describe("tools", () => {
	test("list_auditors filters by area, target, engine and text", async () => {
		const all = await call("list_auditors", {});
		expect(all.result.structuredContent.total).toBe(3);
		const sec = await call("list_auditors", {
			category: "security",
			engine: "builtin",
		});
		expect(
			sec.result.structuredContent.auditors.map((a: { id: string }) => a.id),
		).toEqual(["code.secrets"]);
		const text = await call("list_auditors", { query: "ALT text" });
		expect(text.result.structuredContent.auditors[0].id).toBe("web.a11y");
		const limited = await call("list_auditors", { limit: 1 });
		expect(limited.result.structuredContent.auditors).toHaveLength(1);
	});

	test("list_auditors rejects values the data does not have", async () => {
		const r = await call("list_auditors", { category: "astrology" });
		expect(r.result.isError).toBe(true);
		expect(r.result.content[0].text).toContain("accessibility, security");
	});

	test("get_auditor includes the playbook", async () => {
		const r = await call("get_auditor", { id: "agent.authz" });
		expect(r.result.structuredContent.playbook.markdown).toContain("Checklist");
		expect(r.result.content[0].text).toContain(
			"bunx @openaudit/cli . --only agent.authz",
		);
		const missing = await call("get_auditor", { id: "no.such" });
		expect(missing.result.isError).toBe(true);
	});

	test("search_docs ranks sections and returns snippets with links", async () => {
		const r = await call("search_docs", { query: "baseline findings" });
		const [first] = r.result.structuredContent.results;
		expect(first.url).toBe(
			"https://openaudit.se/docs/configuration/#suppressions",
		);
		expect(first.snippet).toContain("baseline");
		const none = await call("search_docs", { query: "zzzz" });
		expect(none.result.structuredContent.results).toEqual([]);
	});

	test("get_config_schema and get_install_instructions", async () => {
		const s = await call("get_config_schema", {});
		expect(s.result.structuredContent.schema).toEqual(schema);
		const one = await call("get_install_instructions", { method: "mcp" });
		expect(one.result.content[0].text).toBe(docs.install.mcp);
		const all = await call("get_install_instructions");
		expect(Object.keys(all.result.structuredContent.instructions)).toEqual([
			"cli",
			"mcp",
		]);
		const bad = await call("get_install_instructions", { method: "fax" });
		expect(bad.result.isError).toBe(true);
	});

	test("arguments are validated strictly", async () => {
		const cases: Array<[string, unknown]> = [
			["get_auditor", {}],
			["get_auditor", { id: "Bad Id!" }],
			["get_auditor", { id: 7 }],
			["get_auditor", { id: "code.secrets", extra: true }],
			["search_docs", { query: "x" }],
			["search_docs", { query: "ok", limit: 11 }],
			["search_docs", { query: "ok", limit: 1.5 }],
			["list_auditors", { query: "q".repeat(201) }],
			["list_auditors", []],
		];
		for (const [name, args] of cases) {
			const r = await call(name, args);
			expect(r.result.isError).toBe(true);
			expect(r.result.content[0].text).toStartWith("Invalid arguments:");
		}
	});

	test("missing site data is a tool error, retried on the next call", async () => {
		const a = assets({ "/data/catalogue.json": undefined });
		const broken: Assets = {
			fetch: async (r) =>
				new URL(r.url).pathname === "/data/catalogue.json"
					? new Response("", { status: 500 })
					: a.fetch(r),
		};
		const r = await call("list_auditors", {}, broken);
		expect(r.result.isError).toBe(true);
		expect(r.result.content[0].text).not.toContain("HTTP 500");
	});

	test("the build data is read once per isolate", async () => {
		const a = assets();
		await call("list_auditors", {}, a);
		await call("get_auditor", { id: "code.secrets" }, a);
		expect(a.hits.filter((p) => p === "/data/catalogue.json")).toHaveLength(1);
	});

	test("every tool schema is one validate() understands", () => {
		for (const t of TOOLS)
			expect(validate(t.inputSchema, {}) ?? "").not.toContain(
				"must be an object",
			);
	});
});
