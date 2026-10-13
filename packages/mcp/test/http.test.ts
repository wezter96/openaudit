import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import {
	mkdir,
	mkdtemp,
	realpath,
	rm,
	symlink,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { type Auditor, defineAuditor } from "@openaudit/core";
import { Effect } from "effect";

import {
	type HttpServerHandle,
	type HttpServerOptions,
	isRegistryImageRef,
	makeTargetPolicy,
	registryHost,
	startHttpServer,
} from "../src";

const fixtureAuditor: Auditor = defineAuditor({
	id: "test.fixture",
	title: "Fixture auditor",
	description: "Flags TODO comments",
	categories: ["maintainability"],
	targets: ["codebase"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = ctx.workspace;
			if (!ws) return [];
			const text = yield* ws.readText("app.ts");
			if (!text.includes("TODO")) return [];
			return [
				{
					ruleId: "test.fixture/todo",
					title: "TODO left in code",
					severity: "medium" as const,
					category: "maintainability" as const,
					message: "A TODO comment remains.",
					location: { file: "app.ts", line: 3 },
					evidence: "// TODO",
					remediation: "Resolve the TODO.",
				},
			];
		}),
});

const TOKEN = "t".repeat(32);
let base: string; // realpath'd temp dir
let root: string; // allowed root
let outside: string; // sibling dir, not allowed
const handles: HttpServerHandle[] = [];

const start = async (o: HttpServerOptions = {}) => {
	const h = await startHttpServer({
		port: 0,
		token: TOKEN,
		roots: [root],
		server: { auditors: [fixtureAuditor], playbooks: [] },
		...o,
	});
	handles.push(h);
	return h;
};

const INIT = {
	jsonrpc: "2.0",
	id: 1,
	method: "initialize",
	params: {
		protocolVersion: "2025-03-26",
		capabilities: {},
		clientInfo: { name: "raw", version: "1" },
	},
};
const MCP_HEADERS = {
	"content-type": "application/json",
	accept: "application/json, text/event-stream",
};

/** An empty header value means "send none". */
const stripEmpty = (h: Record<string, string>) =>
	Object.fromEntries(Object.entries(h).filter(([, v]) => v !== ""));

const post = (
	h: HttpServerHandle,
	body: unknown,
	headers: Record<string, string> = {},
) =>
	fetch(h.url, {
		method: "POST",
		headers: stripEmpty({
			...MCP_HEADERS,
			authorization: `Bearer ${TOKEN}`,
			...headers,
		}),
		body: typeof body === "string" ? body : JSON.stringify(body),
	});

const connect = async (h: HttpServerHandle, token: string = TOKEN) => {
	const client = new Client({ name: "test", version: "1.0.0" });
	await client.connect(
		new StreamableHTTPClientTransport(new URL(h.url), {
			requestInit: token
				? { headers: { authorization: `Bearer ${token}` } }
				: undefined,
		}),
	);
	return client;
};

const audit = async (client: Client, target: string) =>
	(await client.callTool({
		name: "run_audit",
		arguments: { target },
	})) as {
		isError?: boolean;
		content: Array<{ type: string; text: string }>;
		structuredContent?: { reportId: string };
	};

beforeAll(async () => {
	base = await realpath(await mkdtemp(join(tmpdir(), "openaudit-http-")));
	root = join(base, "root");
	outside = join(base, "outside");
	await mkdir(join(root, "proj"), { recursive: true });
	await mkdir(outside);
	const src = "export const a = 1;\n\n// TODO remove\nexport const b = 2;\n";
	await writeFile(join(root, "proj", "app.ts"), src);
	await writeFile(join(outside, "app.ts"), src);
	await symlink(outside, join(root, "link"));
});

afterAll(async () => {
	await Promise.all(handles.map((h) => h.close()));
	await rm(base, { recursive: true, force: true });
});

describe("mcp over http", () => {
	test("binds loopback by default and generates a token", async () => {
		const h = await startHttpServer({ port: 0 });
		handles.push(h);
		expect(h.generatedToken?.length).toBeGreaterThanOrEqual(40);
		const bare = { ...MCP_HEADERS };
		const anon = await fetch(h.url, {
			method: "POST",
			headers: bare,
			body: JSON.stringify(INIT),
		});
		expect(anon.status).toBe(401);
		const authed = await fetch(h.url, {
			method: "POST",
			headers: { ...bare, authorization: `Bearer ${h.generatedToken}` },
			body: JSON.stringify(INIT),
		});
		expect(authed.status).toBe(200);
		expect(
			await startHttpServer({ port: 0, token: "x".repeat(20) }).then(
				async (g) => {
					handles.push(g);
					return g.generatedToken;
				},
			),
		).toBeUndefined();
		expect(h.host).toBe("127.0.0.1");
		expect(h.url).toStartWith("http://127.0.0.1:");
		const res = await fetch(`http://127.0.0.1:${h.port}/health`);
		expect(await res.json()).toEqual({ status: "ok" });
	});

	test("refuses a non-loopback bind without a (long enough) token", async () => {
		await expect(startHttpServer({ host: "0.0.0.0", port: 0 })).rejects.toThrow(
			/bearer token/,
		);
		await expect(
			startHttpServer({ host: "0.0.0.0", port: 0, token: "short" }),
		).rejects.toThrow(/at least/);
	});

	test("initialize, tools/list and run_audit over HTTP", async () => {
		const h = await start();
		const client = await connect(h);
		expect(client.getServerVersion()?.name).toBe("openaudit");
		const { tools } = await client.listTools();
		expect(tools.map((t) => t.name)).toContain("run_audit");
		const res = await audit(client, join(root, "proj"));
		expect(res.isError).toBeFalsy();
		expect(res.content[0]?.text).toContain("TODO left in code");
		const id = res.structuredContent?.reportId ?? "";
		// The report store is per session.
		const got = await client.callTool({
			name: "get_report",
			arguments: { reportId: id, format: "markdown" },
		});
		expect(got.isError).toBeFalsy();
		const other = await connect(h);
		const missing = await other.callTool({
			name: "get_report",
			arguments: { reportId: id },
		});
		expect(missing.isError).toBe(true);
		expect(h.sessionCount()).toBe(2);
		await client.close();
		await other.close();
	});

	test("requires the bearer token when one is set", async () => {
		const h = await start();
		expect((await post(h, INIT, { authorization: "" })).status).toBe(401);
		const wrong = await post(h, INIT, {
			authorization: `Bearer ${"x".repeat(32)}`,
		});
		expect(wrong.status).toBe(401);
		expect(wrong.headers.get("www-authenticate")).toContain("Bearer");
		expect((await fetch(h.url, { method: "GET" })).status).toBe(401);
		expect((await fetch(h.url, { method: "DELETE" })).status).toBe(401);
		const ok = await post(h, INIT, { authorization: `Bearer ${TOKEN}` });
		expect(ok.status).toBe(200);
		const client = await connect(h, TOKEN);
		expect((await client.listTools()).tools.length).toBeGreaterThan(0);
		await client.close();
	});

	test("rejects unexpected Host and Origin headers", async () => {
		const h = await start({ allowOrigins: ["https://app.example"] });
		const host = await post(h, INIT, { host: "evil.example" });
		expect(host.status).toBe(403);
		const badOrigin = await post(h, INIT, { origin: "https://evil.example" });
		expect(badOrigin.status).toBe(403);
		const okOrigin = await post(h, INIT, { origin: "https://app.example" });
		expect(okOrigin.status).toBe(200);
		const none = await start();
		expect(
			(await post(none, INIT, { origin: "http://localhost:3000" })).status,
		).toBe(403);
	});

	test("confines local targets to --root", async () => {
		const h = await start();
		const client = await connect(h);
		const rejected = [
			outside,
			join(root, "..", "outside"),
			join(root, "link"), // symlink out of the root
			join(root, "proj", "..", "..", "outside"),
			join(root, "missing"),
		];
		for (const target of rejected) {
			const res = await audit(client, target);
			expect(res.isError).toBe(true);
			expect(res.content[0]?.text).toContain("not inside an allowed root");
		}
		const inside = await audit(client, join(root, "proj"));
		expect(inside.isError).toBeFalsy();
		const rel = await audit(client, "proj"); // relative to the first root
		expect(rel.isError).toBeFalsy();
		await client.close();
	});

	test("without --root only URL and image: targets are accepted", async () => {
		const h = await start({ roots: [] });
		const client = await connect(h);
		const local = await audit(client, join(root, "proj"));
		expect(local.isError).toBe(true);
		expect(local.content[0]?.text).toContain("--root");
		const detect = (target: string) =>
			client.callTool({ name: "detect_target", arguments: { target } });
		expect((await detect("https://example.com")).isError).toBeFalsy();
		expect((await detect("image:nginx:latest")).isError).toBeFalsy();
		expect((await detect("image:/tmp/x.tar")).isError).toBe(true);
		expect((await detect("cloud:aws")).isError).toBe(true);
		await client.close();
	});

	test("refuses agentic auditors unless --allow-agentic", async () => {
		const h = await start();
		const client = await connect(h);
		const res = await client.callTool({
			name: "run_audit",
			arguments: { target: join(root, "proj"), agentic: true },
		});
		expect(res.isError).toBe(true);
		expect(JSON.stringify(res.content)).toContain("--allow-agentic");
		const detect = await client.callTool({
			name: "detect_target",
			arguments: { target: join(root, "proj"), agentic: true },
		});
		expect(detect.isError).toBe(true);
		await client.close();
		// Agentic auditors are not even listed.
		const real = await startHttpServer({ port: 0, roots: [root] });
		handles.push(real);
		const c2 = await connect(real, real.generatedToken);
		const listed = await c2.callTool({ name: "list_auditors", arguments: {} });
		expect(JSON.stringify(listed.content)).not.toContain("agentic.");
		await c2.close();
		const open = await start({ allowAgentic: true });
		const c3 = await connect(open);
		const ok = await c3.callTool({
			name: "detect_target",
			arguments: { target: join(root, "proj"), agentic: true },
		});
		expect(ok.isError).toBeFalsy();
		await c3.close();
	});

	test("blocks private URL targets on non-loopback binds", async () => {
		const detect = async (h: HttpServerHandle, target: string) => {
			const c = await connect(h, TOKEN);
			const r = await c.callTool({
				name: "detect_target",
				arguments: { target },
			});
			await c.close();
			return r;
		};
		const priv = [
			"http://169.254.169.254/latest/meta-data/",
			"http://127.0.0.1/",
			"http://10.0.0.5/",
			"http://[fd00::1]/",
			"http://localhost/",
			"http://[::ffff:169.254.169.254]/",
		];
		const remote = await start({ host: "0.0.0.0", token: TOKEN });
		for (const t of priv) {
			const r = await detect(remote, t);
			expect(r.isError).toBe(true);
		}
		const c = await connect(remote, TOKEN);
		const run = await c.callTool({
			name: "run_audit",
			arguments: { target: "http://169.254.169.254/" },
		});
		expect(run.isError).toBe(true);
		expect(JSON.stringify(run.content)).toMatch(/private|loopback|reserved/);
		const browser = await c.callTool({
			name: "run_audit",
			arguments: { target: "https://8.8.8.8/", browser: true },
		});
		expect(browser.isError).toBe(true);
		await c.close();
		// A public literal passes the guard.
		expect((await detect(remote, "https://8.8.8.8/")).isError).toBeFalsy();

		const optOut = await start({
			host: "0.0.0.0",
			token: TOKEN,
			allowPrivateTargets: true,
		});
		expect((await detect(optOut, priv[0] as string)).isError).toBeFalsy();
		expect((await detect(optOut, "http://[fd00::1]/")).isError).toBeFalsy();

		// Loopback binds audit the user's own machine.
		const local = await start({ token: TOKEN });
		for (const t of priv) expect((await detect(local, t)).isError).toBeFalsy();
	});

	test("accepts only registry image references", async () => {
		const policy = makeTargetPolicy([root], false);
		const bad = [
			"docker-archive:/etc/x",
			"oci-dir:/home/u/img",
			"oci-archive:/tmp/a.tar",
			"oci:/tmp/layout",
			"dir:/srv/img",
			"file:/etc/passwd",
			"podman:alpine",
			"docker:alpine",
			"registry:alpine",
			"containerd:alpine",
			"singularity:/x.sif",
			"docker-archive",
			"DIR:/x",
			"/etc/x",
			"./local",
			"../up",
			"~/img",
			"-flag",
			"nginx:",
			"UPPER/case",
			"a/../b",
			"a//b",
			"a b",
			"nginx@sha256:abc",
			"",
		];
		for (const ref of bad) {
			expect(isRegistryImageRef(ref)).toBe(false);
			await expect(policy(`image:${ref}`)).rejects.toThrow(
				/registry references/,
			);
		}
		const digest = `registry:5000/a/b@sha256:${"a".repeat(64)}`;
		for (const ref of [
			"nginx",
			"nginx:1.27",
			"ghcr.io/o/r:tag",
			"localhost:5000/team/app",
			"my.registry.io/a-b/c_d.e",
			digest,
			`nginx:1.27@sha256:${"0".repeat(64)}`,
		]) {
			expect(isRegistryImageRef(ref)).toBe(true);
			expect(await policy(`image:${ref}`)).toBe(`image:${ref}`);
		}
	});

	test("gates image: targets on guarded servers", async () => {
		const detect = async (h: HttpServerHandle, target: string) => {
			const c = await connect(h);
			const r = await c.callTool({
				name: "detect_target",
				arguments: { target },
			});
			await c.close();
			return r;
		};
		const guarded = await start({ host: "0.0.0.0" });
		const off = await detect(guarded, "image:ghcr.io/o/r:tag");
		expect(off.isError).toBe(true);
		expect(JSON.stringify(off.content)).toContain("--allow-images");

		const on = await start({ host: "0.0.0.0", allowImages: true });
		for (const ref of [
			"10.0.0.5:5000/x",
			"169.254.169.254/x",
			"localhost/x",
			"[::1]:5000/x",
			"registry.internal/x",
			"intranet.lan:443/x",
		])
			expect((await detect(on, `image:${ref}`)).isError).toBe(true);
		// Public registries pass the host check (IP literal avoids real DNS).
		expect((await detect(on, "image:8.8.8.8/x")).isError).toBeFalsy();

		const open = await start({
			host: "0.0.0.0",
			allowImages: true,
			allowPrivateTargets: true,
		});
		expect((await detect(open, "image:10.0.0.5:5000/x")).isError).toBeFalsy();
		// Loopback binds accept images with the allowlist validation only.
		const local = await start();
		expect((await detect(local, "image:10.0.0.5:5000/x")).isError).toBeFalsy();
		expect((await detect(local, "image:dir:/etc")).isError).toBe(true);
		expect(registryHost("nginx:1.27")).toBe("registry-1.docker.io");
		expect(registryHost("library/nginx")).toBe("registry-1.docker.io");
		expect(registryHost("registry:5000/a/b")).toBe("registry:5000");
		expect(registryHost("ghcr.io/o/r")).toBe("ghcr.io");
	});

	test("reports are scoped to the session that created them", async () => {
		const h = await start();
		const a = await connect(h);
		const b = await connect(h);
		const res = await audit(a, join(root, "proj"));
		const id = res.structuredContent?.reportId ?? "";
		const fp = (
			res.structuredContent as unknown as {
				report: {
					results: Array<{ findings: Array<{ fingerprint: string }> }>;
				};
			}
		).report.results.flatMap((r) => r.findings)[0]?.fingerprint;
		expect(fp).toBeDefined();
		const theirs = [
			["get_report", { reportId: id }],
			["get_finding", { reportId: id, fingerprint: fp }],
			["compare_reports", { baseReportId: id, headReportId: id }],
			[
				"submit_findings",
				{ playbookId: "agent.manual", reportId: id, findings: [] },
			],
		] as const;
		for (const [name, args] of theirs) {
			const r = await b.callTool({ name, arguments: { ...args } });
			expect(r.isError).toBe(true);
			expect(JSON.stringify(r.content)).toContain("Unknown reportId");
		}
		// The owner is unaffected.
		expect(
			(await a.callTool({ name: "get_report", arguments: { reportId: id } }))
				.isError,
		).toBeFalsy();
		await a.close();
		await b.close();
	});

	test("a shared store cannot be injected into HTTP sessions", async () => {
		const { ReportStore } = await import("../src");
		const shared = new ReportStore();
		const h = await start({
			server: { auditors: [fixtureAuditor], playbooks: [], store: shared },
		} as HttpServerOptions);
		const a = await connect(h);
		const b = await connect(h);
		const id = (await audit(a, join(root, "proj"))).structuredContent?.reportId;
		const r = await b.callTool({
			name: "get_report",
			arguments: { reportId: id ?? "" },
		});
		expect(r.isError).toBe(true);
		await a.close();
		await b.close();
	});

	test("get_finding never reads outside the report root", async () => {
		const h = await start();
		const c = await connect(h);
		await writeFile(join(outside, "secret.txt"), "TOP SECRET\n");
		await symlink(join(outside, "secret.txt"), join(root, "proj", "leak.txt"));
		const first = await audit(c, join(root, "proj"));
		const id = first.structuredContent?.reportId ?? "";
		const files = [
			"../../outside/secret.txt",
			join(outside, "secret.txt"),
			"leak.txt", // symlink out of the root
			"../outside/secret.txt",
		];
		for (const file of files) {
			const sub = (await c.callTool({
				name: "submit_findings",
				arguments: {
					playbookId: "agent.manual",
					reportId: id,
					findings: [
						{
							ruleId: "x",
							title: `probe ${file}`,
							severity: "low",
							category: "security",
							message: "probe",
							location: { file, line: 1 },
						},
					],
				},
			})) as { structuredContent?: { reportId?: string } };
			const rid = sub.structuredContent?.reportId ?? id;
			const rep = (await c.callTool({
				name: "get_report",
				arguments: { reportId: rid, format: "json" },
			})) as unknown as {
				structuredContent: {
					content: string;
				};
			};
			const parsed = JSON.parse(rep.structuredContent.content) as {
				results: Array<{
					findings: Array<{ title: string; fingerprint: string }>;
				}>;
			};
			const f = parsed.results
				.flatMap((r) => r.findings)
				.find((x) => x.title === `probe ${file}`);
			expect(f).toBeDefined();
			const got = await c.callTool({
				name: "get_finding",
				arguments: { reportId: rid, fingerprint: f?.fingerprint ?? "" },
			});
			expect(JSON.stringify(got)).not.toContain("TOP SECRET");
		}
		await c.close();
	});

	test("submit_findings cannot start a report outside --root", async () => {
		const h = await start();
		const c = await connect(h);
		for (const target of [outside, join(root, "link"), join(root, "..")]) {
			const r = await c.callTool({
				name: "submit_findings",
				arguments: { playbookId: "agent.manual", target, findings: [] },
			});
			expect(r.isError).toBe(true);
			expect(JSON.stringify(r.content)).toContain("allowed root");
		}
		await c.close();
	});

	test("does not write reports into roots unless --persist-reports", async () => {
		const h = await start();
		const c = await connect(h);
		const res = await audit(c, join(root, "proj"));
		expect(res.isError).toBeFalsy();
		expect(await Bun.file(join(root, "proj", ".openaudit")).exists()).toBe(
			false,
		);
		const { existsSync } = await import("node:fs");
		expect(existsSync(join(root, "proj", ".openaudit"))).toBe(false);
		// html comes back inline instead of as a server-side path
		const html = (await c.callTool({
			name: "get_report",
			arguments: {
				reportId: res.structuredContent?.reportId ?? "",
				format: "html",
			},
		})) as { structuredContent: { content?: string; path?: string } };
		expect(html.structuredContent.path).toBeUndefined();
		expect(html.structuredContent.content).toContain("<html");
		await c.close();

		// Opt in: persisted, but a planted .openaudit symlink is not followed.
		await mkdir(join(base, "p2"));
		await writeFile(join(base, "p2", "app.ts"), "// TODO\n");
		const root2 = join(base, "p2");
		const sink = join(base, "sink");
		await mkdir(sink);
		await symlink(sink, join(root2, ".openaudit"));
		const h2 = await start({ roots: [root2], persistReports: true });
		const c2 = await connect(h2);
		const r2 = await audit(c2, root2);
		expect(r2.isError).toBeFalsy();
		const { readdirSync } = await import("node:fs");
		expect(readdirSync(sink)).toEqual([]);
		await c2.close();
		const h3 = await start({ persistReports: true });
		const c3 = await connect(h3);
		const r3 = await audit(c3, join(root, "proj"));
		expect(
			(r3.structuredContent as unknown as { reportPath?: string }).reportPath,
		).toContain(join(root, "proj", ".openaudit", "reports"));
		await c3.close();
	});

	test("checks operate on what the SDK and Bun will use", async () => {
		const h = await start({ allowOrigins: ["https://app.example"] });
		const ok = { authorization: `Bearer ${TOKEN}` };
		// Origin: null, duplicate, empty and differently-cased origins are not allow-listed.
		for (const origin of [
			"null",
			"HTTPS://APP.EXAMPLE",
			"https://app.example, https://evil.example",
			"https://app.example/",
		])
			expect((await post(h, INIT, { origin })).status).toBe(403);
		// Host: trailing dot, userinfo, other ports, brackets without port.
		for (const host of [
			`localhost.:${h.port}`,
			`127.0.0.1.:${h.port}`,
			`127.0.0.1:${h.port + 1}`,
			`user@127.0.0.1:${h.port}`,
			"127.0.0.1",
			`[::1]x:${h.port}`,
			`127.0.0.1:${h.port}, evil.example`,
		])
			expect((await post(h, INIT, { host })).status).toBe(403);
		expect((await post(h, INIT, { host: `[::1]:${h.port}` })).status).toBe(200);
		// Authorization: wrong scheme, extra words, duplicates (merged by Headers), padding.
		for (const authorization of [
			TOKEN,
			`Basic ${TOKEN}`,
			`Bearer ${TOKEN} extra`,
			`Bearer ${TOKEN}, Bearer ${TOKEN}`,
			`Bearer ${TOKEN.slice(0, -1)}`,
			"Bearer ",
			"Bearer",
		])
			expect((await post(h, INIT, { authorization })).status).toBe(401);
		expect(
			(await post(h, INIT, { authorization: `bearer ${TOKEN}` })).status,
		).toBe(200);
		void ok;
		// Token with whitespace can never match, so the server refuses to start with one.
		await expect(
			startHttpServer({ port: 0, token: " padded-token-value " }),
		).rejects.toThrow(/whitespace/);
		// Paths are matched exactly.
		for (const path of ["/mcp/", "/%6dcp", "/mcp%2f", "/MCP"]) {
			const r = await fetch(`http://127.0.0.1:${h.port}${path}`, {
				method: "POST",
				headers: { ...MCP_HEADERS, ...ok },
				body: JSON.stringify(INIT),
			});
			expect(r.status).toBe(404);
		}
		// The SDK never re-reads the body: a batch mixing initialize with other
		// calls is rejected without leaving a session behind.
		const before = h.sessionCount();
		const batch = await post(h, [
			INIT,
			{ jsonrpc: "2.0", id: 2, method: "tools/list" },
		]);
		expect(batch.status).toBeGreaterThanOrEqual(400);
		await batch.text();
		expect(h.sessionCount()).toBe(before);
	});

	test("DELETE closes a session and unknown sessions get 404", async () => {
		const h = await start();
		const init = await post(h, INIT);
		const sid = init.headers.get("mcp-session-id") ?? "";
		expect(sid).not.toBe("");
		expect(h.sessionCount()).toBe(1);
		const del = await fetch(h.url, {
			method: "DELETE",
			headers: { "mcp-session-id": sid, authorization: `Bearer ${TOKEN}` },
		});
		expect(del.status).toBe(200);
		expect(h.sessionCount()).toBe(0);
		const after = await post(
			h,
			{ jsonrpc: "2.0", id: 2, method: "tools/list" },
			{ "mcp-session-id": sid },
		);
		expect(after.status).toBe(404);
	});

	test("idle sessions expire", async () => {
		const h = await start({ sessionIdleMs: 100 });
		const init = await post(h, INIT);
		const sid = init.headers.get("mcp-session-id") ?? "";
		await init.text();
		expect(h.sessionCount()).toBe(1);
		for (let i = 0; i < 40 && h.sessionCount() > 0; i++) await Bun.sleep(50);
		expect(h.sessionCount()).toBe(0);
		const after = await post(
			h,
			{ jsonrpc: "2.0", id: 2, method: "tools/list" },
			{ "mcp-session-id": sid },
		);
		expect(after.status).toBe(404);
	});

	test("caps body size and concurrent sessions", async () => {
		const h = await start({ maxBodyBytes: 1024, maxSessions: 1 });
		const big = await post(h, JSON.stringify({ pad: "x".repeat(4096) }));
		expect(big.status).toBe(413);
		expect((await post(h, "{not json")).status).toBe(400);
		expect((await post(h, INIT)).status).toBe(200);
		expect((await post(h, INIT)).status).toBe(503);
	});

	test("close() shuts down sessions and the listener", async () => {
		const h = await start();
		const client = await connect(h);
		await client.listTools();
		await h.close();
		expect(h.sessionCount()).toBe(0);
		await expect(fetch(`http://127.0.0.1:${h.port}/health`)).rejects.toThrow();
	});
});
