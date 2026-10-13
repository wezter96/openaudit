import { describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const BIN = join(import.meta.dir, "..", "src", "bin.ts");

const spawn = (args: string[], env: Record<string, string> = {}) =>
	Bun.spawn(["bun", BIN, ...args], {
		stdout: "pipe",
		stderr: "pipe",
		env: { ...process.env, NO_COLOR: "1", OPENAUDIT_MCP_TOKEN: "", ...env },
	});

describe("openaudit mcp --http", () => {
	test("refuses a non-loopback host without a token", async () => {
		const proc = spawn(["mcp", "--http", "--host", "0.0.0.0", "--port", "0"]);
		const [err, code] = await Promise.all([
			new Response(proc.stderr).text(),
			proc.exited,
		]);
		expect(code).toBe(2);
		expect(err).toContain("without a bearer token");
	});

	test("rejects HTTP-only flags in stdio mode", async () => {
		const proc = spawn(["mcp", "--port", "9"]);
		const [err, code] = await Promise.all([
			new Response(proc.stderr).text(),
			proc.exited,
		]);
		expect(code).toBe(2);
		expect(err).toContain("--http");
	});

	test("generates and saves a token on loopback when none is given", async () => {
		const cfg = await mkdtemp(join(tmpdir(), "openaudit-cfg-"));
		const proc = spawn(["mcp", "--http", "--port", "0"], {
			XDG_CONFIG_HOME: cfg,
		});
		try {
			const reader = proc.stderr.getReader();
			let out = "";
			while (!/Other clients/.test(out)) {
				const { done, value } = await reader.read();
				if (done) break;
				out += new TextDecoder().decode(value);
			}
			const token = /generated: (\S+)/.exec(out)?.[1] ?? "";
			const url = /listening on (\S+)/.exec(out)?.[1] ?? "";
			expect(token.length).toBeGreaterThanOrEqual(40);
			const file = join(cfg, "openaudit", "mcp-token");
			expect((await readFile(file, "utf8")).trim()).toBe(token);
			expect((await stat(file)).mode & 0o777).toBe(0o600);
			expect((await stat(join(cfg, "openaudit"))).mode & 0o777).toBe(0o700);
			expect((await fetch(url, { method: "POST" })).status).toBe(401);
			const ok = await fetch(url, {
				method: "POST",
				headers: {
					authorization: `Bearer ${token}`,
					"content-type": "application/json",
					accept: "application/json, text/event-stream",
				},
				body: JSON.stringify({
					jsonrpc: "2.0",
					id: 1,
					method: "initialize",
					params: {
						protocolVersion: "2025-03-26",
						capabilities: {},
						clientInfo: { name: "t", version: "1" },
					},
				}),
			});
			expect(ok.status).toBe(200);
		} finally {
			proc.kill("SIGTERM");
			await proc.exited;
			await rm(cfg, { recursive: true, force: true });
		}
	});

	test("serves on loopback with the env token and stops on SIGTERM", async () => {
		const token = "s".repeat(32);
		const proc = spawn(["mcp", "--http", "--port", "0"], {
			OPENAUDIT_MCP_TOKEN: token,
		});
		const reader = proc.stderr.getReader();
		let out = "";
		while (!/listening on (\S+)/.test(out)) {
			const { done, value } = await reader.read();
			if (done) break;
			out += new TextDecoder().decode(value);
		}
		const url = /listening on (\S+)/.exec(out)?.[1] ?? "";
		expect(url).toStartWith("http://127.0.0.1:");
		expect(out).not.toContain(token);
		try {
			const health = await fetch(url.replace(/\/mcp$/, "/health"));
			expect(health.status).toBe(200);
			expect((await fetch(url, { method: "POST" })).status).toBe(401);
		} finally {
			proc.kill("SIGTERM");
		}
		expect(await proc.exited).toBe(0);
	});
});
