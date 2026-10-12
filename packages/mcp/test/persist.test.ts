import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
	lstat,
	mkdir,
	mkdtemp,
	readdir,
	readFile,
	realpath,
	rm,
	symlink,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { Report } from "@openaudit/core";

import { createServer, isReportId, persist, ReportStore } from "../src";

let base: string;
let target: string;
let outside: string;

const reportFor = (root: string): Report => ({
	schemaVersion: "1",
	tool: { name: "openaudit", version: "0.1.0" },
	target: {
		input: root,
		type: "directory",
		root,
		kinds: ["codebase"],
		technologies: [],
	},
	startedAt: "2026-01-01T00:00:00.000Z",
	finishedAt: "2026-01-01T00:00:00.000Z",
	durationMs: 0,
	summary: {
		score: 100,
		grade: "A",
		counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
		categories: [],
		auditors: { passed: 0, failed: 0, skipped: 0, error: 0 },
	},
	results: [],
});

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "openaudit-persist-"));
	target = join(base, "repo");
	outside = join(base, "victim");
	await mkdir(target);
	await mkdir(outside);
	await writeFile(join(outside, "authorized_keys"), "ssh-ed25519 AAAA");
});

afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

describe("report persistence against hostile targets", () => {
	test("writes reports and a .gitignore for plain directories", async () => {
		const id = ReportStore.newId();
		expect(isReportId(id)).toBe(true);
		const res = await persist(id, reportFor(target), "json", "{}");
		expect(res).toEqual({
			saved: true,
			path: join(await realpath(target), ".openaudit", "reports", `${id}.json`),
		});
		expect(
			await readFile(join(target, ".openaudit", ".gitignore"), "utf8"),
		).toBe("*\n");
	});

	test("refuses a symlinked .openaudit", async () => {
		await symlink(outside, join(target, ".openaudit"));
		const res = await persist("abc-123", reportFor(target), "json", "{}");
		expect(res.saved).toBe(false);
		expect(await readdir(outside)).toEqual(["authorized_keys"]);
	});

	test("refuses a symlinked .openaudit/reports", async () => {
		await mkdir(join(target, ".openaudit"));
		await symlink(outside, join(target, ".openaudit", "reports"));
		const res = await persist("abc-123", reportFor(target), "json", "{}");
		expect(res.saved).toBe(false);
		expect(await readdir(outside)).toEqual(["authorized_keys"]);
	});

	test("replaces a planted file symlink instead of writing through it", async () => {
		const reports = join(target, ".openaudit", "reports");
		await mkdir(reports, { recursive: true });
		await symlink(
			join(outside, "authorized_keys"),
			join(reports, "abc-123.json"),
		);
		await symlink(
			join(outside, "gitignore"),
			join(target, ".openaudit", ".gitignore"),
		);
		const res = await persist("abc-123", reportFor(target), "json", "{}");
		expect(res.saved).toBe(true);
		expect(await readFile(join(outside, "authorized_keys"), "utf8")).toBe(
			"ssh-ed25519 AAAA",
		);
		expect(await readdir(outside)).toEqual(["authorized_keys"]);
		expect((await lstat(join(reports, "abc-123.json"))).isSymbolicLink()).toBe(
			false,
		);
	});

	test("rejects ids that could form paths", async () => {
		for (const id of ["../../x", "A", "a/b", "", "a.b"]) {
			expect(isReportId(id)).toBe(false);
			const res = await persist(id, reportFor(target), "json", "{}");
			expect(res.saved).toBe(false);
		}
	});

	test("run_audit keeps the report in memory and says so", async () => {
		await symlink(outside, join(target, ".openaudit"));
		const server = createServer({ auditors: [], playbooks: [] });
		const [clientT, serverT] = InMemoryTransport.createLinkedPair();
		const client = new Client({ name: "t", version: "1" });
		await Promise.all([server.connect(serverT), client.connect(clientT)]);
		try {
			const res = (await client.callTool({
				name: "run_audit",
				arguments: { target },
			})) as unknown as {
				content: Array<{ text: string }>;
				structuredContent: {
					reportId: string;
					reportPath?: string;
					notSaved?: string;
				};
			};
			expect(res.structuredContent.reportPath).toBeUndefined();
			expect(res.structuredContent.notSaved).toContain("symlink");
			expect(res.content[0]?.text).toContain("kept in memory only");
			expect(await readdir(outside)).toEqual(["authorized_keys"]);
			// The report is still usable from memory.
			const md = (await client.callTool({
				name: "get_report",
				arguments: { reportId: res.structuredContent.reportId, format: "html" },
			})) as unknown as { structuredContent: { path: string } };
			expect(md.structuredContent.path.startsWith(target)).toBe(false);
			const bad = (await client.callTool({
				name: "get_report",
				arguments: { reportId: "../../etc/passwd", format: "html" },
			})) as { isError?: boolean };
			expect(bad.isError).toBe(true);
		} finally {
			await client.close();
		}
	});
});
