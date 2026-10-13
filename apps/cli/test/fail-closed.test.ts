import { afterAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditorError, defineAuditor } from "@openaudit/core";
import { Effect } from "effect";

import { type AuditFlags, auditCommand, EXIT, type Io } from "../src/audit";

const dir = mkdtempSync(join(tmpdir(), "openaudit-failclosed-"));
writeFileSync(join(dir, "a.txt"), "x");
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const io = (): Io & { err: string[] } => {
	const err: string[] = [];
	return {
		err,
		cwd: dir,
		stdout: () => {},
		stderr: (s: string) => {
			err.push(s);
		},
		stderrIsTTY: false,
	} as unknown as Io & { err: string[] };
};

const flags = (extra: Partial<AuditFlags> = {}): AuditFlags =>
	({
		target: dir,
		format: ["json"],
		only: [],
		exclude: [],
		category: [],
		header: [],
		json: true,
		...extra,
	}) as AuditFlags;

const crashing = defineAuditor({
	id: "code.crash",
	title: "crash",
	description: "crash",
	categories: ["security"],
	targets: ["codebase"],
	engine: "builtin",
	run: () => Effect.fail(new AuditorError({ message: "boom" })),
});

describe("--fail-on fails closed", () => {
	test("an errored auditor exits 3 unless --allow-errors", async () => {
		expect(
			await auditCommand(flags({ failOn: "high" }), io(), [crashing]),
		).toBe(EXIT.incomplete);
		expect(
			await auditCommand(flags({ failOn: "high", allowErrors: true }), io(), [
				crashing,
			]),
		).toBe(EXIT.ok);
		// Without a gate, errors are reported but do not change the exit code.
		expect(await auditCommand(flags(), io(), [crashing])).toBe(EXIT.ok);
	});

	test("a config inside the target cannot switch the gate off", async () => {
		writeFileSync(
			join(dir, "openaudit.config.json"),
			JSON.stringify({ failOn: "none" }),
		);
		const out = io();
		expect(
			await auditCommand(flags({ json: false, format: ["markdown"] }), out, [
				crashing,
			]),
		).toBe(EXIT.ok);
		expect(out.err.join("")).toContain("failOn: none");
		rmSync(join(dir, "openaudit.config.json"));
	});
});
