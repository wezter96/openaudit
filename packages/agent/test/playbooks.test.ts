import { describe, expect, test } from "bun:test";
import { CATEGORIES } from "@openaudit/core";

import {
	agenticAuditors,
	getPlaybook,
	playbooks,
	renderPlaybook,
} from "../src";

describe("playbooks", () => {
	test("ten playbooks with unique agent.* ids", () => {
		expect(playbooks).toHaveLength(10);
		const ids = playbooks.map((p) => p.id);
		expect(new Set(ids).size).toBe(ids.length);
		for (const id of ids) expect(id).toMatch(/^agent\.[a-z0-9-]+$/);
	});

	test("every playbook is complete", () => {
		for (const p of playbooks) {
			expect(p.title.length).toBeGreaterThan(5);
			expect(p.summary.length).toBeGreaterThan(40);
			expect(p.checklist.length).toBeGreaterThanOrEqual(8);
			expect(p.targets.length).toBeGreaterThan(0);
			for (const c of p.categories) expect(CATEGORIES).toContain(c);
			for (const section of [
				"## Scope",
				"## Method",
				"## Severity rubric",
				"## What NOT to report",
				"## Evidence standard",
				"## Reporting",
			])
				expect(p.instructions).toContain(section);
		}
	});

	test("web playbooks carry the responsible-use note", () => {
		for (const p of playbooks.filter((p) =>
			p.targets.some((t) => t === "url" || t === "webapp"),
		))
			expect(p.instructions).toContain("## Responsible use");
	});

	test("renderPlaybook appends the checklist", () => {
		const authz = getPlaybook("agent.authz");
		expect(authz).toBeDefined();
		const md = renderPlaybook(authz as NonNullable<typeof authz>);
		expect(md).toContain("## Checklist");
		expect(md).toContain("- [ ] Built an inventory of entry points");
	});

	test("one opt-in agentic auditor per playbook", () => {
		expect(agenticAuditors.map((a) => a.id)).toEqual(
			playbooks.map((p) => p.id),
		);
		for (const a of agenticAuditors) {
			expect(a.engine).toBe("agentic");
			expect(a.defaultEnabled).toBe(false);
			expect(a.network).toBe(true);
		}
	});
});
