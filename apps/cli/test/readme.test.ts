import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { playbooks } from "@openaudit/agent";

import { allAuditors } from "../src/audit";

// The README states facts the registry owns: how many auditors and tools
// there are, and which tools are wrapped. Hand-written numbers drift (it said
// 37 and 52 while the registry had 39 and 53), so these tests tie them to
// the registry. The site reads the same intro line (apps/site/src/lib/home.ts).

const repo = join(import.meta.dir, "..", "..", "..");
const read = (path: string) => readFileSync(join(repo, path), "utf8");
const readme = read("README.md");

const auditors = allAuditors();
const builtin = auditors.filter((a) => a.engine === "builtin").length;
const tools = [...new Set(auditors.flatMap((a) => (a.tool ? [a.tool] : [])))];

const WORDS = [
	"zero",
	"one",
	"two",
	"three",
	"four",
	"five",
	"six",
	"seven",
	"eight",
	"nine",
	"ten",
	"eleven",
	"twelve",
];

/** From `## heading` to the next `## ` heading. */
const section = (markdown: string, heading: string): string => {
	const start = markdown.indexOf(`\n## ${heading}\n`);
	if (start < 0) throw new Error(`README has no "## ${heading}" section`);
	const end = markdown.indexOf("\n## ", start + 1);
	return markdown.slice(start, end < 0 ? undefined : end);
};

/**
 * The lists in a section: a line ending in `:` or `:**` opens one, and the
 * plain lines under it (no list marker, no heading) are its items.
 */
const lists = (text: string): Array<{ label: string; items: string[] }> => {
	const found: Array<{ label: string; items: string[] }> = [];
	let open: { label: string; items: string[] } | undefined;
	for (const line of text.split("\n")) {
		const trimmed = line.trim();
		if (/:(\*\*)?$/.test(trimmed)) {
			open = { label: trimmed, items: [] };
			found.push(open);
		} else if (trimmed === "" || /^(-|#)/.test(trimmed)) {
			open = undefined;
		} else if (open) {
			open.items.push(trimmed.replace(/[,.]$/, ""));
		}
	}
	return found;
};

const sortKey = (item: string) => item.replace(/[\\*`]/g, "").toLowerCase();

describe("README", () => {
	test("the intro's counts match the registry", () => {
		const intro = readme
			.split("\n")
			.find((line) => line.startsWith("openaudit runs "));
		const match =
			/runs (\d+) built-in auditors and wraps (\d+) .* (\w+) agent \*\*playbooks\*\*/.exec(
				intro ?? "",
			);
		expect(match).not.toBeNull();
		expect({
			builtin: Number(match?.[1]),
			tools: Number(match?.[2]),
			playbooks: WORDS.indexOf(match?.[3]?.toLowerCase() ?? ""),
		}).toEqual({ builtin, tools: tools.length, playbooks: playbooks.length });
	});

	test("the security scanner guide counts the built-in auditors right", () => {
		const guide = read(
			"apps/site/src/guides/open-source-code-security-scanner.md",
		);
		expect(guide).toContain(`It also has ${builtin} auditors of its own`);
	});

	test('"What it checks, by target" names every wrapped tool', () => {
		const text = section(readme, "What it checks, by target").toLowerCase();
		expect(tools.filter((tool) => !text.includes(tool.toLowerCase()))).toEqual(
			[],
		);
	});

	// One item per line, alphabetical: two branches that each add a tool then
	// insert at different lines, and git merges them. The old one-line table
	// cells conflicted in 5 of 26 merges.
	test('"What it checks, by target" keeps each list alphabetical', () => {
		const found = lists(section(readme, "What it checks, by target"));
		expect(found.length).toBeGreaterThan(0);
		const unsorted = found.filter(({ items }) => {
			const keys = items.map(sortKey);
			return keys.some((key, i) => i > 0 && key < (keys[i - 1] ?? ""));
		});
		expect(unsorted.map(({ label }) => label)).toEqual([]);
	});
});
