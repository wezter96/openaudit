import { describe, expect, test } from "bun:test";

import {
	type Commit,
	entryFor,
	parseLog,
	releaseNotes,
} from "../scripts/release-notes";

const commit = (subject: string, body = ""): Commit => ({ subject, body });
const notes = (...subjects: string[]) =>
	releaseNotes(
		subjects.map((s) => commit(s)),
		{
			previous: "v0.3.0",
			target: "v0.3.1",
		},
	);

describe("entryFor", () => {
	test("maps conventional types to sections", () => {
		expect(entryFor(commit("feat: scan containers"))?.section).toBe("Added");
		expect(entryFor(commit("fix: report links"))?.section).toBe("Fixed");
		expect(entryFor(commit("perf: faster walk"))?.section).toBe("Changed");
		expect(entryFor(commit("docs: explain baselines"))?.section).toBe(
			"Documentation",
		);
	});

	test("a security scope is its own section, whatever the type", () => {
		expect(entryFor(commit("fix(security): redact tokens"))).toEqual({
			section: "Security",
			line: "Redact tokens",
		});
		expect(entryFor(commit("chore(security): rotate keys"))?.section).toBe(
			"Security",
		);
	});

	test("housekeeping types, merges and version bumps never reach users", () => {
		for (const subject of [
			"chore: lockfile follows the CLI to 0.3.0",
			"ci: cache bun",
			"build(badge-scanner): pin the image",
			"style: format",
			"test(badge): add a fixture",
			"refactor: split the engine; no behaviour change",
			"Merge branch 'fix/dns-nxdomain'",
			"Release 0.3.1",
		])
			expect(entryFor(commit(subject))).toBeUndefined();
	});

	test("scopes that ship outside the npm package are skipped", () => {
		expect(entryFor(commit("feat(site): a new guide"))).toBeUndefined();
		expect(entryFor(commit("fix(badge): race-safe limits"))).toBeUndefined();
		expect(entryFor(commit("feat(badge-scanner): job runner"))).toBeUndefined();
	});

	test("a breaking change is always published, even under a hidden type or scope", () => {
		expect(entryFor(commit("chore!: drop Node 18"))).toEqual({
			section: "Changed",
			line: "**BREAKING:** Drop Node 18",
		});
		expect(entryFor(commit("feat(site)!: move /docs"))?.line).toBe(
			"**BREAKING:** [site] Move /docs",
		);
		expect(
			entryFor(
				commit("refactor: rename rule ids", "BREAKING CHANGE: ids moved"),
			)?.line,
		).toBe("**BREAKING:** Rename rule ids");
	});

	test("prints the scope, capitalises and drops a full stop", () => {
		expect(entryFor(commit("fix(auditors): compose defaults leak."))).toEqual({
			section: "Fixed",
			line: "[auditors] Compose defaults leak",
		});
	});

	test("a subject that starts with an identifier keeps its case", () => {
		expect(
			entryFor(commit("feat(auditors): code.health and code.history"))?.line,
		).toBe("[auditors] code.health and code.history");
		expect(entryFor(commit("fix: `--browser` waits for the page"))?.line).toBe(
			"`--browser` waits for the page",
		);
	});

	test("a subject that is not conventional lands under Changed as written", () => {
		expect(entryFor(commit("Scans skip what .gitignore excludes"))).toEqual({
			section: "Changed",
			line: "Scans skip what .gitignore excludes",
		});
	});
});

describe("releaseNotes", () => {
	test("orders sections, keeps commit order and drops duplicates", () => {
		expect(
			notes(
				"fix: second fix",
				"feat: a feature",
				"fix: second fix",
				"docs: a guide",
				"fix: third fix",
			),
		).toBe(
			[
				"## Added",
				"",
				"- A feature",
				"",
				"## Fixed",
				"",
				"- Second fix",
				"- Third fix",
				"",
				"## Documentation",
				"",
				"- A guide",
				"",
				"**Full Changelog**: https://github.com/wezter96/openaudit/compare/v0.3.0...v0.3.1",
				"",
			].join("\n"),
		);
	});

	test("says so when nothing user-facing changed", () => {
		expect(notes("chore: bump", "Release 0.3.1")).toBe(
			"Maintenance release: no user-facing changes.\n\n**Full Changelog**: https://github.com/wezter96/openaudit/compare/v0.3.0...v0.3.1\n",
		);
	});

	test("the first release has no compare link", () => {
		expect(releaseNotes([commit("feat: first")], { target: "v0.1.0" })).toBe(
			"## Added\n\n- First\n",
		);
	});
});

describe("parseLog", () => {
	test("splits subjects from bodies", () => {
		expect(parseLog("feat: a\x1fwhy a\n\x1e\nfix: b\x1f\x1e\n")).toEqual([
			{ subject: "feat: a", body: "why a" },
			{ subject: "fix: b", body: "" },
		]);
	});
});
