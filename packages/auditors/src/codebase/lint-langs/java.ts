import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
	AuditorError,
	type Category,
	defineAuditor,
	type FindingInput,
	requireTool,
	requireWorkspace,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, num, parseJson, str } from "../../tool";
import { extOf, isRecord, kebab, truncate } from "../util";
import {
	dedupe,
	type FilePath,
	inRoot,
	isMinor,
	run,
	withTempDir,
} from "./shared";

/* -------------------------------------------------------------------------- */
/*                                    PMD                                     */
/* -------------------------------------------------------------------------- */

const ID = "code.pmd";

/**
 * Built-in rulesets, loaded from PMD's own classpath: the quickstart set
 * (which leaves out the two security rules) plus those security rules.
 */
export const PMD_RULESETS =
	"rulesets/java/quickstart.xml,category/java/security.xml";

/** PMD rule category (the `ruleset` field) to openaudit category. */
const PMD_CATEGORY: Record<string, Category> = {
	"Best Practices": "maintainability",
	"Code Style": "maintainability",
	Design: "maintainability",
	Documentation: "maintainability",
	"Error Prone": "reliability",
	Multithreading: "reliability",
	Performance: "performance",
	Security: "security",
};

/** PMD priority 1 (high) to 5 (low). */
const PMD_SEVERITY: Record<number, Severity> = {
	1: "high",
	2: "medium",
	3: "low",
	4: "info",
	5: "info",
};

const PMD_CWE: Record<string, string> = {
	HardCodedCryptoKey: "cwe-321",
	InsecureCryptoIv: "cwe-329",
};

const pmdSeverity = (v: Record<string, unknown>, category: Category) => {
	const severity = PMD_SEVERITY[num(v.priority) ?? 3] ?? "low";
	// Both security rules are priority 3, but a hardcoded key is not a nit.
	return category === "security" && isMinor(severity) ? "medium" : severity;
};

const pmdViolation = (
	v: Record<string, unknown>,
	file: FilePath,
): FindingInput => {
	const rule = str(v.rule) ?? "violation";
	const ruleset = str(v.ruleset) ?? "";
	const description = str(v.description) ?? rule;
	const category = PMD_CATEGORY[ruleset] ?? "maintainability";
	const url = str(v.externalInfoUrl);
	const cwe = PMD_CWE[rule];
	return {
		ruleId: `${ID}/${kebab(rule)}`,
		title: truncate(description.replace(/\.$/, ""), 100),
		severity: pmdSeverity(v, category),
		category,
		message: `${description} (PMD ${ruleset ? `${ruleset}: ` : ""}${rule})`,
		location: {
			file,
			line: num(v.beginline),
			column: num(v.begincolumn),
		},
		remediation:
			'See the PMD rule documentation, or suppress a justified false positive with `@SuppressWarnings("PMD.<Rule>")` or a `// NOPMD` comment and a reason.',
		references: url ? [url] : [],
		confidence: "high",
		tags: [
			"java",
			...(ruleset ? [`pmd-${kebab(ruleset)}`] : []),
			...(cwe ? [cwe] : []),
		],
	};
};

const pmdFileViolations = (f: unknown, root: FilePath): FindingInput[] => {
	if (!isRecord(f)) return [];
	const file = inRoot(root, str(f.filename));
	if (!file) return [];
	return arr(f.violations).flatMap((v): FindingInput[] =>
		isRecord(v) ? [pmdViolation(v, file)] : [],
	);
};

const pmdParseError = (e: unknown, root: FilePath): FindingInput[] => {
	if (!isRecord(e)) return [];
	const file = inRoot(root, str(e.filename));
	if (!file) return [];
	const raw = str(e.message) ?? "";
	const at = /at line (\d+), column (\d+):\s*([\s\S]*)/.exec(raw);
	const detail = (at?.[3] ?? raw).split("\n")[0]?.trim() ?? "";
	return [
		{
			ruleId: `${ID}/parse-error`,
			title: "Java file could not be parsed",
			severity: "low",
			category: "reliability",
			message: truncate(
				`PMD could not parse this file${detail ? `: ${detail}` : ""}`,
				300,
			),
			location: {
				file,
				line: at ? Number(at[1]) : undefined,
				column: at ? Number(at[2]) : undefined,
			},
			remediation:
				"Fix the syntax error. If the file uses a Java version PMD does not support yet, it was skipped by every rule.",
			confidence: "low",
			tags: ["java", "parse-error"],
		},
	];
};

/** Parses `pmd check -f json`, including files PMD could not parse. */
export const parsePmdReport = (
	json: unknown,
	root: FilePath,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	const violations = arr(json.files).flatMap((f) => pmdFileViolations(f, root));
	const parseErrors = arr(json.processingErrors).flatMap((e) =>
		pmdParseError(e, root),
	);
	return dedupe([...violations, ...parseErrors]);
};

/** PMD splits `--file-list` entries on commas and newlines. */
const listable = (path: FilePath) => !/[,\r\n]/.test(path);

export const pmd = defineAuditor({
	id: ID,
	title: "PMD Java analysis",
	description: `Runs PMD 7 over Java sources with built-in rulesets only (${PMD_RULESETS}), never the project's own ruleset, since rulesets can name rule classes. PMD runs from an empty temp directory, because it resolves ruleset paths against the working directory before its own classpath, and gets an explicit file list. No build is needed and --aux-classpath is never passed, so no project classes are loaded. Categories: Error Prone and Multithreading are reliability, Security security, Performance performance, the rest maintainability; PMD priority 1-5 maps to high, medium, low, info.`,
	categories: ["reliability", "maintainability", "security", "performance"],
	targets: ["codebase"],
	engine: "external",
	tool: "pmd",
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const sources = (yield* ws.files)
				.filter((f) => extOf(f) === "java")
				.map((f) => ws.absolute(f))
				.filter(listable);
			if (sources.length === 0)
				return yield* skip("No Java files in the workspace");
			const bin = yield* requireTool(
				ctx,
				"pmd",
				"Install: brew install pmd, or unzip pmd-dist-<version>-bin.zip from https://github.com/pmd/pmd/releases (needs Java 8+).",
			);
			return yield* withTempDir((tmp) =>
				Effect.gen(function* () {
					const list = join(tmp, "files.txt");
					yield* Effect.tryPromise({
						try: () => writeFile(list, `${sources.join("\n")}\n`),
						catch: (cause) =>
							new AuditorError({
								message: "Could not write the PMD file list",
								cause,
							}),
					});
					const res = yield* run(
						ctx,
						[
							bin,
							"check",
							"--file-list",
							list,
							"-R",
							PMD_RULESETS,
							"-f",
							"json",
							"--no-cache",
							"--no-progress",
						],
						// 4 = violations, 5 = some files could not be processed.
						{ cwd: tmp, okCodes: [0, 4, 5] },
					);
					if (!res.stdout.trim()) return [];
					return parsePmdReport(yield* parseJson(res.stdout, "pmd"), ws.root);
				}),
			);
		}),
});
