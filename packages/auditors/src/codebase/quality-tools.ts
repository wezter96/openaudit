import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
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
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, num, parseJson, relPath, runTool, str } from "../tool";
import { isRecord, truncate } from "./util";

/* -------------------------------------------------------------------------- */
/*                                    jscpd                                   */
/* -------------------------------------------------------------------------- */

/** Blocks shorter than this are reported as `info` rather than `low`. */
const JSCPD_LOW_LINES = 20;
/** Project-wide duplication above this percentage gets an aggregate finding. */
const JSCPD_MAX_PERCENT = 5;

/** Parses the `jscpd-report.json` written by `jscpd --reporters json`. */
export const parseJscpdReport = (
	json: unknown,
	root: string,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	const findings: FindingInput[] = [];
	for (const dup of arr(json.duplicates)) {
		if (!isRecord(dup)) continue;
		const first = isRecord(dup.firstFile) ? dup.firstFile : {};
		const second = isRecord(dup.secondFile) ? dup.secondFile : {};
		const fileA = relPath(root, str(first.name));
		const fileB = relPath(root, str(second.name));
		const lines = num(dup.lines) ?? 0;
		const span = (f: Record<string, unknown>) =>
			`${relPath(root, str(f.name)) ?? "unknown"}:${num(f.start) ?? "?"}-${num(f.end) ?? "?"}`;
		findings.push({
			ruleId: "code.jscpd/duplicate-block",
			title: truncate(`Duplicated code between ${fileA} and ${fileB}`, 120),
			severity: lines < JSCPD_LOW_LINES ? "info" : "low",
			category: "maintainability",
			message: `${lines} lines (${num(dup.tokens) ?? 0} tokens) are copy-pasted between ${span(first)} and ${span(second)}.`,
			location: { file: fileA, line: num(first.start) },
			evidence: `${span(first)} <-> ${span(second)}`,
			remediation:
				"Extract the shared logic into one function or module and call it from both places.",
			references: ["https://github.com/kucherenko/jscpd"],
			confidence: "high",
			tags: ["duplication"],
		});
	}
	const total =
		isRecord(json.statistics) && isRecord(json.statistics.total)
			? json.statistics.total
			: undefined;
	const percentage = num(total?.percentage);
	if (total && percentage !== undefined && percentage > JSCPD_MAX_PERCENT) {
		findings.push({
			ruleId: "code.jscpd/duplication-ratio",
			title: `${percentage.toFixed(1)}% of scanned lines are duplicated`,
			severity: "medium",
			category: "maintainability",
			message: `${num(total.duplicatedLines) ?? 0} of ${num(total.lines) ?? 0} lines across ${num(total.sources) ?? 0} files are duplicated; the threshold is ${JSCPD_MAX_PERCENT}%.`,
			remediation:
				"Work through the duplicate blocks above, starting with the largest, and move shared logic into common modules.",
			references: ["https://github.com/kucherenko/jscpd"],
			confidence: "high",
			tags: ["duplication"],
		});
	}
	return findings;
};

/** Directories and files jscpd never scans. */
const JSCPD_IGNORES = [
	"**/node_modules/**",
	"**/dist/**",
	"**/build/**",
	"**/.git/**",
	"**/*.min.js",
	"**/vendor/**",
];
const MAX_PROJECT_IGNORES = 100;

/**
 * `ignore` globs from the project's `.jscpd.json`. jscpd reads that file from
 * its cwd, but `--ignore` replaces the list instead of adding to it, so the
 * project's own exclusions (generated or vendored files) are passed along.
 * Globs with a comma (`{a,b}`) are dropped: the flag splits on commas.
 */
const jscpdProjectIgnores = (ws: Workspace) =>
	ws.exists(".jscpd.json").pipe(
		Effect.flatMap((exists) =>
			exists ? ws.readText(".jscpd.json") : Effect.succeed("{}"),
		),
		Effect.map((text): string[] => {
			try {
				const config: unknown = JSON.parse(text);
				return isRecord(config)
					? arr(config.ignore)
							.filter(
								(g): g is string =>
									typeof g === "string" && g !== "" && !g.includes(","),
							)
							.slice(0, MAX_PROJECT_IGNORES)
					: [];
			} catch {
				return [];
			}
		}),
		Effect.orElseSucceed((): string[] => []),
	);

export const jscpd = defineAuditor({
	id: "code.jscpd",
	title: "jscpd copy-paste detection",
	description:
		"Runs jscpd to find copy-pasted blocks of 10+ lines across the codebase, honouring the `ignore` list of the project's .jscpd.json. Read-only: writes its report to a temp directory.",
	categories: ["maintainability"],
	targets: ["codebase"],
	engine: "external",
	tool: "jscpd",
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const bin = yield* requireTool(
				ctx,
				"jscpd",
				"Install: npm install -g jscpd (https://github.com/kucherenko/jscpd#installation).",
			);
			const projectIgnores = yield* jscpdProjectIgnores(ws);
			if (projectIgnores.length > 0)
				yield* ctx.log(
					`code.jscpd: also ignoring ${projectIgnores.length} pattern(s) from .jscpd.json`,
				);
			const outDir = yield* Effect.promise(() =>
				mkdtemp(join(tmpdir(), "openaudit-jscpd-")),
			);
			return yield* Effect.gen(function* () {
				yield* runTool(
					ctx,
					[
						bin,
						ws.root,
						"--reporters",
						"json",
						"--output",
						outDir,
						"--silent",
						"--min-lines",
						"10",
						"--ignore",
						[...JSCPD_IGNORES, ...projectIgnores].join(","),
					],
					ws.root,
					[0],
				);
				// jscpd writes no report when it finds no source files; that means no clones.
				const text = yield* Effect.promise(() =>
					readFile(join(outDir, "jscpd-report.json"), "utf8").catch(() => ""),
				);
				return parseJscpdReport(
					text.trim() ? yield* parseJson(text, "jscpd") : {},
					ws.root,
				);
			}).pipe(
				Effect.ensuring(
					Effect.promise(() => rm(outDir, { recursive: true, force: true })),
				),
			);
		}),
});

/* -------------------------------------------------------------------------- */
/*                                    knip                                    */
/* -------------------------------------------------------------------------- */

interface KnipKind {
	readonly rule: string;
	readonly severity: Severity;
	readonly category: Category;
	readonly confidence: "high" | "medium";
	readonly message: (name: string) => string;
	readonly remediation: string;
}

/**
 * knip issue groups we report. `catalog`, `optionalPeerDependencies`,
 * `duplicates` and `cycles` are left out: they are configuration-specific
 * and noisy for a first pass.
 */
const KNIP_KINDS: Readonly<Record<string, KnipKind>> = {
	files: {
		rule: "unused-file",
		severity: "info",
		category: "maintainability",
		confidence: "medium",
		message: (n) => `${n} is not reachable from any entry point.`,
		remediation:
			"Delete the file if it is dead code, or wire it into an entry point if it is needed.",
	},
	dependencies: {
		rule: "unused-dependency",
		severity: "low",
		category: "maintainability",
		confidence: "high",
		message: (n) => `${n} is listed in dependencies but never imported.`,
		remediation: "Remove it from package.json (npm uninstall <name>).",
	},
	devDependencies: {
		rule: "unused-dev-dependency",
		severity: "low",
		category: "maintainability",
		confidence: "high",
		message: (n) => `${n} is listed in devDependencies but never used.`,
		remediation: "Remove it from package.json (npm uninstall -D <name>).",
	},
	unlisted: {
		rule: "unlisted-dependency",
		severity: "medium",
		category: "reliability",
		confidence: "high",
		message: (n) => `${n} is imported but not declared in package.json.`,
		remediation:
			"Declare the package in package.json. Relying on a transitive dependency breaks when the dependency tree changes.",
	},
	binaries: {
		rule: "unlisted-binary",
		severity: "low",
		category: "reliability",
		confidence: "high",
		message: (n) =>
			`Script runs binary \`${n}\`, but no declared package provides it.`,
		remediation:
			"Add the package that provides the binary to devDependencies, or call it through npx with a declared package.",
	},
	unresolved: {
		rule: "unresolved-import",
		severity: "medium",
		category: "reliability",
		confidence: "high",
		message: (n) => `${n} could not be resolved to a file or package.`,
		remediation: "Fix the import path, or install the missing package.",
	},
	exports: {
		rule: "unused-export",
		severity: "info",
		category: "maintainability",
		confidence: "medium",
		message: (n) => `Export \`${n}\` is never imported.`,
		remediation:
			"Remove the export, or make it private if only the file needs it.",
	},
	nsExports: {
		rule: "unused-export",
		severity: "info",
		category: "maintainability",
		confidence: "medium",
		message: (n) => `Namespace export \`${n}\` is never imported.`,
		remediation:
			"Remove the export, or make it private if only the file needs it.",
	},
	types: {
		rule: "unused-type",
		severity: "info",
		category: "maintainability",
		confidence: "medium",
		message: (n) => `Exported type \`${n}\` is never imported.`,
		remediation:
			"Remove the exported type, or make it private if only the file needs it.",
	},
	nsTypes: {
		rule: "unused-type",
		severity: "info",
		category: "maintainability",
		confidence: "medium",
		message: (n) => `Namespace type \`${n}\` is never imported.`,
		remediation:
			"Remove the exported type, or make it private if only the file needs it.",
	},
	enumMembers: {
		rule: "unused-enum-member",
		severity: "info",
		category: "maintainability",
		confidence: "medium",
		message: (n) => `Enum member \`${n}\` is never used.`,
		remediation: "Remove the enum member if nothing reads it.",
	},
	namespaceMembers: {
		rule: "unused-namespace-member",
		severity: "info",
		category: "maintainability",
		confidence: "medium",
		message: (n) => `Namespace member \`${n}\` is never used.`,
		remediation: "Remove the namespace member if nothing reads it.",
	},
};

const KNIP_REFERENCE = "https://knip.dev/reference/issue-types";

/** Parses `knip --reporter json` output. */
export const parseKnipReport = (
	json: unknown,
	root: string,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	const findings: FindingInput[] = [];
	for (const issue of arr(json.issues)) {
		if (!isRecord(issue)) continue;
		const issueFile = relPath(root, str(issue.file));
		for (const [group, kind] of Object.entries(KNIP_KINDS)) {
			for (const item of arr(issue[group])) {
				if (!isRecord(item)) continue;
				const name = str(item.name);
				if (!name) continue;
				// For `files` the item name is the unused file itself.
				const file = group === "files" ? relPath(root, name) : issueFile;
				findings.push({
					ruleId: `code.knip/${kind.rule}`,
					title: truncate(`${kind.rule.replace(/-/g, " ")}: ${name}`, 120),
					severity: kind.severity,
					category: kind.category,
					message: kind.message(name),
					location: {
						file,
						line: group === "files" ? undefined : num(item.line),
						column: group === "files" ? undefined : num(item.col),
					},
					evidence: truncate(name, 120),
					remediation: kind.remediation,
					references: [KNIP_REFERENCE],
					confidence: kind.confidence,
					tags: ["dead-code"],
				});
			}
		}
	}
	return findings;
};

export const knip = defineAuditor({
	id: "code.knip",
	title: "knip unused code scan",
	description:
		"Finds unused files, exports and dependencies in JS/TS projects with knip. Runs the project's JS/TS config files and plugin configs, which executes target code: enable only for trusted code. Skipped without package.json or node_modules.",
	categories: ["maintainability"],
	targets: ["codebase"],
	engine: "external",
	tool: "knip",
	defaultEnabled: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			if (!(yield* ws.exists("package.json")))
				return yield* skip(
					"No package.json; knip only analyses JS/TS projects.",
				);
			if (!(yield* ws.exists("node_modules")))
				return yield* skip(
					"node_modules is missing; install dependencies first so knip can resolve imports.",
				);
			const bin = yield* requireTool(
				ctx,
				"knip",
				"Install: npm install -g knip (https://knip.dev/overview/getting-started).",
			);
			const res = yield* runTool(
				ctx,
				[bin, "--reporter", "json", "--no-progress", "--no-exit-code"],
				ws.root,
				[0],
			);
			return parseKnipReport(
				res.stdout.trim() ? yield* parseJson(res.stdout, "knip") : {},
				ws.root,
			);
		}),
});

/* -------------------------------------------------------------------------- */
/*                                  scancode                                  */
/* -------------------------------------------------------------------------- */

/** Licence expression families, matched per `OR` alternative. */
const isStrongCopyleft = (alt: string) => /(^|\s)(AGPL|GPL|SSPL)-/.test(alt);
const isWeakCopyleft = (alt: string) => /(^|\s)(LGPL|MPL|EPL)-/.test(alt);

/**
 * Classifies an SPDX expression. `A OR B` is strong or weak only when every
 * alternative is, since the recipient may choose a permissive alternative.
 */
export const classifyLicense = (expr: string): "strong" | "weak" | "none" => {
	const alts = expr.replace(/[()]/g, "").split(/\s+OR\s+/i);
	if (alts.every(isStrongCopyleft)) return "strong";
	if (alts.every(isWeakCopyleft)) return "weak";
	return "none";
};

/** A declared project licence that the strong copyleft code above cannot live under. */
const isCopyleftFreeProject = (expr: string) =>
	!/(^|[\s(])(AGPL|GPL|LGPL|MPL|EPL|SSPL)-/.test(expr);

const firstLicenseId = (expr: string) =>
	expr.split(/[\s()]+/).find((t) => t && !/^(AND|OR|WITH)$/i.test(t)) ?? expr;

const SCANCODE_REFERENCE = "https://github.com/nexB/scancode-toolkit";

/**
 * Parses `scancode --json` output (ScanCode v32+ fields). `declared` is the
 * project licence from package.json; when absent, the detected licence of a
 * root LICENSE/COPYING file is used.
 */
export const parseScancodeReport = (
	json: unknown,
	root: string,
	declared?: string,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	const files = arr(json.files)
		.filter(isRecord)
		.filter((f) => str(f.type) !== "directory");
	const rootLicense = files.find((f) =>
		/^(licen[cs]e|copying)(\.\w+)?$/i.test(str(f.path) ?? ""),
	);
	const projectLicense =
		declared ?? str(rootLicense?.detected_license_expression_spdx);
	const findings: FindingInput[] = [];
	const unlicensed: string[] = [];

	for (const f of files) {
		const file = relPath(root, str(f.path));
		if (!file) continue;
		const spdx = str(f.detected_license_expression_spdx);
		if (!spdx) {
			unlicensed.push(file);
			continue;
		}
		const kind = classifyLicense(spdx);
		const matches = arr(f.license_detections)
			.filter(isRecord)
			.flatMap((d) => arr(d.matches))
			.filter(isRecord);
		const starts = matches.map((m) => num(m.start_line) ?? 0);
		const ends = matches.map((m) => num(m.end_line) ?? 0);
		const line = starts.length ? Math.min(...starts) : undefined;
		const evidence = line
			? `${spdx} at lines ${line}-${Math.max(...ends)}`
			: spdx;
		const tags = [`license-${firstLicenseId(spdx).toLowerCase()}`];
		const reference = `https://spdx.org/licenses/${firstLicenseId(spdx)}.html`;

		if (kind === "strong") {
			findings.push({
				ruleId: "code.scancode/strong-copyleft",
				title: truncate(`${file}: ${spdx}`, 120),
				severity: "medium",
				category: "compliance",
				message: `${spdx} is strong copyleft: distributing this file can require releasing the combined work under the same licence.`,
				location: { file, line },
				evidence,
				remediation:
					"Confirm the licence is acceptable for this project. Replace the code, or obtain a licence that permits your use.",
				references: [reference, SCANCODE_REFERENCE],
				confidence: "medium",
				tags,
			});
			if (projectLicense && isCopyleftFreeProject(projectLicense)) {
				findings.push({
					ruleId: "code.scancode/license-conflict",
					title: truncate(`${file} conflicts with ${projectLicense}`, 120),
					severity: "medium",
					category: "compliance",
					message: `${spdx} code cannot be distributed under the project's declared licence (${projectLicense}) without relicensing.`,
					location: { file, line },
					evidence,
					remediation: `Remove the ${spdx} code, or change the project licence after legal review.`,
					references: [reference, SCANCODE_REFERENCE],
					confidence: "medium",
					tags,
				});
			}
		} else if (kind === "weak") {
			findings.push({
				ruleId: "code.scancode/weak-copyleft",
				title: truncate(`${file}: ${spdx}`, 120),
				severity: "low",
				category: "compliance",
				message: `${spdx} is weak copyleft: changes to this file may need to be shared, but the rest of the project can keep its own licence.`,
				location: { file, line },
				evidence,
				remediation:
					"Keep the file unmodified or publish your changes to it, and keep its licence notice intact.",
				references: [reference, SCANCODE_REFERENCE],
				confidence: "medium",
				tags,
			});
		}
	}

	if (unlicensed.length) {
		const total = files.length;
		findings.push({
			ruleId: "code.scancode/no-license-detected",
			title: `${unlicensed.length} ${unlicensed.length === 1 ? "file has" : "files have"} no detected licence`,
			severity: "info",
			category: "compliance",
			message: `ScanCode found no licence in ${unlicensed.length} of ${total} scanned entries. They are covered only by the project licence, if any.`,
			evidence: truncate(unlicensed.slice(0, 5).join(", "), 160),
			remediation:
				"Add licence headers or a licence note to third-party code, and confirm the rest falls under the project LICENSE.",
			references: [SCANCODE_REFERENCE],
			confidence: "medium",
			tags: ["license"],
		});
	}
	return findings;
};

/** Project licence from package.json, if the project declares one. */
const declaredLicense = (ws: Workspace) =>
	ws.exists("package.json").pipe(
		Effect.flatMap((exists) =>
			exists ? ws.readText("package.json") : Effect.succeed("{}"),
		),
		Effect.map((text) => {
			try {
				const pkg: unknown = JSON.parse(text);
				return isRecord(pkg) ? str(pkg.license) : undefined;
			} catch {
				return undefined;
			}
		}),
	);

export const scancode = defineAuditor({
	id: "code.scancode",
	title: "ScanCode licence scan",
	description:
		"Runs ScanCode Toolkit to detect file-level licences and flags strong and weak copyleft code, and code that conflicts with the declared project licence. Slow on large trees: opt-in.",
	categories: ["compliance"],
	targets: ["codebase"],
	engine: "external",
	tool: "scancode",
	defaultEnabled: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const bin = yield* requireTool(
				ctx,
				"scancode",
				"Install: pipx install scancode-toolkit, or run it without installing via uvx --from scancode-toolkit scancode (https://scancode-toolkit.readthedocs.io/).",
			);
			const declared = yield* declaredLicense(ws);
			const dir = yield* Effect.promise(() =>
				mkdtemp(join(tmpdir(), "openaudit-scancode-")),
			);
			return yield* Effect.gen(function* () {
				const out = join(dir, "scancode.json");
				// Exit 1 means some files could not be scanned; the report is still written.
				yield* runTool(
					ctx,
					[
						bin,
						"--license",
						"--copyright",
						"--strip-root",
						"--json",
						out,
						"--quiet",
						"-n",
						"4",
						// ScanCode 32 still scans files under `node_modules/*`; a bare name skips them at every depth.
						"--ignore",
						"node_modules",
						"--ignore",
						".git",
						ws.root,
					],
					ws.root,
					[0, 1],
				);
				const text = yield* Effect.tryPromise({
					try: () => readFile(out, "utf8"),
					catch: (cause) =>
						new AuditorError({
							message: "scancode did not write a report",
							cause,
						}),
				});
				return parseScancodeReport(
					yield* parseJson(text, "scancode"),
					ws.root,
					declared,
				);
			}).pipe(
				Effect.ensuring(
					Effect.promise(() => rm(dir, { recursive: true, force: true })),
				),
			);
		}),
});
