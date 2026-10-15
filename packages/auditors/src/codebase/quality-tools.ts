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
import { recordOf } from "./report-fields";
import { isRecord, truncate } from "./util";

/** A workspace-relative or absolute file path. */
type FilePath = string;
/** An SPDX licence expression, such as `MIT OR Apache-2.0`. */
type LicenseExpression = string;

/* -------------------------------------------------------------------------- */
/*                                    jscpd                                   */
/* -------------------------------------------------------------------------- */

/** Blocks shorter than this are reported as `info` rather than `low`. */
const JSCPD_LOW_LINES = 20;
/** Project-wide duplication above this percentage gets an aggregate finding. */
const JSCPD_MAX_PERCENT = 5;

/** `path:start-end` of one side of a jscpd duplicate. */
const jscpdSpan = (root: FilePath, f: Record<string, unknown>) =>
	`${relPath(root, str(f.name)) ?? "unknown"}:${num(f.start) ?? "?"}-${num(f.end) ?? "?"}`;

const jscpdDuplicateFinding = (
	dup: unknown,
	root: FilePath,
): FindingInput[] => {
	if (!isRecord(dup)) return [];
	const first = recordOf(dup.firstFile);
	const second = recordOf(dup.secondFile);
	const fileA = relPath(root, str(first.name));
	const fileB = relPath(root, str(second.name));
	const lines = num(dup.lines) ?? 0;
	return [
		{
			ruleId: "code.jscpd/duplicate-block",
			title: truncate(`Duplicated code between ${fileA} and ${fileB}`, 120),
			severity: lines < JSCPD_LOW_LINES ? "info" : "low",
			category: "maintainability",
			message: `${lines} lines (${num(dup.tokens) ?? 0} tokens) are copy-pasted between ${jscpdSpan(root, first)} and ${jscpdSpan(root, second)}.`,
			location: { file: fileA, line: num(first.start) },
			evidence: `${jscpdSpan(root, first)} <-> ${jscpdSpan(root, second)}`,
			remediation:
				"Extract the shared logic into one function or module and call it from both places.",
			references: ["https://github.com/kucherenko/jscpd"],
			confidence: "high",
			tags: ["duplication"],
		},
	];
};

/** The aggregate finding when project-wide duplication exceeds the threshold. */
const jscpdRatioFinding = (statistics: unknown): FindingInput[] => {
	if (!isRecord(statistics) || !isRecord(statistics.total)) return [];
	const total = statistics.total;
	const percentage = num(total.percentage);
	const exceeded = percentage !== undefined && percentage > JSCPD_MAX_PERCENT;
	if (!exceeded) return [];
	return [
		{
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
		},
	];
};

/** Parses the `jscpd-report.json` written by `jscpd --reporters json`. */
export const parseJscpdReport = (
	json: unknown,
	root: FilePath,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	return [
		...arr(json.duplicates).flatMap((dup) => jscpdDuplicateFinding(dup, root)),
		...jscpdRatioFinding(json.statistics),
	];
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

/** Where a knip issue item was reported. */
interface KnipSite {
	readonly root: FilePath;
	/** The file of the knip issue the item belongs to. */
	readonly file: FilePath | undefined;
	readonly group: string;
	readonly kind: KnipKind;
}

const knipFinding = (item: unknown, site: KnipSite): FindingInput[] => {
	if (!isRecord(item)) return [];
	const name = str(item.name);
	if (!name) return [];
	const { kind } = site;
	// For `files` the item name is the unused file itself.
	const isFile = site.group === "files";
	return [
		{
			ruleId: `code.knip/${kind.rule}`,
			title: truncate(`${kind.rule.replace(/-/g, " ")}: ${name}`, 120),
			severity: kind.severity,
			category: kind.category,
			message: kind.message(name),
			location: {
				file: isFile ? relPath(site.root, name) : site.file,
				line: isFile ? undefined : num(item.line),
				column: isFile ? undefined : num(item.col),
			},
			evidence: truncate(name, 120),
			remediation: kind.remediation,
			references: [KNIP_REFERENCE],
			confidence: kind.confidence,
			tags: ["dead-code"],
		},
	];
};

const knipIssueFindings = (issue: unknown, root: FilePath): FindingInput[] => {
	if (!isRecord(issue)) return [];
	const file = relPath(root, str(issue.file));
	return Object.entries(KNIP_KINDS).flatMap(([group, kind]) =>
		arr(issue[group]).flatMap((item) =>
			knipFinding(item, { root, file, group, kind }),
		),
	);
};

/** Parses `knip --reporter json` output. */
export const parseKnipReport = (
	json: unknown,
	root: FilePath,
): FindingInput[] =>
	isRecord(json)
		? arr(json.issues).flatMap((issue) => knipIssueFindings(issue, root))
		: [];

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
const isStrongCopyleft = (alt: LicenseExpression) =>
	/(^|\s)(AGPL|GPL|SSPL)-/.test(alt);
const isWeakCopyleft = (alt: LicenseExpression) =>
	/(^|\s)(LGPL|MPL|EPL)-/.test(alt);

/**
 * Classifies an SPDX expression. `A OR B` is strong or weak only when every
 * alternative is, since the recipient may choose a permissive alternative.
 */
export const classifyLicense = (
	expr: LicenseExpression,
): "strong" | "weak" | "none" => {
	const alts = expr.replace(/[()]/g, "").split(/\s+OR\s+/i);
	if (alts.every(isStrongCopyleft)) return "strong";
	if (alts.every(isWeakCopyleft)) return "weak";
	return "none";
};

/** A declared project licence that the strong copyleft code above cannot live under. */
const isCopyleftFreeProject = (expr: LicenseExpression) =>
	!/(^|[\s(])(AGPL|GPL|LGPL|MPL|EPL|SSPL)-/.test(expr);

const firstLicenseId = (expr: LicenseExpression) =>
	expr.split(/[\s()]+/).find((t) => t && !/^(AND|OR|WITH)$/i.test(t)) ?? expr;

const SCANCODE_REFERENCE = "https://github.com/nexB/scancode-toolkit";

/** A file whose detected licence is copyleft, with what every finding on it shares. */
interface ScancodeHit {
	readonly file: FilePath;
	readonly spdx: LicenseExpression;
	readonly line: number | undefined;
	readonly evidence: string;
	readonly tags: string[];
	readonly reference: string;
}

/** The finding fields that differ between scancode rules. */
interface ScancodeRule {
	readonly ruleId: string;
	readonly title: string;
	readonly severity: Severity;
	readonly message: string;
	readonly remediation: string;
}

const scancodeFinding = (
	hit: ScancodeHit,
	rule: ScancodeRule,
): FindingInput => ({
	ruleId: rule.ruleId,
	title: rule.title,
	severity: rule.severity,
	category: "compliance",
	message: rule.message,
	location: { file: hit.file, line: hit.line },
	evidence: hit.evidence,
	remediation: rule.remediation,
	references: [hit.reference, SCANCODE_REFERENCE],
	confidence: "medium",
	tags: hit.tags,
});

const scancodeHit = (
	f: Record<string, unknown>,
	file: FilePath,
	spdx: LicenseExpression,
): ScancodeHit => {
	const matches = arr(f.license_detections)
		.filter(isRecord)
		.flatMap((d) => arr(d.matches))
		.filter(isRecord);
	const starts = matches.map((m) => num(m.start_line) ?? 0);
	const ends = matches.map((m) => num(m.end_line) ?? 0);
	const line = starts.length ? Math.min(...starts) : undefined;
	return {
		file,
		spdx,
		line,
		evidence: line ? `${spdx} at lines ${line}-${Math.max(...ends)}` : spdx,
		tags: [`license-${firstLicenseId(spdx).toLowerCase()}`],
		reference: `https://spdx.org/licenses/${firstLicenseId(spdx)}.html`,
	};
};

const strongCopyleftFindings = (
	hit: ScancodeHit,
	projectLicense: string | undefined,
): FindingInput[] => {
	const { file, spdx } = hit;
	const findings = [
		scancodeFinding(hit, {
			ruleId: "code.scancode/strong-copyleft",
			title: truncate(`${file}: ${spdx}`, 120),
			severity: "medium",
			message: `${spdx} is strong copyleft: distributing this file can require releasing the combined work under the same licence.`,
			remediation:
				"Confirm the licence is acceptable for this project. Replace the code, or obtain a licence that permits your use.",
		}),
	];
	if (projectLicense && isCopyleftFreeProject(projectLicense))
		findings.push(
			scancodeFinding(hit, {
				ruleId: "code.scancode/license-conflict",
				title: truncate(`${file} conflicts with ${projectLicense}`, 120),
				severity: "medium",
				message: `${spdx} code cannot be distributed under the project's declared licence (${projectLicense}) without relicensing.`,
				remediation: `Remove the ${spdx} code, or change the project licence after legal review.`,
			}),
		);
	return findings;
};

const weakCopyleftFinding = (hit: ScancodeHit): FindingInput =>
	scancodeFinding(hit, {
		ruleId: "code.scancode/weak-copyleft",
		title: truncate(`${hit.file}: ${hit.spdx}`, 120),
		severity: "low",
		message: `${hit.spdx} is weak copyleft: changes to this file may need to be shared, but the rest of the project can keep its own licence.`,
		remediation:
			"Keep the file unmodified or publish your changes to it, and keep its licence notice intact.",
	});

const scancodeFileFindings = (
	f: Record<string, unknown>,
	root: FilePath,
	projectLicense: string | undefined,
): FindingInput[] => {
	const file = relPath(root, str(f.path));
	const spdx = str(f.detected_license_expression_spdx);
	if (!file || !spdx) return [];
	const kind = classifyLicense(spdx);
	if (kind === "strong")
		return strongCopyleftFindings(scancodeHit(f, file, spdx), projectLicense);
	if (kind === "weak") return [weakCopyleftFinding(scancodeHit(f, file, spdx))];
	return [];
};

/** Scanned files with no detected licence. */
const unlicensedFiles = (
	files: ReadonlyArray<Record<string, unknown>>,
	root: FilePath,
): string[] =>
	files.flatMap((f) => {
		const file = relPath(root, str(f.path));
		return file && !str(f.detected_license_expression_spdx) ? [file] : [];
	});

const noLicenseFinding = (
	unlicensed: ReadonlyArray<string>,
	total: number,
): FindingInput[] =>
	unlicensed.length
		? [
				{
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
				},
			]
		: [];

/**
 * Parses `scancode --json` output (ScanCode v32+ fields). `declared` is the
 * project licence from package.json; when absent, the detected licence of a
 * root LICENSE/COPYING file is used.
 */
export const parseScancodeReport = (
	json: unknown,
	root: FilePath,
	declared?: LicenseExpression,
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
	return [
		...files.flatMap((f) => scancodeFileFindings(f, root, projectLicense)),
		...noLicenseFinding(unlicensedFiles(files, root), files.length),
	];
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
