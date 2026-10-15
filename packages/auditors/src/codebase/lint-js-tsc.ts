import { realpath } from "node:fs/promises";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";
import {
	type AuditContext,
	type Auditor,
	AuditorError,
	defineAuditor,
	type FindingInput,
	requireWorkspace,
	skip,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import { relPath, runTool } from "../tool";
import {
	type AbsolutePath,
	capFindings,
	dirOf,
	isPackageJson,
	type JsonText,
	type RelativePath,
	withTempDir,
} from "./lint-js-shared";
import {
	isFixturePath,
	isRecord,
	isTestPath,
	parseJsonc,
	scrubLine,
	truncate,
} from "./util";

/** The `code.typecheck` auditor: tsc --noEmit on each project tsconfig.json. */

const MAX_TSCONFIGS = 10;
const MAX_CANDIDATES = 50;
const TSC_LOCATED = /^(.+?)\((\d+),(\d+)\): (error|warning) (TS\d+): (.*)$/;
const TSC_GLOBAL = /^(error|warning) (TS\d+): (.*)$/;
/** "Cannot find module" family; collapsed into one finding per tsconfig. */
const UNRESOLVED_MODULE_CODES = new Set(["TS2307", "TS2792"]);
/** Global diagnostics that only mean "nothing to check". */
const IGNORED_GLOBAL_CODES = new Set(["TS18003"]);

export interface TscDiagnostic {
	/** Workspace-relative POSIX path, absent for global diagnostics. */
	readonly file?: string;
	readonly line?: number;
	readonly column?: number;
	readonly code: string;
	readonly message: string;
}

/** Where tsc ran and where the workspace is, to map its paths back. */
interface TscPaths {
	readonly cwd: AbsolutePath;
	readonly root: AbsolutePath;
	readonly realRoot: AbsolutePath;
}

/** A path tsc printed, relative to the workspace. */
const workspaceFile = (
	reported: string,
	paths: TscPaths,
): RelativePath | undefined => {
	const abs = resolve(paths.cwd, reported);
	// The root may be reached through a symlink; tsc reports real paths.
	const file = abs.startsWith(`${paths.realRoot}/`)
		? join(paths.root, abs.slice(paths.realRoot.length))
		: abs;
	return relPath(paths.root, file);
};

const parseTscLine = (
	line: string,
	paths: TscPaths,
): TscDiagnostic | undefined => {
	const located = TSC_LOCATED.exec(line);
	if (located)
		return {
			file: workspaceFile(located[1] ?? "", paths),
			line: Number(located[2]),
			column: Number(located[3]),
			code: located[5] ?? "TS0000",
			message: (located[6] ?? "")
				.replaceAll(`${paths.realRoot}/`, "")
				.replaceAll(`${paths.root}/`, ""),
		};
	const global = TSC_GLOBAL.exec(line);
	return global
		? { code: global[2] ?? "TS0000", message: global[3] ?? "" }
		: undefined;
};

/**
 * Parses `tsc --pretty false` output. tsc prints paths relative to its cwd,
 * so they are resolved against `cwd` and made relative to the workspace.
 * Continuation lines (indented) are dropped.
 */
export const parseTscOutput = (
	output: string,
	cwd: AbsolutePath,
	root: AbsolutePath,
	realRoot: AbsolutePath = root,
): TscDiagnostic[] =>
	output.split(/\r?\n/).flatMap((line) => {
		const diagnostic = parseTscLine(line, { cwd, root, realRoot });
		return diagnostic ? [diagnostic] : [];
	});

const isDependencyPath = (file: RelativePath) =>
	file.startsWith("../") || /(^|\/)node_modules\//.test(file);

const isUnresolvedImport = (d: TscDiagnostic): boolean =>
	Boolean(d.file) && UNRESOLVED_MODULE_CODES.has(d.code);

const quotedModule = (d: TscDiagnostic): string[] => {
	const m = /'([^']+)'/.exec(d.message);
	return m?.[1] ? [m[1]] : [];
};

const codeAndMessage = (d: TscDiagnostic) => `${d.code}: ${d.message}`;

const unresolvedModulesFinding = (
	unresolved: ReadonlyArray<TscDiagnostic>,
	tsconfig: RelativePath,
): FindingInput => {
	const modules = [...new Set(unresolved.flatMap(quotedModule))];
	const files = new Set(unresolved.map((d) => d.file));
	const first = unresolved[0];
	return {
		ruleId: "code.typecheck/unresolved-modules",
		title: `${modules.length} module${modules.length === 1 ? "" : "s"} cannot be resolved by TypeScript`,
		severity: "medium",
		category: "reliability",
		message: `${unresolved.length} imports in ${files.size} files (${tsconfig}) do not resolve: ${modules.slice(0, 5).join(", ")}${modules.length > 5 ? ", ..." : ""}. This usually means dependencies are missing from package.json or are not installed, or that path aliases are misconfigured.`,
		location: first && { file: first.file, line: first.line },
		evidence: scrubLine(truncate(first?.message ?? "")),
		remediation:
			"Declare the missing packages in package.json (and their @types packages), fix the import paths, or correct `paths`/`moduleResolution` in tsconfig.json.",
		references: ["https://www.typescriptlang.org/tsconfig#moduleResolution"],
		confidence: "medium",
		tags: ["ts2307", "typescript"],
	};
};

const configErrorFinding = (
	d: TscDiagnostic,
	tsconfig: RelativePath,
): FindingInput | undefined => {
	if (IGNORED_GLOBAL_CODES.has(d.code)) return undefined;
	return {
		ruleId: "code.typecheck/config-error",
		title: truncate(codeAndMessage(d), 120),
		severity: "low",
		category: "reliability",
		message: `TypeScript could not use ${tsconfig}: ${d.message}`,
		location: { file: tsconfig },
		evidence: scrubLine(truncate(codeAndMessage(d))),
		remediation: "Fix the tsconfig.json option or path that tsc rejects.",
		confidence: "high",
		tags: [d.code.toLowerCase(), "typescript"],
	};
};

const typeErrorFinding = (
	d: TscDiagnostic,
	file: RelativePath,
): FindingInput | undefined => {
	if (isDependencyPath(file)) return undefined;
	return {
		ruleId: "code.typecheck/type-error",
		title: truncate(codeAndMessage(d), 120),
		severity: isTestPath(file) ? "low" : "medium",
		category: "reliability",
		message: `${file}(${d.line},${d.column}): ${d.message}`,
		location: { file, line: d.line, column: d.column },
		evidence: scrubLine(truncate(codeAndMessage(d))),
		remediation:
			"Fix the type error. Code that does not type-check hides real bugs and defeats refactoring safety.",
		references: [`https://typescript.tv/errors/#${d.code.toLowerCase()}`],
		confidence: "high",
		tags: [d.code.toLowerCase(), "typescript"],
	};
};

/** The finding for one diagnostic; unresolved imports are reported together. */
const diagnosticFinding = (
	d: TscDiagnostic,
	tsconfig: RelativePath,
): FindingInput | undefined => {
	if (isUnresolvedImport(d)) return undefined;
	if (!d.file) return configErrorFinding(d, tsconfig);
	return typeErrorFinding(d, d.file);
};

/** Findings for one tsconfig's diagnostics. */
export const tscFindings = (
	diagnostics: ReadonlyArray<TscDiagnostic>,
	tsconfig: RelativePath,
): FindingInput[] => {
	const unresolved = diagnostics.filter(isUnresolvedImport);
	const findings: FindingInput[] =
		unresolved.length > 0
			? [unresolvedModulesFinding(unresolved, tsconfig)]
			: [];
	for (const d of diagnostics) {
		const finding = diagnosticFinding(d, tsconfig);
		if (finding) findings.push(finding);
	}
	return findings;
};

const findingKey = (f: FindingInput) =>
	`${f.ruleId}|${f.location?.file}|${f.location?.line}|${f.location?.column}|${f.title}`;

/** Unresolved modules first, then errors, then low-severity (test) errors. */
const tscRank = (f: FindingInput) =>
	f.ruleId === "code.typecheck/unresolved-modules"
		? 0
		: f.severity === "low"
			? 2
			: 1;

const fileOf = (f: FindingInput) => f.location?.file ?? "";
const lineOf = (f: FindingInput) => f.location?.line ?? 0;

const compareTscFindings = (a: FindingInput, b: FindingInput) =>
	tscRank(a) - tscRank(b) ||
	fileOf(a).localeCompare(fileOf(b)) ||
	lineOf(a) - lineOf(b);

/**
 * Orders (non-test first, then by file and line), de-duplicates diagnostics that
 * several tsconfigs report for the same file, and applies the per-run cap.
 */
export const finalizeTscFindings = (
	findings: ReadonlyArray<FindingInput>,
): FindingInput[] => {
	const seen = new Set<string>();
	const unique = findings.filter((f) => {
		const key = findingKey(f);
		if (seen.has(key)) return false;
		seen.add(key);
		return true;
	});
	unique.sort(compareTscFindings);
	return capFindings(unique, "code.typecheck/more-errors", "tsc");
};

interface TsconfigFile {
	path: RelativePath;
	text: JsonText;
}

const filesOf = (json: Record<string, unknown>) =>
	Array.isArray(json.files) ? json.files : undefined;

/** A solution-style config: `files: []` with `references`. */
const isSolutionStyle = (json: Record<string, unknown>) =>
	filesOf(json)?.length === 0 && json.references !== undefined;

const listsSources = (json: Record<string, unknown>) =>
	json.include !== undefined || (filesOf(json)?.length ?? 0) > 0;

const isInside = (path: RelativePath, dir: RelativePath) =>
	dir === "" || path.startsWith(`${dir}/`);

const hasNestedConfig = (
	configs: ReadonlyArray<TsconfigFile>,
	path: RelativePath,
) => configs.some((c) => c.path !== path && isInside(c.path, dirOf(path)));

const isPackageRoot = (
	dir: RelativePath,
	packageDirs: ReadonlySet<RelativePath>,
) => dir === "" || packageDirs.has(dir);

const isProjectConfig = (
	config: TsconfigFile,
	configs: ReadonlyArray<TsconfigFile>,
	packageDirs: ReadonlySet<RelativePath>,
): boolean => {
	const json = parseJsonc(config.text);
	if (!isRecord(json) || isSolutionStyle(json)) return false;
	if (listsSources(json)) return true;
	return (
		!hasNestedConfig(configs, config.path) &&
		isPackageRoot(dirOf(config.path), packageDirs)
	);
};

const byDepthThenName = (a: RelativePath, b: RelativePath) =>
	a.split("/").length - b.split("/").length || a.localeCompare(b);

/**
 * tsconfig.json files worth checking: project roots (have `include`/`files`, or
 * sit next to a package.json or at the repo root). Skipped: solution-style
 * configs (`files: []` with `references`) and configs without `include` that
 * have project configs below them (a monorepo base would pull in every package
 * with the wrong options), since the nested projects are checked instead.
 */
export const selectTsconfigs = (
	configs: ReadonlyArray<TsconfigFile>,
	packageDirs: ReadonlySet<RelativePath>,
): string[] =>
	configs
		.filter((c) => isProjectConfig(c, configs, packageDirs))
		.map((c) => c.path)
		.sort(byDepthThenName);

/** Absolute path of the TypeScript compiler bundled with openaudit. */
const bundledTsc = (): AbsolutePath | undefined => {
	try {
		return createRequire(import.meta.url).resolve("typescript/bin/tsc");
	} catch {
		return undefined;
	}
};

const hasInstalledDependencies = (ws: Workspace, dir: RelativePath) =>
	Effect.gen(function* () {
		if (yield* ws.exists("node_modules")) return true;
		return dir !== "" && (yield* ws.exists(`${dir}/node_modules`));
	});

const isTsconfigCandidate = (path: RelativePath) =>
	/(^|\/)tsconfig\.json$/.test(path) && !isFixturePath(path);

const readTsconfig = (ws: Workspace, path: RelativePath) =>
	ws.readText(path).pipe(
		Effect.map((text) => ({ path, text })),
		Effect.orElseSucceed(() => undefined),
	);

/** The project tsconfig.json files of the workspace; skips when there are none. */
const projectTsconfigs = (ws: Workspace, all: ReadonlyArray<RelativePath>) =>
	Effect.gen(function* () {
		const candidates = all.filter(isTsconfigCandidate).slice(0, MAX_CANDIDATES);
		if (candidates.length === 0) return yield* skip("No tsconfig.json found");
		const configs = yield* Effect.forEach(
			candidates,
			(path) => readTsconfig(ws, path),
			{ concurrency: 8 },
		);
		const packageDirs = new Set(all.filter(isPackageJson).map(dirOf));
		return selectTsconfigs(
			configs.filter((c): c is TsconfigFile => !!c),
			packageDirs,
		);
	});

/** The configs whose dependencies are installed, in order. */
const runnableTsconfigs = (
	ws: Workspace,
	leaves: ReadonlyArray<RelativePath>,
) =>
	Effect.gen(function* () {
		const runnable: RelativePath[] = [];
		for (const path of leaves)
			if (yield* hasInstalledDependencies(ws, dirOf(path))) runnable.push(path);
		return runnable;
	});

/** One tsc run: the compiler, the runtime that runs it, and its temp cwd. */
interface TscRun {
	readonly ctx: AuditContext;
	readonly ws: Workspace;
	readonly runtime: AbsolutePath;
	readonly tsc: AbsolutePath;
	readonly realRoot: AbsolutePath;
	readonly cwd: AbsolutePath;
}

const tscCommand = (run: TscRun, path: RelativePath, index: number) => [
	run.runtime,
	run.tsc,
	"-p",
	run.ws.absolute(path),
	"--noEmit",
	"--pretty",
	"false",
	"--skipLibCheck",
	// Incremental and composite projects write .tsbuildinfo even with
	// --noEmit, next to the config. Send it to the temp dir (a no-op
	// for other projects). `--incremental false` is no alternative:
	// composite projects reject it yet still write the file.
	"--tsBuildInfoFile",
	join(run.cwd, `${index}.tsbuildinfo`),
];

const checkTsconfig = (run: TscRun, path: RelativePath, index: number) =>
	runTool(run.ctx, tscCommand(run, path, index), run.cwd, [0, 1, 2]).pipe(
		Effect.map((res) =>
			tscFindings(
				parseTscOutput(
					`${res.stdout}\n${res.stderr}`,
					run.cwd,
					run.ws.root,
					run.realRoot,
				),
				path,
			),
		),
		Effect.map((findings) => ({ findings, failed: undefined })),
		Effect.catch((err) =>
			Effect.succeed({
				findings: [] as FindingInput[],
				failed: err.message,
			}),
		),
	);

const checkTsconfigs = (
	run: Omit<TscRun, "cwd">,
	selected: ReadonlyArray<RelativePath>,
) =>
	withTempDir("openaudit-tsc-", (cwd) =>
		Effect.gen(function* () {
			const perConfig = yield* Effect.forEach(
				selected,
				(path, index) => checkTsconfig({ ...run, cwd }, path, index),
				{ concurrency: 2 },
			);
			if (perConfig.every((r) => r.failed !== undefined))
				return yield* Effect.fail(
					new AuditorError({
						message: `tsc failed for every tsconfig: ${perConfig[0]?.failed}`,
					}),
				);
			return finalizeTscFindings(perConfig.flatMap((r) => r.findings));
		}),
	);

export const typecheck: Auditor = defineAuditor({
	id: "code.typecheck",
	title: "TypeScript type-check (tsc)",
	description:
		"Runs the TypeScript compiler bundled with openaudit (never the target's own) with --noEmit on each project tsconfig.json and reports type errors. tsc does not execute project code; tsconfig `plugins` are only loaded by tsserver. Skipped when dependencies are not installed, because every import would fail.",
	categories: ["reliability", "maintainability"],
	targets: ["codebase"],
	engine: "external",
	tool: "tsc",
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const tsc = bundledTsc();
			if (!tsc)
				return yield* skip("The bundled TypeScript compiler was not found");
			const all = yield* ws.files;
			const leaves = yield* projectTsconfigs(ws, all);
			if (leaves.length === 0)
				return yield* skip("No project tsconfig.json found");
			if (all.includes(".pnp.cjs"))
				return yield* skip(
					"Yarn Plug'n'Play project: dependencies cannot be resolved without running project code",
				);
			const runnable = yield* runnableTsconfigs(ws, leaves);
			if (runnable.length === 0)
				return yield* skip(
					"No node_modules directory: dependencies are not installed, so every import would fail to resolve. Install them (openaudit never does) and re-run.",
				);
			const selected = runnable.slice(0, MAX_TSCONFIGS);
			if (runnable.length > selected.length)
				yield* ctx.log(
					`code.typecheck: checking ${selected.length} of ${runnable.length} tsconfig.json files`,
				);
			const runtime = (yield* ctx.exec.which("node")) ?? process.execPath;
			const realRoot = yield* Effect.promise(() =>
				realpath(ws.root).catch(() => ws.root),
			);
			return yield* checkTsconfigs(
				{ ctx, ws, runtime, tsc, realRoot },
				selected,
			);
		}),
});
