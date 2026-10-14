import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import {
	type Auditor,
	AuditorError,
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
import { lintCategory, lintTags, oxlintEslintId } from "./lint-rules";
import {
	isFixturePath,
	isRecord,
	isTestPath,
	kebab,
	parseJsonc,
	scrubLine,
	truncate,
} from "./util";

/**
 * Type-checking and linting of JavaScript/TypeScript projects.
 *
 * Targets are hostile, so every wrapper either runs a tool that never executes
 * project code (tsc, oxlint with a sanitized config, biome) or is opt-in and
 * says so (eslint, whose config is a JS program).
 */

/** Findings kept per run; the rest collapse into one summary finding. */
const MAX_FINDINGS = 200;

const GENERIC_IGNORES = [
	"**/node_modules/**",
	"**/dist/**",
	"**/build/**",
	"**/coverage/**",
	"**/.next/**",
	"**/vendor/**",
	"**/*.min.js",
];

const capFindings = (
	findings: FindingInput[],
	ruleId: string,
	tool: string,
): FindingInput[] => {
	if (findings.length <= MAX_FINDINGS) return findings;
	const kept = findings.slice(0, MAX_FINDINGS);
	const extra = findings.length - MAX_FINDINGS;
	kept.push({
		ruleId,
		title: `${extra} more ${tool} findings not listed`,
		severity: "info",
		category: "maintainability",
		message: `${tool} reported ${findings.length} findings; only the first ${MAX_FINDINGS} are listed to keep the report readable.`,
		remediation: `Run ${tool} locally for the full list and fix the most common rules first.`,
		confidence: "high",
	});
	return kept;
};

/** Runs `use` with a fresh empty directory that is removed afterwards. */
const withTempDir = <A, E, R>(
	prefix: string,
	use: (dir: string) => Effect.Effect<A, E, R>,
) =>
	Effect.flatMap(
		// Real path: tools print paths relative to their (resolved) cwd.
		Effect.promise(async () => realpath(await mkdtemp(join(tmpdir(), prefix)))),
		(dir) =>
			use(dir).pipe(
				Effect.ensuring(
					Effect.promise(() => rm(dir, { recursive: true, force: true })),
				),
			),
	);

/* -------------------------------------------------------------------------- */
/*                                    tsc                                     */
/* -------------------------------------------------------------------------- */

const MAX_TSCONFIGS = 10;
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

/**
 * Parses `tsc --pretty false` output. tsc prints paths relative to its cwd,
 * so they are resolved against `cwd` and made relative to the workspace.
 * Continuation lines (indented) are dropped.
 */
export const parseTscOutput = (
	output: string,
	cwd: string,
	root: string,
	realRoot = root,
): TscDiagnostic[] => {
	const out: TscDiagnostic[] = [];
	for (const line of output.split(/\r?\n/)) {
		const located = TSC_LOCATED.exec(line);
		if (located) {
			const abs = resolve(cwd, located[1] ?? "");
			// The root may be reached through a symlink; tsc reports real paths.
			const file = abs.startsWith(`${realRoot}/`)
				? join(root, abs.slice(realRoot.length))
				: abs;
			out.push({
				file: relPath(root, file),
				line: Number(located[2]),
				column: Number(located[3]),
				code: located[5] ?? "TS0000",
				message: (located[6] ?? "")
					.replaceAll(`${realRoot}/`, "")
					.replaceAll(`${root}/`, ""),
			});
			continue;
		}
		const global = TSC_GLOBAL.exec(line);
		if (global)
			out.push({ code: global[2] ?? "TS0000", message: global[3] ?? "" });
	}
	return out;
};

const isDependencyPath = (file: string) =>
	file.startsWith("../") || /(^|\/)node_modules\//.test(file);

/** Findings for one tsconfig's diagnostics. */
export const tscFindings = (
	diagnostics: ReadonlyArray<TscDiagnostic>,
	tsconfig: string,
): FindingInput[] => {
	const findings: FindingInput[] = [];
	const unresolved = diagnostics.filter(
		(d) => d.file && UNRESOLVED_MODULE_CODES.has(d.code),
	);
	if (unresolved.length > 0) {
		const modules = [
			...new Set(
				unresolved.flatMap((d) => {
					const m = /'([^']+)'/.exec(d.message);
					return m?.[1] ? [m[1]] : [];
				}),
			),
		];
		const files = new Set(unresolved.map((d) => d.file));
		const first = unresolved[0];
		findings.push({
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
		});
	}
	for (const d of diagnostics) {
		if (UNRESOLVED_MODULE_CODES.has(d.code) && d.file) continue;
		if (!d.file) {
			if (IGNORED_GLOBAL_CODES.has(d.code)) continue;
			findings.push({
				ruleId: "code.typecheck/config-error",
				title: truncate(`${d.code}: ${d.message}`, 120),
				severity: "low",
				category: "reliability",
				message: `TypeScript could not use ${tsconfig}: ${d.message}`,
				location: { file: tsconfig },
				evidence: scrubLine(truncate(`${d.code}: ${d.message}`)),
				remediation: "Fix the tsconfig.json option or path that tsc rejects.",
				confidence: "high",
				tags: [d.code.toLowerCase(), "typescript"],
			});
			continue;
		}
		if (isDependencyPath(d.file)) continue;
		findings.push({
			ruleId: "code.typecheck/type-error",
			title: truncate(`${d.code}: ${d.message}`, 120),
			severity: isTestPath(d.file) ? "low" : "medium",
			category: "reliability",
			message: `${d.file}(${d.line},${d.column}): ${d.message}`,
			location: { file: d.file, line: d.line, column: d.column },
			evidence: scrubLine(truncate(`${d.code}: ${d.message}`)),
			remediation:
				"Fix the type error. Code that does not type-check hides real bugs and defeats refactoring safety.",
			references: [`https://typescript.tv/errors/#${d.code.toLowerCase()}`],
			confidence: "high",
			tags: [d.code.toLowerCase(), "typescript"],
		});
	}
	return findings;
};

/**
 * Orders (non-test first, then by file and line), de-duplicates diagnostics that
 * several tsconfigs report for the same file, and applies the per-run cap.
 */
export const finalizeTscFindings = (
	findings: ReadonlyArray<FindingInput>,
): FindingInput[] => {
	const seen = new Set<string>();
	const unique = findings.filter((f) => {
		const key = `${f.ruleId}|${f.location?.file}|${f.location?.line}|${f.location?.column}|${f.title}`;
		if (seen.has(key)) return false;
		seen.add(key);
		return true;
	});
	const rank = (f: FindingInput) =>
		f.ruleId === "code.typecheck/unresolved-modules"
			? 0
			: f.severity === "low"
				? 2
				: 1;
	unique.sort(
		(a, b) =>
			rank(a) - rank(b) ||
			(a.location?.file ?? "").localeCompare(b.location?.file ?? "") ||
			(a.location?.line ?? 0) - (b.location?.line ?? 0),
	);
	return capFindings(unique, "code.typecheck/more-errors", "tsc");
};

/**
 * tsconfig.json files worth checking: project roots (have `include`/`files`, or
 * sit next to a package.json or at the repo root). Skipped: solution-style
 * configs (`files: []` with `references`) and configs without `include` that
 * have project configs below them (a monorepo base would pull in every package
 * with the wrong options), since the nested projects are checked instead.
 */
export const selectTsconfigs = (
	configs: ReadonlyArray<{ path: string; text: string }>,
	packageDirs: ReadonlySet<string>,
): string[] => {
	const dirOf = (path: string) => (dirname(path) === "." ? "" : dirname(path));
	const leaves: string[] = [];
	for (const { path, text } of configs) {
		const json = parseJsonc(text);
		if (!isRecord(json)) continue;
		const dir = dirOf(path);
		const files = Array.isArray(json.files) ? json.files : undefined;
		if (files && files.length === 0 && json.references !== undefined) continue;
		const explicit = json.include !== undefined || (files && files.length > 0);
		if (explicit) {
			leaves.push(path);
			continue;
		}
		const hasNested = configs.some(
			(c) => c.path !== path && (dir === "" || c.path.startsWith(`${dir}/`)),
		);
		if (!hasNested && (dir === "" || packageDirs.has(dir))) leaves.push(path);
	}
	return leaves.sort(
		(a, b) => a.split("/").length - b.split("/").length || a.localeCompare(b),
	);
};

/** Absolute path of the TypeScript compiler bundled with openaudit. */
const bundledTsc = (): string | undefined => {
	try {
		return createRequire(import.meta.url).resolve("typescript/bin/tsc");
	} catch {
		return undefined;
	}
};

const hasInstalledDependencies = (ws: Workspace, dir: string) =>
	Effect.gen(function* () {
		if (yield* ws.exists("node_modules")) return true;
		return dir !== "" && (yield* ws.exists(`${dir}/node_modules`));
	});

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
			const candidates = all
				.filter((p) => /(^|\/)tsconfig\.json$/.test(p) && !isFixturePath(p))
				.slice(0, 50);
			if (candidates.length === 0) return yield* skip("No tsconfig.json found");
			const configs = yield* Effect.forEach(
				candidates,
				(path) =>
					ws.readText(path).pipe(
						Effect.map((text) => ({ path, text })),
						Effect.orElseSucceed(() => undefined),
					),
				{ concurrency: 8 },
			);
			const packageDirs = new Set(
				all
					.filter((p) => p === "package.json" || p.endsWith("/package.json"))
					.map((p) => (dirname(p) === "." ? "" : dirname(p))),
			);
			const leaves = selectTsconfigs(
				configs.filter((c): c is { path: string; text: string } => !!c),
				packageDirs,
			);
			if (leaves.length === 0)
				return yield* skip("No project tsconfig.json found");
			if (all.includes(".pnp.cjs"))
				return yield* skip(
					"Yarn Plug'n'Play project: dependencies cannot be resolved without running project code",
				);
			const runnable: string[] = [];
			for (const path of leaves) {
				const dir = dirname(path) === "." ? "" : dirname(path);
				if (yield* hasInstalledDependencies(ws, dir)) runnable.push(path);
			}
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

			return yield* withTempDir("openaudit-tsc-", (cwd) =>
				Effect.gen(function* () {
					const perConfig = yield* Effect.forEach(
						selected,
						(path, index) =>
							runTool(
								ctx,
								[
									runtime,
									tsc,
									"-p",
									ws.absolute(path),
									"--noEmit",
									"--pretty",
									"false",
									"--skipLibCheck",
									// Incremental and composite projects write .tsbuildinfo even with
									// --noEmit, next to the config. Send it to the temp dir (a no-op
									// for other projects). `--incremental false` is no alternative:
									// composite projects reject it yet still write the file.
									"--tsBuildInfoFile",
									join(cwd, `${index}.tsbuildinfo`),
								],
								cwd,
								[0, 1, 2],
							).pipe(
								Effect.map((res) =>
									tscFindings(
										parseTscOutput(
											`${res.stdout}\n${res.stderr}`,
											cwd,
											ws.root,
											realRoot,
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
							),
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
		}),
});

/* -------------------------------------------------------------------------- */
/*                                   oxlint                                   */
/* -------------------------------------------------------------------------- */

const OXLINT_CONFIG_FILES = [
	".oxlintrc.json",
	".oxlintrc.jsonc",
	"oxlintrc.json",
];
/**
 * Config keys that are plain data. `jsPlugins` (loads JS), `extends`,
 * `overrides` and `ignorePatterns` (paths relative to the config location) are
 * dropped.
 */
const OXLINT_SAFE_KEYS = [
	"categories",
	"plugins",
	"rules",
	"env",
	"globals",
	"settings",
];

/**
 * oxlint's default plugins (`eslint` is always on). A `plugins` list replaces
 * them, so a list that adds plugins has to repeat them.
 */
const OXLINT_DEFAULT_PLUGINS = ["eslint", "typescript", "unicorn", "oxc"];
/** Dependencies that turn on oxlint plugins, which are off by default. */
const REACT_DEPENDENCIES = ["next", "preact", "react", "react-dom"];
const MAX_PACKAGE_JSONS = 200;

/** oxlint plugins for the frameworks the given package.json files depend on. */
export const frameworkPlugins = (
	packageJsons: ReadonlyArray<string>,
): string[] => {
	const deps = new Set<string>();
	for (const text of packageJsons) {
		const pkg = parseJsonc(text);
		if (!isRecord(pkg)) continue;
		for (const key of ["dependencies", "devDependencies", "peerDependencies"]) {
			const section = pkg[key];
			if (isRecord(section))
				for (const name of Object.keys(section)) deps.add(name);
		}
	}
	const plugins: string[] = [];
	if (REACT_DEPENDENCIES.some((d) => deps.has(d)))
		plugins.push("react", "jsx-a11y");
	if (deps.has("next")) plugins.push("nextjs");
	return plugins;
};

/**
 * Adds framework plugins to a (sanitized) oxlint config that does not choose
 * its own. rules-of-hooks is in oxlint's off-by-default `pedantic` category, so
 * it is turned on unless the config sets it.
 */
export const withFrameworkPlugins = (
	config: string,
	plugins: ReadonlyArray<string>,
): string => {
	const json = parseJsonc(config);
	if (!isRecord(json) || "plugins" in json || plugins.length === 0)
		return config;
	const out: Record<string, unknown> = {
		...json,
		plugins: [...OXLINT_DEFAULT_PLUGINS, ...plugins],
	};
	const rules = isRecord(json.rules) ? json.rules : {};
	if (
		plugins.includes("react") &&
		!("react/rules-of-hooks" in rules) &&
		!("react-hooks/rules-of-hooks" in rules)
	)
		out.rules = { ...rules, "react/rules-of-hooks": "error" };
	return JSON.stringify(out);
};

/** A copy of an oxlint config that cannot load JavaScript. */
export const sanitizeOxlintConfig = (text: string): string | undefined => {
	const json = parseJsonc(text);
	if (!isRecord(json)) return undefined;
	const safe: Record<string, unknown> = {};
	for (const key of OXLINT_SAFE_KEYS) if (key in json) safe[key] = json[key];
	return JSON.stringify(safe);
};

const OXLINT_CODE = /^([\w@-]+)\((.+)\)$/;

export const parseOxlintReport = (
	json: unknown,
	root: string,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	const findings: FindingInput[] = [];
	for (const d of arr(json.diagnostics)) {
		if (!isRecord(d)) continue;
		const code = str(d.code);
		const m = code ? OXLINT_CODE.exec(code) : null;
		const plugin = m?.[1];
		const rule = m?.[2];
		const label = isRecord(arr(d.labels)[0])
			? (arr(d.labels)[0] as Record<string, unknown>)
			: {};
		const span = isRecord(label.span) ? label.span : {};
		const severityLabel = str(d.severity);
		const severity: Severity =
			severityLabel === "error"
				? "medium"
				: severityLabel === "warning"
					? "low"
					: "info";
		const message = str(d.message) ?? "oxlint diagnostic";
		const file = relPath(root, str(d.filename));
		const ruleSlug = rule
			? kebab(plugin === "eslint" ? rule : `${plugin}/${rule}`)
			: "parse-error";
		const eslintId = plugin && rule ? oxlintEslintId(plugin, rule) : undefined;
		findings.push({
			ruleId: `code.oxlint/${ruleSlug}`,
			title: truncate(rule ? `${rule}: ${message}` : message, 120),
			severity: rule ? severity : "medium",
			category: lintCategory(eslintId ?? rule),
			message: `${message}${str(d.help) ? ` ${str(d.help)}` : ""}`,
			location: { file, line: num(span.line), column: num(span.column) },
			evidence: scrubLine(truncate(message)),
			remediation:
				str(d.help) ??
				"Fix the reported issue, or configure the rule in .oxlintrc.json if it does not fit your code base.",
			references: str(d.url) ? [str(d.url) as string] : undefined,
			confidence: "high",
			tags: plugin
				? [plugin, ...(eslintId ? lintTags(eslintId) : [])]
				: undefined,
		});
	}
	return findings;
};

export const oxlint: Auditor = defineAuditor({
	id: "code.oxlint",
	title: "oxlint",
	description:
		"Runs oxlint, a fast Rust linter for JavaScript and TypeScript. Uses a sanitized copy of the project's .oxlintrc.json (rules, categories, plugins only): `jsPlugins` are removed because they would load project JavaScript, and JS config files are never read. When the project depends on React, Preact or Next.js and its config lists no plugins, oxlint's react (including the React hooks rules), jsx-a11y and nextjs plugins are turned on.",
	categories: [
		"maintainability",
		"reliability",
		"accessibility",
		"performance",
	],
	targets: ["codebase"],
	engine: "external",
	tool: "oxlint",
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const bin = yield* requireTool(
				ctx,
				"oxlint",
				"Install: npm install -g oxlint (https://oxc.rs/docs/guide/usage/linter).",
			);
			const all = yield* ws.files;
			if (!all.some((p) => /\.(?:[cm]?[jt]sx?|vue|svelte|astro)$/.test(p)))
				return yield* skip("No JavaScript or TypeScript files");
			const configPath = OXLINT_CONFIG_FILES.find((c) => all.includes(c));
			const configText = configPath
				? yield* ws.readText(configPath).pipe(Effect.orElseSucceed(() => ""))
				: "";
			const sanitized = configText
				? sanitizeOxlintConfig(configText)
				: undefined;
			const packageJsons = yield* Effect.forEach(
				all
					.filter(
						(p) =>
							(p === "package.json" || p.endsWith("/package.json")) &&
							!isFixturePath(p),
					)
					.slice(0, MAX_PACKAGE_JSONS),
				(p) => ws.readText(p).pipe(Effect.orElseSucceed(() => "")),
				{ concurrency: 8 },
			);
			const plugins = frameworkPlugins(packageJsons);
			// Tried in order: the project's config, the framework plugins, defaults.
			const configs = [
				...(sanitized === undefined
					? []
					: [withFrameworkPlugins(sanitized, plugins)]),
				...(plugins.length > 0 ? [withFrameworkPlugins("{}", plugins)] : []),
				undefined,
			].filter((c, i, list) => list.indexOf(c) === i);

			return yield* withTempDir("openaudit-oxlint-", (cwd) =>
				Effect.gen(function* () {
					const base = [
						bin,
						"--format",
						"json",
						"--disable-nested-config",
						"--no-error-on-unmatched-pattern",
						...GENERIC_IGNORES.flatMap((g) => ["--ignore-pattern", g]),
					];
					const attempt = (config: string | undefined) =>
						Effect.gen(function* () {
							const args = [...base];
							if (config !== undefined) {
								const file = join(cwd, "oxlintrc.json");
								yield* Effect.promise(() => writeFile(file, config));
								args.push("-c", file);
							}
							const res = yield* runTool(ctx, [...args, ws.root], cwd, [0, 1]);
							return yield* parseJson(res.stdout, "oxlint");
						});
					// An unusable config (unknown rule, missing plugin): try the next one.
					const firstUsable = ([config, ...rest]: ReadonlyArray<
						string | undefined
					>): ReturnType<typeof attempt> =>
						attempt(config).pipe(
							Effect.catch((err) =>
								rest.length === 0
									? Effect.fail(err)
									: Effect.andThen(
											ctx.log(
												`code.oxlint: config unusable, retrying with ${rest[0] === undefined ? "oxlint's defaults" : "the framework plugins only"}`,
											),
											firstUsable(rest),
										),
							),
						);
					const json = yield* firstUsable(configs);
					return capFindings(
						parseOxlintReport(json, ws.root),
						"code.oxlint/more-findings",
						"oxlint",
					);
				}),
			);
		}),
});

/* -------------------------------------------------------------------------- */
/*                                    biome                                   */
/* -------------------------------------------------------------------------- */

const BIOME_CONFIG_FILES = ["biome.json", "biome.jsonc"];
const BIOME_RELIABILITY_GROUPS = new Set([
	"correctness",
	"suspicious",
	"security",
]);

export const parseBiomeReport = (
	json: unknown,
	root: string,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	const findings: FindingInput[] = [];
	for (const d of arr(json.diagnostics)) {
		if (!isRecord(d)) continue;
		const category = str(d.category) ?? "";
		const parts = category.split("/");
		const isLint = parts[0] === "lint" && parts.length >= 3;
		if (!isLint && category !== "parse" && category !== "plugin") continue;
		const loc = isRecord(d.location) ? d.location : {};
		const start = isRecord(loc.start) ? loc.start : {};
		const message = str(d.message) ?? "Biome diagnostic";
		const group = parts[1] ?? "";
		const rule = parts[2] ?? "";
		const level = str(d.severity);
		const severity: Severity =
			level === "error" || level === "fatal"
				? "medium"
				: level === "warning"
					? "low"
					: "info";
		findings.push({
			ruleId: `code.biome/${isLint ? kebab(rule) : category === "parse" ? "parse-error" : "plugin"}`,
			title: truncate(message, 120),
			severity: isLint ? severity : "medium",
			category:
				!isLint || BIOME_RELIABILITY_GROUPS.has(group)
					? "reliability"
					: "maintainability",
			message: isLint ? `${message} (${group}/${rule})` : message,
			location: {
				file: relPath(root, str(loc.path)),
				line: num(start.line),
				column: num(start.column),
			},
			evidence: scrubLine(truncate(message)),
			remediation: isLint
				? `Fix the code, or tune the rule in biome.json (see https://biomejs.dev/linter/rules/${kebab(rule)}).`
				: "Fix the syntax error so the file can be analysed.",
			references: isLint
				? [`https://biomejs.dev/linter/rules/${kebab(rule)}`]
				: undefined,
			confidence: "high",
			tags: isLint ? [group] : undefined,
		});
	}
	return findings;
};

export const biome: Auditor = defineAuditor({
	id: "code.biome",
	title: "Biome lint",
	description:
		"Runs `biome lint` when the project has a biome.json(c). Biome configuration is data (GritQL plugins are not JavaScript), the config is loaded explicitly from the target root, and the tool runs from a temp directory.",
	categories: ["maintainability", "reliability"],
	targets: ["codebase"],
	engine: "external",
	tool: "biome",
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const all = yield* ws.files;
			if (!BIOME_CONFIG_FILES.some((c) => all.includes(c)))
				return yield* skip("No biome.json or biome.jsonc in the project root");
			const bin = yield* requireTool(
				ctx,
				"biome",
				"Install: npm install -g @biomejs/biome (https://biomejs.dev/guides/getting-started/).",
			);
			return yield* withTempDir("openaudit-biome-", (cwd) =>
				Effect.gen(function* () {
					const res = yield* runTool(
						ctx,
						[
							bin,
							"lint",
							"--reporter=json",
							"--colors=off",
							"--max-diagnostics=none",
							"--no-errors-on-unmatched",
							`--config-path=${ws.root}`,
							// The temp cwd has no .gitignore; look for it in the target.
							`--vcs-root=${ws.root}`,
							ws.root,
						],
						cwd,
						[0, 1],
					);
					const json = yield* parseJson(res.stdout, "biome");
					return capFindings(
						parseBiomeReport(json, ws.root),
						"code.biome/more-findings",
						"biome",
					);
				}),
			);
		}),
});

/* -------------------------------------------------------------------------- */
/*                                   eslint                                   */
/* -------------------------------------------------------------------------- */

const ESLINT_CONFIG = /^eslint\.config\.(?:js|mjs|cjs|ts|mts|cts)$/;

export const parseEslintReport = (
	json: unknown,
	root: string,
): FindingInput[] => {
	const findings: FindingInput[] = [];
	for (const entry of arr(json)) {
		if (!isRecord(entry)) continue;
		const file = relPath(root, str(entry.filePath));
		for (const m of arr(entry.messages)) {
			if (!isRecord(m)) continue;
			const ruleId = str(m.ruleId);
			const message = str(m.message) ?? "ESLint message";
			const level = num(m.severity);
			findings.push({
				ruleId: `code.eslint/${ruleId ? kebab(ruleId) : "parse-error"}`,
				title: truncate(ruleId ? `${ruleId}: ${message}` : message, 120),
				severity: !ruleId || level === 2 ? "medium" : "low",
				category: lintCategory(ruleId),
				message,
				location: { file, line: num(m.line), column: num(m.column) },
				// ESLint's `source` field would echo whole files; only the message is kept.
				evidence: scrubLine(truncate(message)),
				remediation: ruleId
					? "Fix the code, or adjust the rule in the ESLint config."
					: "Fix the syntax error, or check that the parser in the ESLint config supports this file.",
				references:
					ruleId && !ruleId.includes("/")
						? [`https://eslint.org/docs/latest/rules/${ruleId}`]
						: undefined,
				confidence: "high",
				tags: ruleId ? lintTags(ruleId) : ["parse-error"],
			});
		}
	}
	return findings;
};

export const eslint: Auditor = defineAuditor({
	id: "code.eslint",
	title: "ESLint",
	description:
		"Runs the project's own ESLint with its own flat config, for the rules oxlint and Biome cannot cover (custom and project-specific plugins). A finding for the same rule at the same file and line as one from code.oxlint is merged with it. WARNING: eslint.config.* is JavaScript that runs on load, together with every plugin it imports, so this executes code from the audited project. Opt-in only (--only code.eslint); use on code you trust.",
	categories: [
		"maintainability",
		"reliability",
		"accessibility",
		"performance",
	],
	targets: ["codebase"],
	engine: "external",
	tool: "eslint",
	defaultEnabled: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const all = yield* ws.files;
			if (!all.some((p) => ESLINT_CONFIG.test(p)))
				return yield* skip(
					all.some((p) => /^\.eslintrc(?:\.|$)/.test(p))
						? "Only a legacy .eslintrc config was found; ESLint flat config (eslint.config.js) is required"
						: "No eslint.config.* in the project root",
				);
			// The project's own ESLint matches its config and plugins; PATH is the fallback.
			const local = ws.absolute("node_modules/.bin/eslint");
			const bin = (yield* ws.exists("node_modules/.bin/eslint"))
				? local
				: yield* requireTool(
						ctx,
						"eslint",
						"Install the project's dependencies, or: npm install -g eslint.",
					);
			const res = yield* runTool(
				ctx,
				[
					bin,
					"--format",
					"json",
					"--no-error-on-unmatched-pattern",
					...GENERIC_IGNORES.flatMap((g) => ["--ignore-pattern", g]),
					".",
				],
				ws.root,
				[0, 1],
			);
			const json = yield* parseJson(res.stdout, "eslint");
			return capFindings(
				parseEslintReport(json, ws.root),
				"code.eslint/more-findings",
				"eslint",
			);
		}),
});

export const lintJsAuditors: ReadonlyArray<Auditor> = [
	typecheck,
	oxlint,
	biome,
	eslint,
];
