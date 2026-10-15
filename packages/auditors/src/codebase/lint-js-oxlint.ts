import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
	type AuditContext,
	type Auditor,
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
import {
	type AbsolutePath,
	capFindings,
	IGNORE_ARGS,
	isPackageJson,
	type JsonText,
	type RelativePath,
	withTempDir,
} from "./lint-js-shared";
import { lintCategory, lintTags, oxlintEslintId } from "./lint-rules";
import {
	isFixturePath,
	isRecord,
	kebab,
	parseJsonc,
	scrubLine,
	truncate,
} from "./util";

/** The `code.oxlint` auditor, run with a sanitized copy of the project config. */

type JsonObject = Record<string, unknown>;
type PluginName = string;

const OXLINT_CONFIG_FILES = [
	".oxlintrc.json",
	".oxlintrc.jsonc",
	"oxlintrc.json",
];
/**
 * Config keys that are plain data. `jsPlugins` (loads JS), `extends` and
 * `ignorePatterns` (paths relative to the config location) are dropped;
 * `overrides` is kept through `anchoredOverrides`.
 */
const OXLINT_SAFE_KEYS = [
	"categories",
	"plugins",
	"rules",
	"env",
	"globals",
	"settings",
];
/** Override keys that are plain data; `jsPlugins` is dropped here too. */
const OXLINT_SAFE_OVERRIDE_KEYS = ["rules", "plugins", "env", "globals"];
/** Characters that would turn the root path itself into a glob. */
const GLOB_SPECIAL = /[*?[\]{}!\\]/;

/**
 * oxlint's default plugins (`eslint` is always on). A `plugins` list replaces
 * them, so a list that adds plugins has to repeat them.
 */
const OXLINT_DEFAULT_PLUGINS = ["eslint", "typescript", "unicorn", "oxc"];
/** Dependencies that turn on oxlint plugins, which are off by default. */
const REACT_DEPENDENCIES = ["next", "preact", "react", "react-dom"];
const DEPENDENCY_SECTIONS = [
	"dependencies",
	"devDependencies",
	"peerDependencies",
];
const MAX_PACKAGE_JSONS = 200;
const JS_SOURCE = /\.(?:[cm]?[jt]sx?|vue|svelte|astro)$/;

/** Names of every package a package.json depends on. */
const dependencyNames = (text: JsonText): string[] => {
	const pkg = parseJsonc(text);
	if (!isRecord(pkg)) return [];
	return DEPENDENCY_SECTIONS.flatMap((key) => {
		const section = pkg[key];
		return isRecord(section) ? Object.keys(section) : [];
	});
};

/** oxlint plugins for the frameworks the given package.json files depend on. */
export const frameworkPlugins = (
	packageJsons: ReadonlyArray<JsonText>,
): PluginName[] => {
	const deps = new Set(packageJsons.flatMap(dependencyNames));
	const plugins: PluginName[] = [];
	if (REACT_DEPENDENCIES.some((d) => deps.has(d)))
		plugins.push("react", "jsx-a11y");
	if (deps.has("next")) plugins.push("nextjs");
	return plugins;
};

const setsRulesOfHooks = (rules: JsonObject) =>
	"react/rules-of-hooks" in rules || "react-hooks/rules-of-hooks" in rules;

/**
 * Adds framework plugins to a (sanitized) oxlint config that does not choose
 * its own. rules-of-hooks is in oxlint's off-by-default `pedantic` category, so
 * it is turned on unless the config sets it.
 */
export const withFrameworkPlugins = (
	config: JsonText,
	plugins: ReadonlyArray<PluginName>,
): JsonText => {
	if (plugins.length === 0) return config;
	const json = parseJsonc(config);
	if (!isRecord(json) || "plugins" in json) return config;
	const out: JsonObject = {
		...json,
		plugins: [...OXLINT_DEFAULT_PLUGINS, ...plugins],
	};
	const rules = isRecord(json.rules) ? json.rules : {};
	if (plugins.includes("react") && !setsRulesOfHooks(rules))
		out.rules = { ...rules, "react/rules-of-hooks": "error" };
	return JSON.stringify(out);
};

/** The entries of `source` under `keys`, in the order of `keys`. */
const pickKeys = (
	source: JsonObject,
	keys: ReadonlyArray<string>,
): JsonObject => {
	const picked: JsonObject = {};
	for (const key of keys) if (key in source) picked[key] = source[key];
	return picked;
};

const anchorGlob = (pattern: string, base: AbsolutePath) => {
	const glob = pattern.replace(/^\.?\//, "");
	return glob.startsWith("**/") ? glob : `${base}/${glob}`;
};

const anchoredOverride = (
	override: unknown,
	base: AbsolutePath,
): JsonObject | undefined => {
	if (!isRecord(override)) return undefined;
	const files = arr(override.files).filter(
		(f): f is string => typeof f === "string",
	);
	if (files.length === 0) return undefined;
	return {
		files: files.map((f) => anchorGlob(f, base)),
		...pickKeys(override, OXLINT_SAFE_OVERRIDE_KEYS),
	};
};

/**
 * oxlint matches `overrides[].files` relative to the config file, and the
 * sanitized copy lives in a temp dir, so each glob is anchored at the target
 * root (globs that start with `**` match anywhere already). Without overrides,
 * the rules a project turns off for its tests or scripts come back as
 * findings. A root that contains glob characters cannot be anchored; its
 * overrides are dropped.
 */
const anchoredOverrides = (
	overrides: unknown,
	root: AbsolutePath,
): JsonObject[] => {
	if (GLOB_SPECIAL.test(root)) return [];
	const base = root.replace(/\/+$/, "");
	return arr(overrides).flatMap((o) => {
		const safe = anchoredOverride(o, base);
		return safe ? [safe] : [];
	});
};

/** A copy of an oxlint config that cannot load JavaScript. */
export const sanitizeOxlintConfig = (
	text: JsonText,
	root: AbsolutePath,
): JsonText | undefined => {
	const json = parseJsonc(text);
	if (!isRecord(json)) return undefined;
	const safe = pickKeys(json, OXLINT_SAFE_KEYS);
	const overrides = anchoredOverrides(json.overrides, root);
	if (overrides.length > 0) safe.overrides = overrides;
	return JSON.stringify(safe);
};

const OXLINT_CODE = /^([\w@-]+)\((.+)\)$/;
const OXLINT_SEVERITIES = new Map<string, Severity>([
	["error", "medium"],
	["warning", "low"],
]);

/** The plugin and rule of an oxlint code such as `eslint(no-debugger)`. */
interface OxlintRule {
	readonly plugin?: PluginName;
	readonly rule?: string;
}

const oxlintRule = (code: string | undefined): OxlintRule => {
	const m = code ? OXLINT_CODE.exec(code) : null;
	return { plugin: m?.[1], rule: m?.[2] };
};

const oxlintRuleSlug = ({ plugin, rule }: OxlintRule) =>
	rule
		? kebab(plugin === "eslint" ? rule : `${plugin}/${rule}`)
		: "parse-error";

const eslintIdOf = ({ plugin, rule }: OxlintRule) =>
	plugin && rule ? oxlintEslintId(plugin, rule) : undefined;

const oxlintTags = (plugin: PluginName | undefined, eslintId?: string) =>
	plugin ? [plugin, ...(eslintId ? lintTags(eslintId) : [])] : undefined;

/** The span of a diagnostic's first label. */
const labelSpan = (d: JsonObject): JsonObject => {
	const label = arr(d.labels)[0];
	return isRecord(label) && isRecord(label.span) ? label.span : {};
};

const oxlintSeverity = (level: string | undefined): Severity =>
	OXLINT_SEVERITIES.get(level ?? "") ?? "info";

const oxlintFinding = (d: JsonObject, root: AbsolutePath): FindingInput => {
	const parsed = oxlintRule(str(d.code));
	const { plugin, rule } = parsed;
	const span = labelSpan(d);
	const message = str(d.message) ?? "oxlint diagnostic";
	const help = str(d.help);
	const url = str(d.url);
	const eslintId = eslintIdOf(parsed);
	return {
		ruleId: `code.oxlint/${oxlintRuleSlug(parsed)}`,
		title: truncate(rule ? `${rule}: ${message}` : message, 120),
		severity: rule ? oxlintSeverity(str(d.severity)) : "medium",
		category: lintCategory(eslintId ?? rule),
		message: `${message}${help ? ` ${help}` : ""}`,
		location: {
			file: relPath(root, str(d.filename)),
			line: num(span.line),
			column: num(span.column),
		},
		evidence: scrubLine(truncate(message)),
		remediation:
			help ??
			"Fix the reported issue, or configure the rule in .oxlintrc.json if it does not fit your code base.",
		references: url ? [url] : undefined,
		confidence: "high",
		tags: oxlintTags(plugin, eslintId),
	};
};

export const parseOxlintReport = (
	json: unknown,
	root: AbsolutePath,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	return arr(json.diagnostics)
		.filter(isRecord)
		.map((d) => oxlintFinding(d, root));
};

const readOrEmpty = (ws: Workspace, path: RelativePath) =>
	ws.readText(path).pipe(Effect.orElseSucceed(() => ""));

/** The sanitized project config, if the project has a usable one. */
const projectConfig = (ws: Workspace, all: ReadonlyArray<RelativePath>) =>
	Effect.gen(function* () {
		const configPath = OXLINT_CONFIG_FILES.find((c) => all.includes(c));
		const configText = configPath ? yield* readOrEmpty(ws, configPath) : "";
		return configText ? sanitizeOxlintConfig(configText, ws.root) : undefined;
	});

const isProjectPackageJson = (path: RelativePath) =>
	isPackageJson(path) && !isFixturePath(path);

const projectPlugins = (ws: Workspace, all: ReadonlyArray<RelativePath>) =>
	Effect.map(
		Effect.forEach(
			all.filter(isProjectPackageJson).slice(0, MAX_PACKAGE_JSONS),
			(path) => readOrEmpty(ws, path),
			{ concurrency: 8 },
		),
		frameworkPlugins,
	);

/** Tried in order: the project's config, the framework plugins, defaults. */
const candidateConfigs = (
	sanitized: JsonText | undefined,
	plugins: ReadonlyArray<PluginName>,
) =>
	[
		...(sanitized === undefined
			? []
			: [withFrameworkPlugins(sanitized, plugins)]),
		...(plugins.length > 0 ? [withFrameworkPlugins("{}", plugins)] : []),
		undefined,
	].filter((c, i, list) => list.indexOf(c) === i);

/** One oxlint invocation from a temp dir. */
interface OxlintRun {
	readonly ctx: AuditContext;
	readonly ws: Workspace;
	readonly bin: AbsolutePath;
	readonly cwd: AbsolutePath;
}

const runOxlint = (run: OxlintRun, config: JsonText | undefined) =>
	Effect.gen(function* () {
		const args = [
			run.bin,
			"--format",
			"json",
			"--disable-nested-config",
			"--no-error-on-unmatched-pattern",
			...IGNORE_ARGS,
		];
		if (config !== undefined) {
			const file = join(run.cwd, "oxlintrc.json");
			yield* Effect.promise(() => writeFile(file, config));
			args.push("-c", file);
		}
		const res = yield* runTool(
			run.ctx,
			[...args, run.ws.root],
			run.cwd,
			[0, 1],
		);
		return yield* parseJson(res.stdout, "oxlint");
	});

const fallbackName = (config: JsonText | undefined) =>
	config === undefined ? "oxlint's defaults" : "the framework plugins only";

/** An unusable config (unknown rule, missing plugin): try the next one. */
const firstUsableConfig = (
	run: OxlintRun,
	[config, ...rest]: ReadonlyArray<JsonText | undefined>,
): ReturnType<typeof runOxlint> =>
	runOxlint(run, config).pipe(
		Effect.catch((err) =>
			rest.length === 0
				? Effect.fail(err)
				: Effect.andThen(
						run.ctx.log(
							`code.oxlint: config unusable, retrying with ${fallbackName(rest[0])}`,
						),
						firstUsableConfig(run, rest),
					),
		),
	);

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
			if (!all.some((p) => JS_SOURCE.test(p)))
				return yield* skip("No JavaScript or TypeScript files");
			const sanitized = yield* projectConfig(ws, all);
			const plugins = yield* projectPlugins(ws, all);
			const configs = candidateConfigs(sanitized, plugins);
			return yield* withTempDir("openaudit-oxlint-", (cwd) =>
				firstUsableConfig({ ctx, ws, bin, cwd }, configs).pipe(
					Effect.map((json) =>
						capFindings(
							parseOxlintReport(json, ws.root),
							"code.oxlint/more-findings",
							"oxlint",
						),
					),
				),
			);
		}),
});
