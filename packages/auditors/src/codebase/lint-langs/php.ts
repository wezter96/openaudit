import { lstat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
	type AuditContext,
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

import { arr, num, parseJson, str } from "../../tool";
import { extOf, isRecord, kebab, truncate } from "../util";
import {
	dedupe,
	type FilePath,
	inRoot,
	manifestDirs,
	run,
	withTempDir,
} from "./shared";

/* -------------------------------------------------------------------------- */
/*                                  PHPStan                                   */
/* -------------------------------------------------------------------------- */

const ID = "code.phpstan";

/** Level 5 adds argument type checks; 6+ mostly asks for missing typehints. */
export const PHPSTAN_DEFAULT_LEVEL = 5;

/** The integer levels PHPStan accepts, 0 to 10. */
const PHPSTAN_LEVELS = new Set<unknown>(
	Array.from({ length: 11 }, (_, i) => i),
);

/** `settings["code.phpstan"].level`: an integer 0-10 or "max". */
export const phpstanLevel = (
	settings: Record<string, unknown> | undefined,
): string => {
	const level = settings?.level;
	if (level === "max") return "max";
	return String(PHPSTAN_LEVELS.has(level) ? level : PHPSTAN_DEFAULT_LEVEL);
};

/** A NEON double-quoted string; `%` would otherwise expand DI parameters. */
const neonString = (s: string) => JSON.stringify(s).replaceAll("%", "%%");

/**
 * The only config PHPStan sees: a level, the files to analyse and directories
 * to scan statically for symbols. No includes, bootstrapFiles or services, so
 * nothing in it can execute PHP.
 */
export const phpstanNeon = (opts: {
	level: string;
	tmpDir: string;
	paths: ReadonlyArray<string>;
	scanDirectories: ReadonlyArray<string>;
}): string => {
	const list = (key: string, items: ReadonlyArray<string>) =>
		items.length === 0
			? ""
			: `\t${key}:\n${items.map((i) => `\t\t- ${neonString(i)}\n`).join("")}`;
	return [
		"parameters:\n",
		`\tlevel: ${opts.level}\n`,
		`\ttmpDir: ${neonString(opts.tmpDir)}\n`,
		list("paths", opts.paths),
		list("scanDirectories", opts.scanDirectories),
	].join("");
};

/** Missing symbols: usually dependencies that are not installed or loaded. */
const PHPSTAN_SYMBOL_NOT_FOUND = new Set([
	"class.notFound",
	"interface.notFound",
	"trait.notFound",
	"enum.notFound",
	"function.notFound",
	"constant.notFound",
]);
/** Typehint, PHPDoc and dead-code hygiene rather than likely bugs. */
const PHPSTAN_HYGIENE_GROUPS = new Set([
	"missingType",
	"phpDoc",
	"deadCode",
	"varTag",
	"paramTag",
]);
const PHPSTAN_HYGIENE_KINDS = new Set([
	"unused",
	"unusedType",
	"onlyWritten",
	"onlyRead",
	"alwaysTrue",
	"alwaysFalse",
	"alreadyNarrowedType",
]);

const phpstanClass = (
	identifier: string | undefined,
): { category: Category; severity: Severity } => {
	if (identifier === "phpstan.parse")
		return { category: "reliability", severity: "high" };
	if (identifier && PHPSTAN_SYMBOL_NOT_FOUND.has(identifier))
		return { category: "reliability", severity: "low" };
	const [group = "", kind = ""] = identifier?.split(".") ?? [];
	if (PHPSTAN_HYGIENE_GROUPS.has(group) || PHPSTAN_HYGIENE_KINDS.has(kind))
		return { category: "maintainability", severity: "low" };
	return { category: "reliability", severity: "medium" };
};

const phpstanRemediation = (missing: boolean, tip: string | undefined) =>
	[
		missing
			? "The project's dependencies are not loaded, so this may be a symbol from an uninstalled package."
			: "Fix the reported type or logic error, or suppress a justified false positive with `// @phpstan-ignore <identifier>` and a reason.",
		tip ? `Tip: ${tip.replace(/<[^>]*>/g, "")}` : "",
	]
		.filter(Boolean)
		.join(" ");

const phpstanMessage = (
	m: Record<string, unknown>,
	file: FilePath,
): FindingInput => {
	const message = str(m.message) ?? "PHPStan error";
	const identifier = str(m.identifier);
	const { category, severity } = phpstanClass(identifier);
	const missing =
		identifier !== undefined && PHPSTAN_SYMBOL_NOT_FOUND.has(identifier);
	return {
		ruleId: `${ID}/${identifier ? kebab(identifier) : "error"}`,
		title: truncate(message.replace(/\.$/, ""), 100),
		severity,
		category,
		message: identifier ? `${message} [${identifier}]` : message,
		location: { file, line: num(m.line) },
		remediation: phpstanRemediation(missing, str(m.tip)),
		references: identifier
			? [`https://phpstan.org/error-identifiers/${identifier}`]
			: [],
		confidence: missing ? "low" : "high",
		tags: ["php", ...(identifier ? [kebab(identifier)] : [])],
	};
};

const phpstanFile = (
	path: FilePath,
	entry: unknown,
	root: FilePath,
): FindingInput[] => {
	const file = inRoot(root, path);
	if (!file || !isRecord(entry)) return [];
	return arr(entry.messages).flatMap((m): FindingInput[] =>
		isRecord(m) ? [phpstanMessage(m, file)] : [],
	);
};

/** Parses `phpstan analyse --error-format=json`; general (non-file) errors are dropped. */
export const parsePhpstanReport = (
	json: unknown,
	root: FilePath,
): FindingInput[] => {
	if (!isRecord(json) || !isRecord(json.files)) return [];
	return dedupe(
		Object.entries(json.files).flatMap(([path, entry]) =>
			phpstanFile(path, entry, root),
		),
	);
};

/** A real (not symlinked) `vendor` directory next to a composer.json. */
const vendorDirs = (ws: Workspace, dirs: ReadonlyArray<string>) =>
	Effect.gen(function* () {
		const out: string[] = [];
		for (const dir of dirs) {
			const vendor = ws.absolute(dir ? `${dir}/vendor` : "vendor");
			const real = yield* Effect.promise(() =>
				lstat(vendor).then(
					(s) => s.isDirectory(),
					() => false,
				),
			);
			if (real) out.push(vendor);
		}
		return out;
	});

/**
 * PHPStan treats paths with a backslash as Windows separators, and a path it
 * cannot find aborts the whole run.
 */
const analysable = (path: FilePath) => !/[\\\r\n]/.test(path);

interface PhpstanRun {
	readonly ctx: AuditContext;
	readonly bin: FilePath;
	readonly tmp: FilePath;
	readonly level: string;
	readonly scanDirectories: ReadonlyArray<FilePath>;
	readonly root: FilePath;
}

const writeConfig = (config: FilePath, neon: string) =>
	Effect.tryPromise({
		try: () => writeFile(config, neon),
		catch: (cause) =>
			new AuditorError({
				message: "Could not write the PHPStan config",
				cause,
			}),
	});

const analyse = (
	opts: PhpstanRun,
	paths: ReadonlyArray<FilePath>,
	pass: number,
) =>
	Effect.gen(function* () {
		const { ctx, bin, tmp } = opts;
		const config = join(tmp, `phpstan-${pass}.neon`);
		yield* writeConfig(
			config,
			phpstanNeon({
				level: opts.level,
				tmpDir: join(tmp, "cache"),
				paths,
				scanDirectories: opts.scanDirectories,
			}),
		);
		const res = yield* run(
			ctx,
			[
				bin,
				"analyse",
				"-c",
				config,
				"--error-format=json",
				"--no-progress",
				"--no-interaction",
				"--memory-limit=2G",
			],
			// 1 = errors found. The temp cwd keeps PHPStan from finding the
			// project's config and Composer autoloader.
			{ cwd: tmp, okCodes: [0, 1] },
		);
		if (!res.stdout.trim())
			return yield* new AuditorError({
				message: `phpstan exited with code ${res.code}: ${truncate(res.stderr, 300)}`,
			});
		return parsePhpstanReport(
			yield* parseJson(res.stdout, "phpstan"),
			opts.root,
		);
	});

/** A parse error makes PHPStan stop before analysing anything else. */
const analyseWithRetry = (
	opts: PhpstanRun,
	sources: ReadonlyArray<FilePath>,
	absolute: (file: FilePath) => FilePath,
) =>
	Effect.gen(function* () {
		const first = yield* analyse(opts, sources, 1);
		const parse = first.filter((f) => f.ruleId === `${ID}/phpstan-parse`);
		if (parse.length === 0) return first;
		const broken = new Set(parse.map((f) => absolute(f.location?.file ?? "")));
		const rest = sources.filter((s) => !broken.has(s));
		if (rest.length === 0) return parse;
		return [...parse, ...(yield* analyse(opts, rest, 2))];
	});

export const phpstan = defineAuditor({
	id: ID,
	title: "PHPStan PHP static analysis",
	description: `Runs PHPStan 2 over PHP files at level ${PHPSTAN_DEFAULT_LEVEL} (settings["${ID}"].level: 0-10 or "max"). The project's phpstan.neon(.dist) is ignored because it can declare bootstrapFiles, includes and extensions that execute PHP; PHPStan instead gets a generated config listing the files, and runs from an empty temp directory so it never requires the project's Composer autoloader (vendor/autoload.php), which it otherwise loads from the working directory. Analysis is then purely static: no target code runs. An installed vendor/ directory is only scanned statically for symbols; without one, unknown classes and functions are reported with low confidence. Files that do not parse are reported and the rest re-analysed.`,
	categories: ["reliability", "maintainability"],
	targets: ["codebase"],
	engine: "external",
	tool: "phpstan",
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const files = yield* ws.files;
			const sources = files
				.filter((f) => extOf(f) === "php")
				.map((f) => ws.absolute(f))
				.filter(analysable);
			if (sources.length === 0)
				return yield* skip("No PHP files in the workspace");
			const bin = yield* requireTool(
				ctx,
				"phpstan",
				"Install: download phpstan.phar from https://github.com/phpstan/phpstan/releases (needs PHP 7.4+) or composer global require phpstan/phpstan.",
			);
			const level = phpstanLevel(ctx.options.settings?.[ID]);
			const scanDirectories = yield* vendorDirs(
				ws,
				manifestDirs(files, "composer.json", true),
			);
			return yield* withTempDir((tmp) =>
				analyseWithRetry(
					{ ctx, bin, tmp, level, scanDirectories, root: ws.root },
					sources,
					(file) => ws.absolute(file),
				),
			);
		}),
});
