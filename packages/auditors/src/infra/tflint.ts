import { mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
	type AuditContext,
	AuditorError,
	type Category,
	defineAuditor,
	type FindingInput,
	requireTool,
	type Severity,
	skip,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import { isRecord, kebab, scrubLine, truncate } from "../codebase/util";
import { arr, num, parseJson, relPath, runTool, str } from "../tool";
import { readOptional, targetFiles } from "./shared";

const ID = "iac.tflint";
const TF_RE = /\.tf(\.json)?$/;

/**
 * Cloud rulesets (invalid instance types, regions, deprecated resources) that
 * openaudit enables when their binaries sit in the trusted plugin directory.
 * The project can never add plugins: its `.tflint.hcl` is not loaded.
 */
export const TFLINT_RULESETS = {
	aws: /\b(resource|data)\s+"aws_/,
	azurerm: /\b(resource|data)\s+"azurerm_/,
	google: /\b(resource|data)\s+"google_/,
} as const;
export type TflintRuleset = keyof typeof TFLINT_RULESETS;

/** Where the Docker image installs the pinned ruleset plugins. */
export const DEFAULT_TFLINT_PLUGIN_DIR = "/opt/tflint-plugins";

type DirPath = string;
type FilePath = string;
type RootDir = DirPath;
type RuleName = string;
type RuleLevel = string;
type Ruleset = string;
type Url = string;
type HclText = string;

const hclString = (s: string) =>
	JSON.stringify(s)
		.replace(/\$\{/g, () => "$${")
		.replace(/%\{/g, () => "%%{");

/**
 * The only config tflint gets: the bundled Terraform ruleset (recommended
 * preset) plus the given cloud rulesets, all from `pluginDir`. Setting
 * `plugin_dir` here means tflint never looks in the target's
 * `./.tflint.d/plugins`.
 */
export const tflintConfig = (
	pluginDir: DirPath,
	rulesets: ReadonlyArray<TflintRuleset>,
): string =>
	[
		"config {",
		`  plugin_dir       = ${hclString(pluginDir)}`,
		'  call_module_type = "none"',
		"}",
		"",
		'plugin "terraform" {',
		"  enabled = true",
		'  preset  = "recommended"',
		"}",
		...rulesets.flatMap((r) => [
			"",
			`plugin "${r}" {`,
			"  enabled = true",
			"}",
		]),
		"",
	].join("\n");

const SUPPLY_CHAIN: Record<string, Severity> = {
	terraform_module_pinned_source: "medium",
	terraform_module_version: "medium",
	terraform_required_providers: "low",
};

const RELIABILITY = new Set([
	"terraform_map_duplicate_keys",
	"terraform_empty_list_equality",
	"terraform_workspace_remote",
	"terraform_json_syntax",
]);

const REMEDIATION: Record<string, string> = {
	terraform_module_pinned_source:
		"Pin the git or mercurial module source to a tag or commit (?ref=v1.2.3), so a moved branch cannot change what is deployed.",
	terraform_module_version:
		"Set `version` on registry module calls (an exact version or a bounded constraint), so a new release is not pulled in unreviewed.",
	terraform_required_providers:
		"Declare every provider in `terraform { required_providers { ... } }` with a source and a version constraint.",
	terraform_required_version:
		"Set `required_version` in the `terraform` block to the Terraform versions the configuration is tested with.",
	terraform_typed_variables: "Give the variable an explicit `type`.",
	terraform_unused_declarations:
		"Remove the unused variable, local or data source, or use it.",
	terraform_deprecated_interpolation:
		// biome-ignore lint/suspicious/noTemplateCurlyInString: Terraform interpolation syntax
		'Use the expression directly instead of wrapping it in "${...}".',
	terraform_deprecated_index:
		"Use [index] instead of the legacy .index syntax.",
	terraform_deprecated_lookup:
		"Use map[key], or lookup() with a default value.",
	terraform_map_duplicate_keys:
		"Remove the duplicate map key; only the last value is kept.",
	terraform_empty_list_equality:
		"Compare length(x) == 0 instead of x == []; the comparison is otherwise always false for non-list values.",
};

const RULESET_DOCS = (ruleset: Ruleset) =>
	`https://github.com/terraform-linters/tflint-ruleset-${ruleset}/blob/master/docs/rules/README.md`;

const rulesetOf = (rule: RuleName) => {
	const prefix = rule.split("_")[0] ?? "";
	return prefix in TFLINT_RULESETS || prefix === "terraform"
		? prefix
		: undefined;
};

/** Source line lookup for evidence; `undefined` when the file was not read. */
export type SourceLookup = (file: string) => string | undefined;

type Json = Record<string, unknown>;

interface ReportContext {
	readonly root: RootDir;
	readonly source: SourceLookup;
}

interface Location {
	readonly file?: string;
	readonly line?: number;
	readonly column?: number;
}

const record = (v: unknown): Json => (isRecord(v) ? v : {});

const locationOf = (root: RootDir, range: Json): Location => {
	const file = relPath(root, str(range.filename));
	const start = record(range.start);
	const line = num(start.line);
	return {
		file,
		line: line && line > 0 ? line : undefined,
		column: num(start.column) || undefined,
	};
};

const evidenceAt = (source: SourceLookup, { file, line }: Location) => {
	if (!file || line === undefined) return undefined;
	const text = source(file)?.split("\n")[line - 1]?.trim();
	return text ? scrubLine(truncate(text)) : undefined;
};

const categoryOf = (name: RuleName, level: RuleLevel): Category => {
	if (name in SUPPLY_CHAIN) return "supply-chain";
	if (level === "error" || RELIABILITY.has(name)) return "reliability";
	return "best-practices";
};

const levelSeverity = (name: RuleName, level: RuleLevel): Severity => {
	if (level === "error") return "high";
	if (RELIABILITY.has(name)) return "medium";
	return level === "notice" ? "info" : "low";
};

const remediationOf = (name: RuleName, link: Url | undefined): string =>
	REMEDIATION[name] ??
	(/_invalid_/.test(name)
		? `Use a value the provider accepts; Terraform fails at plan or apply otherwise. See ${link ?? "the tflint rule documentation"}.`
		: `See the tflint rule documentation${link ? `: ${link}` : "."}`);

/** The rule's own docs link, else its ruleset's rule list. */
const linkOf = (rule: Json, ruleset: Ruleset | undefined): Url | undefined =>
	str(rule.link) || (ruleset ? RULESET_DOCS(ruleset) : undefined);

const issueFinding = (raw: unknown, ctx: ReportContext): FindingInput[] => {
	if (!isRecord(raw)) return [];
	const rule = record(raw.rule);
	const name = str(rule.name);
	if (!name) return [];
	const level = str(rule.severity) ?? "warning";
	const ruleset = rulesetOf(name);
	const location = locationOf(ctx.root, record(raw.range));
	const link = linkOf(rule, ruleset);
	const message = str(raw.message) ?? name;
	return [
		{
			ruleId: `${ID}/${kebab(name)}`,
			title: `${name}: ${truncate(message, 120)}`,
			severity: SUPPLY_CHAIN[name] ?? levelSeverity(name, level),
			category: categoryOf(name, level),
			message: truncate(message, 300),
			remediation: remediationOf(name, link),
			location,
			evidence: evidenceAt(ctx.source, location),
			references: link ? [link] : undefined,
			tags: ["tflint", "terraform", name, ...(ruleset ? [ruleset] : [])],
		},
	];
};

const errorMessage = (raw: Json) => str(raw.message) ?? "unknown error";

/** An HCL error that points into a file. */
const syntaxErrorFinding = (raw: Json, ctx: ReportContext): FindingInput => {
	const message = errorMessage(raw);
	const location = locationOf(ctx.root, record(raw.range));
	const summary = str(raw.summary);
	return {
		ruleId: `${ID}/syntax-error`,
		title: summary
			? `Terraform syntax error: ${summary}`
			: "Terraform syntax error",
		severity: "high",
		category: "reliability",
		message: truncate(summary ? `${summary}: ${message}` : message, 300),
		remediation:
			"Fix the syntax error; Terraform cannot load the module, and tflint could not lint it.",
		location,
		evidence: evidenceAt(ctx.source, location),
		references: ["https://developer.hashicorp.com/terraform/language/syntax"],
		tags: ["tflint", "terraform", "syntax-error"],
	};
};

const hasRange = (raw: Json) => isRecord(raw.range);

/**
 * Parses `tflint --format json` output. Issues become findings; errors that
 * point into a file (HCL syntax errors) become `syntax-error` findings, while
 * errors without a range are returned separately as tool failures.
 */
export const parseTflintReport = (
	json: unknown,
	root: RootDir,
	source: SourceLookup = () => undefined,
): { findings: FindingInput[]; errors: string[] } => {
	if (!isRecord(json)) return { findings: [], errors: [] };
	const ctx: ReportContext = { root, source };
	const errors = arr(json.errors).filter(isRecord);
	return {
		findings: [
			...arr(json.issues).flatMap((raw) => issueFinding(raw, ctx)),
			...errors.filter(hasRange).map((raw) => syntaxErrorFinding(raw, ctx)),
		],
		errors: errors.filter((raw) => !hasRange(raw)).map(errorMessage),
	};
};

/** True when `path` is an existing regular file. */
const isFile = (path: FilePath) =>
	Effect.promise(() =>
		stat(path).then(
			(s) => s.isFile(),
			() => false,
		),
	);

type Texts = ReadonlyMap<string, string>;

/** The readable target files' text, keyed by path. */
const readTexts = (ws: Workspace, files: ReadonlyArray<string>) =>
	Effect.gen(function* () {
		const texts = new Map<string, string>();
		for (const file of files) {
			const text = yield* readOptional(ws, file);
			if (text !== undefined) texts.set(file, text);
		}
		return texts;
	});

const usesProvider = (texts: Texts, used: RegExp) =>
	[...texts.values()].some((t) => used.test(t));

/** Cloud rulesets the code uses and whose plugin is installed in `pluginDir`. */
const usedRulesets = (texts: Texts, pluginDir: DirPath) =>
	Effect.gen(function* () {
		const rulesets: TflintRuleset[] = [];
		for (const [name, used] of Object.entries(TFLINT_RULESETS) as Array<
			[TflintRuleset, RegExp]
		>) {
			if (
				usesProvider(texts, used) &&
				(yield* isFile(join(pluginDir, `tflint-ruleset-${name}`)))
			)
				rulesets.push(name);
		}
		return rulesets;
	});

const makeConfigDir = Effect.tryPromise({
	try: () => mkdtemp(join(tmpdir(), "openaudit-tflint-")),
	catch: (cause) =>
		new AuditorError({
			message: "Could not create a TFLint config dir",
			cause,
		}),
});

const writeConfig = (config: FilePath, text: HclText) =>
	Effect.tryPromise({
		try: () => writeFile(config, text, { mode: 0o600 }),
		catch: (cause) =>
			new AuditorError({
				message: "Could not write the TFLint config",
				cause,
			}),
	});

interface TflintRun {
	readonly ctx: AuditContext;
	readonly bin: string;
	readonly config: FilePath;
	readonly root: RootDir;
	readonly filter: ReadonlyArray<string>;
}

/** Only the target file, for single-file targets. */
const fileFilter = (ctx: AuditContext): string[] =>
	ctx.target.type === "file" && ctx.target.file
		? [`--filter=${ctx.target.file.split("/").pop()}`]
		: [];

/** Runs tflint in one module directory and parses its JSON report. */
const lintDir = (run: TflintRun, dir: DirPath) =>
	runTool(
		run.ctx,
		[
			run.bin,
			`--config=${run.config}`,
			// "./" plus "=" keep hostile directory names from being read as flags.
			`--chdir=./${dir}`,
			"--format=json",
			"--call-module-type=none",
			"--no-color",
			...run.filter,
		],
		run.root,
		// 2 = issues found; 1 = errors (syntax errors are still JSON).
		[0, 1, 2],
	).pipe(
		Effect.flatMap((res) =>
			res.stdout.trim()
				? parseJson(res.stdout, "tflint")
				: Effect.fail(
						new AuditorError({
							message: `tflint produced no output in ${dir}: ${truncate(res.stderr, 300)}`,
						}),
					),
		),
	);

/** Findings from every report; the first tool error fails the audit. */
const collectFindings = (
	reports: ReadonlyArray<unknown>,
	root: RootDir,
	texts: Texts,
) =>
	Effect.gen(function* () {
		const findings: FindingInput[] = [];
		for (const json of reports) {
			const parsed = parseTflintReport(json, root, (f) => texts.get(f));
			if (parsed.errors.length > 0)
				return yield* new AuditorError({
					message: `tflint failed: ${truncate(parsed.errors[0] ?? "", 300)}`,
				});
			// tflint follows symlinked .tf files, which the Workspace never reads;
			// their messages could quote content from outside the target.
			findings.push(
				...parsed.findings.filter(
					(f) => !f.location?.file || texts.has(f.location.file),
				),
			);
		}
		return findings;
	});

/** Wraps tflint, a Terraform linter, with an openaudit-owned config. */
export const tflint = defineAuditor({
	id: ID,
	title: "TFLint",
	description: `Runs TFLint over every Terraform module directory with the bundled Terraform ruleset (recommended preset): unpinned module sources and versions, missing provider constraints, deprecated syntax, unused declarations, syntax errors. The project's .tflint.hcl and .tflint.d plugins are never loaded and \`tflint --init\` never runs: openaudit passes its own config. The AWS, Azure and Google rulesets (invalid instance types, sizes, regions) are enabled when their plugin binaries are installed in OPENAUDIT_TFLINT_PLUGIN_DIR (default ${DEFAULT_TFLINT_PLUGIN_DIR}, as in the Docker image) and the code uses that provider. Module calls are not followed (--call-module-type=none), so nothing is downloaded.`,
	categories: ["reliability", "best-practices", "supply-chain"],
	targets: ["iac"],
	engine: "external",
	tool: "tflint",
	run: (ctx) =>
		Effect.gen(function* () {
			const { ws, files } = yield* targetFiles(ctx, TF_RE);
			if (files.length === 0) return yield* skip("No Terraform files found");
			const bin = yield* requireTool(
				ctx,
				"tflint",
				"Install: brew install tflint or download a release from https://github.com/terraform-linters/tflint/releases (https://github.com/terraform-linters/tflint#installation).",
			);

			const texts = yield* readTexts(ws, files);
			const pluginDir =
				process.env.OPENAUDIT_TFLINT_PLUGIN_DIR || DEFAULT_TFLINT_PLUGIN_DIR;
			const rulesets = yield* usedRulesets(texts, pluginDir);

			const configDir = yield* makeConfigDir;
			const config = join(configDir, "tflint.hcl");
			// Without cloud rulesets, point plugin_dir at the empty temp dir: the
			// bundled Terraform ruleset is then always the one that runs.
			const text = tflintConfig(
				rulesets.length > 0 ? pluginDir : configDir,
				rulesets,
			);

			const dirs = [...new Set(files.map((f) => dirname(f)))].sort();
			const run: TflintRun = {
				ctx,
				bin,
				config,
				root: ws.root,
				filter: fileFilter(ctx),
			};
			const reports = yield* writeConfig(config, text).pipe(
				Effect.andThen(
					Effect.forEach(dirs, (dir) => lintDir(run, dir), { concurrency: 4 }),
				),
				Effect.ensuring(
					Effect.promise(() => rm(configDir, { recursive: true, force: true })),
				),
			);
			return yield* collectFindings(reports, ws.root, texts);
		}),
});
