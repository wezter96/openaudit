import { posix } from "node:path";
import {
	defineAuditor,
	type FindingInput,
	requireWorkspace,
} from "@openaudit/core";
import { Effect } from "effect";

import {
	baseName,
	extOf,
	isFixturePath,
	isGeneratedPath,
	isRecord,
	isSourcePath,
	isTestPath,
	languageOf,
	lineLocator,
	parseJsonc,
	readTextFiles,
	type SourceFile,
} from "./util";

const LARGE_FILE_LINES = 1000;
const DEEP_NESTING = 5;
const ANY_THRESHOLD = 10;

const CONTROL_KEYWORD =
	/\b(?:if|else|for|foreach|while|switch|try|catch|finally|do|case|select|match|unless|until)\b/;

const stripCode = (line: string) =>
	line
		.replace(/\\./g, "")
		.replace(/"[^"]*"|'[^']*'|`[^`]*`/g, '""')
		.replace(/\/\/.*$/, "");

export interface Nesting {
	readonly depth: number;
	readonly line: number;
}

/** Whether the `{` at `index` opens a control-flow block (keyword before it, or on the previous line). */
const isControlBrace = (code: string, index: number, prevCode: string) => {
	const before = code.slice(0, index);
	return (
		CONTROL_KEYWORD.test(before) ||
		(before.trim() === "" && CONTROL_KEYWORD.test(prevCode))
	);
};

/** Deepest control-flow nesting in a brace language (best-effort). */
export const braceNesting = (text: string): Nesting => {
	const stack: boolean[] = [];
	let controls = 0;
	let max: Nesting = { depth: 0, line: 0 };
	let inComment = false;
	let prevCode = "";
	const lines = text.split("\n");
	for (let n = 0; n < lines.length; n++) {
		let code = stripCode(lines[n] ?? "");
		if (inComment) {
			const end = code.indexOf("*/");
			if (end === -1) continue;
			code = code.slice(end + 2);
			inComment = false;
		}
		code = code.replace(/\/\*.*?\*\//g, "");
		const open = code.indexOf("/*");
		if (open !== -1) {
			code = code.slice(0, open);
			inComment = true;
		}
		for (let i = 0; i < code.length; i++) {
			const ch = code[i];
			if (ch === "}") {
				if (stack.pop()) controls--;
				continue;
			}
			if (ch !== "{") continue;
			const isControl = isControlBrace(code, i, prevCode);
			stack.push(isControl);
			if (!isControl) continue;
			controls++;
			if (controls > max.depth) max = { depth: controls, line: n + 1 };
		}
		if (code.trim()) prevCode = code;
	}
	return max;
};

/** Deepest control-flow nesting in Python (indentation-based). */
export const pythonNesting = (text: string): Nesting => {
	const stack: Array<{ indent: number; control: boolean }> = [];
	let max: Nesting = { depth: 0, line: 0 };
	const lines = text.split("\n");
	for (let n = 0; n < lines.length; n++) {
		const raw = (lines[n] ?? "").replace(/\t/g, "    ");
		if (!raw.trim() || raw.trimStart().startsWith("#")) continue;
		const indent = raw.length - raw.trimStart().length;
		while (stack.length && (stack[stack.length - 1]?.indent ?? 0) >= indent)
			stack.pop();
		const control =
			/^\s*(?:if|elif|else|for|async\s+for|while|with|async\s+with|try|except|finally|match|case)\b.*:\s*(?:#.*)?$/.test(
				raw,
			);
		const block =
			control || /^\s*(?:def|async\s+def|class)\b.*:\s*(?:#.*)?$/.test(raw);
		if (!block) continue;
		stack.push({ indent, control });
		const depth = stack.filter((s) => s.control).length;
		if (depth > max.depth) max = { depth, line: n + 1 };
	}
	return max;
};

const nestingOf = (file: SourceFile): Nesting | undefined => {
	const lang = languageOf(file.path);
	if (lang === "python") return pythonNesting(file.text);
	if (lang === "ruby" || lang === undefined) return undefined;
	return braceNesting(file.text);
};

const TODO = /(?:\/\/|#|\/\*|\*|<!--|--)\s*(TODO|FIXME|HACK|XXX)\b/g;
const TS_IGNORE = /(?:\/\/|\/\*+|^[ \t]*\*)[ \t]*@ts-ignore\b/gm;
const TS_EXPECT_ERROR = /(?:\/\/|\/\*+|^[ \t]*\*)[ \t]*@ts-expect-error\b/gm;
/** `@ts-nocheck` only counts in the leading comments, as TypeScript does. */
const TS_NOCHECK = /^[ \t]*(?:\/\/|\/\*+)[ \t]*@ts-nocheck\b/m;
/** Minimum `@ts-expect-error` count before the ignore/expect-error ratio is reported. */
const TS_IGNORE_RATIO_MIN = 5;
const EXPLICIT_ANY = /:\s*any\b(?!\s*[(.])|\bas\s+any\b|<any>|\bany\[\]/g;

export interface QualityStats {
	readonly todos: Map<string, number>;
	readonly todoFiles: Map<string, number>;
	readonly tsIgnores: Array<{ path: string; line: number }>;
	/** Number of `@ts-expect-error` directives. */
	tsExpectErrors: number;
	readonly anyCount: Map<string, number>;
}

/** Per-file findings (large files, deep nesting) and aggregated counters. */
export const scanQualityFile = (
	file: SourceFile,
	stats: QualityStats,
): FindingInput[] => {
	const { path, text } = file;
	const findings: FindingInput[] = [];
	const lines = text.split("\n").length;
	if (lines > LARGE_FILE_LINES)
		findings.push({
			ruleId: "code.quality/large-file",
			title: `Large file (${lines} lines)`,
			severity: "low",
			category: "maintainability",
			message: `${path} has ${lines} lines. Very large files are hard to review, test and change safely.`,
			location: { file: path },
			remediation:
				"Split it into smaller modules with a single responsibility each.",
			confidence: "high",
		});

	const nesting = nestingOf(file);
	if (nesting && nesting.depth >= DEEP_NESTING)
		findings.push({
			ruleId: "code.quality/deep-nesting",
			title: `Deeply nested control flow (${nesting.depth} levels)`,
			severity: "low",
			category: "maintainability",
			message: `Control flow in ${path} nests ${nesting.depth} levels deep, which makes the logic hard to follow and test.`,
			location: { file: path, line: nesting.line },
			remediation:
				"Use early returns/guard clauses, extract helper functions, or replace nested conditionals with lookup tables.",
			references: [
				"https://refactoring.guru/replace-nested-conditional-with-guard-clauses",
			],
			confidence: "low",
		});

	let todoCount = 0;
	for (const m of text.matchAll(TODO)) {
		const tag = m[1] ?? "TODO";
		stats.todos.set(tag, (stats.todos.get(tag) ?? 0) + 1);
		todoCount++;
	}
	if (todoCount) stats.todoFiles.set(path, todoCount);

	const ext = extOf(path);
	if (["ts", "tsx", "mts", "cts"].includes(ext)) {
		const lineOf = lineLocator(text);
		for (const m of text.matchAll(TS_IGNORE))
			stats.tsIgnores.push({ path, line: lineOf(m.index ?? 0) });
		stats.tsExpectErrors += [...text.matchAll(TS_EXPECT_ERROR)].length;
		const nocheck = TS_NOCHECK.exec(text);
		if (nocheck)
			findings.push({
				ruleId: "code.quality/ts-nocheck",
				title: "File opts out of type checking with @ts-nocheck",
				severity: "medium",
				category: "reliability",
				message: `${path} starts with @ts-nocheck, so TypeScript reports no errors anywhere in the file.`,
				location: { file: path, line: lineOf(nocheck.index) },
				evidence: nocheck[0].trim(),
				remediation:
					"Remove @ts-nocheck and fix the errors, or narrow the suppression to individual lines with @ts-expect-error and a comment.",
				references: [
					"https://www.typescriptlang.org/docs/handbook/type-checking-javascript-files.html#ts-nocheck-in-typescript-files",
				],
				confidence: "high",
			});
		const anys = [...text.matchAll(EXPLICIT_ANY)].length;
		if (anys) stats.anyCount.set(path, anys);
	}
	return findings;
};

const topFiles = (counts: ReadonlyMap<string, number>, n = 3) =>
	[...counts.entries()]
		.sort((a, b) => b[1] - a[1])
		.slice(0, n)
		.map(([p, c]) => `${p} (${c})`)
		.join(", ");

export const aggregateFindings = (stats: QualityStats): FindingInput[] => {
	const findings: FindingInput[] = [];
	const totalTodos = [...stats.todos.values()].reduce((a, b) => a + b, 0);
	if (totalTodos > 0) {
		const breakdown = [...stats.todos.entries()]
			.map(([t, c]) => `${c} ${t}`)
			.join(", ");
		const top = [...stats.todoFiles.entries()].sort((a, b) => b[1] - a[1])[0];
		findings.push({
			ruleId: "code.quality/todo-comments",
			title: `${totalTodos} TODO/FIXME/HACK comments`,
			severity: "info",
			category: "maintainability",
			message: `Found ${breakdown} across ${stats.todoFiles.size} files (most in ${topFiles(stats.todoFiles)}).`,
			location: top ? { file: top[0] } : undefined,
			remediation:
				"Track outstanding work in your issue tracker and resolve or remove stale markers, especially FIXME and HACK.",
			confidence: "high",
		});
	}
	if (stats.tsIgnores.length > 0) {
		const first = stats.tsIgnores[0];
		const files = new Set(stats.tsIgnores.map((t) => t.path));
		findings.push({
			ruleId: "code.quality/ts-ignore",
			title: `${stats.tsIgnores.length} @ts-ignore directives`,
			severity: "low",
			category: "maintainability",
			message: `${stats.tsIgnores.length} @ts-ignore directives in ${files.size} files silence the type checker, hiding real errors.`,
			location: first ? { file: first.path, line: first.line } : undefined,
			remediation:
				"Fix the underlying type errors, or use @ts-expect-error with a comment so the suppression fails once it is no longer needed.",
			references: [
				"https://www.typescriptlang.org/docs/handbook/release-notes/typescript-3-9.html#-ts-expect-error-comments",
			],
			confidence: "high",
		});
	}
	if (
		stats.tsIgnores.length >= TS_IGNORE_RATIO_MIN &&
		stats.tsIgnores.length > stats.tsExpectErrors
	) {
		const first = stats.tsIgnores[0];
		findings.push({
			ruleId: "code.quality/ts-ignore-over-expect-error",
			title: `@ts-ignore outnumbers @ts-expect-error (${stats.tsIgnores.length} vs ${stats.tsExpectErrors})`,
			severity: "low",
			category: "maintainability",
			message: `@ts-ignore keeps suppressing errors that no longer exist, while @ts-expect-error fails once the error is fixed. Found ${stats.tsIgnores.length} @ts-ignore and ${stats.tsExpectErrors} @ts-expect-error.`,
			location: first ? { file: first.path, line: first.line } : undefined,
			remediation:
				"Replace @ts-ignore with @ts-expect-error (or enable @typescript-eslint/ban-ts-comment) so stale suppressions are reported.",
			references: [
				"https://www.typescriptlang.org/docs/handbook/release-notes/typescript-3-9.html#-ts-expect-error-comments",
			],
			confidence: "high",
		});
	}
	const anyTotal = [...stats.anyCount.values()].reduce((a, b) => a + b, 0);
	if (anyTotal >= ANY_THRESHOLD) {
		const top = [...stats.anyCount.entries()].sort((a, b) => b[1] - a[1])[0];
		findings.push({
			ruleId: "code.quality/explicit-any",
			title: `${anyTotal} explicit \`any\` types`,
			severity: "info",
			category: "maintainability",
			message: `Explicit \`any\` appears ${anyTotal} times (most in ${topFiles(stats.anyCount)}), opting those values out of type checking.`,
			location: top ? { file: top[0] } : undefined,
			remediation:
				"Prefer `unknown` plus narrowing, precise types or generics; enable @typescript-eslint/no-explicit-any to stop new ones.",
			confidence: "medium",
		});
	}
	return findings;
};

/** `strict: false`, or a root tsconfig with no strict and no `extends`. */
export const checkTsconfig = (file: SourceFile): FindingInput | undefined => {
	const json = parseJsonc(file.text);
	if (!isRecord(json)) return undefined;
	const options = isRecord(json.compilerOptions) ? json.compilerOptions : {};
	const lineOf = lineLocator(file.text);
	const strictAt = file.text.search(/"strict"\s*:/);
	if (options.strict === false)
		return {
			ruleId: "code.quality/ts-strict-disabled",
			title: "TypeScript strict mode disabled",
			severity: "medium",
			category: "maintainability",
			message: `${file.path} sets "strict": false, turning off null checks and implicit-any errors that catch many runtime bugs.`,
			location: {
				file: file.path,
				line: strictAt === -1 ? undefined : lineOf(strictAt),
			},
			evidence: '"strict": false',
			remediation:
				'Set "strict": true (adopt incrementally with per-flag overrides or @ts-expect-error if needed).',
			references: ["https://www.typescriptlang.org/tsconfig#strict"],
			confidence: "high",
		};
	if (
		options.strict === undefined &&
		json.extends === undefined &&
		baseName(file.path) === "tsconfig.json"
	)
		return {
			ruleId: "code.quality/ts-strict-disabled",
			title: "TypeScript strict mode not enabled",
			severity: "low",
			category: "maintainability",
			message: `${file.path} does not enable "strict" (it is off by default).`,
			location: { file: file.path, line: 1 },
			remediation: 'Add "strict": true to compilerOptions.',
			references: ["https://www.typescriptlang.org/tsconfig#strict"],
			confidence: "high",
		};
	return undefined;
};

/* ------------------------------ tsconfig flags ----------------------------- */

interface ResolvedOptions {
	readonly options: Readonly<Record<string, unknown>>;
	/** False when an `extends` could not be followed (npm package, other folder). */
	readonly complete: boolean;
}

/** compilerOptions of a tsconfig merged along its relative `extends` chain. */
export const resolveTsconfigOptions = (
	path: string,
	texts: ReadonlyMap<string, string>,
	depth = 0,
): ResolvedOptions => {
	const json = parseJsonc(texts.get(path) ?? "");
	if (!isRecord(json) || depth > 6) return { options: {}, complete: false };
	let options: Record<string, unknown> = {};
	let complete = true;
	const parents = Array.isArray(json.extends)
		? json.extends
		: json.extends === undefined
			? []
			: [json.extends];
	for (const parent of parents) {
		const target =
			typeof parent === "string" && parent.startsWith(".")
				? posix.normalize(posix.join(posix.dirname(path), parent))
				: undefined;
		const resolved = target
			? [target, `${target}.json`].find((t) => texts.has(t))
			: undefined;
		if (!resolved) {
			complete = false;
			continue;
		}
		const inherited = resolveTsconfigOptions(resolved, texts, depth + 1);
		options = { ...options, ...inherited.options };
		complete &&= inherited.complete;
	}
	if (isRecord(json.compilerOptions))
		options = { ...options, ...json.compilerOptions };
	return { options, complete };
};

interface TsFlagRule {
	readonly rule: string;
	readonly flag: string;
	readonly severity: "low" | "info";
	readonly missing: (options: Readonly<Record<string, unknown>>) => boolean;
	readonly title: string;
	readonly why: string;
	readonly remediation: string;
}

const TS_FLAG_RULES: ReadonlyArray<TsFlagRule> = [
	{
		rule: "ts-no-unchecked-indexed-access",
		flag: "noUncheckedIndexedAccess",
		severity: "low",
		missing: (o) => o.noUncheckedIndexedAccess !== true,
		title: "noUncheckedIndexedAccess is not enabled",
		why: "array and record lookups are typed as always present, so `items[0].name` type-checks even on an empty array",
		remediation:
			'Set "noUncheckedIndexedAccess": true; indexed reads become `T | undefined` and force a check.',
	},
	{
		rule: "ts-no-implicit-override",
		flag: "noImplicitOverride",
		severity: "info",
		missing: (o) => o.noImplicitOverride !== true,
		title: "noImplicitOverride is not enabled",
		why: "renaming or removing a base-class method silently turns subclass overrides into unrelated methods",
		remediation:
			'Set "noImplicitOverride": true and mark overrides with `override`.',
	},
	{
		rule: "ts-no-fallthrough-cases",
		flag: "noFallthroughCasesInSwitch",
		severity: "low",
		missing: (o) => o.noFallthroughCasesInSwitch !== true,
		title: "noFallthroughCasesInSwitch is not enabled",
		why: "a missing `break` in a switch case falls into the next case without any error",
		remediation: 'Set "noFallthroughCasesInSwitch": true.',
	},
	{
		rule: "ts-allow-js-without-check-js",
		flag: "checkJs",
		severity: "info",
		missing: (o) => o.allowJs === true && o.checkJs !== true,
		title: "allowJs is enabled without checkJs",
		why: "JavaScript files are compiled but never type-checked",
		remediation:
			'Set "checkJs": true (or add `// @ts-check` per file) so JavaScript files get type errors too.',
	},
];

/** Strictness flags beyond `strict`, aggregated into one finding per flag. */
export const checkTsStrictness = (
	configs: ReadonlyArray<SourceFile>,
): FindingInput[] => {
	const texts = new Map(configs.map((c) => [c.path, c.text]));
	const projects = configs.flatMap((c) => {
		if (baseName(c.path) !== "tsconfig.json") return [];
		const json = parseJsonc(c.text);
		if (!isRecord(json)) return [];
		if (Array.isArray(json.files) && json.files.length === 0) return [];
		const { options, complete } = resolveTsconfigOptions(c.path, texts);
		return complete ? [{ path: c.path, options }] : [];
	});
	const findings: FindingInput[] = [];
	for (const rule of TS_FLAG_RULES) {
		const lacking = projects.filter((p) => rule.missing(p.options));
		const first = lacking[0];
		if (!first) continue;
		const text = texts.get(first.path) ?? "";
		const at = text.indexOf("compilerOptions");
		findings.push({
			ruleId: `code.quality/${rule.rule}`,
			title: rule.title,
			severity: rule.severity,
			category: "maintainability",
			message: `${rule.flag} is off in ${
				lacking.length === 1
					? first.path
					: `${lacking.length} tsconfig.json files (${lacking
							.slice(0, 3)
							.map((p) => p.path)
							.join(", ")}${lacking.length > 3 ? ", ..." : ""})`
			}: ${rule.why}.`,
			location: {
				file: first.path,
				line: at === -1 ? 1 : lineLocator(text)(at),
			},
			evidence: `"${rule.flag}" is not true`,
			remediation: rule.remediation,
			references: [`https://www.typescriptlang.org/tsconfig#${rule.flag}`],
			confidence: "high",
		});
	}
	return findings;
};

/* ----------------------------- CI static analysis --------------------------- */

const CI_FILE =
	/^(?:\.github\/workflows\/[^/]+\.ya?ml|\.gitlab-ci\.ya?ml|\.circleci\/config\.yml|azure-pipelines\.ya?ml|\.travis\.yml|bitbucket-pipelines\.yml|Jenkinsfile|\.buildkite\/[^/]+\.ya?ml)$/;

/** Static-analysis commands per language, matched against CI text. */
const CI_CHECKS: Readonly<
	Record<string, { label: string; pattern: RegExp; hint: string }>
> = {
	js: {
		label: "JavaScript/TypeScript",
		pattern:
			/(?<![\w.-])(?:tsc|vue-tsc|tsgo)(?![\w-])|\bbiome\s+(?:check|ci|lint)\b|\beslint\b|\boxlint\b|\bnext\s+lint\b|\bng\s+lint\b|\bdeno\s+(?:lint|check)\b|\bflow\s+check\b|\bxo\b(?=\s)/,
		hint: "tsc --noEmit, biome ci, eslint or oxlint",
	},
	rust: {
		label: "Rust",
		pattern: /\bcargo\s+(?:\+\S+\s+)?(?:clippy|check)\b|\bclippy\b/,
		hint: "cargo clippy -- -D warnings or cargo check",
	},
	python: {
		label: "Python",
		pattern:
			/\b(?:ruff|mypy|pyright|basedpyright|pylint|flake8|pyre)\b|\bty\s+check\b/,
		hint: "ruff check, mypy or pyright",
	},
	go: {
		label: "Go",
		pattern: /\bgo\s+vet\b|\bgolangci-lint\b|\bstaticcheck\b/,
		hint: "go vet ./..., golangci-lint run or staticcheck",
	},
	shell: {
		label: "Shell",
		pattern: /\bshellcheck\b/,
		hint: "shellcheck",
	},
};

/** Minimum number of files before a language counts as part of the project. */
const CI_LANGUAGE_MIN_FILES = 3;

/** Helper files that CI delegates to: matched on a mention in the CI text. */
const CI_DELEGATES: ReadonlyArray<{ mention: RegExp; file: RegExp }> = [
	{ mention: /\bmake\b/, file: /^(?:GNUmakefile|Makefile|makefile)$/ },
	{ mention: /\bjust\b/, file: /^(?:justfile|Justfile)$/ },
	{ mention: /\bpre-commit\b/, file: /^\.pre-commit-config\.ya?ml$/ },
	{ mention: /\btox\b/, file: /^tox\.ini$/ },
	{ mention: /\bnox\b/, file: /^noxfile\.py$/ },
	{ mention: /\btask\b/, file: /^Taskfile\.ya?ml$/ },
];

const stripYamlComments = (text: string) =>
	text
		.split("\n")
		.filter((l) => !/^\s*#/.test(l))
		.join("\n");

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export interface CiInput {
	/** CI configuration files (workflows, .gitlab-ci.yml, ...). */
	readonly ci: ReadonlyArray<SourceFile>;
	/** `scripts` of every package.json, by script name. */
	readonly scripts: ReadonlyMap<string, ReadonlyArray<string>>;
	/** Helper files (Makefile, tox.ini, ...), by base name. */
	readonly helpers: ReadonlyArray<SourceFile>;
	/** Number of source files per language key of CI_CHECKS. */
	readonly languages: ReadonlyMap<string, number>;
}

/**
 * Text that CI effectively runs: the CI files, plus the bodies of the
 * package.json scripts and helper files they invoke (transitively).
 */
export const expandCiText = (input: CiInput): string => {
	let text = input.ci.map((f) => stripYamlComments(f.text)).join("\n");
	const added = new Set<string>();
	for (let round = 0; round < 3; round++) {
		let grew = false;
		for (const [name, bodies] of input.scripts) {
			if (added.has(name)) continue;
			const invoke = new RegExp(
				`(?:\\b(?:npm|pnpm|yarn|bun|bunx|npx|turbo|nx|lerna|make|nr)\\b[^\\n]*?[ "'=:])${escapeRe(name)}(?![\\w:.-])`,
			);
			if (!invoke.test(text)) continue;
			added.add(name);
			text += `\n${bodies.join("\n")}`;
			grew = true;
		}
		for (const d of CI_DELEGATES) {
			const hits = input.helpers.filter((h) => d.file.test(baseName(h.path)));
			if (!d.mention.test(text)) continue;
			for (const h of hits) {
				if (added.has(h.path)) continue;
				added.add(h.path);
				text += `\n${h.text}`;
				grew = true;
			}
		}
		if (!grew) break;
	}
	return text;
};

/** One low-confidence finding per detected language that CI never statically checks. */
export const checkCiStaticAnalysis = (input: CiInput): FindingInput[] => {
	const first = input.ci[0];
	if (!first) return [];
	const text = expandCiText(input);
	const findings: FindingInput[] = [];
	for (const [language, check] of Object.entries(CI_CHECKS)) {
		if ((input.languages.get(language) ?? 0) < CI_LANGUAGE_MIN_FILES) continue;
		if (check.pattern.test(text)) continue;
		findings.push({
			ruleId: "code.quality/ci-no-static-analysis",
			title: `CI never type-checks or lints ${check.label}`,
			severity: "low",
			category: "maintainability",
			message: `${check.label} sources (${input.languages.get(language)} files) are present, but no CI workflow, or script it invokes, runs a type checker or linter for them (${check.hint}). Type and lint errors then only surface in reviews or in production.`,
			location: { file: first.path },
			evidence:
				`no ${check.hint.replace(/ or /g, "/")} in ${input.ci.map((f) => f.path).join(", ")}`.slice(
					0,
					160,
				),
			remediation: `Add a CI step that runs ${check.hint} and fails the build on errors.`,
			confidence: "low",
			tags: ["ci", language],
		});
	}
	return findings;
};

const TEST_DIR = /(^|\/)(tests?|spec|__tests__|e2e|testing)\//;

export const quality = defineAuditor({
	id: "code.quality",
	title: "Code quality",
	description:
		"Maintainability heuristics: oversized files, deep nesting, TODO/FIXME debt, TypeScript strictness flags and escape hatches (@ts-ignore, @ts-nocheck), CI that never type-checks or lints, missing tests and Node engines.",
	categories: ["maintainability", "reliability", "best-practices"],
	targets: ["codebase"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const all = yield* ws.files;
			const findings: FindingInput[] = [];
			const sources = yield* readTextFiles(
				ws,
				(p) =>
					isSourcePath(p) &&
					!isTestPath(p) &&
					!isFixturePath(p) &&
					!isGeneratedPath(p),
			);
			const stats: QualityStats = {
				todos: new Map(),
				todoFiles: new Map(),
				tsIgnores: [],
				tsExpectErrors: 0,
				anyCount: new Map(),
			};
			for (const file of sources)
				findings.push(...scanQualityFile(file, stats));
			findings.push(...aggregateFindings(stats));

			const tsconfigs = yield* readTextFiles(
				ws,
				(p) => /(^|\/)tsconfig(\.[\w-]+)?\.json$/.test(p) && !isFixturePath(p),
			);
			for (const t of tsconfigs) {
				const f = checkTsconfig(t);
				if (f) findings.push(f);
			}
			findings.push(...checkTsStrictness(tsconfigs));

			const ciFiles = all.filter((p) => CI_FILE.test(p));
			if (ciFiles.length > 0) {
				const languages = new Map<string, number>();
				for (const s of sources) {
					const lang = languageOf(s.path);
					if (lang) languages.set(lang, (languages.get(lang) ?? 0) + 1);
				}
				languages.set(
					"shell",
					all.filter((p) => /\.(?:sh|bash)$/.test(p) && !isFixturePath(p))
						.length,
				);
				const ci = yield* readTextFiles(ws, (p) => ciFiles.includes(p), {
					allowMinified: true,
				});
				const helpers = yield* readTextFiles(ws, (p) =>
					CI_DELEGATES.some((d) => !p.includes("/") && d.file.test(p)),
				);
				const manifests = yield* readTextFiles(
					ws,
					(p) => baseName(p) === "package.json" && !isFixturePath(p),
					{ limit: 100 },
				);
				const scripts = new Map<string, string[]>();
				for (const m of manifests) {
					const pkg = parseJsonc(m.text);
					if (!isRecord(pkg) || !isRecord(pkg.scripts)) continue;
					for (const [name, body] of Object.entries(pkg.scripts))
						if (typeof body === "string")
							scripts.set(name, [...(scripts.get(name) ?? []), body]);
				}
				findings.push(
					...checkCiStaticAnalysis({ ci, scripts, helpers, languages }),
				);
			}

			const hasTests = all.some(
				(p) => (isTestPath(p) || TEST_DIR.test(p)) && !isFixturePath(p),
			);
			if (!hasTests && sources.length >= 3)
				findings.push({
					ruleId: "code.quality/tests-missing",
					title: "No automated tests",
					severity: "medium",
					category: "reliability",
					message: `No test files were found alongside ${sources.length} source files, so regressions go unnoticed.`,
					remediation:
						"Add unit tests for core logic (bun test, vitest, pytest, go test…) and run them in CI.",
					confidence: "medium",
				});

			if (all.includes("package.json")) {
				const text = yield* ws
					.readText("package.json")
					.pipe(Effect.orElseSucceed(() => ""));
				const pkg = parseJsonc(text);
				if (isRecord(pkg) && !isRecord(pkg.engines))
					findings.push({
						ruleId: "code.quality/engines-missing",
						title: "No Node.js engines constraint",
						severity: "info",
						category: "best-practices",
						message:
							"package.json has no `engines` field, so the supported runtime version is undocumented and unenforced.",
						location: { file: "package.json", line: 1 },
						remediation:
							'Add e.g. "engines": { "node": ">=20" } (and .nvmrc / packageManager) to pin supported runtimes.',
						references: [
							"https://docs.npmjs.com/cli/configuring-npm/package-json#engines",
						],
						confidence: "high",
					});
			}
			return findings;
		}),
});
