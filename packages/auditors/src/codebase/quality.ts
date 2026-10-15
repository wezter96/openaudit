import {
	defineAuditor,
	type FindingInput,
	requireWorkspace,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import { ciFindings } from "./quality-ci";
import { braceNesting, type Nesting, pythonNesting } from "./quality-nesting";
import { checkTsconfig, checkTsStrictness } from "./quality-tsconfig";
import type { FilePath, LineNumber } from "./quality-types";
import {
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

export {
	type CiInput,
	checkCiStaticAnalysis,
	expandCiText,
} from "./quality-ci";
export { braceNesting, type Nesting, pythonNesting } from "./quality-nesting";
export {
	checkTsconfig,
	checkTsStrictness,
	resolveTsconfigOptions,
} from "./quality-tsconfig";

const LARGE_FILE_LINES = 1000;
const DEEP_NESTING = 5;
const ANY_THRESHOLD = 10;

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
const TS_EXTENSIONS = ["ts", "tsx", "mts", "cts"];
const TS_EXPECT_ERROR_DOCS =
	"https://www.typescriptlang.org/docs/handbook/release-notes/typescript-3-9.html#-ts-expect-error-comments";

export interface QualityStats {
	readonly todos: Map<string, number>;
	readonly todoFiles: Map<string, number>;
	readonly tsIgnores: Array<{ path: string; line: number }>;
	/** Number of `@ts-expect-error` directives. */
	tsExpectErrors: number;
	readonly anyCount: Map<string, number>;
}

const largeFileFindings = (file: SourceFile): FindingInput[] => {
	const lines = file.text.split("\n").length;
	if (lines <= LARGE_FILE_LINES) return [];
	return [
		{
			ruleId: "code.quality/large-file",
			title: `Large file (${lines} lines)`,
			severity: "low",
			category: "maintainability",
			message: `${file.path} has ${lines} lines. Very large files are hard to review, test and change safely.`,
			location: { file: file.path },
			remediation:
				"Split it into smaller modules with a single responsibility each.",
			confidence: "high",
		},
	];
};

const deepNestingFindings = (file: SourceFile): FindingInput[] => {
	const nesting = nestingOf(file);
	if (nesting === undefined || nesting.depth < DEEP_NESTING) return [];
	return [
		{
			ruleId: "code.quality/deep-nesting",
			title: `Deeply nested control flow (${nesting.depth} levels)`,
			severity: "low",
			category: "maintainability",
			message: `Control flow in ${file.path} nests ${nesting.depth} levels deep, which makes the logic hard to follow and test.`,
			location: { file: file.path, line: nesting.line },
			remediation:
				"Use early returns/guard clauses, extract helper functions, or replace nested conditionals with lookup tables.",
			references: [
				"https://refactoring.guru/replace-nested-conditional-with-guard-clauses",
			],
			confidence: "low",
		},
	];
};

const countTodos = (file: SourceFile, stats: QualityStats) => {
	let todoCount = 0;
	for (const m of file.text.matchAll(TODO)) {
		const tag = m[1] ?? "TODO";
		stats.todos.set(tag, (stats.todos.get(tag) ?? 0) + 1);
		todoCount++;
	}
	if (todoCount) stats.todoFiles.set(file.path, todoCount);
};

const tsNocheckFindings = (
	file: SourceFile,
	lineOf: (index: number) => LineNumber,
): FindingInput[] => {
	const nocheck = TS_NOCHECK.exec(file.text);
	if (!nocheck) return [];
	return [
		{
			ruleId: "code.quality/ts-nocheck",
			title: "File opts out of type checking with @ts-nocheck",
			severity: "medium",
			category: "reliability",
			message: `${file.path} starts with @ts-nocheck, so TypeScript reports no errors anywhere in the file.`,
			location: { file: file.path, line: lineOf(nocheck.index) },
			evidence: nocheck[0].trim(),
			remediation:
				"Remove @ts-nocheck and fix the errors, or narrow the suppression to individual lines with @ts-expect-error and a comment.",
			references: [
				"https://www.typescriptlang.org/docs/handbook/type-checking-javascript-files.html#ts-nocheck-in-typescript-files",
			],
			confidence: "high",
		},
	];
};

/** Counts TypeScript escape hatches into `stats` and reports `@ts-nocheck`. */
const scanTypeScript = (
	file: SourceFile,
	stats: QualityStats,
): FindingInput[] => {
	const { path, text } = file;
	if (!TS_EXTENSIONS.includes(extOf(path))) return [];
	const lineOf = lineLocator(text);
	for (const m of text.matchAll(TS_IGNORE))
		stats.tsIgnores.push({ path, line: lineOf(m.index ?? 0) });
	stats.tsExpectErrors += [...text.matchAll(TS_EXPECT_ERROR)].length;
	const anys = [...text.matchAll(EXPLICIT_ANY)].length;
	if (anys) stats.anyCount.set(path, anys);
	return tsNocheckFindings(file, lineOf);
};

/** Per-file findings (large files, deep nesting) and aggregated counters. */
export const scanQualityFile = (
	file: SourceFile,
	stats: QualityStats,
): FindingInput[] => {
	const findings = [...largeFileFindings(file), ...deepNestingFindings(file)];
	countTodos(file, stats);
	findings.push(...scanTypeScript(file, stats));
	return findings;
};

const topFiles = (counts: ReadonlyMap<string, number>, n = 3) =>
	[...counts.entries()]
		.sort((a, b) => b[1] - a[1])
		.slice(0, n)
		.map(([p, c]) => `${p} (${c})`)
		.join(", ");

const sum = (counts: ReadonlyMap<string, number>) =>
	[...counts.values()].reduce((a, b) => a + b, 0);

/** Location of the file with the highest count. */
const topLocation = (counts: ReadonlyMap<string, number>) => {
	const top = [...counts.entries()].sort((a, b) => b[1] - a[1])[0];
	return top ? { file: top[0] } : undefined;
};

const todoFindings = (stats: QualityStats): FindingInput[] => {
	const totalTodos = sum(stats.todos);
	if (totalTodos <= 0) return [];
	const breakdown = [...stats.todos.entries()]
		.map(([t, c]) => `${c} ${t}`)
		.join(", ");
	return [
		{
			ruleId: "code.quality/todo-comments",
			title: `${totalTodos} TODO/FIXME/HACK comments`,
			severity: "info",
			category: "maintainability",
			message: `Found ${breakdown} across ${stats.todoFiles.size} files (most in ${topFiles(stats.todoFiles)}).`,
			location: topLocation(stats.todoFiles),
			remediation:
				"Track outstanding work in your issue tracker and resolve or remove stale markers, especially FIXME and HACK.",
			confidence: "high",
		},
	];
};

interface TsIgnoreDraft {
	readonly ruleId: string;
	readonly title: string;
	readonly message: string;
	readonly remediation: string;
}

/** A @ts-expect-error finding located at the first directive. */
const tsIgnoreFinding = (
	stats: QualityStats,
	draft: TsIgnoreDraft,
): FindingInput => {
	const first = stats.tsIgnores[0];
	return {
		ruleId: draft.ruleId,
		title: draft.title,
		severity: "low",
		category: "maintainability",
		message: draft.message,
		location: first ? { file: first.path, line: first.line } : undefined,
		remediation: draft.remediation,
		references: [TS_EXPECT_ERROR_DOCS],
		confidence: "high",
	};
};

const tsIgnoreFindings = (stats: QualityStats): FindingInput[] => {
	const count = stats.tsIgnores.length;
	if (count === 0) return [];
	const files = new Set(stats.tsIgnores.map((t) => t.path));
	return [
		tsIgnoreFinding(stats, {
			ruleId: "code.quality/ts-ignore",
			title: `${count} @ts-ignore directives`,
			message: `${count} @ts-ignore directives in ${files.size} files silence the type checker, hiding real errors.`,
			remediation:
				"Fix the underlying type errors, or use @ts-expect-error with a comment so the suppression fails once it is no longer needed.",
		}),
	];
};

const tsIgnoreRatioFindings = (stats: QualityStats): FindingInput[] => {
	const ignores = stats.tsIgnores.length;
	const expects = stats.tsExpectErrors;
	if (ignores < TS_IGNORE_RATIO_MIN || ignores <= expects) return [];
	return [
		tsIgnoreFinding(stats, {
			ruleId: "code.quality/ts-ignore-over-expect-error",
			title: `@ts-ignore outnumbers @ts-expect-error (${ignores} vs ${expects})`,
			message: `@ts-ignore keeps suppressing errors that no longer exist, while @ts-expect-error fails once the error is fixed. Found ${ignores} @ts-ignore and ${expects} @ts-expect-error.`,
			remediation:
				"Replace @ts-ignore with @ts-expect-error (or enable @typescript-eslint/ban-ts-comment) so stale suppressions are reported.",
		}),
	];
};

const explicitAnyFindings = (stats: QualityStats): FindingInput[] => {
	const anyTotal = sum(stats.anyCount);
	if (anyTotal < ANY_THRESHOLD) return [];
	return [
		{
			ruleId: "code.quality/explicit-any",
			title: `${anyTotal} explicit \`any\` types`,
			severity: "info",
			category: "maintainability",
			message: `Explicit \`any\` appears ${anyTotal} times (most in ${topFiles(stats.anyCount)}), opting those values out of type checking.`,
			location: topLocation(stats.anyCount),
			remediation:
				"Prefer `unknown` plus narrowing, precise types or generics; enable @typescript-eslint/no-explicit-any to stop new ones.",
			confidence: "medium",
		},
	];
};

const AGGREGATES = [
	todoFindings,
	tsIgnoreFindings,
	tsIgnoreRatioFindings,
	explicitAnyFindings,
];

export const aggregateFindings = (stats: QualityStats): FindingInput[] =>
	AGGREGATES.flatMap((aggregate) => aggregate(stats));

/* --------------------------------- auditor --------------------------------- */

const TEST_DIR = /(^|\/)(tests?|spec|__tests__|e2e|testing)\//;

const isQualitySource = (p: FilePath) =>
	isSourcePath(p) && !isTestPath(p) && !isFixturePath(p) && !isGeneratedPath(p);

const isTsconfigPath = (p: FilePath) =>
	/(^|\/)tsconfig(\.[\w-]+)?\.json$/.test(p) && !isFixturePath(p);

const looksLikeTest = (p: FilePath) => isTestPath(p) || TEST_DIR.test(p);

const isTestFile = (p: FilePath) => looksLikeTest(p) && !isFixturePath(p);

const sourceFindings = (sources: ReadonlyArray<SourceFile>): FindingInput[] => {
	const stats: QualityStats = {
		todos: new Map(),
		todoFiles: new Map(),
		tsIgnores: [],
		tsExpectErrors: 0,
		anyCount: new Map(),
	};
	const findings = sources.flatMap((file) => scanQualityFile(file, stats));
	return [...findings, ...aggregateFindings(stats)];
};

const tsconfigFindings = (
	tsconfigs: ReadonlyArray<SourceFile>,
): FindingInput[] => [
	...tsconfigs.flatMap((t) => checkTsconfig(t) ?? []),
	...checkTsStrictness(tsconfigs),
];

const testsMissingFindings = (
	all: ReadonlyArray<FilePath>,
	sources: ReadonlyArray<SourceFile>,
): FindingInput[] => {
	if (all.some(isTestFile) || sources.length < 3) return [];
	return [
		{
			ruleId: "code.quality/tests-missing",
			title: "No automated tests",
			severity: "medium",
			category: "reliability",
			message: `No test files were found alongside ${sources.length} source files, so regressions go unnoticed.`,
			remediation:
				"Add unit tests for core logic (bun test, vitest, pytest, go test…) and run them in CI.",
			confidence: "medium",
		},
	];
};

const enginesMissingFinding = (): FindingInput => ({
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

const enginesFindings = (ws: Workspace, all: ReadonlyArray<FilePath>) =>
	Effect.gen(function* () {
		if (!all.includes("package.json")) return [];
		const text = yield* ws
			.readText("package.json")
			.pipe(Effect.orElseSucceed(() => ""));
		const pkg = parseJsonc(text);
		if (!isRecord(pkg) || isRecord(pkg.engines)) return [];
		return [enginesMissingFinding()];
	});

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
			const sources = yield* readTextFiles(ws, isQualitySource);
			const findings = sourceFindings(sources);
			const tsconfigs = yield* readTextFiles(ws, isTsconfigPath);
			findings.push(...tsconfigFindings(tsconfigs));
			findings.push(...(yield* ciFindings(ws, all, sources)));
			findings.push(...testsMissingFindings(all, sources));
			findings.push(...(yield* enginesFindings(ws, all)));
			return findings;
		}),
});
