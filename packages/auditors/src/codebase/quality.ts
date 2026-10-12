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
			if (ch === "{") {
				const before = code.slice(0, i);
				const isControl =
					CONTROL_KEYWORD.test(before) ||
					(before.trim() === "" && CONTROL_KEYWORD.test(prevCode));
				stack.push(isControl);
				if (isControl) {
					controls++;
					if (controls > max.depth) max = { depth: controls, line: n + 1 };
				}
			} else if (ch === "}") {
				if (stack.pop()) controls--;
			}
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
const TS_IGNORE = /@ts-(?:ignore|nocheck)\b/g;
const EXPLICIT_ANY = /:\s*any\b(?!\s*[(.])|\bas\s+any\b|<any>|\bany\[\]/g;

export interface QualityStats {
	readonly todos: Map<string, number>;
	readonly todoFiles: Map<string, number>;
	readonly tsIgnores: Array<{ path: string; line: number }>;
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
			title: `${stats.tsIgnores.length} @ts-ignore/@ts-nocheck directives`,
			severity: "low",
			category: "maintainability",
			message: `${stats.tsIgnores.length} TypeScript suppression directives in ${files.size} files silence the type checker, hiding real errors.`,
			location: first ? { file: first.path, line: first.line } : undefined,
			remediation:
				"Fix the underlying type errors, or use @ts-expect-error with a comment so the suppression fails once it is no longer needed.",
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

const TEST_DIR = /(^|\/)(tests?|spec|__tests__|e2e|testing)\//;

export const quality = defineAuditor({
	id: "code.quality",
	title: "Code quality",
	description:
		"Maintainability heuristics: oversized files, deep nesting, TODO/FIXME debt, TypeScript strictness and escape hatches, missing tests and Node engines.",
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
