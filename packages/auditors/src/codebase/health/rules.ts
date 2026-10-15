import type { FileMetrics, FunctionMetrics } from "./metrics";

/**
 * Code Health rules: CodeScene's smells, default thresholds and (fitted)
 * score impacts, so a file scores close to what CodeScene would give it.
 * Names match CodeScene's, which keeps `.codescene/code-health-rules.json`
 * and `@codescene(disable:"...")` directives working for both tools.
 */
export type RuleName =
	| "Complex Method"
	| "Large Method"
	| "Bumpy Road Ahead"
	| "Complex Conditional"
	| "Deep, Nested Complexity"
	| "Excess Number of Function Arguments"
	| "Constructor Over-Injection"
	| "Overall Code Complexity"
	| "Overall Function Size"
	| "Primitive Obsession"
	| "String Heavy Function Arguments"
	| "Code Duplication"
	| "Lines of Code in a Single File";

export interface Thresholds {
	readonly function_cyclomatic_complexity_warning: number;
	readonly function_lines_of_code_warning: number;
	readonly function_max_arguments: number;
	readonly constructor_max_arguments: number;
	readonly function_nesting_depth_warning: number;
	readonly function_bumpy_road_bumps_for_warning: number;
	readonly function_complex_conditional_branches_warning: number;
	readonly file_mean_cyclomatic_complexity_warning: number;
	readonly file_lines_of_code_for_warning: number;
	readonly file_lines_of_code_for_alert: number;
	readonly file_primitive_obsession_percentage_for_warning: number;
	readonly file_string_arguments_percentage_for_warning: number;
	readonly file_median_function_lines_of_code_warning: number;
	readonly function_duplication_min_lines_of_code_for_check: number;
	readonly function_duplication_min_similarity_percentage: number;
}

/**
 * CodeScene's defaults where it publishes them. The file-level argument and
 * duplication thresholds are stricter than a literal reading of CodeScene's,
 * because openaudit sees every function (CodeScene's parser skips arrow
 * functions with multi-line parameters), and it compares functions by text,
 * not by whether they changed together.
 */
export const DEFAULT_THRESHOLDS: Thresholds = {
	function_cyclomatic_complexity_warning: 9,
	function_lines_of_code_warning: 70,
	function_max_arguments: 4,
	constructor_max_arguments: 5,
	function_nesting_depth_warning: 4,
	function_bumpy_road_bumps_for_warning: 2,
	function_complex_conditional_branches_warning: 2,
	file_mean_cyclomatic_complexity_warning: 4,
	file_lines_of_code_for_warning: 1000,
	file_lines_of_code_for_alert: 5000,
	file_primitive_obsession_percentage_for_warning: 60,
	file_string_arguments_percentage_for_warning: 50,
	file_median_function_lines_of_code_warning: 50,
	function_duplication_min_lines_of_code_for_check: 10,
	function_duplication_min_similarity_percentage: 90,
};

/** File-level rules need this many functions to say something about the file. */
const MIN_FUNCTIONS_FOR_FILE_RULES = 7;
/** Argument mix rules need this many arguments. */
const MIN_ARGUMENTS_FOR_MIX = 12;

export interface SmellFunction {
	readonly name: string;
	readonly line: number;
	readonly endLine: number;
	/** e.g. `cc = 23`, `LoC = 82`, `5 arguments`. */
	readonly detail: string;
}

export interface Smell {
	readonly rule: RuleName;
	readonly impact: number;
	readonly functions: ReadonlyArray<SmellFunction>;
	/** What the smell means for this file, for file-level rules. */
	readonly detail?: string;
}

export interface RuleSet {
	readonly thresholds: Thresholds;
	/** Relative weight per rule; 0 disables it. */
	readonly weights: Readonly<Partial<Record<RuleName, number>>>;
}

const isOff = (f: FunctionMetrics, rule: RuleName) =>
	f.disabled.includes("*") || f.disabled.includes(rule);

const at = (
	f: FunctionMetrics,
	detail: string,
	line = f.startLine,
): SmellFunction => ({
	name: f.name,
	line,
	endLine: f.endLine,
	detail,
});

const sum = (xs: ReadonlyArray<number>) => xs.reduce((a, b) => a + b, 0);

const median = (xs: ReadonlyArray<number>) => {
	const s = [...xs].sort((a, b) => a - b);
	const mid = Math.floor(s.length / 2);
	return s.length % 2 ? (s[mid] ?? 0) : ((s[mid - 1] ?? 0) + (s[mid] ?? 0)) / 2;
};

const smell = (
	rule: RuleName,
	impact: number,
	functions: ReadonlyArray<SmellFunction>,
	detail?: string,
): Smell[] => [{ rule, impact, functions, ...(detail ? { detail } : {}) }];

/* ----------------------------- function rules ----------------------------- */

const complexMethods = (fns: ReadonlyArray<FunctionMetrics>, t: Thresholds) =>
	fns.filter(
		(f) =>
			f.cc >= t.function_cyclomatic_complexity_warning &&
			!isOff(f, "Complex Method"),
	);

const complexMethod = (fns: ReadonlyArray<FunctionMetrics>, t: Thresholds) => {
	const hits = complexMethods(fns, t);
	if (!hits.length) return [];
	const impact = Math.max(1, 0.09 * sum(hits.map((f) => f.cc)));
	return smell(
		"Complex Method",
		impact,
		hits.map((f) => at(f, `cc = ${f.cc}`)),
	);
};

/** A long function that is also complex is charged once, as complex. */
const largeMethod = (fns: ReadonlyArray<FunctionMetrics>, t: Thresholds) => {
	const hits = fns.filter(
		(f) =>
			f.loc >= t.function_lines_of_code_warning && !isOff(f, "Large Method"),
	);
	if (!hits.length) return [];
	const complex = new Set(complexMethods(fns, t));
	const impact =
		0.018 * sum(hits.filter((f) => !complex.has(f)).map((f) => f.loc));
	return smell(
		"Large Method",
		impact,
		hits.map((f) => at(f, `LoC = ${f.loc} lines`)),
	);
};

const bumpImpact = (bumps: number) => (bumps < 5 ? 0.5 : bumps < 10 ? 2 : 3.5);

const bumpyRoad = (fns: ReadonlyArray<FunctionMetrics>, t: Thresholds) => {
	const hits = fns.filter(
		(f) =>
			f.bumps.length >= t.function_bumpy_road_bumps_for_warning &&
			!isOff(f, "Bumpy Road Ahead"),
	);
	if (!hits.length) return [];
	const impact = sum(hits.map((f) => bumpImpact(f.bumps.length)));
	return smell(
		"Bumpy Road Ahead",
		impact,
		hits.map((f) => at(f, `bumps = ${f.bumps.length}`)),
	);
};

const complexConditional = (
	fns: ReadonlyArray<FunctionMetrics>,
	t: Thresholds,
) => {
	const hits = fns.flatMap((f) =>
		isOff(f, "Complex Conditional")
			? []
			: f.conditionals
					.filter(
						(c) =>
							c.branches >= t.function_complex_conditional_branches_warning,
					)
					.map((c) => ({ f, c })),
	);
	if (!hits.length) return [];
	const impact = 0.5 * sum(hits.map((h) => h.c.branches));
	return smell(
		"Complex Conditional",
		impact,
		hits.map(({ f, c }) => ({
			name: `${f.name}:${c.line}`,
			line: c.line,
			endLine: c.endLine,
			detail: `${c.branches} logical operators`,
		})),
	);
};

const deepNesting = (fns: ReadonlyArray<FunctionMetrics>, t: Thresholds) => {
	const hits = fns.filter(
		(f) =>
			f.nesting >= t.function_nesting_depth_warning &&
			!isOff(f, "Deep, Nested Complexity"),
	);
	if (!hits.length) return [];
	return smell(
		"Deep, Nested Complexity",
		2,
		hits.map((f) => at(f, `nesting depth = ${f.nesting}`)),
	);
};

const argumentRule = (
	fns: ReadonlyArray<FunctionMetrics>,
	rule: RuleName,
	max: number,
	constructors: boolean,
) => {
	const hits = fns.filter(
		(f) =>
			f.isConstructor === constructors &&
			f.params.length > max &&
			!isOff(f, rule),
	);
	if (!hits.length) return [];
	return smell(
		rule,
		1,
		hits.map((f) => at(f, `${f.params.length} arguments`)),
	);
};

/* ------------------------------- file rules ------------------------------- */

/** The functions file-level averages are taken over: those with a block body. */
const blockFunctions = (fns: ReadonlyArray<FunctionMetrics>) =>
	fns.filter((f) => !f.expressionBody);

const overallComplexity = (
	fns: ReadonlyArray<FunctionMetrics>,
	t: Thresholds,
) => {
	const block = blockFunctions(fns);
	if (block.length < MIN_FUNCTIONS_FOR_FILE_RULES) return [];
	const mean = sum(block.map((f) => f.cc)) / block.length;
	if (mean < t.file_mean_cyclomatic_complexity_warning) return [];
	const impact = mean < 14 ? 2 : mean < 18 ? 3 : 4;
	return smell(
		"Overall Code Complexity",
		impact,
		[],
		`mean cyclomatic complexity ${mean.toFixed(2)} across ${block.length} functions`,
	);
};

const overallFunctionSize = (
	fns: ReadonlyArray<FunctionMetrics>,
	t: Thresholds,
) => {
	const block = blockFunctions(fns);
	if (block.length < MIN_FUNCTIONS_FOR_FILE_RULES) return [];
	const m = median(block.map((f) => f.loc));
	if (m < t.file_median_function_lines_of_code_warning) return [];
	return smell(
		"Overall Function Size",
		2,
		[],
		`median function length ${m} lines`,
	);
};

const argumentMix = (fns: ReadonlyArray<FunctionMetrics>, t: Thresholds) => {
	const block = blockFunctions(fns);
	const params = block.flatMap((f) => f.params);
	if (block.length < MIN_FUNCTIONS_FOR_FILE_RULES) return [];
	if (params.length < MIN_ARGUMENTS_FOR_MIX) return [];
	const pct = (n: number) => Math.round((100 * n) / params.length);
	const primitive = pct(params.filter((p) => p.primitive).length);
	const strings = pct(params.filter((p) => p.string).length);
	return [
		...(primitive >= t.file_primitive_obsession_percentage_for_warning
			? smell(
					"Primitive Obsession",
					1,
					[],
					`${primitive}% of arguments are primitive types`,
				)
			: []),
		...(strings >= t.file_string_arguments_percentage_for_warning
			? smell(
					"String Heavy Function Arguments",
					1,
					[],
					`${strings}% of arguments are strings`,
				)
			: []),
	];
};

const largeFile = (file: FileMetrics, t: Thresholds) => {
	if (file.codeLines <= t.file_lines_of_code_for_warning) return [];
	const impact = file.codeLines > t.file_lines_of_code_for_alert ? 4 : 2;
	return smell(
		"Lines of Code in a Single File",
		impact,
		[],
		`${file.codeLines} lines of code`,
	);
};

/* ------------------------------- duplication ------------------------------ */

/** Similarity of two token lists, 0 to 1 (longest common subsequence). */
export const similarity = (
	a: ReadonlyArray<string>,
	b: ReadonlyArray<string>,
) => {
	if (!a.length || !b.length) return 0;
	let prev = new Uint16Array(b.length + 1);
	let row = new Uint16Array(b.length + 1);
	for (const x of a) {
		for (let j = 0; j < b.length; j++)
			row[j + 1] =
				x === b[j]
					? (prev[j] ?? 0) + 1
					: Math.max(prev[j + 1] ?? 0, row[j] ?? 0);
		[prev, row] = [row, prev];
	}
	return (2 * (prev[b.length] ?? 0)) / (a.length + b.length);
};

/** Token lists this long are compared; longer ones would cost too much. */
const MAX_TOKENS = 2000;

const similarPair = (a: FunctionMetrics, b: FunctionMetrics, min: number) => {
	const [short, long] = [a.tokens.length, b.tokens.length].sort(
		(x, y) => x - y,
	);
	if ((short ?? 0) / (long ?? 1) < min) return false;
	return similarity(a.tokens, b.tokens) >= min;
};

const duplication = (
	fns: ReadonlyArray<FunctionMetrics>,
	t: Thresholds,
	isTest: boolean,
) => {
	if (isTest) return [];
	const min = t.function_duplication_min_similarity_percentage / 100;
	const candidates = fns.filter(
		(f) =>
			f.loc >= t.function_duplication_min_lines_of_code_for_check &&
			f.tokens.length <= MAX_TOKENS &&
			!isOff(f, "Code Duplication"),
	);
	const hits = new Set<FunctionMetrics>();
	candidates.forEach((a, i) => {
		for (const b of candidates.slice(i + 1))
			if (similarPair(a, b, min)) hits.add(a).add(b);
	});
	if (!hits.size) return [];
	return smell(
		"Code Duplication",
		2,
		[...hits].map((f) => at(f, "similar to another function in this file")),
	);
};

/* ---------------------------------- score --------------------------------- */

const weighted = (smells: ReadonlyArray<Smell>, rules: RuleSet): Smell[] =>
	smells.flatMap((s) => {
		const w = rules.weights[s.rule] ?? 1;
		return w > 0 ? [{ ...s, impact: s.impact * w }] : [];
	});

/** The smells of one file, after rule weights and directives. */
export const smellsOf = (
	file: FileMetrics,
	rules: RuleSet,
	isTest: boolean,
): Smell[] => {
	const t = rules.thresholds;
	const fns = file.functions;
	return weighted(
		[
			...complexMethod(fns, t),
			...largeMethod(fns, t),
			...bumpyRoad(fns, t),
			...complexConditional(fns, t),
			...deepNesting(fns, t),
			...argumentRule(
				fns,
				"Excess Number of Function Arguments",
				t.function_max_arguments,
				false,
			),
			...argumentRule(
				fns,
				"Constructor Over-Injection",
				t.constructor_max_arguments,
				true,
			),
			...overallComplexity(fns, t),
			...overallFunctionSize(fns, t),
			...argumentMix(fns, t),
			...duplication(fns, t, isTest),
			...largeFile(file, t),
		],
		rules,
	);
};

/**
 * File score from 1 to 10. Impacts add up and the score decays towards 1, the
 * way CodeScene's does: an impact of 1 gives 9.69, 4 gives 8.82, 20 gives 5.43.
 */
export const scoreOf = (smells: ReadonlyArray<Smell>): number => {
	const impact = sum(smells.map((s) => s.impact));
	return impact > 0 ? 1 + 9 * Math.exp(-0.0352 * impact) : 10;
};
