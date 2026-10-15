import {
	defineAuditor,
	type FindingInput,
	requireWorkspace,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { hotspotsOf, readHistory, revisionsOf } from "../history/git-log";
import {
	extOf,
	isFixturePath,
	isGeneratedPath,
	isTestPath,
	readTextFiles,
} from "../util";
import {
	type MatchedRuleSet,
	parseRulesFile,
	RULES_FILE,
	rulesFor,
} from "./config";
import { analyzeJs } from "./js";
import { type RuleName, type Smell, scoreOf, smellsOf } from "./rules";

const ID = "code.health";
const DOCS = "https://openaudit.se/auditors/code.health/";

const JS_EXTENSIONS = new Set([
	"ts",
	"tsx",
	"mts",
	"cts",
	"js",
	"jsx",
	"mjs",
	"cjs",
]);

const isAnalyzable = (path: string) =>
	JS_EXTENSIONS.has(extOf(path)) &&
	!path.endsWith(".d.ts") &&
	!isGeneratedPath(path) &&
	!isFixturePath(path);

interface RuleText {
	readonly slug: string;
	readonly one: string;
	readonly many: (n: number) => string;
	readonly fix: string;
	readonly confidence: "high" | "medium";
}

const RULE_TEXT: Readonly<Record<RuleName, RuleText>> = {
	"Complex Method": {
		slug: "complex-method",
		one: "Function is too complex",
		many: (n) => `${n} functions are too complex`,
		fix: "Split the function: move each decision or case into a small, well-named function, or replace a long if/else chain with a lookup table.",
		confidence: "high",
	},
	"Large Method": {
		slug: "large-method",
		one: "Function is too long",
		many: (n) => `${n} functions are too long`,
		fix: "Look for the natural chunks (often a comment followed by a block) and extract each into its own function.",
		confidence: "high",
	},
	"Bumpy Road Ahead": {
		slug: "bumpy-road",
		one: "Function has several chunks of nested logic",
		many: (n) => `${n} functions have several chunks of nested logic`,
		fix: "Each chunk of nested conditionals is a missing function. Extract them, so the function reads as a sequence of named steps.",
		confidence: "medium",
	},
	"Complex Conditional": {
		slug: "complex-conditional",
		one: "Complex conditional",
		many: (n) => `${n} complex conditionals`,
		fix: "Move the condition into a function or a variable whose name says what it checks.",
		confidence: "high",
	},
	"Deep, Nested Complexity": {
		slug: "deep-nesting",
		one: "Deeply nested logic",
		many: (n) => `${n} functions have deeply nested logic`,
		fix: "Return early for the edge cases and extract the inner loops or branches into functions.",
		confidence: "high",
	},
	"Excess Number of Function Arguments": {
		slug: "excess-arguments",
		one: "Function takes too many arguments",
		many: (n) => `${n} functions take too many arguments`,
		fix: "Group arguments that travel together into one object or type.",
		confidence: "high",
	},
	"Constructor Over-Injection": {
		slug: "constructor-over-injection",
		one: "Constructor takes too many arguments",
		many: (n) => `${n} constructors take too many arguments`,
		fix: "The class likely does too much. Split it, or group related dependencies.",
		confidence: "high",
	},
	"Overall Code Complexity": {
		slug: "overall-complexity",
		one: "High average complexity across the file",
		many: () => "High average complexity across the file",
		fix: "Start with the most complex functions in the file; splitting them lowers the average.",
		confidence: "high",
	},
	"Overall Function Size": {
		slug: "overall-function-size",
		one: "Functions are long throughout the file",
		many: () => "Functions are long throughout the file",
		fix: "Extract the natural steps of the long functions into smaller ones.",
		confidence: "high",
	},
	"Primitive Obsession": {
		slug: "primitive-obsession",
		one: "Most arguments are plain strings, numbers or booleans",
		many: () => "Most arguments are plain strings, numbers or booleans",
		fix: "Introduce small types for the domain concepts the arguments stand for, so meaning and validation travel with the value.",
		confidence: "medium",
	},
	"String Heavy Function Arguments": {
		slug: "string-heavy-arguments",
		one: "Most arguments are strings",
		many: () => "Most arguments are strings",
		fix: "Replace strings that stand for domain values with types (a union of literals, a branded type or an object).",
		confidence: "medium",
	},
	"Code Duplication": {
		slug: "duplication",
		one: "Functions repeat each other",
		many: (n) => `${n} functions repeat each other`,
		fix: "Extract what the functions share and pass in what differs.",
		confidence: "medium",
	},
	"Lines of Code in a Single File": {
		slug: "large-file",
		one: "Very large file",
		many: () => "Very large file",
		fix: "Split the file by responsibility.",
		confidence: "high",
	},
};

const MAX_LISTED = 8;

const describe = (s: Smell): string => {
	if (s.detail) return s.detail;
	const listed = s.functions
		.slice(0, MAX_LISTED)
		.map((f) => `${f.name} (${f.detail})`);
	const more = s.functions.length - listed.length;
	return `${listed.join(", ")}${more > 0 ? ` and ${more} more` : ""}`;
};

interface Scored {
	readonly path: string;
	readonly codeLines: number;
	readonly score: number;
	readonly smells: ReadonlyArray<Smell>;
}

const HOTSPOT_NOTE =
	", and it is a hotspot (one of the most often changed files), so this costs on every change";

/** The functions involved, by name: stable while the code changes. */
const evidenceOf = (s: Smell): string => {
	const names = new Set(s.functions.map((f) => f.name.replace(/:\d+$/, "")));
	return [...names].join(", ").slice(0, 160) || s.rule;
};

const severityOf = (s: Smell, hotspot: boolean): Severity =>
	hotspot || s.impact >= 4 ? "medium" : "low";

const findingOf = (file: Scored, s: Smell, hotspot: boolean): FindingInput => {
	const text = RULE_TEXT[s.rule];
	const count = s.functions.length;
	const first = s.functions[0];
	return {
		ruleId: `${ID}/${text.slug}`,
		title: count > 1 ? text.many(count) : text.one,
		severity: severityOf(s, hotspot),
		category: "maintainability",
		message: `${s.rule}: ${describe(s)}. Code Health of ${file.path} is ${file.score.toFixed(1)}/10${hotspot ? HOTSPOT_NOTE : ""}.`,
		location: { file: file.path, ...(first ? { line: first.line } : {}) },
		evidence: evidenceOf(s),
		remediation: text.fix,
		references: [DOCS],
		confidence: text.confidence,
		tags: ["code-health", text.slug],
	};
};

/** LoC-weighted average, as CodeScene aggregates Code Health. */
const weightedAverage = (files: ReadonlyArray<Scored>) => {
	const weight = files.reduce((n, f) => n + f.codeLines, 0);
	return weight
		? files.reduce((n, f) => n + f.score * f.codeLines, 0) / weight
		: 10;
};

interface Overview {
	readonly scored: ReadonlyArray<Scored>;
	readonly hotspots: ReadonlySet<string>;
	/** Why there is no history, when there is none. */
	readonly noHistory: string | undefined;
	/** Rule sets read from the project's rules file. */
	readonly ruleSets: number;
}

const summaryOf = ({
	scored,
	hotspots,
	noHistory,
	ruleSets,
}: Overview): FindingInput => {
	const worst = scored.reduce<Scored | undefined>(
		(w, f) => (!w || f.score < w.score ? f : w),
		undefined,
	);
	const hot = scored.filter((f) => hotspots.has(f.path));
	const below = scored.filter((f) => f.score < 10).length;
	const parts = [
		`Average ${weightedAverage(scored).toFixed(2)}/10 across ${scored.length} files (weighted by lines of code)`,
		hot.length
			? `hotspots ${weightedAverage(hot).toFixed(2)}/10 across ${hot.length} most-changed files`
			: `no hotspots (${noHistory ?? "no history"})`,
		worst ? `worst ${worst.score.toFixed(2)} in ${worst.path}` : "",
		`${below} files below 10`,
		ruleSets ? `${ruleSets} rule sets from ${RULES_FILE} applied` : "",
	].filter(Boolean);
	return {
		ruleId: `${ID}/summary`,
		title: `Code Health ${weightedAverage(scored).toFixed(1)}/10`,
		severity: "info",
		category: "maintainability",
		message: `${parts.join("; ")}.`,
		references: [DOCS],
		tags: ["code-health"],
	};
};

const readRuleSets = (ws: {
	readonly readText: (p: string) => Effect.Effect<string, unknown>;
}) =>
	ws.readText(RULES_FILE).pipe(
		Effect.map((text) => {
			try {
				return parseRulesFile(JSON.parse(text));
			} catch {
				return [];
			}
		}),
		Effect.orElseSucceed((): MatchedRuleSet[] => []),
	);

const loadTypeScript = Effect.tryPromise({
	try: async () => (await import("typescript")).default,
	catch: () => undefined,
}).pipe(Effect.orElseSucceed(() => undefined));

export const codeHealth = defineAuditor({
	id: ID,
	title: "Code Health",
	description:
		"Scores every JavaScript and TypeScript file from 1 to 10 for how easy it is to change, using CodeScene's Code Health rules and thresholds: complex, long and deeply nested functions, complex conditionals, bumpy roads (several chunks of nested logic), too many arguments, duplicated functions, primitive-heavy arguments and large files. Hotspots (the most often changed files in the last year of git history) get a higher severity. Honours `.codescene/code-health-rules.json` and `@codescene(disable:...)` comments.",
	categories: ["maintainability"],
	targets: ["codebase"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const ts = yield* loadTypeScript;
			if (!ts) return yield* skip("The typescript package is not installed.");
			const files = yield* readTextFiles(ws, isAnalyzable);
			if (!files.length)
				return yield* skip("No JavaScript or TypeScript files.");
			const sets = yield* readRuleSets(ws);
			const scored: Scored[] = files.map(({ path, text }) => {
				const metrics = analyzeJs(ts, path, text);
				const smells = smellsOf(
					metrics,
					rulesFor(path, sets),
					isTestPath(path),
				);
				return {
					path,
					codeLines: metrics.codeLines,
					score: scoreOf(smells),
					smells,
				};
			});
			const history = yield* readHistory(ctx, ws.root);
			const hotspots =
				"commits" in history
					? hotspotsOf(
							scored.map((f) => f.path),
							revisionsOf(history.commits),
						)
					: new Set<string>();
			return [
				...scored.flatMap((f) =>
					f.smells.map((s) => findingOf(f, s, hotspots.has(f.path))),
				),
				summaryOf({
					scored,
					hotspots,
					noHistory: "unavailable" in history ? history.unavailable : undefined,
					ruleSets: sets.length,
				}),
			];
		}),
});
