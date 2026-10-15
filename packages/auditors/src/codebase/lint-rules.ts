import type { Category } from "@openaudit/core";

/**
 * How JS/TS lint rules are classified, shared by code.oxlint and code.eslint:
 * the openaudit category of a rule, its correlation tags, and the ESLint id of
 * an oxlint rule.
 */

/** Rules that point at likely runtime bugs rather than style. */
const RELIABILITY_RULE =
	/use-isnan|const-comparisons|no-unsafe-negation|no-self-assign|no-dupe|no-unreachable|no-undef\b|no-const-assign|no-cond-assign|no-unsafe-optional-chaining|no-fallthrough|valid-typeof|no-compare-neg-zero|no-setter-return|no-empty-pattern|no-sparse-array|no-loss-of-precision|no-constant-condition|no-global-assign|no-obj-calls|require-yield|no-this-before-super|getter-return|no-async-promise-executor|no-floating|no-misused|no-unsafe-|noUnreachable|useIsNan|noSelfAssign|noConstAssign|noGlobalAssign|noUndeclared|noInvalid|noUnsafe|useValidTypeof|useYield|noFallthrough|noDuplicate|noCompareNegZero|noSparseArray/;

/** Next.js rules about loading speed rather than correctness. */
const NEXT_PERFORMANCE_RULES = new Set([
	"google-font-display",
	"google-font-preconnect",
	"next-script-for-ga",
	"no-css-tags",
	"no-img-element",
	"no-page-custom-font",
	"no-sync-scripts",
	"no-unwanted-polyfillio",
]);

/** Category of a lint rule, by its ESLint id (or bare rule name). */
export const lintCategory = (rule: string | undefined): Category => {
	if (!rule) return "reliability";
	if (rule.startsWith("jsx-a11y/")) return "accessibility";
	if (rule.startsWith("react-hooks/")) return "reliability";
	if (rule.startsWith("@next/next/"))
		return NEXT_PERFORMANCE_RULES.has(rule.slice("@next/next/".length))
			? "performance"
			: "reliability";
	return RELIABILITY_RULE.test(rule) ? "reliability" : "maintainability";
};

/**
 * WCAG success criteria of jsx-a11y rules, only where the rule tests one
 * directly. Where code.accessibility has a twin rule they share a criterion,
 * so the engine merges the two reports of one element.
 */
const JSX_A11Y_WCAG: Readonly<Record<string, ReadonlyArray<string>>> = {
	"alt-text": ["1.1.1"],
	"anchor-ambiguous-text": ["2.4.4"],
	"anchor-has-content": ["2.4.4", "4.1.2"],
	"anchor-is-valid": ["2.1.1"],
	"aria-props": ["4.1.2"],
	"aria-proptypes": ["4.1.2"],
	"aria-role": ["4.1.2"],
	"autocomplete-valid": ["1.3.5"],
	"click-events-have-key-events": ["2.1.1"],
	"control-has-associated-label": ["4.1.2"],
	"html-has-lang": ["3.1.1"],
	"iframe-has-title": ["4.1.2"],
	"interactive-supports-focus": ["2.1.1"],
	"label-has-associated-control": ["1.3.1", "3.3.2", "4.1.2"],
	lang: ["3.1.1"],
	"media-has-caption": ["1.2.2"],
	"mouse-events-have-key-events": ["2.1.1"],
	"no-aria-hidden-on-focusable": ["4.1.2"],
	"no-autofocus": ["2.4.3", "3.2.1"],
	"no-distracting-elements": ["2.2.2"],
	"no-noninteractive-element-interactions": ["4.1.2"],
	"no-static-element-interactions": ["4.1.2"],
	"role-has-required-aria-props": ["4.1.2"],
	"role-supports-aria-props": ["4.1.2"],
	"tabindex-no-positive": ["2.4.3"],
};

/**
 * typescript-eslint rules that replace the core rule of the same name; oxlint
 * reports the core rule for TypeScript files.
 */
const TS_EXTENSION_RULES = new Set([
	"class-methods-use-this",
	"consistent-return",
	"default-param-last",
	"dot-notation",
	"init-declarations",
	"max-params",
	"no-array-constructor",
	"no-dupe-class-members",
	"no-empty-function",
	"no-implied-eval",
	"no-invalid-this",
	"no-loop-func",
	"no-magic-numbers",
	"no-redeclare",
	"no-restricted-imports",
	"no-shadow",
	"no-unused-expressions",
	"no-unused-vars",
	"no-use-before-define",
	"no-useless-constructor",
	"prefer-destructuring",
]);

/** typescript-eslint extension rules merge with the core rule they extend. */
const eslintKey = (lower: string): string => {
	const ts = /^@typescript-eslint\/(.+)$/.exec(lower)?.[1];
	return ts && TS_EXTENSION_RULES.has(ts) ? ts : lower;
};

const wcagCriteria = (lower: string) => {
	const a11y = /^jsx-a11y\/(.+)$/.exec(lower)?.[1];
	return a11y ? JSX_A11Y_WCAG[a11y] || [] : [];
};

/**
 * Tags of an ESLint rule id: `eslint:<id>`, the key correlate merges code.eslint
 * and code.oxlint findings on, plus WCAG criteria for jsx-a11y rules.
 */
export const lintTags = (id: string): string[] => {
	const lower = id.toLowerCase();
	return [
		`eslint:${eslintKey(lower)}`,
		...wcagCriteria(lower).map((sc) => `wcag-${sc}`),
	];
};

/**
 * React Compiler rules, which eslint-plugin-react-hooks ships and oxlint files
 * under its `react` plugin.
 */
const REACT_HOOKS_RULES = new Set([
	"capitalized-calls",
	"error-boundaries",
	"exhaustive-effect-dependencies",
	"globals",
	"hooks",
	"immutability",
	"incompatible-library",
	"invariant",
	"memo-dependencies",
	"no-deriving-state-in-effects",
	"preserve-manual-memoization",
	"purity",
	"refs",
	"rule-suppression",
	"set-state-in-effect",
	"set-state-in-render",
	"static-components",
	"syntax",
	"todo",
	"unsupported-syntax",
	"use-memo",
	"void-use-memo",
]);

/** ESLint plugin prefixes of oxlint plugins whose names differ. */
const OXLINT_ESLINT_PREFIX: Readonly<Record<string, string>> = {
	next: "@next/next",
	node: "n",
	typescript: "@typescript-eslint",
	"typescript-eslint": "@typescript-eslint",
};

/**
 * The ESLint id of an oxlint rule (`react-hooks(exhaustive-deps)` is
 * `react-hooks/exhaustive-deps`), or undefined for oxc's own rules.
 */
export const oxlintEslintId = (
	plugin: string,
	rule: string,
): string | undefined => {
	if (plugin === "oxc") return undefined;
	if (plugin === "eslint") return rule;
	if (plugin === "react" && REACT_HOOKS_RULES.has(rule))
		return `react-hooks/${rule}`;
	return `${OXLINT_ESLINT_PREFIX[plugin] ?? plugin}/${rule}`;
};
