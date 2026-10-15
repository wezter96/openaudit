import { posix } from "node:path";
import type { FindingInput } from "@openaudit/core";

import type { FilePath, SourceText } from "./quality-types";
import {
	baseName,
	isRecord,
	lineLocator,
	parseJsonc,
	type SourceFile,
} from "./util";

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
	const inheritsNothing =
		options.strict === undefined && json.extends === undefined;
	if (inheritsNothing && baseName(file.path) === "tsconfig.json")
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

type CompilerOptions = Readonly<Record<string, unknown>>;
type TsconfigTexts = ReadonlyMap<FilePath, SourceText>;

interface ResolvedOptions {
	readonly options: CompilerOptions;
	/** False when an `extends` could not be followed (npm package, other folder). */
	readonly complete: boolean;
}

const extendsList = (value: unknown): ReadonlyArray<unknown> =>
	Array.isArray(value) ? value : value === undefined ? [] : [value];

/** The tsconfig a relative `extends` entry points at, when it is in `texts`. */
const resolveExtends = (
	path: FilePath,
	parent: unknown,
	texts: TsconfigTexts,
): FilePath | undefined => {
	if (typeof parent !== "string" || !parent.startsWith(".")) return undefined;
	const target = posix.normalize(posix.join(posix.dirname(path), parent));
	return [target, `${target}.json`].find((t) => texts.has(t));
};

/** compilerOptions of a tsconfig merged along its relative `extends` chain. */
export const resolveTsconfigOptions = (
	path: FilePath,
	texts: TsconfigTexts,
	depth = 0,
): ResolvedOptions => {
	const json = parseJsonc(texts.get(path) ?? "");
	if (!isRecord(json) || depth > 6) return { options: {}, complete: false };
	let options: Record<string, unknown> = {};
	let complete = true;
	for (const parent of extendsList(json.extends)) {
		const resolved = resolveExtends(path, parent, texts);
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
	readonly missing: (options: CompilerOptions) => boolean;
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

interface TsProject {
	readonly path: FilePath;
	readonly options: CompilerOptions;
}

const listsNoFiles = (json: Readonly<Record<string, unknown>>) =>
	Array.isArray(json.files) && json.files.length === 0;

/** A tsconfig.json project whose options could be resolved completely. */
const tsProject = (
	config: SourceFile,
	texts: TsconfigTexts,
): ReadonlyArray<TsProject> => {
	if (baseName(config.path) !== "tsconfig.json") return [];
	const json = parseJsonc(config.text);
	if (!isRecord(json)) return [];
	if (listsNoFiles(json)) return [];
	const { options, complete } = resolveTsconfigOptions(config.path, texts);
	return complete ? [{ path: config.path, options }] : [];
};

const lackingProjects = (
	lacking: ReadonlyArray<TsProject>,
	first: TsProject,
): string =>
	lacking.length === 1
		? first.path
		: `${lacking.length} tsconfig.json files (${lacking
				.slice(0, 3)
				.map((p) => p.path)
				.join(", ")}${lacking.length > 3 ? ", ..." : ""})`;

/** One finding for a flag, located at the first project that lacks it. */
const flagFindings = (
	rule: TsFlagRule,
	projects: ReadonlyArray<TsProject>,
	texts: TsconfigTexts,
): FindingInput[] => {
	const lacking = projects.filter((p) => rule.missing(p.options));
	const first = lacking[0];
	if (!first) return [];
	const text = texts.get(first.path) ?? "";
	const at = text.indexOf("compilerOptions");
	return [
		{
			ruleId: `code.quality/${rule.rule}`,
			title: rule.title,
			severity: rule.severity,
			category: "maintainability",
			message: `${rule.flag} is off in ${lackingProjects(lacking, first)}: ${rule.why}.`,
			location: {
				file: first.path,
				line: at === -1 ? 1 : lineLocator(text)(at),
			},
			evidence: `"${rule.flag}" is not true`,
			remediation: rule.remediation,
			references: [`https://www.typescriptlang.org/tsconfig#${rule.flag}`],
			confidence: "high",
		},
	];
};

/** Strictness flags beyond `strict`, aggregated into one finding per flag. */
export const checkTsStrictness = (
	configs: ReadonlyArray<SourceFile>,
): FindingInput[] => {
	const texts = new Map(configs.map((c) => [c.path, c.text]));
	const projects = configs.flatMap((c) => tsProject(c, texts));
	return TS_FLAG_RULES.flatMap((rule) => flagFindings(rule, projects, texts));
};
