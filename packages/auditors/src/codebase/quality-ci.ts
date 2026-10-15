import type { FindingInput, Workspace } from "@openaudit/core";
import { Effect } from "effect";

import type { FilePath, ScriptName, SourceText } from "./quality-types";
import {
	baseName,
	isFixturePath,
	isRecord,
	languageOf,
	parseJsonc,
	readTextFiles,
	type SourceFile,
} from "./util";

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

const stripYamlComments = (text: SourceText) =>
	text
		.split("\n")
		.filter((l) => !/^\s*#/.test(l))
		.join("\n");

const escapeRe = (s: ScriptName) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

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

interface CiExpansion {
	text: SourceText;
	/** Script names and helper paths already appended. */
	readonly added: Set<string>;
}

const invokesScript = (text: SourceText, name: ScriptName) =>
	new RegExp(
		`(?:\\b(?:npm|pnpm|yarn|bun|bunx|npx|turbo|nx|lerna|make|nr)\\b[^\\n]*?[ "'=:])${escapeRe(name)}(?![\\w:.-])`,
	).test(text);

/** Appends the bodies of the package.json scripts the text invokes; true when any were new. */
const addInvokedScripts = (
	expansion: CiExpansion,
	scripts: CiInput["scripts"],
): boolean => {
	let grew = false;
	for (const [name, bodies] of scripts) {
		if (expansion.added.has(name)) continue;
		if (!invokesScript(expansion.text, name)) continue;
		expansion.added.add(name);
		expansion.text += `\n${bodies.join("\n")}`;
		grew = true;
	}
	return grew;
};

const addHelperFiles = (
	expansion: CiExpansion,
	hits: ReadonlyArray<SourceFile>,
): boolean => {
	let grew = false;
	for (const h of hits) {
		if (expansion.added.has(h.path)) continue;
		expansion.added.add(h.path);
		expansion.text += `\n${h.text}`;
		grew = true;
	}
	return grew;
};

/** Appends the helper files (Makefile, ...) the text mentions; true when any were new. */
const addDelegates = (
	expansion: CiExpansion,
	helpers: CiInput["helpers"],
): boolean => {
	let grew = false;
	for (const d of CI_DELEGATES) {
		if (!d.mention.test(expansion.text)) continue;
		const hits = helpers.filter((h) => d.file.test(baseName(h.path)));
		grew = addHelperFiles(expansion, hits) || grew;
	}
	return grew;
};

/**
 * Text that CI effectively runs: the CI files, plus the bodies of the
 * package.json scripts and helper files they invoke (transitively).
 */
export const expandCiText = (input: CiInput): string => {
	const expansion: CiExpansion = {
		text: input.ci.map((f) => stripYamlComments(f.text)).join("\n"),
		added: new Set<string>(),
	};
	for (let round = 0; round < 3; round++) {
		const grewScripts = addInvokedScripts(expansion, input.scripts);
		const grewDelegates = addDelegates(expansion, input.helpers);
		if (!grewScripts && !grewDelegates) break;
	}
	return expansion.text;
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

/* ------------------------------ workspace input ----------------------------- */

const isShellScript = (p: FilePath) =>
	/\.(?:sh|bash)$/.test(p) && !isFixturePath(p);

/** A root-level helper file that CI may delegate to. */
const isRootDelegate = (p: FilePath) =>
	!p.includes("/") && CI_DELEGATES.some((d) => d.file.test(p));

const isPackageManifest = (p: FilePath) =>
	baseName(p) === "package.json" && !isFixturePath(p);

const languageCounts = (
	sources: ReadonlyArray<SourceFile>,
	all: ReadonlyArray<FilePath>,
): Map<string, number> => {
	const languages = new Map<string, number>();
	for (const s of sources) {
		const lang = languageOf(s.path);
		if (lang) languages.set(lang, (languages.get(lang) ?? 0) + 1);
	}
	languages.set("shell", all.filter(isShellScript).length);
	return languages;
};

const addManifestScripts = (
	scripts: Map<string, string[]>,
	manifest: SourceFile,
) => {
	const pkg = parseJsonc(manifest.text);
	if (!isRecord(pkg) || !isRecord(pkg.scripts)) return;
	for (const [name, body] of Object.entries(pkg.scripts))
		if (typeof body === "string")
			scripts.set(name, [...(scripts.get(name) ?? []), body]);
};

const manifestScripts = (
	manifests: ReadonlyArray<SourceFile>,
): Map<string, string[]> => {
	const scripts = new Map<string, string[]>();
	for (const m of manifests) addManifestScripts(scripts, m);
	return scripts;
};

/** CI static-analysis findings, read from the workspace when it has CI files. */
export const ciFindings = (
	ws: Workspace,
	all: ReadonlyArray<FilePath>,
	sources: ReadonlyArray<SourceFile>,
) =>
	Effect.gen(function* () {
		const ciFiles = all.filter((p) => CI_FILE.test(p));
		if (ciFiles.length === 0) return [];
		const languages = languageCounts(sources, all);
		const ci = yield* readTextFiles(ws, (p) => ciFiles.includes(p), {
			allowMinified: true,
		});
		const helpers = yield* readTextFiles(ws, isRootDelegate);
		const manifests = yield* readTextFiles(ws, isPackageManifest, {
			limit: 100,
		});
		const scripts = manifestScripts(manifests);
		return checkCiStaticAnalysis({ ci, scripts, helpers, languages });
	});
