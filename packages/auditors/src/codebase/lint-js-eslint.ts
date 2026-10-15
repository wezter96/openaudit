import {
	type AuditContext,
	type Auditor,
	defineAuditor,
	type FindingInput,
	requireTool,
	requireWorkspace,
	skip,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, num, parseJson, relPath, runTool, str } from "../tool";
import {
	type AbsolutePath,
	capFindings,
	IGNORE_ARGS,
	type RelativePath,
} from "./lint-js-shared";
import { lintCategory, lintTags } from "./lint-rules";
import { isRecord, kebab, scrubLine, truncate } from "./util";

/** The opt-in `code.eslint` auditor, which runs the project's own ESLint. */

const ESLINT_CONFIG = /^eslint\.config\.(?:js|mjs|cjs|ts|mts|cts)$/;
const LEGACY_ESLINT_CONFIG = /^\.eslintrc(?:\.|$)/;

/** A rule from ESLint itself, documented on eslint.org. */
const isCoreRule = (ruleId: string | undefined): ruleId is string =>
	ruleId ? !ruleId.includes("/") : false;

const eslintFinding = (
	m: Record<string, unknown>,
	file: RelativePath | undefined,
): FindingInput => {
	const ruleId = str(m.ruleId);
	const message = str(m.message) ?? "ESLint message";
	const level = num(m.severity);
	return {
		ruleId: `code.eslint/${ruleId ? kebab(ruleId) : "parse-error"}`,
		title: truncate(ruleId ? `${ruleId}: ${message}` : message, 120),
		severity: !ruleId || level === 2 ? "medium" : "low",
		category: lintCategory(ruleId),
		message,
		location: { file, line: num(m.line), column: num(m.column) },
		// ESLint's `source` field would echo whole files; only the message is kept.
		evidence: scrubLine(truncate(message)),
		remediation: ruleId
			? "Fix the code, or adjust the rule in the ESLint config."
			: "Fix the syntax error, or check that the parser in the ESLint config supports this file.",
		references: isCoreRule(ruleId)
			? [`https://eslint.org/docs/latest/rules/${ruleId}`]
			: undefined,
		confidence: "high",
		tags: ruleId ? lintTags(ruleId) : ["parse-error"],
	};
};

const fileFindings = (entry: unknown, root: AbsolutePath): FindingInput[] => {
	if (!isRecord(entry)) return [];
	const file = relPath(root, str(entry.filePath));
	return arr(entry.messages)
		.filter(isRecord)
		.map((m) => eslintFinding(m, file));
};

export const parseEslintReport = (
	json: unknown,
	root: AbsolutePath,
): FindingInput[] => arr(json).flatMap((entry) => fileFindings(entry, root));

const noConfigReason = (all: ReadonlyArray<RelativePath>) =>
	all.some((p) => LEGACY_ESLINT_CONFIG.test(p))
		? "Only a legacy .eslintrc config was found; ESLint flat config (eslint.config.js) is required"
		: "No eslint.config.* in the project root";

/** The project's own ESLint matches its config and plugins; PATH is the fallback. */
const eslintBinary = (ctx: AuditContext, ws: Workspace) =>
	Effect.gen(function* () {
		if (yield* ws.exists("node_modules/.bin/eslint"))
			return ws.absolute("node_modules/.bin/eslint");
		return yield* requireTool(
			ctx,
			"eslint",
			"Install the project's dependencies, or: npm install -g eslint.",
		);
	});

export const eslint: Auditor = defineAuditor({
	id: "code.eslint",
	title: "ESLint",
	description:
		"Runs the project's own ESLint with its own flat config, for the rules oxlint and Biome cannot cover (custom and project-specific plugins). A finding for the same rule at the same file and line as one from code.oxlint is merged with it. WARNING: eslint.config.* is JavaScript that runs on load, together with every plugin it imports, so this executes code from the audited project. Opt-in only (--only code.eslint); use on code you trust.",
	categories: [
		"maintainability",
		"reliability",
		"accessibility",
		"performance",
	],
	targets: ["codebase"],
	engine: "external",
	tool: "eslint",
	defaultEnabled: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const all = yield* ws.files;
			if (!all.some((p) => ESLINT_CONFIG.test(p)))
				return yield* skip(noConfigReason(all));
			const bin = yield* eslintBinary(ctx, ws);
			const res = yield* runTool(
				ctx,
				[
					bin,
					"--format",
					"json",
					"--no-error-on-unmatched-pattern",
					...IGNORE_ARGS,
					".",
				],
				ws.root,
				[0, 1],
			);
			const json = yield* parseJson(res.stdout, "eslint");
			return capFindings(
				parseEslintReport(json, ws.root),
				"code.eslint/more-findings",
				"eslint",
			);
		}),
});
