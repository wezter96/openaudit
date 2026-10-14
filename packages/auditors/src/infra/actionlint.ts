import {
	AuditorError,
	type Category,
	defineAuditor,
	type FindingInput,
	requireTool,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { isRecord, kebab, scrubLine, truncate } from "../codebase/util";
import { arr, num, parseJson, relPath, str } from "../tool";
import { workflowFiles } from "./shared";

const DOCS = "https://github.com/rhysd/actionlint/blob/main/docs/checks.md";
const INJECTION_DOCS =
	"https://docs.github.com/en/actions/reference/security/secure-use#good-practices-for-mitigating-script-injection-attacks";

const UNTRUSTED_RE = /potentially untrusted/i;

/**
 * actionlint only reports errors, so most kinds map to medium reliability.
 * Script injection (an untrusted expression in `run:`) and credential
 * problems are real security findings; ShellCheck/pyflakes output is advisory.
 */
const classify = (
	kind: string,
	message: string,
): { category: Category; severity: Severity } => {
	if (kind === "expression" && UNTRUSTED_RE.test(message))
		return { category: "security", severity: "high" };
	if (kind === "credentials") return { category: "security", severity: "high" };
	if (kind === "permissions")
		return { category: "security", severity: "medium" };
	if (kind === "shellcheck")
		return {
			category: /SC2086|SC2046|SC2091|SC2006/.test(message)
				? "security"
				: "best-practices",
			severity: "low",
		};
	if (kind === "pyflakes")
		return { category: "best-practices", severity: "low" };
	if (kind === "deprecated-commands")
		return { category: "best-practices", severity: "medium" };
	return { category: "reliability", severity: "medium" };
};

/** Parses `actionlint -format '{{json .}}'` output (a JSON array, or null). */
export const parseActionlintReport = (
	json: unknown,
	root: string,
): FindingInput[] =>
	arr(json).flatMap((raw): FindingInput[] => {
		if (!isRecord(raw)) return [];
		const kind = str(raw.kind) ?? "unknown";
		const message = str(raw.message) ?? kind;
		const { category, severity } = classify(kind, message);
		const injection = kind === "expression" && UNTRUSTED_RE.test(message);
		const snippet = str(raw.snippet)?.split("\n")[0];
		return [
			{
				ruleId: `iac.actionlint/${kebab(kind)}`,
				title: truncate(message.split(/\. see https?:/i)[0] ?? message, 100),
				severity,
				category,
				message,
				remediation: injection
					? "Pass the untrusted value through an environment variable instead of expanding it inside the script."
					: `Fix the reported problem; see the actionlint "${kind}" check documentation.`,
				location: {
					file: relPath(root, str(raw.filepath)),
					line: num(raw.line),
					column: num(raw.column),
				},
				evidence: snippet ? scrubLine(truncate(snippet)) : undefined,
				references: injection ? [DOCS, INJECTION_DOCS] : [DOCS],
				tags: ["actionlint", kind, ...(injection ? ["cwe-94"] : [])],
			},
		];
	});

/** Wraps actionlint, the GitHub Actions workflow linter. */
export const actionlint = defineAuditor({
	id: "iac.actionlint",
	title: "actionlint",
	description:
		"Runs actionlint over GitHub Actions workflows: syntax, expression types, action inputs, script injection, credentials, and (when installed) ShellCheck and pyflakes on run scripts. Read-only; nothing is executed from the target.",
	categories: ["reliability", "best-practices", "security"],
	targets: ["iac"],
	engine: "external",
	tool: "actionlint",
	run: (ctx) =>
		Effect.gen(function* () {
			const { ws, files } = yield* workflowFiles(ctx);
			if (files.length === 0)
				return yield* skip("No GitHub Actions workflows found");
			const bin = yield* requireTool(
				ctx,
				"actionlint",
				"Install: brew install actionlint (https://github.com/rhysd/actionlint/blob/main/docs/install.md).",
			);
			const res = yield* ctx.exec.run(
				[
					bin,
					"-format",
					"{{json .}}",
					"-no-color",
					...files.map((f) => `./${f}`),
				],
				{ cwd: ws.root, timeoutMs: 120_000 },
			);
			// 0 = clean, 1 = problems found, 2+ = bad invocation or fatal error.
			if (res.code > 1)
				return yield* new AuditorError({
					message: `actionlint exited with code ${res.code}: ${truncate(res.stderr || res.stdout, 300)}`,
				});
			return parseActionlintReport(
				yield* parseJson(res.stdout.trim() || "[]", "actionlint"),
				ws.root,
			);
		}),
});
