import {
	type Category,
	defineAuditor,
	type FindingInput,
	requireTool,
	requireWorkspace,
	type Severity,
	skip,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, jsonLines, num, parseJson, relPath, str } from "../../tool";
import { baseName, extOf, isRecord, kebab, truncate } from "../util";
import { dedupe, run, withTempDir } from "./shared";

/* -------------------------------------------------------------------------- */
/*                                    ruff                                    */
/* -------------------------------------------------------------------------- */

/**
 * Rules selected when the project has no ruff configuration: pycodestyle
 * errors that signal bugs (E4, E7, E9), pyflakes (F), flake8-bugbear (B),
 * pylint errors (PLE) and flake8-bandit (S).
 */
export const RUFF_DEFAULT_SELECT = "E4,E7,E9,F,B,PLE,S";

/** Rules that are noisy or tidiness-only; reported as info. */
const RUFF_INFO = /^(I|W|D|Q|COM|ISC|E5|UP|RUF100|T20|FA|EM|TD|FIX|ERA|PTH)/;
const RUFF_RELIABILITY_MEDIUM =
	/^(F821|F822|F823|F63\d|F70\d|F5\d\d|F601|F811|PLE|E9)/;
const RUFF_SECURITY_LOW = new Set([
	"S101",
	"S104",
	"S110",
	"S112",
	"S311",
	"S404",
	"S603",
	"S607",
]);

const isRuffCode = (code: string | undefined): code is string =>
	code !== undefined && /^[A-Z]{1,4}\d{1,4}$/.test(code);

/** Parses `ruff check --output-format json`. */
export const parseRuffReport = (json: unknown, root: string): FindingInput[] =>
	arr(json).flatMap((d): FindingInput[] => {
		if (!isRecord(d)) return [];
		const code = str(d.code);
		const name = str(d.name) ?? code ?? "diagnostic";
		const message = str(d.message) ?? name;
		const loc = isRecord(d.location) ? d.location : {};
		const file = relPath(root, str(d.filename));
		const syntax = !isRuffCode(code);
		const fixable = isRecord(d.fix);
		let category: Category = "maintainability";
		let severity: Severity = "low";
		let confidence: "high" | "medium" | "low" = "high";
		if (syntax) {
			category = "reliability";
			severity = "high";
		} else if (code.startsWith("S")) {
			category = "security";
			severity = RUFF_SECURITY_LOW.has(code) ? "low" : "medium";
			confidence = "medium";
		} else if (RUFF_RELIABILITY_MEDIUM.test(code)) {
			category = "reliability";
			severity = "medium";
		} else if (code.startsWith("B")) {
			category = "reliability";
			severity = "low";
		} else if (RUFF_INFO.test(code)) {
			severity = "info";
		}
		const rule = syntax ? "syntax-error" : `${code.toLowerCase()}-${name}`;
		return [
			{
				ruleId: `code.ruff/${rule}`,
				title: truncate(message.replace(/\.$/, ""), 100),
				severity,
				category,
				message: syntax ? message : `${message} (ruff ${code}: ${name})`,
				location: { file, line: num(loc.row), column: num(loc.column) },
				remediation: fixable
					? "Apply the autofix with `ruff check --fix`, or review the rule documentation."
					: "See the ruff rule documentation, or suppress a justified false positive with `# noqa: <code>`.",
				references: str(d.url) ? [str(d.url) as string] : [],
				confidence,
				tags: [
					"python",
					...(syntax ? [] : [code.toLowerCase()]),
					...(fixable ? ["autofixable"] : []),
				],
			},
		];
	});

/** True when the project configures ruff itself (data files only). */
const hasRuffConfig = (ws: Workspace, files: ReadonlyArray<string>) =>
	Effect.gen(function* () {
		if (
			files.some((f) => {
				const b = baseName(f);
				return b === "ruff.toml" || b === ".ruff.toml";
			})
		)
			return true;
		for (const f of files
			.filter((p) => baseName(p) === "pyproject.toml")
			.slice(0, 20)) {
			const text = yield* ws.readText(f).pipe(Effect.orElseSucceed(() => ""));
			if (/^\s*\[tool\.ruff[\].]/m.test(text)) return true;
		}
		return false;
	});

export const ruff = defineAuditor({
	id: "code.ruff",
	title: "Ruff Python lints",
	description: `Runs Ruff over Python sources. Ruff is a standalone Rust binary that parses code and reads pyproject.toml/ruff.toml as plain data; it never imports or executes the target and has no plugin mechanism. When the project has its own ruff configuration it is honoured; otherwise ruff runs with --isolated (no config discovered from parent directories) and the rule set ${RUFF_DEFAULT_SELECT} (pycodestyle errors, pyflakes, bugbear, pylint errors, bandit-like security rules; S rules are skipped in tests/).`,
	categories: ["reliability", "maintainability", "security"],
	targets: ["codebase"],
	engine: "external",
	tool: "ruff",
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const files = yield* ws.files;
			if (!files.some((f) => extOf(f) === "py"))
				return yield* skip("No Python files in the workspace");
			const bin = yield* requireTool(
				ctx,
				"ruff",
				"Install: brew install ruff or pipx install ruff (https://docs.astral.sh/ruff/installation/).",
			);
			const configured = yield* hasRuffConfig(ws, files);
			const res = yield* run(
				ctx,
				[
					bin,
					"check",
					"--output-format",
					"json",
					"--no-cache",
					...(configured
						? []
						: [
								"--isolated",
								"--select",
								RUFF_DEFAULT_SELECT,
								"--extend-per-file-ignores",
								"**/tests/**:S",
								"--extend-per-file-ignores",
								"**/test_*.py:S",
							]),
					".",
				],
				// 1 = violations found.
				{ cwd: ws.root, okCodes: [0, 1] },
			);
			if (!res.stdout.trim()) return [];
			return parseRuffReport(yield* parseJson(res.stdout, "ruff"), ws.root);
		}),
});

/* -------------------------------------------------------------------------- */
/*                                    mypy                                    */
/* -------------------------------------------------------------------------- */

/** Errors about missing annotations or unresolved imports: hygiene. */
const MYPY_HYGIENE = new Set([
	"no-untyped-def",
	"no-untyped-call",
	"no-any-return",
	"no-any-unimported",
	"import-untyped",
	"import-not-found",
	"unused-ignore",
	"unused-awaitable",
	"type-arg",
	"var-annotated",
	"misc",
	"redundant-cast",
	"redundant-expr",
	"explicit-override",
]);
const MYPY_ENVIRONMENT = new Set(["import-untyped", "import-not-found"]);

/** Parses `mypy --output json` (one JSON object per line). */
export const parseMypyReport = (stdout: string, root: string): FindingInput[] =>
	dedupe(
		jsonLines(stdout).flatMap((item): FindingInput[] => {
			if (item.severity !== "error") return [];
			const code = str(item.code) ?? "error";
			const message = str(item.message) ?? code;
			const hint = str(item.hint);
			const hygiene = MYPY_HYGIENE.has(code);
			const column = num(item.column);
			return [
				{
					ruleId: `code.mypy/${kebab(code)}`,
					title: truncate(message, 100),
					severity: hygiene ? "low" : "medium",
					category: hygiene ? "maintainability" : "reliability",
					message: `${message}${hint ? ` (${hint})` : ""} [${code}]`,
					location: {
						file: relPath(root, str(item.file)),
						line: num(item.line),
						// mypy columns are 0-based.
						column: column === undefined ? undefined : column + 1,
					},
					remediation:
						"Fix the type error, or add a narrow `# type: ignore[code]` with a reason if the checker is wrong.",
					references: [
						`https://mypy.readthedocs.io/en/stable/error_code_list.html#code-${code}`,
					],
					confidence: MYPY_ENVIRONMENT.has(code) ? "low" : "high",
					tags: ["python", "typing", code],
				},
			];
		}),
	);

export const mypy = defineAuditor({
	id: "code.mypy",
	title: "mypy type check",
	description:
		"Runs mypy over Python sources with the project's own mypy configuration. NOT safe on untrusted code: mypy.ini, setup.cfg and pyproject.toml can list `plugins` that mypy imports and executes, which is why it is opt-in. mypy uses a throwaway cache dir and never installs stub packages. Imports that cannot be resolved because the project's dependencies are not installed are reported with low confidence.",
	categories: ["reliability", "maintainability"],
	targets: ["codebase"],
	engine: "external",
	tool: "mypy",
	defaultEnabled: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			if (!(yield* ws.files).some((f) => extOf(f) === "py"))
				return yield* skip("No Python files in the workspace");
			const bin = yield* requireTool(
				ctx,
				"mypy",
				"Install: pipx install mypy or brew install mypy (https://mypy.readthedocs.io).",
			);
			const res = yield* withTempDir((cache) =>
				run(
					ctx,
					[
						bin,
						"--output",
						"json",
						"--cache-dir",
						cache,
						"--no-error-summary",
						"--no-color-output",
						"--hide-error-context",
						"--no-install-types",
						"--exclude",
						"(^|/)(\\.venv|venv|env|node_modules|site-packages|build|dist|\\.tox)/",
						".",
					],
					// 1 = type errors found.
					{ cwd: ws.root, okCodes: [0, 1] },
				),
			);
			return parseMypyReport(res.stdout, ws.root);
		}),
});
