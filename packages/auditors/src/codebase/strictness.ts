import {
	type AuditorError,
	defineAuditor,
	type FindingInput,
	requireWorkspace,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import { findShellScripts } from "./lint-langs";
import {
	type FilePath,
	finding,
	readOrEmpty,
	type SourceText,
} from "./strictness-common";
import { goStrictness } from "./strictness-go";
import { pythonStrictness } from "./strictness-python";
import { rustStrictness } from "./strictness-rust";
import { isTestPath } from "./util";

/**
 * Language-specific strictness hygiene for Rust, Python, Go and shell:
 * whether the project configures the compiler/linters/type checkers to catch
 * problems. Reads configuration through the workspace only; nothing is
 * executed. TypeScript strictness is audited elsewhere.
 */

const MAX_SHELL_FINDINGS = 25;

/* -------------------------------------------------------------------------- */
/*                                    Shell                                   */
/* -------------------------------------------------------------------------- */

const SHEBANG_LINE = /^#!.*$/m;

/** One whitespace-separated word of a `set` command. */
type ShellWord = string;

export interface ShellStrictMode {
	errexit: boolean;
	nounset: boolean;
	pipefail: boolean;
}

const LONG_OPTIONS = new Set(["pipefail", "errexit", "nounset"]);

/** `-o <name>`: the option name that follows the flag. */
const applyLongOption = (
	mode: ShellStrictMode,
	name: ShellWord | undefined,
) => {
	if (name && LONG_OPTIONS.has(name))
		mode[name as keyof ShellStrictMode] = true;
};

const applySetFlag = (
	mode: ShellStrictMode,
	flag: ShellWord,
	next: ShellWord | undefined,
) => {
	if (!/^-[a-zA-Z]+$/.test(flag)) return;
	if (flag.includes("e")) mode.errexit = true;
	if (flag.includes("u")) mode.nounset = true;
	if (flag.includes("o")) applyLongOption(mode, next);
};

/** Which of errexit/nounset/pipefail a script enables. */
export const shellStrictMode = (text: SourceText): ShellStrictMode => {
	const code = text
		.split("\n")
		.filter((l) => !/^\s*#/.test(l))
		.join("\n");
	const mode = { errexit: false, nounset: false, pipefail: false };
	for (const m of code.matchAll(/^\s*set\s+([^\n;&|]*)/gm)) {
		const args = (m[1] ?? "").trim().split(/\s+/);
		for (const [i, a] of args.entries()) applySetFlag(mode, a, args[i + 1]);
	}
	return mode;
};

/** Scripts this short are trivial wrappers, not worth flagging. */
const isTrivialScript = (text: SourceText) =>
	text.split("\n").filter((l) => l.trim() && !/^\s*#/.test(l)).length < 4;

const missingFlags = (mode: ShellStrictMode, bashLike: boolean) => [
	...(mode.errexit ? [] : ["-e"]),
	...(mode.nounset ? [] : ["-u"]),
	// pipefail is not POSIX: only expect it from bash/ksh scripts.
	...(mode.pipefail || !bashLike ? [] : ["-o pipefail"]),
];

const scriptFinding = (
	path: FilePath,
	text: SourceText,
): FindingInput | undefined => {
	if (isTrivialScript(text)) return undefined;
	const shebang = SHEBANG_LINE.exec(text)?.[0] ?? "";
	if (/\b(zsh|fish|csh|tcsh)\b/.test(shebang)) return undefined;
	const bashLike = /\b(bash|ksh)\b/.test(shebang);
	const missing = missingFlags(shellStrictMode(text), bashLike);
	if (missing.length === 0) return undefined;
	return finding("shell-missing-strict-mode", {
		title: `Script lacks \`set ${bashLike ? "-euo pipefail" : "-eu"}\``,
		severity: "low",
		message: `The script does not enable ${missing.join(", ")}: failed commands${missing.includes("-u") ? ", unset variables" : ""}${missing.includes("-o pipefail") ? " and failures inside pipelines" : ""} are silently ignored.`,
		remediation: bashLike
			? "Add `set -euo pipefail` near the top, and handle expected failures explicitly with `|| true` or `if`."
			: "Add `set -eu` near the top, and handle expected failures explicitly with `|| true` or `if`.",
		file: path,
		line: 1,
		confidence: "low",
		tags: ["shell"],
	});
};

const shellStrictness = (ws: Workspace) =>
	Effect.gen(function* () {
		const scripts = (yield* findShellScripts(ws)).filter((p) => !isTestPath(p));
		const findings: FindingInput[] = [];
		for (const p of scripts) {
			if (findings.length >= MAX_SHELL_FINDINGS) break;
			const found = scriptFinding(p, yield* readOrEmpty(ws, p));
			if (found) findings.push(found);
		}
		return findings;
	});

/* -------------------------------------------------------------------------- */
/*                                  auditor                                   */
/* -------------------------------------------------------------------------- */

export const strictness = defineAuditor({
	id: "code.strictness",
	title: "Language strictness config",
	description:
		"Checks that Rust, Python, Go and shell projects configure their compilers, linters and type checkers strictly: Cargo [lints], unsafe_code and overflow-checks; a Python type checker (mypy strict, pyright mode) and linter; golangci-lint config and //nolint density; and `set -euo pipefail` in shell scripts. Reads configuration files only; nothing is executed. These are hygiene checks, so severities are info/low and the shell check is low-confidence. TypeScript strictness is covered elsewhere.",
	categories: ["maintainability"],
	targets: ["codebase"],
	engine: "builtin",
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const files = yield* ws.files;
			const parts: ReadonlyArray<Effect.Effect<FindingInput[], AuditorError>> =
				[
					rustStrictness(ws, files),
					pythonStrictness(ws, files),
					goStrictness(ws, files),
					shellStrictness(ws),
				];
			const findings: FindingInput[] = [];
			for (const part of parts) findings.push(...(yield* part));
			return findings;
		}),
});
