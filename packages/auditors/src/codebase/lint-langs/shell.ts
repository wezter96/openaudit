import { tmpdir } from "node:os";
import {
	defineAuditor,
	type FindingInput,
	requireTool,
	requireWorkspace,
	type Severity,
	skip,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, num, parseJson, relPath, str } from "../../tool";
import { baseName, extOf, isGeneratedPath, isRecord, truncate } from "../util";
import { dedupe, type FilePath, run, SHELL_FILE_LIMIT } from "./shared";

/* -------------------------------------------------------------------------- */
/*                                 shellcheck                                 */
/* -------------------------------------------------------------------------- */

const SHELLCHECK_SECURITY = new Set([2029, 2046, 2068, 2086, 2091, 2115, 2294]);
const SHELL_EXTS = new Set(["sh", "bash", "ksh", "dash"]);
const SHEBANG = /^#!\s*\S*(?:\/env\s+(?:-\S+\s+)*)?(?:ba|da|k)?sh\b/;
const MAX_SHEBANG_SIZE = 256 * 1024;

/** Shell scripts by extension, or extensionless files with a sh/bash shebang. */
export const findShellScripts = (ws: Workspace) =>
	Effect.gen(function* () {
		const files = (yield* ws.files).filter((f) => !isGeneratedPath(f));
		const scripts = files.filter((f) => SHELL_EXTS.has(extOf(f)));
		const candidates = files
			.filter(
				(f) =>
					extOf(f) === "" &&
					!/^(LICENSE|COPYING|README|Makefile|Dockerfile|Gemfile|Rakefile)/i.test(
						baseName(f),
					),
			)
			.slice(0, 2000);
		for (const f of candidates) {
			if (scripts.length >= SHELL_FILE_LIMIT) break;
			const ok = yield* Effect.gen(function* () {
				if ((yield* ws.size(f)) > MAX_SHEBANG_SIZE) return false;
				const bytes = yield* ws.readBytes(f);
				const head = new TextDecoder().decode(bytes.slice(0, 120));
				return SHEBANG.test(head);
			}).pipe(Effect.orElseSucceed(() => false));
			if (ok) scripts.push(f);
		}
		return scripts.slice(0, SHELL_FILE_LIMIT);
	});

const SHELLCHECK_SEVERITY = new Map<string, Severity>([
	["error", "medium"],
	["warning", "low"],
]);

const shellcheckSeverity = (level: string, security: boolean): Severity => {
	const severity = SHELLCHECK_SEVERITY.get(level) ?? "info";
	// Quoting bugs are injection and globbing hazards.
	return security && severity === "info" ? "low" : severity;
};

const shellcheckComment = (
	c: Record<string, unknown>,
	code: number,
	root: FilePath,
): FindingInput => {
	const level = str(c.level) ?? "style";
	const message = str(c.message) ?? `SC${code}`;
	const security = SHELLCHECK_SECURITY.has(code);
	return {
		ruleId: `code.shellcheck/sc${code}`,
		title: truncate(message, 100),
		severity: shellcheckSeverity(level, security),
		category: security ? "security" : "reliability",
		message: `${message} (SC${code}, ${level})`,
		location: {
			file: relPath(root, str(c.file)),
			line: num(c.line),
			column: num(c.column),
		},
		remediation: isRecord(c.fix)
			? `Apply the suggested quoting/rewrite; see https://www.shellcheck.net/wiki/SC${code}.`
			: `See https://www.shellcheck.net/wiki/SC${code}, or disable a justified false positive with \`# shellcheck disable=SC${code}\`.`,
		references: [`https://www.shellcheck.net/wiki/SC${code}`],
		confidence: "high",
		tags: ["shell", `sc${code}`],
	};
};

/** Parses `shellcheck -f json1` output. */
export const parseShellcheckReport = (
	json: unknown,
	root: FilePath,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	return dedupe(
		arr(json.comments).flatMap((c): FindingInput[] => {
			if (!isRecord(c)) return [];
			const code = num(c.code);
			return code === undefined ? [] : [shellcheckComment(c, code, root)];
		}),
	);
};

export const shellcheck = defineAuditor({
	id: "code.shellcheck",
	title: "ShellCheck",
	description:
		"Runs ShellCheck over *.sh/*.bash/*.ksh files and extensionless files with a sh/bash shebang. ShellCheck only parses scripts; it never executes them. It runs with --norc so a repository's .shellcheckrc (source-path, external-sources, enable=...) cannot change what is read or checked, and from a temp directory with absolute file paths. Errors are medium, warnings low, info/style info; quoting hazards (SC2086, SC2046, SC2115, ...) are reported as security.",
	categories: ["reliability", "security"],
	targets: ["codebase"],
	engine: "external",
	tool: "shellcheck",
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const scripts = yield* findShellScripts(ws);
			if (scripts.length === 0)
				return yield* skip("No shell scripts in the workspace");
			const bin = yield* requireTool(
				ctx,
				"shellcheck",
				"Install: brew install shellcheck (https://github.com/koalaman/shellcheck#installing).",
			);
			const findings: FindingInput[] = [];
			for (let i = 0; i < scripts.length; i += 100) {
				const chunk = scripts.slice(i, i + 100).map((f) => ws.absolute(f));
				const res = yield* run(ctx, [bin, "--norc", "-f", "json1", ...chunk], {
					cwd: tmpdir(),
					// 1 = findings, 2 = some file could not be processed.
					okCodes: [0, 1, 2],
					env: { SHELLCHECK_OPTS: "" },
				});
				if (!res.stdout.trim()) continue;
				findings.push(
					...parseShellcheckReport(
						yield* parseJson(res.stdout, "shellcheck"),
						ws.root,
					),
				);
			}
			return findings;
		}),
});
