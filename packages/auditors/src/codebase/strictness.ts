import {
	type AuditorError,
	defineAuditor,
	type FindingInput,
	requireWorkspace,
	type Severity,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import { findShellScripts } from "./lint-langs";
import {
	baseName,
	extOf,
	isGeneratedPath,
	isRecord,
	isTestPath,
	nonCodeMask,
	readTextFiles,
} from "./util";

/**
 * Language-specific strictness hygiene for Rust, Python, Go and shell:
 * whether the project configures the compiler/linters/type checkers to catch
 * problems. Reads configuration through the workspace only; nothing is
 * executed. TypeScript strictness is audited elsewhere.
 */

const MANIFEST_LIMIT = 10;
const SOURCE_LIMIT = 2000;
/** Occurrences at or above which usage counts as widespread. */
const UNSAFE_WIDESPREAD = 10;
const NOLINT_NOTABLE = 10;
const NOLINT_HEAVY = 30;
const MAX_SHELL_FINDINGS = 25;

const depth = (path: string) => path.split("/").length;
const byDepth = (a: string, b: string) =>
	depth(a) - depth(b) || a.localeCompare(b);

const finding = (
	rule: string,
	f: {
		title: string;
		severity: Severity;
		message: string;
		remediation: string;
		file?: string;
		line?: number;
		evidence?: string;
		confidence?: "high" | "medium" | "low";
		tags?: ReadonlyArray<string>;
		references?: ReadonlyArray<string>;
	},
): FindingInput => ({
	ruleId: `code.strictness/${rule}`,
	title: f.title,
	severity: f.severity,
	category: "maintainability",
	message: f.message,
	location: f.file ? { file: f.file, line: f.line } : undefined,
	evidence: f.evidence,
	remediation: f.remediation,
	references: f.references ?? [],
	confidence: f.confidence ?? "high",
	tags: ["strictness", ...(f.tags ?? [])],
});

const readOrEmpty = (ws: Workspace, path: string) =>
	ws.readText(path).pipe(Effect.orElseSucceed(() => ""));

const parseToml = (text: string): Record<string, unknown> => {
	try {
		const doc: unknown = Bun.TOML.parse(text);
		return isRecord(doc) ? doc : {};
	} catch {
		return {};
	}
};

const asRecord = (v: unknown): Record<string, unknown> =>
	isRecord(v) ? v : {};

/** `"forbid"` out of `"forbid"` or `{ level = "forbid", priority = -1 }`. */
const lintLevel = (v: unknown): string | undefined =>
	typeof v === "string" ? v : isRecord(v) ? lintLevel(v.level) : undefined;

/* -------------------------------------------------------------------------- */
/*                                    Rust                                    */
/* -------------------------------------------------------------------------- */

interface CargoManifest {
	readonly path: string;
	readonly doc: Record<string, unknown>;
	readonly isPackage: boolean;
	readonly isWorkspace: boolean;
	/** `[lints]`, `[lints] workspace = true` or `[workspace.lints]`. */
	readonly hasLints: boolean;
	readonly unsafeLevel: string | undefined;
}

const parseCargo = (path: string, text: string): CargoManifest => {
	const doc = parseToml(text);
	const workspace = asRecord(doc.workspace);
	const own = asRecord(doc.lints);
	const shared = asRecord(workspace.lints);
	const rust = (t: Record<string, unknown>) => asRecord(t.rust);
	return {
		path,
		doc,
		isPackage: isRecord(doc.package),
		isWorkspace: isRecord(doc.workspace),
		hasLints: Object.keys(own).length > 0 || Object.keys(shared).length > 0,
		unsafeLevel:
			lintLevel(rust(own).unsafe_code) ?? lintLevel(rust(shared).unsafe_code),
	};
};

const FORBIDDING = new Set(["forbid", "deny"]);

const UNSAFE_USE = /\bunsafe\s*(?:\{|fn\b|impl\b|trait\b|extern\b)/g;
const CRATE_FORBIDS_UNSAFE = /#!\[\s*(?:forbid|deny)\s*\([^)]*\bunsafe_code\b/;
const BLANKET_ALLOW =
	/#!?\[\s*allow\s*\([^\]]*\b(clippy::all|clippy::correctness|warnings)\b/g;

const lineOfIndex = (text: string, index: number) => {
	let line = 1;
	for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) line++;
	return line;
};

/** Source with string literals and comments blanked out. */
const codeOnly = (text: string, lang: string) => {
	const mask = nonCodeMask(text, lang);
	let out = "";
	for (let i = 0; i < text.length; i++)
		out += mask[i] && text[i] !== "\n" ? " " : text[i];
	return out;
};

const rustStrictness = (ws: Workspace, files: ReadonlyArray<string>) =>
	Effect.gen(function* () {
		const manifestPaths = files
			.filter((f) => baseName(f) === "Cargo.toml")
			.sort(byDepth)
			.slice(0, MANIFEST_LIMIT);
		if (manifestPaths.length === 0) return [];
		const findings: FindingInput[] = [];
		const manifests: CargoManifest[] = [];
		for (const p of manifestPaths)
			manifests.push(parseCargo(p, yield* readOrEmpty(ws, p)));
		const root = manifests[0] as CargoManifest;
		const anyLints = manifests.some((m) => m.hasLints);

		const sources = yield* readTextFiles(
			ws,
			(p) => extOf(p) === "rs" && !isGeneratedPath(p) && !isTestPath(p),
			{ limit: SOURCE_LIMIT },
		);

		if (!anyLints)
			findings.push(
				finding("rust-no-lints-table", {
					title: "Cargo.toml has no [lints] table",
					severity: "info",
					message:
						"No Cargo.toml configures [lints] (or [workspace.lints]), so compiler and clippy strictness is whatever each developer's command line says.",
					remediation:
						'Add a [lints] table, e.g. `[lints.rust] unsafe_code = "forbid"` and `[lints.clippy] all = { level = "warn", priority = -1 }`, and inherit it in workspace members with `[lints] workspace = true`.',
					file: root.path,
					references: [
						"https://doc.rust-lang.org/cargo/reference/manifest.html#the-lints-section",
					],
					tags: ["rust"],
				}),
			);

		const forbidsInManifest = manifests.some(
			(m) => m.unsafeLevel && FORBIDDING.has(m.unsafeLevel),
		);
		const forbidsInCode = sources.some((s) =>
			CRATE_FORBIDS_UNSAFE.test(s.text),
		);
		let unsafeCount = 0;
		const unsafeFiles = new Set<string>();
		let firstUnsafe: { file: string; line: number } | undefined;
		for (const s of sources) {
			const clean = codeOnly(s.text, "rust");
			for (const m of clean.matchAll(UNSAFE_USE)) {
				unsafeCount++;
				unsafeFiles.add(s.path);
				firstUnsafe ??= { file: s.path, line: lineOfIndex(clean, m.index) };
			}
			for (const m of clean.matchAll(BLANKET_ALLOW))
				findings.push(
					finding("rust-blanket-allow", {
						title: `Blanket \`allow(${m[1]})\` disables lints`,
						severity: "low",
						message: `\`${m[0].trim()}\` switches off ${m[1] === "warnings" ? "every compiler warning" : "clippy's default lint groups"} for the whole crate or module.`,
						remediation:
							"Remove the blanket allow and fix the warnings, or allow individual lints on the specific items that need it, with a reason.",
						file: s.path,
						line: lineOfIndex(clean, m.index),
						evidence: m[0].trim(),
						tags: ["rust", "clippy"],
					}),
				);
		}

		if (!forbidsInManifest && !forbidsInCode)
			findings.push(
				finding("rust-unsafe-not-forbidden", {
					title: "unsafe_code is not forbidden or denied",
					severity: "info",
					message:
						unsafeCount === 0
							? "The code uses no `unsafe`, but nothing stops it from being introduced: unsafe_code is not set to forbid/deny."
							: "unsafe_code is not set to forbid/deny, so new `unsafe` code is not flagged in review or CI.",
					remediation:
						'Set `[lints.rust] unsafe_code = "forbid"` (or "deny" with narrow `#[allow(unsafe_code)]` where required), or `#![forbid(unsafe_code)]` in the crate root.',
					file: root.path,
					tags: ["rust", "unsafe"],
				}),
			);

		if (unsafeCount > 0 && firstUnsafe)
			findings.push(
				finding("rust-unsafe-usage", {
					title: `${unsafeCount} unsafe block${unsafeCount === 1 ? "" : "s"} or item${unsafeCount === 1 ? "" : "s"}`,
					severity: unsafeCount >= UNSAFE_WIDESPREAD ? "low" : "info",
					message: `Found ${unsafeCount} \`unsafe\` block(s), fn(s) or impl(s) in ${unsafeFiles.size} file(s).${unsafeCount >= UNSAFE_WIDESPREAD ? " Widespread unsafe code multiplies the surface for memory-safety bugs." : ""}`,
					remediation:
						"Keep unsafe code small and isolated behind safe APIs, document each block with a `// SAFETY:` comment, and run Miri over it.",
					file: firstUnsafe.file,
					line: firstUnsafe.line,
					confidence: "medium",
					tags: ["rust", "unsafe"],
				}),
			);

		for (const m of manifests) {
			if (!m.isPackage && !m.isWorkspace) continue;
			const release = asRecord(asRecord(m.doc.profile).release);
			// Profiles are only honoured in the workspace root manifest.
			if (m !== root && !m.isWorkspace) continue;
			if (release.panic === "abort")
				findings.push(
					finding("rust-panic-abort", {
						title: 'Release profile sets panic = "abort"',
						severity: "info",
						message:
							'`[profile.release] panic = "abort"` skips unwinding: destructors do not run on panic, `catch_unwind` and panic-isolating test harnesses do not work, and a panic in any thread ends the process.',
						remediation:
							"Fine for many binaries; make sure nothing relies on Drop for cleanup or on catching panics at a boundary.",
						file: m.path,
						tags: ["rust"],
					}),
				);
			if (release["overflow-checks"] !== true)
				findings.push(
					finding("rust-release-overflow-checks-off", {
						title: "Integer overflow checks are off in release builds",
						severity: "info",
						message:
							"`[profile.release] overflow-checks` is not enabled, so arithmetic overflow silently wraps in release builds while panicking in debug builds.",
						remediation:
							"Set `overflow-checks = true` under `[profile.release]` for code that handles untrusted sizes or money, or use checked/saturating arithmetic.",
						file: m.path,
						tags: ["rust"],
					}),
				);
		}
		return findings;
	});

/* -------------------------------------------------------------------------- */
/*                                   Python                                   */
/* -------------------------------------------------------------------------- */

const hasSection = (text: string, section: string) =>
	new RegExp(`^\\s*\\[${section}\\]`, "m").test(text);

/** The `key = value` lines of an INI section. */
const iniSection = (text: string, section: string): string => {
	const m = new RegExp(
		`^\\s*\\[${section}\\]\\s*$([\\s\\S]*?)(?=^\\s*\\[|$(?![\\s\\S]))`,
		"m",
	).exec(text);
	return m?.[1] ?? "";
};

const TRUTHY = /^\s*strict\s*=\s*(true|1|yes|on)\b/im;

interface PythonConfig {
	typeChecker: string | undefined;
	linter: string | undefined;
	mypy: { path: string; strict: boolean } | undefined;
	pyright: { path: string; mode: string } | undefined;
}

const pythonConfig = (ws: Workspace, files: ReadonlyArray<string>) =>
	Effect.gen(function* () {
		const cfg: PythonConfig = {
			typeChecker: undefined,
			linter: undefined,
			mypy: undefined,
			pyright: undefined,
		};
		const named = (...names: string[]) =>
			files.filter((f) => names.includes(baseName(f))).sort(byDepth);
		const typeChecker = (name: string) => {
			cfg.typeChecker ??= name;
		};
		const linter = (name: string) => {
			cfg.linter ??= name;
		};

		for (const p of named("mypy.ini", ".mypy.ini").slice(0, 5)) {
			typeChecker("mypy");
			const text = yield* readOrEmpty(ws, p);
			cfg.mypy ??= { path: p, strict: TRUTHY.test(iniSection(text, "mypy")) };
		}
		for (const p of named("pyrightconfig.json").slice(0, 5)) {
			typeChecker("pyright");
			const text = yield* readOrEmpty(ws, p);
			const mode = /"typeCheckingMode"\s*:\s*"(\w+)"/.exec(text)?.[1];
			cfg.pyright ??= { path: p, mode: mode ?? "standard" };
		}
		if (named("ruff.toml", ".ruff.toml").length > 0) linter("ruff");
		if (named(".flake8").length > 0) linter("flake8");
		if (named(".pylintrc", "pylintrc").length > 0) linter("pylint");
		for (const p of named("setup.cfg", "tox.ini").slice(0, 10)) {
			const text = yield* readOrEmpty(ws, p);
			if (hasSection(text, "mypy")) {
				typeChecker("mypy");
				cfg.mypy ??= { path: p, strict: TRUTHY.test(iniSection(text, "mypy")) };
			}
			if (hasSection(text, "flake8")) linter("flake8");
			if (/^\s*\[(pylint|MESSAGES CONTROL)/im.test(text)) linter("pylint");
		}
		for (const p of named("pyproject.toml").slice(0, 10)) {
			const tool = asRecord(parseToml(yield* readOrEmpty(ws, p)).tool);
			const mypyTool = tool.mypy;
			if (isRecord(mypyTool)) {
				typeChecker("mypy");
				cfg.mypy ??= { path: p, strict: mypyTool.strict === true };
			}
			for (const name of ["basedpyright", "pyright"] as const) {
				const t = tool[name];
				if (!isRecord(t)) continue;
				typeChecker(name);
				cfg.pyright ??= {
					path: p,
					// basedpyright defaults to "recommended", pyright to "standard".
					mode:
						typeof t.typeCheckingMode === "string"
							? t.typeCheckingMode
							: name === "basedpyright"
								? "recommended"
								: "standard",
				};
			}
			for (const name of ["ty", "pyrefly"])
				if (isRecord(tool[name])) typeChecker(name);
			if (isRecord(tool.ruff)) linter("ruff");
			if (isRecord(tool.pylint)) linter("pylint");
			if (isRecord(tool.flake8)) linter("flake8");
		}
		return cfg;
	});

const pythonStrictness = (ws: Workspace, files: ReadonlyArray<string>) =>
	Effect.gen(function* () {
		const pyFiles = files.filter((f) => extOf(f) === "py");
		if (pyFiles.length === 0) return [];
		const cfg = yield* pythonConfig(ws, files);
		const findings: FindingInput[] = [];
		const anchor =
			files.find((f) => baseName(f) === "pyproject.toml") ?? pyFiles[0];

		if (!cfg.typeChecker)
			findings.push(
				finding("python-no-type-checker", {
					title: "No Python type checker is configured",
					severity: "low",
					message: `${pyFiles.length} Python file(s) but no mypy, pyright/basedpyright, ty or pyrefly configuration (pyproject.toml, mypy.ini, setup.cfg, pyrightconfig.json).`,
					remediation:
						'Add a type checker to the project and CI, e.g. `[tool.mypy] strict = true` or `[tool.pyright] typeCheckingMode = "strict"`, and annotate incrementally.',
					file: anchor,
					tags: ["python", "typing"],
				}),
			);
		if (cfg.mypy && !cfg.mypy.strict)
			findings.push(
				finding("python-mypy-not-strict", {
					title: "mypy is not in strict mode",
					severity: "info",
					message:
						"mypy is configured without `strict = true`, so untyped functions and implicit `Any` are not reported.",
					remediation:
						"Enable `strict = true` (or at least `disallow_untyped_defs`, `warn_return_any`, `no_implicit_optional`), using per-module overrides for legacy code.",
					file: cfg.mypy.path,
					references: [
						"https://mypy.readthedocs.io/en/stable/command_line.html#cmdoption-mypy-strict",
					],
					tags: ["python", "typing", "mypy"],
				}),
			);
		if (
			cfg.pyright &&
			(cfg.pyright.mode === "basic" || cfg.pyright.mode === "off")
		)
			findings.push(
				finding("python-pyright-lenient", {
					title: `pyright typeCheckingMode is "${cfg.pyright.mode}"`,
					severity: cfg.pyright.mode === "off" ? "low" : "info",
					message:
						cfg.pyright.mode === "off"
							? 'pyright is configured with `typeCheckingMode = "off"`, which turns type checking off.'
							: 'pyright is configured with `typeCheckingMode = "basic"`, the most lenient mode that still checks types.',
					remediation:
						'Use "standard" (the default) or "strict" and fix or suppress the findings narrowly.',
					file: cfg.pyright.path,
					references: [
						"https://microsoft.github.io/pyright/#/configuration?id=type-check-diagnostics-settings",
					],
					tags: ["python", "typing", "pyright"],
				}),
			);
		if (!cfg.linter)
			findings.push(
				finding("python-no-linter-config", {
					title: "No Python linter configuration found",
					severity: "low",
					message:
						"No ruff, flake8 or pylint configuration (ruff.toml, [tool.ruff], .flake8, .pylintrc, setup.cfg) was found.",
					remediation:
						"Add a ruff configuration (`[tool.ruff.lint] select = [...]` in pyproject.toml) and run it in CI.",
					file: anchor,
					tags: ["python", "lint"],
				}),
			);
		return findings;
	});

/* -------------------------------------------------------------------------- */
/*                                     Go                                     */
/* -------------------------------------------------------------------------- */

const GOLANGCI_CONFIG = new Set([
	".golangci.yml",
	".golangci.yaml",
	".golangci.toml",
	".golangci.json",
]);
const NOLINT = /\/\/\s*nolint\b(?!\w)(:[^\s]*)?/g;

const goStrictness = (ws: Workspace, files: ReadonlyArray<string>) =>
	Effect.gen(function* () {
		const mods = files.filter((f) => baseName(f) === "go.mod").sort(byDepth);
		if (mods.length === 0) return [];
		const findings: FindingInput[] = [];
		const rootMod = mods[0] as string;
		if (!files.some((f) => GOLANGCI_CONFIG.has(baseName(f))))
			findings.push(
				finding("go-no-golangci-config", {
					title: "No golangci-lint configuration",
					severity: "info",
					message:
						"No .golangci.yml/.yaml/.toml/.json was found, so lint strictness depends on golangci-lint's small default set (errcheck, govet, ineffassign, staticcheck, unused).",
					remediation:
						"Commit a .golangci.yml that enables the linters you want (e.g. gosec, errorlint, bodyclose, gocritic) and run it in CI.",
					file: rootMod,
					references: ["https://golangci-lint.run/usage/configuration/"],
					tags: ["go", "lint"],
				}),
			);

		const sources = yield* readTextFiles(
			ws,
			(p) => extOf(p) === "go" && !isGeneratedPath(p),
			{ limit: SOURCE_LIMIT },
		);
		let total = 0;
		let blanket = 0;
		let first: { file: string; line: number } | undefined;
		let firstBlanket: { file: string; line: number } | undefined;
		for (const s of sources) {
			for (const m of s.text.matchAll(NOLINT)) {
				total++;
				const loc = { file: s.path, line: lineOfIndex(s.text, m.index) };
				first ??= loc;
				// `//nolint` without `:linter` silences every linter on the line.
				if (!m[1]) {
					blanket++;
					firstBlanket ??= loc;
				}
			}
		}
		if (total >= NOLINT_NOTABLE && first)
			findings.push(
				finding("go-nolint-density", {
					title: `${total} //nolint directives`,
					severity: total >= NOLINT_HEAVY ? "low" : "info",
					message: `${total} \`//nolint\` directives across ${sources.length} Go file(s) suppress lint findings instead of fixing them.`,
					remediation:
						"Review the suppressions, fix what can be fixed, and require `//nolint:<linter> // reason` (enable the nolintlint linter) for the rest.",
					file: first.file,
					line: first.line,
					confidence: "medium",
					tags: ["go", "lint"],
				}),
			);
		if (blanket > 0 && firstBlanket)
			findings.push(
				finding("go-blanket-nolint", {
					title: `${blanket} blanket //nolint directive${blanket === 1 ? "" : "s"}`,
					severity: "info",
					message: `${blanket} \`//nolint\` directive(s) name no linter, so they silence every linter on that line, including ones added later.`,
					remediation:
						"Name the linter and the reason: `//nolint:errcheck // best-effort cleanup`.",
					file: firstBlanket.file,
					line: firstBlanket.line,
					confidence: "medium",
					tags: ["go", "lint"],
				}),
			);
		return findings;
	});

/* -------------------------------------------------------------------------- */
/*                                    Shell                                   */
/* -------------------------------------------------------------------------- */

const SHEBANG_LINE = /^#!.*$/m;

/** Which of errexit/nounset/pipefail a script enables. */
export const shellStrictMode = (
	text: string,
): { errexit: boolean; nounset: boolean; pipefail: boolean } => {
	const code = text
		.split("\n")
		.filter((l) => !/^\s*#/.test(l))
		.join("\n");
	let errexit = false;
	let nounset = false;
	let pipefail = false;
	for (const m of code.matchAll(/^\s*set\s+([^\n;&|]*)/gm)) {
		const args = (m[1] ?? "").trim().split(/\s+/);
		for (let i = 0; i < args.length; i++) {
			const a = args[i] ?? "";
			if (/^-[a-zA-Z]+$/.test(a)) {
				if (a.includes("e")) errexit = true;
				if (a.includes("u")) nounset = true;
				if (a.includes("o") && args[i + 1]) {
					if (args[i + 1] === "pipefail") pipefail = true;
					if (args[i + 1] === "errexit") errexit = true;
					if (args[i + 1] === "nounset") nounset = true;
				}
			}
		}
	}
	return { errexit, nounset, pipefail };
};

const shellStrictness = (ws: Workspace) =>
	Effect.gen(function* () {
		const scripts = (yield* findShellScripts(ws)).filter((p) => !isTestPath(p));
		const findings: FindingInput[] = [];
		for (const p of scripts) {
			if (findings.length >= MAX_SHELL_FINDINGS) break;
			const text = yield* readOrEmpty(ws, p);
			const lines = text
				.split("\n")
				.filter((l) => l.trim() && !/^\s*#/.test(l));
			// Trivial wrappers are not worth flagging.
			if (lines.length < 4) continue;
			const shebang = SHEBANG_LINE.exec(text)?.[0] ?? "";
			if (/\b(zsh|fish|csh|tcsh)\b/.test(shebang)) continue;
			const bashLike = /\b(bash|ksh)\b/.test(shebang);
			const mode = shellStrictMode(text);
			const missing = [
				...(mode.errexit ? [] : ["-e"]),
				...(mode.nounset ? [] : ["-u"]),
				// pipefail is not POSIX: only expect it from bash/ksh scripts.
				...(mode.pipefail || !bashLike ? [] : ["-o pipefail"]),
			];
			if (missing.length === 0) continue;
			findings.push(
				finding("shell-missing-strict-mode", {
					title: `Script lacks \`set ${bashLike ? "-euo pipefail" : "-eu"}\``,
					severity: "low",
					message: `The script does not enable ${missing.join(", ")}: failed commands${missing.includes("-u") ? ", unset variables" : ""}${missing.includes("-o pipefail") ? " and failures inside pipelines" : ""} are silently ignored.`,
					remediation: bashLike
						? "Add `set -euo pipefail` near the top, and handle expected failures explicitly with `|| true` or `if`."
						: "Add `set -eu` near the top, and handle expected failures explicitly with `|| true` or `if`.",
					file: p,
					line: 1,
					confidence: "low",
					tags: ["shell"],
				}),
			);
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
