import type { FindingInput, Workspace } from "@openaudit/core";
import { Effect } from "effect";

import {
	asRecord,
	byDepth,
	type FilePath,
	finding,
	parseToml,
	readOrEmpty,
	type SourceText,
} from "./strictness-common";
import { baseName, extOf, isRecord } from "./util";

/** A tool name such as `mypy` or `ruff`. */
type ToolName = string;
/** An INI section name; always one of this module's literals. */
type SectionName = string;

// section is one of this module's literals (mypy, flake8, ...).
const hasSection = (text: SourceText, section: SectionName) =>
	// nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
	new RegExp(`^\\s*\\[${section}\\]`, "m").test(text);

/** The `key = value` lines of an INI section. */
const iniSection = (text: SourceText, section: SectionName): string => {
	// nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
	const m = new RegExp(
		`^\\s*\\[${section}\\]\\s*$([\\s\\S]*?)(?=^\\s*\\[|$(?![\\s\\S]))`,
		"m",
	).exec(text);
	return m?.[1] ?? "";
};

const TRUTHY = /^\s*strict\s*=\s*(true|1|yes|on)\b/im;

interface PythonConfig {
	typeChecker: ToolName | undefined;
	linter: ToolName | undefined;
	mypy: { path: FilePath; strict: boolean } | undefined;
	pyright: { path: FilePath; mode: string } | undefined;
}

/** The project being scanned and the configuration found so far. */
interface PythonScan {
	readonly ws: Workspace;
	readonly files: ReadonlyArray<FilePath>;
	readonly cfg: PythonConfig;
}

const named = (scan: PythonScan, ...names: string[]) =>
	scan.files.filter((f) => names.includes(baseName(f))).sort(byDepth);

const useTypeChecker = (cfg: PythonConfig, name: ToolName) => {
	cfg.typeChecker ??= name;
};

const useLinter = (cfg: PythonConfig, name: ToolName) => {
	cfg.linter ??= name;
};

const iniMypy = (path: FilePath, text: SourceText) => ({
	path,
	strict: TRUTHY.test(iniSection(text, "mypy")),
});

const scanMypyIni = (scan: PythonScan) =>
	Effect.gen(function* () {
		for (const p of named(scan, "mypy.ini", ".mypy.ini").slice(0, 5)) {
			useTypeChecker(scan.cfg, "mypy");
			const text = yield* readOrEmpty(scan.ws, p);
			scan.cfg.mypy ??= iniMypy(p, text);
		}
	});

const scanPyrightConfig = (scan: PythonScan) =>
	Effect.gen(function* () {
		for (const p of named(scan, "pyrightconfig.json").slice(0, 5)) {
			useTypeChecker(scan.cfg, "pyright");
			const text = yield* readOrEmpty(scan.ws, p);
			const mode = /"typeCheckingMode"\s*:\s*"(\w+)"/.exec(text)?.[1];
			scan.cfg.pyright ??= { path: p, mode: mode ?? "standard" };
		}
	});

const scanLinterFiles = (scan: PythonScan) => {
	if (named(scan, "ruff.toml", ".ruff.toml").length > 0)
		useLinter(scan.cfg, "ruff");
	if (named(scan, ".flake8").length > 0) useLinter(scan.cfg, "flake8");
	if (named(scan, ".pylintrc", "pylintrc").length > 0)
		useLinter(scan.cfg, "pylint");
};

/** mypy, flake8 and pylint sections of a setup.cfg or tox.ini. */
const applyIni = (cfg: PythonConfig, path: FilePath, text: SourceText) => {
	if (hasSection(text, "mypy")) {
		useTypeChecker(cfg, "mypy");
		cfg.mypy ??= iniMypy(path, text);
	}
	if (hasSection(text, "flake8")) useLinter(cfg, "flake8");
	if (/^\s*\[(pylint|MESSAGES CONTROL)/im.test(text)) useLinter(cfg, "pylint");
};

const scanIniFiles = (scan: PythonScan) =>
	Effect.gen(function* () {
		for (const p of named(scan, "setup.cfg", "tox.ini").slice(0, 10))
			applyIni(scan.cfg, p, yield* readOrEmpty(scan.ws, p));
	});

const PYRIGHTS = ["basedpyright", "pyright"] as const;

// basedpyright defaults to "recommended", pyright to "standard".
const pyrightMode = (
	name: (typeof PYRIGHTS)[number],
	t: Record<string, unknown>,
): string =>
	typeof t.typeCheckingMode === "string"
		? t.typeCheckingMode
		: name === "basedpyright"
			? "recommended"
			: "standard";

/** `[tool.*]` type checkers of a pyproject.toml. */
const applyTypeCheckers = (
	cfg: PythonConfig,
	path: FilePath,
	tool: Record<string, unknown>,
) => {
	const mypyTool = tool.mypy;
	if (isRecord(mypyTool)) {
		useTypeChecker(cfg, "mypy");
		cfg.mypy ??= { path, strict: mypyTool.strict === true };
	}
	for (const name of PYRIGHTS) {
		const t = tool[name];
		if (!isRecord(t)) continue;
		useTypeChecker(cfg, name);
		cfg.pyright ??= { path, mode: pyrightMode(name, t) };
	}
	for (const name of ["ty", "pyrefly"].filter((n) => isRecord(tool[n])))
		useTypeChecker(cfg, name);
};

/** `[tool.*]` linters of a pyproject.toml. */
const applyLinters = (cfg: PythonConfig, tool: Record<string, unknown>) => {
	if (isRecord(tool.ruff)) useLinter(cfg, "ruff");
	if (isRecord(tool.pylint)) useLinter(cfg, "pylint");
	if (isRecord(tool.flake8)) useLinter(cfg, "flake8");
};

const scanPyproject = (scan: PythonScan) =>
	Effect.gen(function* () {
		for (const p of named(scan, "pyproject.toml").slice(0, 10)) {
			const tool = asRecord(parseToml(yield* readOrEmpty(scan.ws, p)).tool);
			applyTypeCheckers(scan.cfg, p, tool);
			applyLinters(scan.cfg, tool);
		}
	});

const pythonConfig = (ws: Workspace, files: ReadonlyArray<FilePath>) =>
	Effect.gen(function* () {
		const scan: PythonScan = {
			ws,
			files,
			cfg: {
				typeChecker: undefined,
				linter: undefined,
				mypy: undefined,
				pyright: undefined,
			},
		};
		yield* scanMypyIni(scan);
		yield* scanPyrightConfig(scan);
		scanLinterFiles(scan);
		yield* scanIniFiles(scan);
		yield* scanPyproject(scan);
		return scan.cfg;
	});

const noTypeCheckerFindings = (
	cfg: PythonConfig,
	pyFiles: ReadonlyArray<FilePath>,
	anchor: FilePath | undefined,
): FindingInput[] =>
	cfg.typeChecker
		? []
		: [
				finding("python-no-type-checker", {
					title: "No Python type checker is configured",
					severity: "low",
					message: `${pyFiles.length} Python file(s) but no mypy, pyright/basedpyright, ty or pyrefly configuration (pyproject.toml, mypy.ini, setup.cfg, pyrightconfig.json).`,
					remediation:
						'Add a type checker to the project and CI, e.g. `[tool.mypy] strict = true` or `[tool.pyright] typeCheckingMode = "strict"`, and annotate incrementally.',
					file: anchor,
					tags: ["python", "typing"],
				}),
			];

const mypyFindings = (mypy: PythonConfig["mypy"]): FindingInput[] =>
	!mypy || mypy.strict
		? []
		: [
				finding("python-mypy-not-strict", {
					title: "mypy is not in strict mode",
					severity: "info",
					message:
						"mypy is configured without `strict = true`, so untyped functions and implicit `Any` are not reported.",
					remediation:
						"Enable `strict = true` (or at least `disallow_untyped_defs`, `warn_return_any`, `no_implicit_optional`), using per-module overrides for legacy code.",
					file: mypy.path,
					references: [
						"https://mypy.readthedocs.io/en/stable/command_line.html#cmdoption-mypy-strict",
					],
					tags: ["python", "typing", "mypy"],
				}),
			];

const LENIENT_PYRIGHT = new Set(["basic", "off"]);

const pyrightFindings = (pyright: PythonConfig["pyright"]): FindingInput[] =>
	!pyright || !LENIENT_PYRIGHT.has(pyright.mode)
		? []
		: [
				finding("python-pyright-lenient", {
					title: `pyright typeCheckingMode is "${pyright.mode}"`,
					severity: pyright.mode === "off" ? "low" : "info",
					message:
						pyright.mode === "off"
							? 'pyright is configured with `typeCheckingMode = "off"`, which turns type checking off.'
							: 'pyright is configured with `typeCheckingMode = "basic"`, the most lenient mode that still checks types.',
					remediation:
						'Use "standard" (the default) or "strict" and fix or suppress the findings narrowly.',
					file: pyright.path,
					references: [
						"https://microsoft.github.io/pyright/#/configuration?id=type-check-diagnostics-settings",
					],
					tags: ["python", "typing", "pyright"],
				}),
			];

const noLinterFindings = (
	cfg: PythonConfig,
	anchor: FilePath | undefined,
): FindingInput[] =>
	cfg.linter
		? []
		: [
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
			];

export const pythonStrictness = (
	ws: Workspace,
	files: ReadonlyArray<FilePath>,
) =>
	Effect.gen(function* () {
		const pyFiles = files.filter((f) => extOf(f) === "py");
		if (pyFiles.length === 0) return [];
		const cfg = yield* pythonConfig(ws, files);
		const anchor =
			files.find((f) => baseName(f) === "pyproject.toml") ?? pyFiles[0];
		return [
			...noTypeCheckerFindings(cfg, pyFiles, anchor),
			...mypyFindings(cfg.mypy),
			...pyrightFindings(cfg.pyright),
			...noLinterFindings(cfg, anchor),
		];
	});
