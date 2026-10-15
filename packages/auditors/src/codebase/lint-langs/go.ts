import { tmpdir } from "node:os";
import {
	type Category,
	defineAuditor,
	type FindingInput,
	requireTool,
	requireWorkspace,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, jsonLines, num, parseJson, str } from "../../tool";
import { isRecord, kebab, scrubLine, truncate } from "../util";
import {
	dedupe,
	type FilePath,
	GO_ENV,
	inRoot,
	type LintCode,
	manifestDirs,
	run,
} from "./shared";

/* -------------------------------------------------------------------------- */
/*                                staticcheck                                 */
/* -------------------------------------------------------------------------- */

type LintClass = { category: Category; severity: Severity };

const STATICCHECK_CLASSES: ReadonlyArray<[RegExp, LintClass]> = [
	// SA1019 = use of a deprecated API.
	[/^SA1019$/, { category: "maintainability", severity: "low" }],
	[/^SA/, { category: "reliability", severity: "medium" }],
	// ST (style) and QF (quick fixes).
	[/^(ST|QF)/, { category: "maintainability", severity: "info" }],
];

// Anything else (S1xxx) is a code simplification.
const staticcheckClass = (code: LintCode): LintClass =>
	STATICCHECK_CLASSES.find(([pattern]) => pattern.test(code))?.[1] ?? {
		category: "maintainability",
		severity: "low",
	};

/** Prefixes a module-relative file with the module directory. */
const withPrefix = (prefix: FilePath, file: FilePath | undefined) =>
	file && prefix ? `${prefix}/${file}` : file;

/** A file the tool reported that lies outside the module (dependencies, GOROOT). */
const isForeign = (
	reported: FilePath | undefined,
	file: FilePath | undefined,
) => Boolean(reported) && !file;

type StaticcheckItem = {
	message: string;
	loc: Record<string, unknown>;
	root: FilePath;
	prefix: FilePath;
};

// The package did not type-check; the first `file:line:col:` in the message
// locates it, else the reported location, else the module's go.mod.
const compileLocation = ({ message, loc, root, prefix }: StaticcheckItem) => {
	const m = /^\.?\/?([^\s:]+\.go):(\d+):(\d+):/m.exec(message);
	if (m)
		return {
			file: withPrefix(prefix, m[1]),
			line: Number(m[2]),
			column: Number(m[3]),
		};
	const reported = inRoot(root, str(loc.file));
	if (reported)
		return {
			file: withPrefix(prefix, reported),
			line: num(loc.line),
			column: num(loc.column),
		};
	return { file: withPrefix(prefix, "go.mod") };
};

// Usually a missing dependency or build tag.
const compileFinding = (item: StaticcheckItem): FindingInput => ({
	ruleId: "code.staticcheck/compile-error",
	title: "Go package does not compile",
	severity: "medium",
	category: "reliability",
	message: truncate(item.message.replace(/^#.*\n/, ""), 300),
	location: compileLocation(item),
	remediation:
		"Make the module build (go build ./...); staticcheck cannot analyse packages that fail to type-check.",
	confidence: "low",
	tags: ["go", "compile"],
});

const staticcheckFinding = (
	code: LintCode,
	{ message, loc, root, prefix }: StaticcheckItem,
): FindingInput[] => {
	const file = inRoot(root, str(loc.file));
	if (isForeign(str(loc.file), file)) return [];
	const { category, severity } = staticcheckClass(code);
	return [
		{
			ruleId: `code.staticcheck/${code.toLowerCase()}`,
			title: truncate(message, 100),
			severity,
			category,
			message: `${message} (staticcheck ${code})`,
			location: {
				file: withPrefix(prefix, file),
				line: num(loc.line),
				column: num(loc.column),
			},
			remediation: `See https://staticcheck.dev/docs/checks/#${code} for the rationale and fix.`,
			references: [`https://staticcheck.dev/docs/checks/#${code}`],
			confidence: "high",
			tags: ["go", code.toLowerCase()],
		},
	];
};

/** Parses `staticcheck -f json` (one JSON object per line). */
export const parseStaticcheckReport = (
	stdout: string,
	root: FilePath,
	prefix: FilePath = "",
): FindingInput[] =>
	dedupe(
		jsonLines(stdout).flatMap((item): FindingInput[] => {
			const code = str(item.code) ?? "";
			const parsed: StaticcheckItem = {
				message: str(item.message) ?? code,
				loc: isRecord(item.location) ? item.location : {},
				root,
				prefix,
			};
			if (code === "compile") return [compileFinding(parsed)];
			return code ? staticcheckFinding(code, parsed) : [];
		}),
	);

export const staticcheck = defineAuditor({
	id: "code.staticcheck",
	title: "staticcheck Go lints",
	description:
		"Runs staticcheck over each Go module (go.mod). staticcheck type-checks packages through the Go toolchain, which may download missing modules but never compiles to binaries, runs go:generate or executes the target's code (cgo is disabled and toolchain downloads are blocked). SA checks are medium (likely bugs), S simplifications low, ST style info.",
	categories: ["reliability", "maintainability"],
	targets: ["codebase"],
	engine: "external",
	tool: "staticcheck",
	network: true,
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const modules = manifestDirs(yield* ws.files, "go.mod", true);
			if (modules.length === 0)
				return yield* skip("No go.mod in the workspace");
			const bin = yield* requireTool(
				ctx,
				"staticcheck",
				"Install: brew install staticcheck or go install honnef.co/go/tools/cmd/staticcheck@latest.",
			);
			const findings: FindingInput[] = [];
			for (const dir of modules) {
				// Exit 1 = problems found.
				const res = yield* run(ctx, [bin, "-f", "json", "./..."], {
					cwd: ws.absolute(dir || "."),
					okCodes: [0, 1],
					env: GO_ENV,
				});
				findings.push(
					...parseStaticcheckReport(res.stdout, ws.absolute(dir || "."), dir),
				);
			}
			return findings;
		}),
});

/* -------------------------------------------------------------------------- */
/*                               golangci-lint                                */
/* -------------------------------------------------------------------------- */

/** A golangci-lint linter name, such as `gosec`. */
type Linter = string;

const GOLANGCI_SECURITY = new Set(["gosec", "gas"]);
const GOLANGCI_BUGS = new Set([
	"govet",
	"staticcheck",
	"errcheck",
	"ineffassign",
	"errorlint",
	"nilerr",
	"nilnil",
	"bodyclose",
	"rowserrcheck",
	"sqlclosecheck",
	"contextcheck",
	"copyloopvar",
	"exhaustive",
	"forcetypeassert",
	"makezero",
	"noctx",
	"durationcheck",
	"asasalint",
	"bidichk",
	"typecheck",
]);

// A severity the project assigned in .golangci.yml wins.
const CONFIGURED_SEVERITY = new Map<string, Severity>([
	["error", "high"],
	["info", "info"],
]);

const linterClass = (linter: Linter): LintClass =>
	GOLANGCI_SECURITY.has(linter)
		? { category: "security", severity: "medium" }
		: GOLANGCI_BUGS.has(linter)
			? { category: "reliability", severity: "medium" }
			: { category: "maintainability", severity: "low" };

const golangciClass = (
	linter: Linter,
	configured: string | undefined,
): LintClass => {
	const { category, severity } = linterClass(linter);
	return {
		category,
		severity: CONFIGURED_SEVERITY.get(configured ?? "") ?? severity,
	};
};

const golangciIssue = (
	i: Record<string, unknown>,
	root: FilePath,
	prefix: FilePath,
): FindingInput[] => {
	const linter = str(i.FromLinter) ?? "lint";
	const text = str(i.Text) ?? linter;
	const pos = isRecord(i.Pos) ? i.Pos : {};
	const file = inRoot(root, str(pos.Filename));
	if (isForeign(str(pos.Filename), file)) return [];
	const source = arr(i.SourceLines).find(
		(l): l is string => typeof l === "string",
	);
	const { category, severity } = golangciClass(
		linter,
		str(i.Severity)?.toLowerCase(),
	);
	// gosec (and staticcheck) put the rule id in the text: `G401: ...`.
	const rule = /^([A-Z]{1,3}\d{3,4}):/.exec(text)?.[1];
	return [
		{
			ruleId: `code.golangci-lint/${kebab(linter)}${rule ? `-${rule.toLowerCase()}` : ""}`,
			title: truncate(text, 100),
			severity,
			category,
			message: `${text} (${linter})`,
			location: {
				file: withPrefix(prefix, file),
				line: num(pos.Line),
				column: num(pos.Column),
			},
			evidence: source ? truncate(scrubLine(source)) : undefined,
			remediation:
				"Fix the reported issue, or suppress a justified false positive with `//nolint:<linter> // reason`.",
			references: [`https://golangci-lint.run/usage/linters/#${linter}`],
			confidence: "high",
			tags: ["go", linter],
		},
	];
};

/** Parses `golangci-lint run` JSON output (v1 and v2 share the issue shape). */
export const parseGolangciReport = (
	json: unknown,
	root: FilePath,
	prefix: FilePath = "",
): FindingInput[] => {
	if (!isRecord(json)) return [];
	return dedupe(
		arr(json.Issues).flatMap((i): FindingInput[] =>
			isRecord(i) ? golangciIssue(i, root, prefix) : [],
		),
	);
};

export const golangciLint = defineAuditor({
	id: "code.golangci-lint",
	title: "golangci-lint",
	description:
		"Runs golangci-lint with the project's own .golangci config over each Go module. NOT safe on untrusted code: the config can load Go plugins (.so files and module plugins) that run inside the linter, which is why it is opt-in. Like the other Go wrappers it disables cgo and toolchain downloads and never builds or runs the target. gosec findings are security, bug-class linters (govet, errcheck, staticcheck, ...) reliability, the rest maintainability.",
	categories: ["reliability", "maintainability", "security"],
	targets: ["codebase"],
	engine: "external",
	tool: "golangci-lint",
	network: true,
	defaultEnabled: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const modules = manifestDirs(yield* ws.files, "go.mod", true);
			if (modules.length === 0)
				return yield* skip("No go.mod in the workspace");
			const bin = yield* requireTool(
				ctx,
				"golangci-lint",
				"Install: brew install golangci-lint (https://golangci-lint.run/welcome/install/).",
			);
			const version = yield* run(ctx, [bin, "--version"], {
				cwd: tmpdir(),
				okCodes: [0],
			});
			const v1 = /version\s+v?1\./.test(version.stdout);
			const findings: FindingInput[] = [];
			for (const dir of modules) {
				const res = yield* run(
					ctx,
					[
						bin,
						"run",
						...(v1
							? ["--out-format", "json"]
							: ["--output.json.path", "stdout", "--show-stats=false"]),
						"--issues-exit-code",
						"1",
						"--max-issues-per-linter",
						"0",
						"--max-same-issues",
						"0",
						"--modules-download-mode",
						"readonly",
						"./...",
					],
					{ cwd: ws.absolute(dir || "."), okCodes: [0, 1], env: GO_ENV },
				);
				if (!res.stdout.trim()) continue;
				findings.push(
					...parseGolangciReport(
						yield* parseJson(res.stdout, "golangci-lint"),
						ws.absolute(dir || "."),
						dir,
					),
				);
			}
			return findings;
		}),
});
