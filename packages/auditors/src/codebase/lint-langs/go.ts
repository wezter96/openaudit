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

import { arr, num, parseJson, str } from "../../tool";
import { isRecord, kebab, scrubLine, truncate } from "../util";
import { dedupe, GO_ENV, inRoot, manifestDirs, run } from "./shared";

/* -------------------------------------------------------------------------- */
/*                                staticcheck                                 */
/* -------------------------------------------------------------------------- */

const staticcheckClass = (
	code: string,
): { category: Category; severity: Severity } => {
	// SA1019 = use of a deprecated API.
	if (code === "SA1019")
		return { category: "maintainability", severity: "low" };
	if (code.startsWith("SA"))
		return { category: "reliability", severity: "medium" };
	// ST (style) and QF (quick fixes).
	if (code.startsWith("ST") || code.startsWith("QF"))
		return { category: "maintainability", severity: "info" };
	// S1xxx: code simplifications.
	return { category: "maintainability", severity: "low" };
};

/** Parses `staticcheck -f json` (one JSON object per line). */
export const parseStaticcheckReport = (
	stdout: string,
	root: string,
	prefix = "",
): FindingInput[] =>
	dedupe(
		stdout.split("\n").flatMap((line): FindingInput[] => {
			const text = line.trim();
			if (!text.startsWith("{")) return [];
			let item: unknown;
			try {
				item = JSON.parse(text);
			} catch {
				return [];
			}
			if (!isRecord(item)) return [];
			const code = str(item.code) ?? "";
			const message = str(item.message) ?? code;
			const loc = isRecord(item.location) ? item.location : {};
			const withPrefix = (f: string | undefined) =>
				f && prefix ? `${prefix}/${f}` : f;
			if (code === "compile") {
				// The package did not type-check; the first `file:line:col:` in the
				// message locates it. Usually a missing dependency or build tag.
				const m = /^\.?\/?([^\s:]+\.go):(\d+):(\d+):/m.exec(message);
				return [
					{
						ruleId: "code.staticcheck/compile-error",
						title: "Go package does not compile",
						severity: "medium",
						category: "reliability",
						message: truncate(message.replace(/^#.*\n/, ""), 300),
						location: m
							? {
									file: withPrefix(m[1]),
									line: Number(m[2]),
									column: Number(m[3]),
								}
							: undefined,
						remediation:
							"Make the module build (go build ./...); staticcheck cannot analyse packages that fail to type-check.",
						confidence: "low",
						tags: ["go", "compile"],
					},
				];
			}
			if (!code) return [];
			// Findings in files outside the module (dependencies, GOROOT).
			const file = inRoot(root, str(loc.file));
			if (str(loc.file) && !file) return [];
			const { category, severity } = staticcheckClass(code);
			return [
				{
					ruleId: `code.staticcheck/${code.toLowerCase()}`,
					title: truncate(message, 100),
					severity,
					category,
					message: `${message} (staticcheck ${code})`,
					location: {
						file: withPrefix(file),
						line: num(loc.line),
						column: num(loc.column),
					},
					remediation: `See https://staticcheck.dev/docs/checks/#${code} for the rationale and fix.`,
					references: [`https://staticcheck.dev/docs/checks/#${code}`],
					confidence: "high",
					tags: ["go", code.toLowerCase()],
				},
			];
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

/** Parses `golangci-lint run` JSON output (v1 and v2 share the issue shape). */
export const parseGolangciReport = (
	json: unknown,
	root: string,
	prefix = "",
): FindingInput[] => {
	if (!isRecord(json)) return [];
	return dedupe(
		arr(json.Issues).flatMap((i): FindingInput[] => {
			if (!isRecord(i)) return [];
			const linter = str(i.FromLinter) ?? "lint";
			const text = str(i.Text) ?? linter;
			const pos = isRecord(i.Pos) ? i.Pos : {};
			const file = inRoot(root, str(pos.Filename));
			if (str(pos.Filename) && !file) return [];
			const source = arr(i.SourceLines).find(
				(l): l is string => typeof l === "string",
			);
			const configured = str(i.Severity)?.toLowerCase();
			let category: Category = "maintainability";
			let severity: Severity = "low";
			if (GOLANGCI_SECURITY.has(linter)) {
				category = "security";
				severity = "medium";
			} else if (GOLANGCI_BUGS.has(linter)) {
				category = "reliability";
				severity = "medium";
			}
			// A severity the project assigned in .golangci.yml wins.
			if (configured === "error") severity = "high";
			else if (configured === "info") severity = "info";
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
						file: file && prefix ? `${prefix}/${file}` : file,
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
		}),
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
