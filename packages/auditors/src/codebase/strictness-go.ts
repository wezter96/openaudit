import type { FindingInput, Workspace } from "@openaudit/core";
import { Effect } from "effect";

import {
	byDepth,
	type FilePath,
	finding,
	lineOfIndex,
	SOURCE_LIMIT,
	type SourceLocation,
} from "./strictness-common";
import {
	baseName,
	extOf,
	isGeneratedPath,
	readTextFiles,
	type SourceFile,
} from "./util";

const NOLINT_NOTABLE = 10;
const NOLINT_HEAVY = 30;

const GOLANGCI_CONFIG = new Set([
	".golangci.yml",
	".golangci.yaml",
	".golangci.toml",
	".golangci.json",
]);
const NOLINT = /\/\/\s*nolint\b(?!\w)(:[^\s]*)?/g;

const noGolangciFindings = (
	files: ReadonlyArray<FilePath>,
	rootMod: FilePath,
): FindingInput[] =>
	files.some((f) => GOLANGCI_CONFIG.has(baseName(f)))
		? []
		: [
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
			];

interface NolintStats {
	total: number;
	blanket: number;
	first: SourceLocation | undefined;
	firstBlanket: SourceLocation | undefined;
}

const countNolint = (stats: NolintStats, s: SourceFile) => {
	for (const m of s.text.matchAll(NOLINT)) {
		stats.total++;
		const loc = { file: s.path, line: lineOfIndex(s.text, m.index) };
		stats.first ??= loc;
		// `//nolint` without `:linter` silences every linter on the line.
		if (!m[1]) {
			stats.blanket++;
			stats.firstBlanket ??= loc;
		}
	}
};

const nolintStats = (sources: ReadonlyArray<SourceFile>): NolintStats => {
	const stats: NolintStats = {
		total: 0,
		blanket: 0,
		first: undefined,
		firstBlanket: undefined,
	};
	for (const s of sources) countNolint(stats, s);
	return stats;
};

const densityFindings = (
	{ total, first }: NolintStats,
	fileCount: number,
): FindingInput[] => {
	if (total < NOLINT_NOTABLE || !first) return [];
	return [
		finding("go-nolint-density", {
			title: `${total} //nolint directives`,
			severity: total >= NOLINT_HEAVY ? "low" : "info",
			message: `${total} \`//nolint\` directives across ${fileCount} Go file(s) suppress lint findings instead of fixing them.`,
			remediation:
				"Review the suppressions, fix what can be fixed, and require `//nolint:<linter> // reason` (enable the nolintlint linter) for the rest.",
			file: first.file,
			line: first.line,
			confidence: "medium",
			tags: ["go", "lint"],
		}),
	];
};

const blanketFindings = ({
	blanket,
	firstBlanket,
}: NolintStats): FindingInput[] => {
	if (blanket <= 0 || !firstBlanket) return [];
	return [
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
	];
};

const isGoSource = (p: FilePath) => extOf(p) === "go" && !isGeneratedPath(p);

export const goStrictness = (ws: Workspace, files: ReadonlyArray<FilePath>) =>
	Effect.gen(function* () {
		const rootMod = files
			.filter((f) => baseName(f) === "go.mod")
			.sort(byDepth)[0];
		if (rootMod === undefined) return [];
		const sources = yield* readTextFiles(ws, isGoSource, {
			limit: SOURCE_LIMIT,
		});
		const stats = nolintStats(sources);
		return [
			...noGolangciFindings(files, rootMod),
			...densityFindings(stats, sources.length),
			...blanketFindings(stats),
		];
	});
