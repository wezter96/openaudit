import { type Auditor, makeWorkspace, resolveTarget } from "@openaudit/core";
import { Effect } from "effect";

import { CONFIG_SCHEMA_URL } from "./config";

/** What `openaudit init` found in the project. */
export interface ProjectFacts {
	readonly technologies: ReadonlyArray<string>;
	/** Project files, relative and POSIX, as the audit sees them. */
	readonly files: ReadonlyArray<string>;
}

const TEST_DIR = /^(test|tests|__tests__|spec|e2e)$/;

/**
 * Directories whose findings are noise by design, as `[glob, reason]`. Only
 * fixtures under a test directory count: elsewhere `fixtures/` can be seed
 * data that ships. `vendor/` and build output are skipped by every auditor
 * already, so they need no entry.
 */
export const noisyPaths = (
	files: ReadonlyArray<string>,
): Array<readonly [string, string]> => {
	const found = new Map<string, string>();
	for (const file of files) {
		const parts = file.split("/").slice(0, -1);
		for (const [i, dir] of parts.entries()) {
			const parent = parts[i - 1] ?? "";
			if (dir === "fixtures" && TEST_DIR.test(parent))
				found.set(
					`**/${parent}/fixtures/**`,
					"Test fixtures: deliberately broken or vulnerable inputs",
				);
			else if (dir === "__fixtures__" || dir === "testdata")
				found.set(
					`**/${dir}/**`,
					"Test fixtures: deliberately broken or vulnerable inputs",
				);
			else if (dir === "third_party" || dir === "third-party")
				found.set(
					`**/${dir}/**`,
					"Vendored third-party code, fixed upstream rather than here",
				);
		}
	}
	return [...found].sort(([a], [b]) => a.localeCompare(b));
};

/** Opt-in auditors worth knowing about, per detected technology. */
const OPT_IN: ReadonlyArray<readonly [string, ReadonlyArray<string>]> = [
	[
		"node",
		["code.dependency-health", "code.eslint", "code.knip", "code.guarddog"],
	],
	["python", ["code.mypy", "code.guarddog"]],
	["go", ["code.govulncheck", "code.golangci-lint"]],
	["rust", ["code.clippy"]],
	["terraform", ["iac.kics"]],
	["kubernetes", ["iac.kubescape", "iac.kics"]],
];

export const suggestedOptIns = (
	technologies: ReadonlyArray<string>,
	auditors: ReadonlyArray<Auditor>,
): string[] => {
	const optIn = new Set(
		auditors
			.filter((a) => a.engine !== "agentic" && a.defaultEnabled === false)
			.map((a) => a.id),
	);
	const ids = [
		...OPT_IN.filter(([tech]) => technologies.includes(tech)).flatMap(
			([, ids]) => ids,
		),
		"code.secrets-history",
	];
	return [...new Set(ids)].filter((id) => optIn.has(id));
};

/** Wraps comment text at about 76 columns, each line prefixed with `indent// `. */
const comment = (indent: string, text: string): string[] => {
	const lines: string[] = [];
	let line = "";
	for (const word of text.split(" ")) {
		if (line && line.length + word.length + 1 > 76) {
			lines.push(`${indent}// ${line}`);
			line = word;
		} else line = line ? `${line} ${word}` : word;
	}
	if (line) lines.push(`${indent}// ${line}`);
	return lines;
};

/** The commented `openaudit.config.jsonc` that `init` writes. */
export const initConfig = (
	facts: ProjectFacts,
	auditors: ReadonlyArray<Auditor>,
): string => {
	const paths = noisyPaths(facts.files).map(
		([path, reason]) =>
			`\t\t\t{ "path": ${JSON.stringify(path)}, "reason": ${JSON.stringify(reason)} }`,
	);
	const optIns = suggestedOptIns(facts.technologies, auditors);
	return [
		"{",
		`\t"$schema": ${JSON.stringify(CONFIG_SCHEMA_URL)},`,
		"\t// Exit 1 when a finding is at least this severe (--fail-on overrides it).",
		'\t"failOn": "high",',
		'\t"ignore": {',
		'\t\t// Each entry: a string, or { "path", "reason", "until": "YYYY-MM-DD" }.',
		'\t\t// Reports count what each entry hides; after "until" it stops applying.',
		paths.length
			? `\t\t"paths": [\n${paths.join(",\n")}\n\t\t],`
			: '\t\t"paths": [],',
		'\t\t"rules": [],',
		'\t\t"fingerprints": []',
		"\t},",
		'\t"options": {',
		"\t\t// A dependency licence policy turns on code.licenses:",
		'\t\t// "settings": { "code.licenses": { "deny": ["AGPL-*", "GPL-*", "SSPL-1.0"] } }',
		"\t}",
		...(optIns.length
			? comment(
					"\t",
					`Opt-in auditors that fit this project: ${optIns.join(", ")}. Run them with --only <id>; a config inside the audited repository cannot turn them on.`,
				)
			: []),
		"\t// Also: openaudit <url> --browser audits a deployed site, --agentic adds AI review.",
		"}",
		"",
	].join("\n");
};

/** Technologies and files of `dir`, through the same detection as an audit. */
export const detectProject = async (dir: string): Promise<ProjectFacts> => {
	const workspace = makeWorkspace(dir);
	const target = await Effect.runPromise(
		resolveTarget(dir, {}, () => workspace),
	);
	const files = await Effect.runPromise(
		workspace.files.pipe(Effect.orElseSucceed(() => [])),
	);
	return { technologies: target.info.technologies, files };
};
