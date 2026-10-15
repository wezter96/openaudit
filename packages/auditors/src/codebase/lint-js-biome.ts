import {
	type Auditor,
	defineAuditor,
	type FindingInput,
	requireTool,
	requireWorkspace,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, num, parseJson, relPath, runTool, str } from "../tool";
import {
	type AbsolutePath,
	capFindings,
	type RelativePath,
	withTempDir,
} from "./lint-js-shared";
import { isRecord, kebab, scrubLine, truncate } from "./util";

/** The `code.biome` auditor: `biome lint` with the project's biome.json. */

type JsonObject = Record<string, unknown>;

const BIOME_CONFIG_FILES = ["biome.json", "biome.jsonc"];
const BIOME_RELIABILITY_GROUPS = new Set([
	"correctness",
	"suspicious",
	"security",
]);
/** Diagnostic categories other than `lint/<group>/<rule>` that are reported. */
const BIOME_OTHER_CATEGORIES = new Set(["parse", "plugin"]);
const BIOME_SEVERITIES = new Map<string, Severity>([
	["error", "medium"],
	["fatal", "medium"],
	["warning", "low"],
]);

/** A diagnostic category such as `lint/suspicious/noDebugger`, split up. */
interface BiomeCategory {
	readonly category: string;
	readonly isLint: boolean;
	readonly group: string;
	readonly rule: string;
}

const biomeCategory = (d: JsonObject): BiomeCategory => {
	const category = str(d.category) ?? "";
	const parts = category.split("/");
	return {
		category,
		isLint: parts[0] === "lint" && parts.length >= 3,
		group: parts[1] ?? "",
		rule: parts[2] ?? "",
	};
};

const isReported = (c: BiomeCategory) =>
	c.isLint || BIOME_OTHER_CATEGORIES.has(c.category);

/** The parts of a finding that depend on whether it is a lint rule. */
interface BiomeKind {
	readonly slug: string;
	readonly severity: Severity;
	readonly category: FindingInput["category"];
	readonly message: string;
	readonly remediation: string;
	readonly references?: string[];
	readonly tags?: string[];
}

const lintKind = (
	c: BiomeCategory,
	d: JsonObject,
	message: string,
): BiomeKind => ({
	slug: kebab(c.rule),
	severity: BIOME_SEVERITIES.get(str(d.severity) ?? "") ?? "info",
	category: BIOME_RELIABILITY_GROUPS.has(c.group)
		? "reliability"
		: "maintainability",
	message: `${message} (${c.group}/${c.rule})`,
	remediation: `Fix the code, or tune the rule in biome.json (see https://biomejs.dev/linter/rules/${kebab(c.rule)}).`,
	references: [`https://biomejs.dev/linter/rules/${kebab(c.rule)}`],
	tags: [c.group],
});

const otherKind = (c: BiomeCategory, message: string): BiomeKind => ({
	slug: c.category === "parse" ? "parse-error" : "plugin",
	severity: "medium",
	category: "reliability",
	message,
	remediation: "Fix the syntax error so the file can be analysed.",
	references: undefined,
	tags: undefined,
});

const biomeLocation = (d: JsonObject, root: AbsolutePath) => {
	const loc = isRecord(d.location) ? d.location : {};
	const start = isRecord(loc.start) ? loc.start : {};
	return {
		file: relPath(root, str(loc.path)),
		line: num(start.line),
		column: num(start.column),
	};
};

const biomeFinding = (
	d: JsonObject,
	c: BiomeCategory,
	root: AbsolutePath,
): FindingInput => {
	const message = str(d.message) ?? "Biome diagnostic";
	const kind = c.isLint ? lintKind(c, d, message) : otherKind(c, message);
	return {
		ruleId: `code.biome/${kind.slug}`,
		title: truncate(message, 120),
		severity: kind.severity,
		category: kind.category,
		message: kind.message,
		location: biomeLocation(d, root),
		evidence: scrubLine(truncate(message)),
		remediation: kind.remediation,
		references: kind.references,
		confidence: "high",
		tags: kind.tags,
	};
};

export const parseBiomeReport = (
	json: unknown,
	root: AbsolutePath,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	return arr(json.diagnostics)
		.filter(isRecord)
		.flatMap((d) => {
			const c = biomeCategory(d);
			return isReported(c) ? [biomeFinding(d, c, root)] : [];
		});
};

const hasBiomeConfig = (all: ReadonlyArray<RelativePath>) =>
	BIOME_CONFIG_FILES.some((c) => all.includes(c));

const biomeCommand = (bin: AbsolutePath, root: AbsolutePath) => [
	bin,
	"lint",
	"--reporter=json",
	"--colors=off",
	"--max-diagnostics=none",
	"--no-errors-on-unmatched",
	`--config-path=${root}`,
	// The temp cwd has no .gitignore; look for it in the target.
	`--vcs-root=${root}`,
	root,
];

export const biome: Auditor = defineAuditor({
	id: "code.biome",
	title: "Biome lint",
	description:
		"Runs `biome lint` when the project has a biome.json(c). Biome configuration is data (GritQL plugins are not JavaScript), the config is loaded explicitly from the target root, and the tool runs from a temp directory.",
	categories: ["maintainability", "reliability"],
	targets: ["codebase"],
	engine: "external",
	tool: "biome",
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			if (!hasBiomeConfig(yield* ws.files))
				return yield* skip("No biome.json or biome.jsonc in the project root");
			const bin = yield* requireTool(
				ctx,
				"biome",
				"Install: npm install -g @biomejs/biome (https://biomejs.dev/guides/getting-started/).",
			);
			return yield* withTempDir("openaudit-biome-", (cwd) =>
				Effect.gen(function* () {
					const res = yield* runTool(
						ctx,
						biomeCommand(bin, ws.root),
						cwd,
						[0, 1],
					);
					const json = yield* parseJson(res.stdout, "biome");
					return capFindings(
						parseBiomeReport(json, ws.root),
						"code.biome/more-findings",
						"biome",
					);
				}),
			);
		}),
});
