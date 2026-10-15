import {
	AuditorError,
	type Confidence,
	defineAuditor,
	type FindingInput,
	requireTool,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { isRecord, kebab, scrubLine, truncate } from "../codebase/util";
import { arr, num, parseJson, relPath, str } from "../tool";
import { workflowFiles } from "./shared";

/** Workflows and composite actions. */
const ACTIONS_RE =
	/(^|\/)(\.github\/workflows\/[^/]+|action)\.ya?ml$|(^|\/)\.github\/actions\/.+\/action\.ya?ml$/;

/** zizmor severities; "Informational"/"Unknown" are advisory only. */
const SEVERITY: Record<string, Severity> = {
	high: "high",
	medium: "medium",
	low: "low",
	informational: "info",
	unknown: "info",
};

const CONFIDENCE: Record<string, Confidence> = {
	high: "high",
	medium: "medium",
	low: "low",
};

/** Audits about what code a workflow pulls in rather than how it is written. */
const SUPPLY_CHAIN = new Set([
	"unpinned-uses",
	"ref-confusion",
	"impostor-commit",
	"known-vulnerable-actions",
	"ref-version-mismatch",
	"archived-uses",
	"stale-action-refs",
	"forbidden-uses",
	"unpinned-images",
	"cache-poisoning",
	"use-trusted-publishing",
	"obfuscation",
]);

const CWE: Record<string, string> = {
	"template-injection": "cwe-94",
	"hardcoded-container-credentials": "cwe-798",
	"excessive-permissions": "cwe-250",
	"dangerous-triggers": "cwe-284",
	"secrets-outside-env": "cwe-522",
};

type FilePath = string;
type Url = string;
/** A zizmor audit id, e.g. `template-injection`. */
type Ident = string;
type JsonObject = Record<string, unknown>;

/** `value[key]` when it is an object, else an empty object. */
const objectAt = (value: JsonObject, key: string): JsonObject => {
	const child = value[key];
	return isRecord(child) ? child : {};
};

const isPrimary = (location: JsonObject): boolean =>
	isRecord(location.symbolic) && location.symbolic.kind === "Primary";

/** The primary location of a finding, else its first one. */
const primaryLocation = (raw: JsonObject): JsonObject => {
	const locations = arr(raw.locations).filter(isRecord);
	return locations.find(isPrimary) ?? locations[0] ?? {};
};

const oneBased = (n: number | undefined): number | undefined =>
	n === undefined ? undefined : n + 1;

/** zizmor's 0-based start point, shifted to a 1-based location. */
const zizmorLocation = (primary: JsonObject, root: FilePath) => {
	const key = objectAt(objectAt(primary, "symbolic"), "key");
	const concrete = objectAt(primary, "concrete");
	const start = objectAt(objectAt(concrete, "location"), "start_point");
	return {
		file: relPath(root, str(objectAt(key, "Local").verbatim_path)),
		line: oneBased(num(start.row)),
		column: oneBased(num(start.column)),
	};
};

const remediationOf = (fixes: unknown, url: Url): string => {
	const fix = arr(fixes).find(isRecord);
	const fixTitle = fix ? str(fix.title) : undefined;
	return fixTitle
		? `Suggested fix: ${fixTitle}. See ${url}`
		: `See the zizmor audit documentation: ${url}`;
};

const zizmorFinding = (
	raw: JsonObject,
	ident: Ident,
	root: FilePath,
): FindingInput => {
	const primary = primaryLocation(raw);
	const determinations = objectAt(raw, "determinations");
	const desc = str(raw.desc) ?? ident;
	const annotation = str(objectAt(primary, "symbolic").annotation);
	const feature = str(objectAt(primary, "concrete").feature)?.split("\n")[0];
	const url = str(raw.url) ?? `https://docs.zizmor.sh/audits/#${ident}`;
	const cwe = CWE[ident];
	return {
		ruleId: `iac.zizmor/${kebab(ident)}`,
		title: desc,
		severity:
			SEVERITY[String(determinations.severity).toLowerCase()] ?? "medium",
		category: SUPPLY_CHAIN.has(ident) ? "supply-chain" : "security",
		message: annotation ? `${desc}: ${annotation}` : desc,
		remediation: remediationOf(raw.fixes, url),
		location: zizmorLocation(primary, root),
		evidence: feature ? scrubLine(truncate(feature)) : undefined,
		references: [url],
		confidence: CONFIDENCE[String(determinations.confidence).toLowerCase()],
		tags: ["zizmor", ident, ...(cwe ? [cwe] : [])],
	};
};

/**
 * Parses `zizmor --format json` output. Locations are 0-based rows/columns in
 * zizmor, so they are shifted to 1-based. Findings zizmor marks as ignored
 * (via `# zizmor: ignore`) are dropped.
 */
export const parseZizmorReport = (
	json: unknown,
	root: string,
): FindingInput[] =>
	arr(json).flatMap((raw): FindingInput[] => {
		if (!isRecord(raw) || raw.ignored === true) return [];
		const ident = str(raw.ident);
		return ident ? [zizmorFinding(raw, ident, root)] : [];
	});

/** The token for zizmor's online audits, or undefined to run offline. */
const onlineToken = (offline: boolean | undefined): string | undefined => {
	const token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN;
	return offline ? undefined : token || undefined;
};

/** 10-14 = findings by highest severity/confidence. */
const isFindingsExit = (code: number): boolean => code >= 10 && code <= 14;

/** 0 = clean, 10-14 = findings; anything else (1 = error) is a failure. */
const isZizmorFailure = (code: number): boolean =>
	code !== 0 && !isFindingsExit(code);

/** Wraps zizmor, a static analyser for GitHub Actions security issues. */
export const zizmor = defineAuditor({
	id: "iac.zizmor",
	title: "zizmor",
	description:
		"Runs zizmor over GitHub Actions workflows and composite actions: template injection, dangerous triggers, excessive permissions, credential persistence, unpinned actions. Runs offline (static audits only); when GH_TOKEN or GITHUB_TOKEN is set it also runs zizmor's online audits, which query the GitHub API for the actions referenced.",
	categories: ["security", "supply-chain"],
	targets: ["iac"],
	engine: "external",
	tool: "zizmor",
	run: (ctx) =>
		Effect.gen(function* () {
			const { ws, files } = yield* workflowFiles(ctx, ACTIONS_RE);
			if (files.length === 0)
				return yield* skip("No GitHub Actions workflows found");
			const bin = yield* requireTool(
				ctx,
				"zizmor",
				"Install: brew install zizmor, pipx install zizmor or cargo install zizmor (https://docs.zizmor.sh/installation/).",
			);
			const token = onlineToken(ctx.options.offline);
			const res = yield* ctx.exec.run(
				[
					bin,
					"--format",
					"json",
					...(token ? [] : ["--offline"]),
					// "./" keeps hostile file names from being read as flags.
					...files.map((f) => `./${f}`),
				],
				{
					cwd: ws.root,
					timeoutMs: 5 * 60_000,
					env: token ? { GH_TOKEN: token } : undefined,
				},
			);
			if (isZizmorFailure(res.code))
				return yield* new AuditorError({
					message: `zizmor exited with code ${res.code}: ${truncate(res.stderr || res.stdout, 300)}`,
				});
			return parseZizmorReport(
				yield* parseJson(res.stdout || "[]", "zizmor"),
				ws.root,
			);
		}),
});
