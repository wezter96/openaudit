import {
	AuditorError,
	type Category,
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
import { targetFiles } from "./shared";

const WORKFLOW_RE =
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
		if (!ident) return [];
		const locations = arr(raw.locations).filter(isRecord);
		const primary =
			locations.find(
				(l) => isRecord(l.symbolic) && l.symbolic.kind === "Primary",
			) ?? locations[0];
		const symbolic = isRecord(primary?.symbolic) ? primary.symbolic : {};
		const key = isRecord(symbolic.key) ? symbolic.key : {};
		const local = isRecord(key.Local) ? key.Local : {};
		const file = relPath(root, str(local.verbatim_path));
		const concrete = isRecord(primary?.concrete) ? primary.concrete : {};
		const loc = isRecord(concrete.location) ? concrete.location : {};
		const start = isRecord(loc.start_point) ? loc.start_point : {};
		const row = num(start.row);
		const col = num(start.column);
		const determinations = isRecord(raw.determinations)
			? raw.determinations
			: {};
		const desc = str(raw.desc) ?? ident;
		const annotation = str(symbolic.annotation);
		const feature = str(concrete.feature)?.split("\n")[0];
		const fix = arr(raw.fixes).find(isRecord);
		const fixTitle = fix ? str(fix.title) : undefined;
		const url = str(raw.url) ?? `https://docs.zizmor.sh/audits/#${ident}`;
		const category: Category = SUPPLY_CHAIN.has(ident)
			? "supply-chain"
			: "security";
		const cwe = CWE[ident];
		return [
			{
				ruleId: `iac.zizmor/${kebab(ident)}`,
				title: desc,
				severity:
					SEVERITY[String(determinations.severity).toLowerCase()] ?? "medium",
				category,
				message: annotation ? `${desc}: ${annotation}` : desc,
				remediation: fixTitle
					? `Suggested fix: ${fixTitle}. See ${url}`
					: `See the zizmor audit documentation: ${url}`,
				location: {
					file,
					line: row === undefined ? undefined : row + 1,
					column: col === undefined ? undefined : col + 1,
				},
				evidence: feature ? scrubLine(truncate(feature)) : undefined,
				references: [url],
				confidence: CONFIDENCE[String(determinations.confidence).toLowerCase()],
				tags: ["zizmor", ident, ...(cwe ? [cwe] : [])],
			},
		];
	});

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
			const { ws, files } = yield* targetFiles(
				ctx,
				ctx.target.type === "file" ? /\.ya?ml$/ : WORKFLOW_RE,
			);
			if (files.length === 0)
				return yield* skip("No GitHub Actions workflows found");
			const bin = yield* requireTool(
				ctx,
				"zizmor",
				"Install: brew install zizmor, pipx install zizmor or cargo install zizmor (https://docs.zizmor.sh/installation/).",
			);
			const token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN;
			const online = Boolean(token) && !ctx.options.offline;
			const res = yield* ctx.exec.run(
				[
					bin,
					"--format",
					"json",
					...(online ? [] : ["--offline"]),
					// "./" keeps hostile file names from being read as flags.
					...files.map((f) => `./${f}`),
				],
				{
					cwd: ws.root,
					timeoutMs: 5 * 60_000,
					env: online && token ? { GH_TOKEN: token } : undefined,
				},
			);
			// 0 = clean, 10-14 = findings by highest severity/confidence; 1 = error.
			if (res.code !== 0 && !(res.code >= 10 && res.code <= 14))
				return yield* new AuditorError({
					message: `zizmor exited with code ${res.code}: ${truncate(res.stderr || res.stdout, 300)}`,
				});
			return parseZizmorReport(
				yield* parseJson(res.stdout || "[]", "zizmor"),
				ws.root,
			);
		}),
});
