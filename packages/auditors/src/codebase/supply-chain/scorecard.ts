import {
	defineAuditor,
	type FindingInput,
	requireTool,
	requireWorkspace,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, num, parseJson, str } from "../../tool";
import { isRecord, kebab, truncate } from "../util";
import { type Json, strings } from "./report";
import { lower, run } from "./shared";

/* -------------------------------------------------------------------------- */
/*                                  scorecard                                 */
/* -------------------------------------------------------------------------- */

/** Risk per check, from https://github.com/ossf/scorecard/blob/main/docs/checks.md. */
const SCORECARD_RISK: Record<string, Severity> = {
	"Dangerous-Workflow": "critical",
	Webhooks: "critical",
	"Binary-Artifacts": "high",
	"Branch-Protection": "high",
	"Code-Review": "high",
	"Dependency-Update-Tool": "high",
	Maintained: "high",
	"Signed-Releases": "high",
	"Token-Permissions": "high",
	Vulnerabilities: "high",
	Fuzzing: "medium",
	Packaging: "medium",
	"Pinned-Dependencies": "medium",
	SAST: "medium",
	"Security-Policy": "medium",
	"CI-Tests": "low",
	"CII-Best-Practices": "low",
	Contributors: "low",
	License: "low",
};

/** Risk lowered by how well the repository scored: 0-3 keeps it, 4-6 -1, 7-9 -2. */
export const scorecardSeverity = (risk: Severity, score: number): Severity =>
	lower(risk, score <= 3 ? 0 : score <= 6 ? 1 : 2);

/** Inconclusive (-1) and perfect scores need no attention. */
const needsAttention = (score: number | undefined): score is number =>
	score !== undefined && score >= 0 && score < 10;

/** `--show-details` lists passing "Info:" lines too; the problems are the "Warn:" ones. */
const checkDetails = (check: Json) => {
	const lines = strings(check.details);
	const warnings = lines.filter((d) => d.startsWith("Warn:"));
	return warnings.length > 0 ? warnings : lines;
};

const checkFinding = (
	c: Json,
	{ name, score }: { readonly name: string; readonly score: number },
	repo: string | undefined,
): FindingInput => {
	const doc = isRecord(c.documentation) ? c.documentation : {};
	const url =
		str(doc.url) ??
		`https://github.com/ossf/scorecard/blob/main/docs/checks.md#${kebab(name)}`;
	const details = checkDetails(c);
	return {
		ruleId: `code.scorecard/${kebab(name)}`,
		title: `OpenSSF Scorecard ${name}: ${score}/10`,
		severity: scorecardSeverity(SCORECARD_RISK[name] ?? "medium", score),
		category: "supply-chain",
		message: `${repo ? `${repo}: ` : ""}${str(c.reason) ?? `${name} scored ${score}/10`}${str(doc.short) ? ` (${str(doc.short)})` : ""}`,
		evidence: details.length
			? truncate(details.slice(0, 3).join(" | "), 240)
			: undefined,
		remediation: `Follow the Scorecard guidance for ${name} to raise the score: ${url}`,
		references: [url],
		confidence: "high",
		tags: ["openssf-scorecard"],
	};
};

/** Parses `scorecard --format json`. Inconclusive (-1) and perfect scores are skipped. */
export const parseScorecardReport = (json: unknown): FindingInput[] => {
	if (!isRecord(json)) return [];
	const repo = isRecord(json.repo) ? str(json.repo.name) : undefined;
	const findings: FindingInput[] = [];
	for (const c of arr(json.checks).filter(isRecord)) {
		const name = str(c.name);
		const score = num(c.score);
		if (name && needsAttention(score))
			findings.push(checkFinding(c, { name, score }, repo));
	}
	return findings;
};

const GITHUB_REMOTE = /github\.com[:/]+([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/;

/** `owner/repo` of the `origin` remote when it points at GitHub. */
export const githubRepoFromGitConfig = (
	config: string,
): { owner: string; repo: string } | undefined => {
	const section = /\[remote "origin"\]([^[]*)/.exec(config)?.[1] ?? "";
	const url = /^\s*url\s*=\s*(\S+)/m.exec(section)?.[1] ?? "";
	const [, owner, repo] = GITHUB_REMOTE.exec(url) ?? [];
	return owner && repo ? { owner, repo } : undefined;
};

export const scorecard = defineAuditor({
	id: "code.scorecard",
	title: "OpenSSF Scorecard",
	description:
		"Runs OpenSSF Scorecard against the GitHub repository named by the workspace's origin remote and reports checks that scored 0-9, with severity from each check's documented risk scaled by score. Needs GITHUB_AUTH_TOKEN or GITHUB_TOKEN; it calls the GitHub API about the remote repository, not the local files.",
	categories: ["supply-chain"],
	targets: ["codebase"],
	engine: "external",
	tool: "scorecard",
	network: true,
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const config = yield* ws
				.readText(".git/config")
				.pipe(Effect.orElseSucceed(() => undefined));
			if (!config)
				return yield* skip("No .git/config found (not a git checkout)");
			const gh = githubRepoFromGitConfig(config);
			if (!gh)
				return yield* skip("The origin remote is not a GitHub repository");
			const token = process.env.GITHUB_AUTH_TOKEN || process.env.GITHUB_TOKEN;
			if (!token)
				return yield* skip(
					"Set GITHUB_AUTH_TOKEN or GITHUB_TOKEN to run OpenSSF Scorecard",
				);
			const bin = yield* requireTool(
				ctx,
				"scorecard",
				"Install: brew install scorecard or go install github.com/ossf/scorecard/v5@latest.",
			);
			const res = yield* run(
				ctx,
				[
					bin,
					`--repo=github.com/${gh.owner}/${gh.repo}`,
					"--format",
					"json",
					// Without it every check's `details` is null.
					"--show-details",
				],
				{ cwd: ws.root, okCodes: [0], env: { GITHUB_AUTH_TOKEN: token } },
			);
			return parseScorecardReport(yield* parseJson(res.stdout, "scorecard"));
		}),
});
