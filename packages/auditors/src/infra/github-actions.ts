import { defineAuditor, type FindingInput, skip } from "@openaudit/core";
import { Effect } from "effect";

import {
	asArray,
	asRecord,
	parseYaml,
	readOptional,
	workflowFiles,
	type YamlPath,
} from "./shared";

const HARDENING =
	"https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions";

/** Event fields an outside contributor controls. */
const UNTRUSTED_RE =
	/github\.head_ref|github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.(?:ref|label|repo\.default_branch))|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)|pages\.[^.\s}]+\.page_name|commits\.[^.\s}]+\.(?:message|author\.(?:email|name))|head_commit\.(?:message|author\.(?:email|name))|workflow_run\.(?:head_branch|head_commit\.(?:message|author\.(?:email|name))|pull_requests\.[^.\s}]+\.head\.ref))/;

const EXPRESSION_RE = /\$\{\{([\s\S]*?)\}\}/g;

const PR_HEAD_RE = /github\.event\.pull_request\.head\.|github\.head_ref/;

const PUBLIC_TRIGGERS = new Set([
	"pull_request",
	"pull_request_target",
	"issue_comment",
	"issues",
	"discussion",
	"discussion_comment",
	"fork",
	"watch",
]);

const SECURITY_STEP_RE =
	/codeql|trivy|snyk|semgrep|gitleaks|trufflehog|grype|osv-scanner|dependency-review|bandit|zap|checkov|tfsec|audit|security|vulnerab|openaudit/i;

const triggersOf = (on: unknown): ReadonlyArray<string> => {
	if (typeof on === "string") return [on];
	if (Array.isArray(on)) return on.filter((t) => typeof t === "string");
	const rec = asRecord(on);
	return rec ? Object.keys(rec) : [];
};

const isTruthy = (v: unknown) => v === true || v === "true";

type FilePath = string;
/** An action or reusable workflow reference (`owner/repo@ref`, `./local`). */
type ActionRef = string;
/** A `run:` script or `github-script` body. */
type Script = string;
type YamlMap = Record<string, unknown>;

/** A parsed workflow with the lookups the rules share. */
interface Workflow {
	readonly file: FilePath;
	readonly wf: YamlMap;
	readonly lines: ReadonlyArray<string>;
	readonly line: (path: YamlPath) => number;
	readonly triggers: ReadonlyArray<string>;
	readonly jobEntries: ReadonlyArray<readonly [string, YamlMap]>;
}

/** One step of a job, with its string fields resolved. */
interface Step {
	readonly wf: Workflow;
	readonly raw: YamlMap;
	readonly path: YamlPath;
	readonly name: string;
	readonly uses: ActionRef | undefined;
	readonly run: Script | undefined;
	readonly with: YamlMap;
	readonly jobSecretsInEnv: boolean;
	readonly isPrTarget: boolean;
}

/** What every step of a job shares. */
type JobContext = Pick<Step, "wf" | "jobSecretsInEnv" | "isPrTarget">;

/** First line at or after `from` (1-based) that contains `needle`. */
const lineContaining = (
	lines: ReadonlyArray<string>,
	from: number,
	needle: string,
): number => {
	for (let i = Math.max(0, from - 1); i < lines.length; i++) {
		if (lines[i]?.includes(needle)) return i + 1;
	}
	return from;
};

/** First line at or after the key at `path` that contains `needle`. */
const lineAfter = (wf: Workflow, path: YamlPath, needle: string): number =>
	lineContaining(wf.lines, wf.line(path), needle);

const mentionsSecrets = (value: unknown): boolean =>
	JSON.stringify(value ?? {}).includes("secrets.");

const parseWorkflow = (file: FilePath, text: string): Workflow | undefined => {
	const doc = parseYaml(text).docs[0];
	if (!doc) return undefined;
	const wf = asRecord(doc.value);
	if (!wf) return undefined;
	const jobs = asRecord(wf.jobs);
	if (!jobs) return undefined;
	return {
		file,
		wf,
		lines: text.split("\n"),
		line: (path) => doc.lineOf(path) ?? 1,
		triggers: triggersOf(wf.on ?? wf.true),
		jobEntries: Object.entries(jobs).map(
			([id, j]) => [id, asRecord(j) ?? {}] as const,
		),
	};
};

/** Top-level permissions missing, unless every job scopes its own. */
const permissionsMissing = ({
	file,
	wf,
	jobEntries,
}: Workflow): ReadonlyArray<FindingInput> => {
	if (wf.permissions !== undefined) return [];
	if (jobEntries.every(([, j]) => j.permissions !== undefined)) return [];
	return [
		{
			ruleId: "iac.github-actions/permissions-missing",
			title: "Workflow does not restrict GITHUB_TOKEN permissions",
			severity: "medium",
			category: "security",
			message:
				"No top-level `permissions` block, so the GITHUB_TOKEN gets the repository default, which may be read/write on everything.",
			remediation:
				"Add `permissions: contents: read` at the top of the workflow and grant extra scopes per job only where needed.",
			location: { file, line: 1 },
			references: [
				`${HARDENING}#using-secrets`,
				"https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/controlling-permissions-for-github_token",
			],
			tags: ["cwe-250", "least-privilege"],
			confidence: "high",
		},
	];
};

/** `permissions: write-all` at workflow or job level. */
const permissionsWriteAll = ({
	file,
	wf,
	line,
	jobEntries,
}: Workflow): ReadonlyArray<FindingInput> => {
	const blocks: Array<[YamlPath, unknown]> = [
		[["permissions"], wf.permissions],
		...jobEntries.map(
			([id, j]) =>
				[["jobs", id, "permissions"], j.permissions] as [YamlPath, unknown],
		),
	];
	return blocks
		.filter(([, value]) => value === "write-all")
		.map(([path]) => ({
			ruleId: "iac.github-actions/permissions-write-all",
			title: "GITHUB_TOKEN granted write-all permissions",
			severity: "high",
			category: "security",
			message: `\`${path.join(".")}: write-all\` gives every step write access to code, packages, issues and more.`,
			remediation:
				"Replace `write-all` with the specific scopes the job needs (e.g. `contents: read`, `pull-requests: write`).",
			location: { file, line: line(path) },
			evidence: "permissions: write-all",
			references: [
				"https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/controlling-permissions-for-github_token",
			],
			tags: ["cwe-250", "least-privilege"],
			confidence: "high",
		}));
};

/** Every `env:` block in the workflow, its jobs and their steps. */
const envBlocksOf = ({
	wf,
	jobEntries,
}: Workflow): Array<[YamlPath, unknown]> => {
	const envBlocks: Array<[YamlPath, unknown]> = [[["env"], wf.env]];
	for (const [id, job] of jobEntries) {
		envBlocks.push([["jobs", id, "env"], job.env]);
		asArray(job.steps).forEach((s, i) => {
			envBlocks.push([["jobs", id, "steps", i, "env"], asRecord(s)?.env]);
		});
	}
	return envBlocks;
};

/** ACTIONS_ALLOW_UNSECURE_COMMANDS anywhere. */
const unsecureCommands = (wf: Workflow): ReadonlyArray<FindingInput> =>
	envBlocksOf(wf)
		.filter(([, env]) =>
			isTruthy(asRecord(env)?.ACTIONS_ALLOW_UNSECURE_COMMANDS),
		)
		.map(([path]) => ({
			ruleId: "iac.github-actions/unsecure-commands",
			title: "Deprecated unsafe workflow commands enabled",
			severity: "high",
			category: "security",
			message:
				"ACTIONS_ALLOW_UNSECURE_COMMANDS re-enables `set-env`/`add-path`, letting anything printed to the log inject environment variables (CVE-2020-15228).",
			remediation:
				"Remove ACTIONS_ALLOW_UNSECURE_COMMANDS and write to $GITHUB_ENV / $GITHUB_PATH instead.",
			location: {
				file: wf.file,
				line: wf.line([...path, "ACTIONS_ALLOW_UNSECURE_COMMANDS"]),
			},
			evidence: "ACTIONS_ALLOW_UNSECURE_COMMANDS: true",
			references: [
				"https://github.blog/changelog/2020-10-01-github-actions-deprecating-set-env-and-add-path-commands/",
			],
			tags: ["cwe-77"],
			confidence: "high",
		}));

/** Labels of a job's `runs-on` (a label, a list, or a `{ labels }` group). */
const runnerLabels = (runsOn: unknown): ReadonlyArray<unknown> => {
	if (typeof runsOn === "string") return [runsOn];
	if (Array.isArray(runsOn)) return runsOn;
	return asArray(asRecord(runsOn)?.labels);
};

/** Self-hosted runners exposed to untrusted triggers. */
const selfHostedRunner = (
	{ file, line, triggers }: Workflow,
	jobId: string,
	job: YamlMap,
): ReadonlyArray<FindingInput> => {
	const isPublicTrigger = triggers.some((t) => PUBLIC_TRIGGERS.has(t));
	const labels = runnerLabels(job["runs-on"]);
	if (!isPublicTrigger || !labels.some((l) => l === "self-hosted")) return [];
	return [
		{
			ruleId: "iac.github-actions/self-hosted-runner-public",
			title: "Self-hosted runner used for untrusted triggers",
			severity: "medium",
			category: "security",
			message: `Job \`${jobId}\` runs on a self-hosted runner and is triggered by ${triggers.filter((t) => PUBLIC_TRIGGERS.has(t)).join(", ")}; fork contributors could execute code on your infrastructure and persist on the runner.`,
			remediation:
				"Use GitHub-hosted runners for public PR triggers, or ephemeral, isolated self-hosted runners and require approval for fork PRs.",
			location: { file, line: line(["jobs", jobId, "runs-on"]) },
			references: [
				"https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security",
			],
			tags: ["cwe-94"],
			confidence: "medium",
		},
	];
};

const stringOr = <T>(value: unknown, fallback: T): string | T =>
	typeof value === "string" ? value : fallback;

const toStep = (
	jobContext: JobContext,
	jobPath: YamlPath,
	raw: YamlMap,
	i: number,
): Step => ({
	...jobContext,
	raw,
	path: [...jobPath, "steps", i],
	name: stringOr(raw.name, stringOr(raw.uses, `step ${i + 1}`)),
	uses: stringOr(raw.uses, undefined),
	run: stringOr(raw.run, undefined),
	with: asRecord(raw.with) ?? {},
});

const refIsPrHead = (ref: unknown): boolean =>
	typeof ref === "string" && PR_HEAD_RE.test(ref);

const runFetchesPrHead = (run: Script | undefined): boolean => {
	if (run === undefined) return false;
	return (
		/\b(checkout|fetch|gh pr checkout)\b/.test(run) && PR_HEAD_RE.test(run)
	);
};

const checksOutPrHead = ({ uses, run, with: withRec }: Step): boolean => {
	if (uses?.startsWith("actions/checkout") && refIsPrHead(withRec.ref))
		return true;
	return runFetchesPrHead(run);
};

/** pull_request_target + checkout of the PR head. */
const prTargetCheckout = (step: Step): ReadonlyArray<FindingInput> => {
	if (!step.isPrTarget || !checksOutPrHead(step)) return [];
	const ref = step.with.ref;
	return [
		{
			ruleId: "iac.github-actions/pr-target-checkout",
			title: "pull_request_target checks out untrusted PR code",
			severity: "critical",
			category: "security",
			message: `Step \`${step.name}\` checks out the pull request head in a \`pull_request_target\` workflow. Fork code then runs with repository secrets and a write token ("pwn request").`,
			remediation:
				"Use the `pull_request` trigger for building untrusted code, or split into a privileged `workflow_run` that never executes PR code.",
			location: {
				file: step.wf.file,
				line: step.wf.line(
					ref !== undefined
						? [...step.path, "with", "ref"]
						: [...step.path, "run"],
				),
			},
			evidence: typeof ref === "string" ? `ref: ${ref}` : undefined,
			references: [
				"https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
				HARDENING,
			],
			tags: ["cwe-829", "cwe-94"],
			confidence: "high",
		},
	];
};

/** The scripts of a step, keyed by the step field they live under. */
const scriptsOf = ({
	uses,
	run,
	with: withRec,
}: Step): Array<[string, Script]> => {
	const scripts: Array<[string, Script]> = [];
	if (run) scripts.push(["run", run]);
	if (
		uses?.startsWith("actions/github-script") &&
		typeof withRec.script === "string"
	)
		scripts.push(["with", withRec.script]);
	return scripts;
};

const injectionFinding = (
	step: Step,
	key: string,
	match: RegExpMatchArray,
): FindingInput => ({
	ruleId: "iac.github-actions/script-injection",
	title: "Untrusted input interpolated into a script",
	severity: "high",
	category: "security",
	message: `Step \`${step.name}\` expands \`${match[0].trim()}\` directly into a script. Anyone who controls that value (PR title, branch name, comment...) can run arbitrary commands with the job's token and secrets.`,
	remediation:
		// biome-ignore lint/suspicious/noTemplateCurlyInString: GitHub Actions expression syntax
		'Pass the value through an environment variable (`env: TITLE: ${{ github.event.pull_request.title }}`) and reference it as "$TITLE" in the script.',
	location: {
		file: step.wf.file,
		line: lineAfter(step.wf, [...step.path, key], match[0]),
	},
	evidence: match[0].trim(),
	references: [
		`${HARDENING}#understanding-the-risk-of-script-injections`,
		"https://cwe.mitre.org/data/definitions/78.html",
	],
	tags: ["cwe-78", "cwe-94", "owasp-a03"],
	confidence: "high",
});

/** Script injection via ${{ }} in run / github-script. */
const scriptInjection = (step: Step): ReadonlyArray<FindingInput> =>
	scriptsOf(step).flatMap(([key, script]) =>
		[...script.matchAll(EXPRESSION_RE)]
			.filter((match) => UNTRUSTED_RE.test(match[1] ?? ""))
			.map((match) => injectionFinding(step, key, match)),
	);

const echoesSecret = (scriptLine: string): boolean =>
	/\b(echo|printf|cat)\b/.test(scriptLine) && /secrets\.\w+/.test(scriptLine);

/** Secrets echoed in a run step. */
const secretEchoed = (step: Step, run: Script): ReadonlyArray<FindingInput> =>
	run
		.split("\n")
		.filter(echoesSecret)
		.map((l) => ({
			ruleId: "iac.github-actions/secret-echoed",
			title: "Secret printed in a run step",
			severity: "medium",
			category: "security",
			message: `Step \`${step.name}\` prints a secret. Log masking is best-effort and fails for transformed or multi-line values.`,
			remediation:
				"Never echo secrets; pass them via `env:` to the tool that needs them.",
			location: {
				file: step.wf.file,
				line: lineAfter(step.wf, [...step.path, "run"], l.trim()),
			},
			evidence: l.trim().slice(0, 160),
			references: [`${HARDENING}#using-secrets`],
			tags: ["cwe-532"],
			confidence: "medium",
		}));

const shellTraces = (shell: unknown): boolean =>
	typeof shell === "string" && /\s-\w*x/.test(shell);

const stepUsesSecrets = (step: Step, run: Script): boolean => {
	if (run.includes("secrets.")) return true;
	return step.jobSecretsInEnv || mentionsSecrets(step.raw.env);
};

/** Secrets exposed through shell tracing. */
const secretXtrace = (step: Step, run: Script): ReadonlyArray<FindingInput> => {
	const usesSecrets = stepUsesSecrets(step, run);
	const traced = /\bset\s+-[a-wyz]*x/.test(run) || shellTraces(step.raw.shell);
	if (!traced || !usesSecrets) return [];
	return [
		{
			ruleId: "iac.github-actions/secret-xtrace",
			title: "Shell tracing enabled in a step with secrets",
			severity: "medium",
			category: "security",
			message: `Step \`${step.name}\` enables \`set -x\` while secrets are available; traced commands can leak secret values into logs.`,
			remediation:
				"Remove `set -x` from steps that handle secrets, or disable tracing around secret usage.",
			location: {
				file: step.wf.file,
				line: lineAfter(step.wf, [...step.path, "run"], "-x"),
			},
			references: [`${HARDENING}#using-secrets`],
			tags: ["cwe-532"],
			confidence: "medium",
		},
	];
};

/** Secrets echoed or exposed through shell tracing. */
const secretLeaks = (step: Step): ReadonlyArray<FindingInput> => {
	const { run } = step;
	if (!run) return [];
	return [...secretEchoed(step, run), ...secretXtrace(step, run)];
};

const looksLikeSecurityStep = ({ raw, uses, run }: Step): boolean =>
	SECURITY_STEP_RE.test(`${raw.name ?? ""} ${uses ?? ""} ${run ?? ""}`);

/** continue-on-error on security tooling. */
const securityStepContinueOnError = (
	step: Step,
): ReadonlyArray<FindingInput> => {
	if (!isTruthy(step.raw["continue-on-error"])) return [];
	if (!looksLikeSecurityStep(step)) return [];
	return [
		{
			ruleId: "iac.github-actions/security-step-continue-on-error",
			title: "Security check is allowed to fail",
			severity: "info",
			category: "best-practices",
			message: `Step \`${step.name}\` looks like a security check but has \`continue-on-error: true\`, so failures never block the pipeline.`,
			remediation:
				"Remove `continue-on-error` or gate on severity so real findings fail the build.",
			location: {
				file: step.wf.file,
				line: step.wf.line([...step.path, "continue-on-error"]),
			},
			tags: ["ci"],
			confidence: "low",
		},
	];
};

const stepFindings = (step: Step): ReadonlyArray<FindingInput> => [
	...(step.uses ? pinFindings(step.wf, step.uses, [...step.path, "uses"]) : []),
	...prTargetCheckout(step),
	...scriptInjection(step),
	...secretLeaks(step),
	...securityStepContinueOnError(step),
];

const jobFindings = (
	wf: Workflow,
	jobId: string,
	job: YamlMap,
): ReadonlyArray<FindingInput> => {
	const jobPath: YamlPath = ["jobs", jobId];
	const jobContext: JobContext = {
		wf,
		isPrTarget: wf.triggers.includes("pull_request_target"),
		jobSecretsInEnv: mentionsSecrets(wf.wf.env) || mentionsSecrets(job.env),
	};
	return [
		// Reusable workflow call.
		...(typeof job.uses === "string"
			? pinFindings(wf, job.uses, [...jobPath, "uses"])
			: []),
		...selfHostedRunner(wf, jobId, job),
		...asArray(job.steps).flatMap((raw, i) => {
			const rec = asRecord(raw);
			return rec ? stepFindings(toStep(jobContext, jobPath, rec, i)) : [];
		}),
	];
};

/** Audits a single workflow file. Pure; exported for tests. */
export const auditWorkflow = (
	file: string,
	text: string,
): ReadonlyArray<FindingInput> => {
	const wf = parseWorkflow(file, text);
	if (!wf) return [];
	return [
		...permissionsMissing(wf),
		...permissionsWriteAll(wf),
		...unsecureCommands(wf),
		...wf.jobEntries.flatMap(([jobId, job]) => jobFindings(wf, jobId, job)),
	];
};

const isLocalOrDocker = (uses: ActionRef): boolean =>
	uses.startsWith("./") || uses.startsWith("docker://");

/** The ref after the last `@`, or "" when there is none. */
const refOf = (uses: ActionRef): string => {
	const at = uses.lastIndexOf("@");
	return at === -1 ? "" : uses.slice(at + 1);
};

const isFirstParty = (uses: ActionRef): boolean => {
	const owner = uses.split("/")[0]?.toLowerCase() ?? "";
	return owner === "actions" || owner === "github";
};

/** Findings for an action/reusable-workflow reference not pinned to a SHA. */
const pinFindings = (
	{ file, line }: Workflow,
	uses: ActionRef,
	path: YamlPath,
): ReadonlyArray<FindingInput> => {
	if (isLocalOrDocker(uses)) return [];
	const ref = refOf(uses);
	if (/^[0-9a-f]{40}$/i.test(ref)) return [];
	const firstParty = isFirstParty(uses);
	return [
		{
			ruleId: "iac.github-actions/action-not-pinned",
			title: firstParty
				? "First-party action not pinned to a commit SHA"
				: "Third-party action not pinned to a commit SHA",
			severity: firstParty ? "low" : "medium",
			category: "supply-chain",
			message: `\`${uses}\` is referenced by ${ref ? `the mutable ref \`${ref}\`` : "no ref at all"}. If the tag or branch is moved (e.g. after a maintainer compromise), your workflow runs the new code with your secrets.`,
			remediation:
				"Pin to a full 40-character commit SHA and keep the version in a comment (`uses: owner/action@<sha> # v4.1.0`); let Dependabot/Renovate update it.",
			location: { file, line: line(path) },
			evidence: `uses: ${uses}`,
			references: [
				`${HARDENING}#using-third-party-actions`,
				"https://cwe.mitre.org/data/definitions/829.html",
			],
			tags: ["cwe-829", "supply-chain"],
			confidence: "high",
		},
	];
};

/** GitHub Actions workflow hardening. */
export const githubActions = defineAuditor({
	id: "iac.github-actions",
	title: "GitHub Actions workflows",
	description:
		"Checks workflows for unpinned actions, over-broad token permissions, pwn requests, script injection, leaked secrets and unsafe runners.",
	categories: ["security", "supply-chain", "best-practices"],
	targets: ["iac"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const { ws, files } = yield* workflowFiles(ctx);
			const findings: FindingInput[] = [];
			let audited = 0;
			for (const file of files) {
				const text = yield* readOptional(ws, file);
				if (text === undefined || !/^jobs\s*:/m.test(text)) continue;
				audited++;
				findings.push(...auditWorkflow(file, text));
			}
			if (audited === 0)
				return yield* skip("No GitHub Actions workflows found");
			return findings;
		}),
});
