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

/** Audits a single workflow file. Pure; exported for tests. */
export const auditWorkflow = (
	file: string,
	text: string,
): ReadonlyArray<FindingInput> => {
	const { docs } = parseYaml(text);
	const doc = docs[0];
	const wf = asRecord(doc?.value);
	if (!doc || !wf || !asRecord(wf.jobs)) return [];
	const jobs = asRecord(wf.jobs) ?? {};
	const lines = text.split("\n");
	const line = (path: YamlPath) => doc.lineOf(path) ?? 1;
	const triggers = triggersOf(wf.on ?? wf.true);
	const findings: FindingInput[] = [];

	// Permissions: top-level missing (unless every job scopes its own) or write-all.
	const jobEntries = Object.entries(jobs).map(
		([id, j]) => [id, asRecord(j) ?? {}] as const,
	);
	if (wf.permissions === undefined) {
		if (!jobEntries.every(([, j]) => j.permissions !== undefined))
			findings.push({
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
			});
	}
	const writeAll: Array<[YamlPath, unknown]> = [
		[["permissions"], wf.permissions],
		...jobEntries.map(
			([id, j]) =>
				[["jobs", id, "permissions"], j.permissions] as [YamlPath, unknown],
		),
	];
	for (const [path, value] of writeAll) {
		if (value === "write-all")
			findings.push({
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
			});
	}

	// ACTIONS_ALLOW_UNSECURE_COMMANDS anywhere.
	const envBlocks: Array<[YamlPath, unknown]> = [[["env"], wf.env]];
	for (const [id, job] of jobEntries) {
		envBlocks.push([["jobs", id, "env"], job.env]);
		asArray(job.steps).forEach((s, i) => {
			envBlocks.push([["jobs", id, "steps", i, "env"], asRecord(s)?.env]);
		});
	}
	for (const [path, env] of envBlocks) {
		const value = asRecord(env)?.ACTIONS_ALLOW_UNSECURE_COMMANDS;
		if (value !== undefined && isTruthy(value))
			findings.push({
				ruleId: "iac.github-actions/unsecure-commands",
				title: "Deprecated unsafe workflow commands enabled",
				severity: "high",
				category: "security",
				message:
					"ACTIONS_ALLOW_UNSECURE_COMMANDS re-enables `set-env`/`add-path`, letting anything printed to the log inject environment variables (CVE-2020-15228).",
				remediation:
					"Remove ACTIONS_ALLOW_UNSECURE_COMMANDS and write to $GITHUB_ENV / $GITHUB_PATH instead.",
				location: {
					file,
					line: line([...path, "ACTIONS_ALLOW_UNSECURE_COMMANDS"]),
				},
				evidence: "ACTIONS_ALLOW_UNSECURE_COMMANDS: true",
				references: [
					"https://github.blog/changelog/2020-10-01-github-actions-deprecating-set-env-and-add-path-commands/",
				],
				tags: ["cwe-77"],
				confidence: "high",
			});
	}

	const isPrTarget = triggers.includes("pull_request_target");
	const isPublicTrigger = triggers.some((t) => PUBLIC_TRIGGERS.has(t));
	const workflowSecretsInEnv = JSON.stringify(wf.env ?? {}).includes(
		"secrets.",
	);

	for (const [jobId, job] of jobEntries) {
		const jobPath: YamlPath = ["jobs", jobId];

		// Reusable workflow call.
		if (typeof job.uses === "string")
			findings.push(...pinFindings(file, job.uses, line([...jobPath, "uses"])));

		// Self-hosted runners exposed to untrusted triggers.
		const runsOn = job["runs-on"];
		const labels =
			typeof runsOn === "string"
				? [runsOn]
				: Array.isArray(runsOn)
					? runsOn
					: asArray(asRecord(runsOn)?.labels);
		if (isPublicTrigger && labels.some((l) => l === "self-hosted"))
			findings.push({
				ruleId: "iac.github-actions/self-hosted-runner-public",
				title: "Self-hosted runner used for untrusted triggers",
				severity: "medium",
				category: "security",
				message: `Job \`${jobId}\` runs on a self-hosted runner and is triggered by ${triggers.filter((t) => PUBLIC_TRIGGERS.has(t)).join(", ")}; fork contributors could execute code on your infrastructure and persist on the runner.`,
				remediation:
					"Use GitHub-hosted runners for public PR triggers, or ephemeral, isolated self-hosted runners and require approval for fork PRs.",
				location: { file, line: line([...jobPath, "runs-on"]) },
				references: [
					"https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security",
				],
				tags: ["cwe-94"],
				confidence: "medium",
			});

		const jobSecretsInEnv =
			workflowSecretsInEnv ||
			JSON.stringify(job.env ?? {}).includes("secrets.");

		asArray(job.steps).forEach((raw, i) => {
			const step = asRecord(raw);
			if (!step) return;
			const stepPath: YamlPath = [...jobPath, "steps", i];
			const stepName =
				typeof step.name === "string"
					? step.name
					: typeof step.uses === "string"
						? step.uses
						: `step ${i + 1}`;
			const uses = typeof step.uses === "string" ? step.uses : undefined;
			const run = typeof step.run === "string" ? step.run : undefined;
			const withRec = asRecord(step.with) ?? {};

			if (uses)
				findings.push(...pinFindings(file, uses, line([...stepPath, "uses"])));

			// pull_request_target + checkout of the PR head.
			if (isPrTarget) {
				const ref = withRec.ref;
				const checksOutHead =
					(uses?.startsWith("actions/checkout") &&
						typeof ref === "string" &&
						PR_HEAD_RE.test(ref)) ||
					(run !== undefined &&
						/\b(checkout|fetch|gh pr checkout)\b/.test(run) &&
						PR_HEAD_RE.test(run));
				if (checksOutHead)
					findings.push({
						ruleId: "iac.github-actions/pr-target-checkout",
						title: "pull_request_target checks out untrusted PR code",
						severity: "critical",
						category: "security",
						message: `Step \`${stepName}\` checks out the pull request head in a \`pull_request_target\` workflow. Fork code then runs with repository secrets and a write token ("pwn request").`,
						remediation:
							"Use the `pull_request` trigger for building untrusted code, or split into a privileged `workflow_run` that never executes PR code.",
						location: {
							file,
							line: line(
								ref !== undefined
									? [...stepPath, "with", "ref"]
									: [...stepPath, "run"],
							),
						},
						evidence: typeof ref === "string" ? `ref: ${ref}` : undefined,
						references: [
							"https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
							HARDENING,
						],
						tags: ["cwe-829", "cwe-94"],
						confidence: "high",
					});
			}

			// Script injection via ${{ }} in run / github-script.
			const scripts: Array<[string, string]> = [];
			if (run) scripts.push(["run", run]);
			if (
				uses?.startsWith("actions/github-script") &&
				typeof withRec.script === "string"
			)
				scripts.push(["with", withRec.script]);
			for (const [key, script] of scripts) {
				for (const match of script.matchAll(EXPRESSION_RE)) {
					const expr = match[1] ?? "";
					if (!UNTRUSTED_RE.test(expr)) continue;
					findings.push({
						ruleId: "iac.github-actions/script-injection",
						title: "Untrusted input interpolated into a script",
						severity: "high",
						category: "security",
						message: `Step \`${stepName}\` expands \`${match[0].trim()}\` directly into a script. Anyone who controls that value (PR title, branch name, comment...) can run arbitrary commands with the job's token and secrets.`,
						remediation:
							// biome-ignore lint/suspicious/noTemplateCurlyInString: GitHub Actions expression syntax
							'Pass the value through an environment variable (`env: TITLE: ${{ github.event.pull_request.title }}`) and reference it as "$TITLE" in the script.',
						location: {
							file,
							line: lineContaining(lines, line([...stepPath, key]), match[0]),
						},
						evidence: match[0].trim(),
						references: [
							`${HARDENING}#understanding-the-risk-of-script-injections`,
							"https://cwe.mitre.org/data/definitions/78.html",
						],
						tags: ["cwe-78", "cwe-94", "owasp-a03"],
						confidence: "high",
					});
				}
			}

			// Secrets echoed or exposed through shell tracing.
			if (run) {
				const stepUsesSecrets =
					run.includes("secrets.") ||
					jobSecretsInEnv ||
					JSON.stringify(step.env ?? {}).includes("secrets.");
				for (const l of run.split("\n")) {
					if (/\b(echo|printf|cat)\b/.test(l) && /secrets\.\w+/.test(l)) {
						findings.push({
							ruleId: "iac.github-actions/secret-echoed",
							title: "Secret printed in a run step",
							severity: "medium",
							category: "security",
							message: `Step \`${stepName}\` prints a secret. Log masking is best-effort and fails for transformed or multi-line values.`,
							remediation:
								"Never echo secrets; pass them via `env:` to the tool that needs them.",
							location: {
								file,
								line: lineContaining(
									lines,
									line([...stepPath, "run"]),
									l.trim(),
								),
							},
							evidence: l.trim().slice(0, 160),
							references: [`${HARDENING}#using-secrets`],
							tags: ["cwe-532"],
							confidence: "medium",
						});
					}
				}
				const traced =
					/\bset\s+-[a-wyz]*x/.test(run) ||
					(typeof step.shell === "string" && /\s-\w*x/.test(step.shell));
				if (traced && stepUsesSecrets)
					findings.push({
						ruleId: "iac.github-actions/secret-xtrace",
						title: "Shell tracing enabled in a step with secrets",
						severity: "medium",
						category: "security",
						message: `Step \`${stepName}\` enables \`set -x\` while secrets are available; traced commands can leak secret values into logs.`,
						remediation:
							"Remove `set -x` from steps that handle secrets, or disable tracing around secret usage.",
						location: {
							file,
							line: lineContaining(lines, line([...stepPath, "run"]), "-x"),
						},
						references: [`${HARDENING}#using-secrets`],
						tags: ["cwe-532"],
						confidence: "medium",
					});
			}

			// continue-on-error on security tooling.
			if (
				isTruthy(step["continue-on-error"]) &&
				SECURITY_STEP_RE.test(`${step.name ?? ""} ${uses ?? ""} ${run ?? ""}`)
			)
				findings.push({
					ruleId: "iac.github-actions/security-step-continue-on-error",
					title: "Security check is allowed to fail",
					severity: "info",
					category: "best-practices",
					message: `Step \`${stepName}\` looks like a security check but has \`continue-on-error: true\`, so failures never block the pipeline.`,
					remediation:
						"Remove `continue-on-error` or gate on severity so real findings fail the build.",
					location: { file, line: line([...stepPath, "continue-on-error"]) },
					tags: ["ci"],
					confidence: "low",
				});
		});
	}

	return findings;
};

/** Findings for an action/reusable-workflow reference not pinned to a SHA. */
const pinFindings = (
	file: string,
	uses: string,
	line: number,
): ReadonlyArray<FindingInput> => {
	if (uses.startsWith("./") || uses.startsWith("docker://")) return [];
	const at = uses.lastIndexOf("@");
	const ref = at === -1 ? "" : uses.slice(at + 1);
	if (/^[0-9a-f]{40}$/i.test(ref)) return [];
	const owner = uses.split("/")[0]?.toLowerCase() ?? "";
	const firstParty = owner === "actions" || owner === "github";
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
			location: { file, line },
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
