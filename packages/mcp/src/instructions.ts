import type * as Agent from "@openaudit/agent";

type Playbook = Agent.Playbook;

/** Free-form playbook so host agents can submit issues found outside a playbook. */
export const MANUAL_PLAYBOOK: Playbook = {
	id: "agent.manual",
	title: "Manual review",
	summary:
		"Free-form findings the host agent discovered while reviewing the target.",
	categories: [
		"security",
		"accessibility",
		"performance",
		"seo",
		"privacy",
		"best-practices",
		"reliability",
		"maintainability",
		"supply-chain",
		"compliance",
	],
	targets: ["codebase", "url", "webapp", "container", "iac", "mobile"],
	needs: ["code"],
	instructions: [
		"Record issues you verified yourself that no openaudit auditor reported.",
		"Only submit issues you have evidence for: cite the file and line or URL and selector, and quote a short, redacted snippet as evidence.",
		'Prefer one finding per root cause. Use `confidence: "low"` for suspicions you could not confirm.',
	].join("\n\n"),
	checklist: [
		"Each finding has a precise location",
		"Evidence is short and contains no secrets",
		"Remediation is concrete and actionable",
	],
};

export const SERVER_INSTRUCTIONS = `openaudit audits codebases, URLs, running web apps, containers, IaC and mobile builds (security, accessibility, performance, SEO, privacy, supply chain, ...).
Recommended workflow:
1. detect_target to see what will run, then run_audit (pass an absolute path or URL). Keep the returned reportId.
2. Triage the most severe findings; use get_finding (reportId + fingerprint) for remediation and source context.
3. For judgment-heavy checks (authz, business logic, UX accessibility), call list_playbooks / get_playbook, do the work with your own tools, then submit_findings into the same reportId.
4. Fix issues, run_audit again, and compare_reports(base, head) to confirm what is fixed and that nothing new appeared.
Use get_report for markdown (PR comments), SARIF (code scanning) or HTML. Never paste secrets from evidence into chat.`;

export const auditProjectPrompt = (
	target: string,
	focus: string | undefined,
	playbooks: ReadonlyArray<Playbook>,
) => `Audit ${target} with the openaudit MCP tools${focus ? `, focusing on ${focus}` : ""}.

1. Call detect_target with target "${target}" to see its kinds, technologies and which auditors will run.
2. Call run_audit with that target${focus ? ` and categories that match "${focus}"` : ""}. Keep the reportId. If auditors were skipped for missing tools, mention how to install them, but do not install anything without asking.
3. Triage: group findings by root cause, discard likely false positives (say why), and use get_finding for remediation and source context on anything critical or high.
4. Judgment work: pick the relevant playbooks (${playbooks.map((p) => p.id).join(", ")}). For each, call get_playbook, follow its instructions and checklist with your own tools, then call submit_findings with the same reportId, even when you found nothing.
5. Propose fixes, most severe first. Apply them only with the user's approval, keeping each change small and explained.
6. Call run_audit again, then compare_reports(base, head) to show what was fixed and confirm nothing new appeared.
7. Finish with a short summary: score before and after, what remains, and what needs a human decision. Use get_report with format markdown if the user wants a PR comment.

Never print secrets from evidence; refer to them by file and line.`;
