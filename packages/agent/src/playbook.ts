import type { Category, TargetKind } from "@openaudit/core";

/**
 * A judgment-heavy audit procedure. Playbooks are executed either by the
 * built-in agentic auditors (Claude Agent SDK, headless) or handed to a host
 * agent over MCP (`get_playbook` → work → `submit_findings`).
 */
export interface Playbook {
	/** Matches the agentic auditor id, e.g. `agent.authz`. */
	readonly id: string;
	readonly title: string;
	readonly summary: string;
	readonly categories: ReadonlyArray<Category>;
	readonly targets: ReadonlyArray<TargetKind>;
	/** Capabilities the executing agent needs. */
	readonly needs: ReadonlyArray<"code" | "browser" | "shell" | "network">;
	/** Markdown instructions: scope, method, what counts as a finding. */
	readonly instructions: string;
	/** Concrete items the agent must check off. */
	readonly checklist: ReadonlyArray<string>;
}

/** Instructions plus the checklist as one markdown document. */
export const renderPlaybook = (playbook: Playbook): string =>
	`${playbook.instructions}\n\n## Checklist\n\n${playbook.checklist.map((item) => `- [ ] ${item}`).join("\n")}\n`;
