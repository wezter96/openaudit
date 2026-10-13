export {
	type AgenticAuditorDeps,
	AgentSettings,
	type ClaudeRunInput,
	type ClaudeRunner,
	DEFAULT_MODEL,
	defaultRunner,
	makeAgenticAuditor,
	makeToolGuard,
	playbookAuditors,
	resolveModel,
	type ToolDecision,
	type ToolGuard,
	type ToolHandler,
	type ToolResult,
} from "./auditors";
export {
	type AiInsightsOptions,
	aiInsights,
	compactReport,
	type InsightsClient,
} from "./insights";
export { type Playbook, renderPlaybook } from "./playbook";
export { playbooks } from "./playbooks";

import type { Auditor } from "@openaudit/core";

import { playbookAuditors } from "./auditors";
import { deepsecAuditor } from "./deepsec";
import { playbooks } from "./playbooks";

export {
	DEEPSEC_VERSION,
	DeepsecSettings,
	deepsecAuditor,
	makeDeepsecAuditor,
	parseDeepsecExport,
} from "./deepsec";

/** Playbook auditors plus agentic external tools (deepsec, opt-in). */
export const agenticAuditors: ReadonlyArray<Auditor> = [
	...playbookAuditors,
	deepsecAuditor,
];

/** Playbook by id (`agent.authz`), or undefined. */
export const getPlaybook = (id: string) => playbooks.find((p) => p.id === id);
