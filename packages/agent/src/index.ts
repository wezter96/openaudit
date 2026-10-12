export {
	type AgenticAuditorDeps,
	AgentSettings,
	agenticAuditors,
	type ClaudeRunInput,
	type ClaudeRunner,
	DEFAULT_MODEL,
	defaultRunner,
	makeAgenticAuditor,
	makeToolGuard,
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

import { playbooks } from "./playbooks";

/** Playbook by id (`agent.authz`), or undefined. */
export const getPlaybook = (id: string) => playbooks.find((p) => p.id === id);
