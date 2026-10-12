import type { AiInsights, Auditor, AuditorError, Report } from "@openaudit/core";
import type { Effect } from "effect";

export type { Playbook } from "./playbook";
import type { Playbook } from "./playbook";

/** STUB — implemented by the agent workstream. */
export const playbooks: ReadonlyArray<Playbook> = [];

/** STUB — one agentic auditor per playbook (engine "agentic"). */
export const agenticAuditors: ReadonlyArray<Auditor> = [];

/** STUB — summarise and prioritise a report with Claude. */
export declare const aiInsights: (
	report: Report,
	options?: { readonly model?: string },
) => Effect.Effect<AiInsights, AuditorError>;
