import type { McpServerConfig, Options } from "@anthropic-ai/claude-agent-sdk";
import {
	type Auditor,
	AuditorError,
	defineAuditor,
	type FindingInput,
	SkipAudit,
	VERSION,
} from "@openaudit/core";
import { Effect } from "effect";

import { browserGuardFiles } from "../browser-guard";
import type { Playbook } from "../playbook";
import { playbooks } from "../playbooks";
import { buildSystemPrompt } from "./prompts";
import { makeSession, reportingServer, truncate } from "./reporting";
import {
	AUTH_HINT,
	type ClaudeRunner,
	defaultRunner,
	errorText,
	pump,
	type RunState,
} from "./runner";
import { resolveScope } from "./scope";
import {
	browserEnv,
	DEFAULT_MAX_FINDINGS,
	DEFAULT_MAX_TURNS,
	PLAYWRIGHT_MCP,
	readSettings,
	resolveModel,
	storageStateArgs,
} from "./settings";
import { makeToolGuard } from "./tool-guard";

/* -------------------------------------------------------------------------- */
/*                                  Auditors                                  */
/* -------------------------------------------------------------------------- */

export interface AgenticAuditorDeps {
	readonly runner?: ClaudeRunner;
}

/** One headless Claude Agent SDK auditor driven by `playbook`. */
export const makeAgenticAuditor = (
	playbook: Playbook,
	deps: AgenticAuditorDeps = {},
): Auditor =>
	defineAuditor({
		id: playbook.id,
		title: playbook.title,
		description: `${playbook.summary} (agentic, uses Claude)`,
		categories: playbook.categories,
		targets: playbook.targets,
		engine: "agentic",
		network: true,
		defaultEnabled: false,
		run: (ctx) =>
			Effect.gen(function* () {
				const runner = deps.runner ?? defaultRunner;
				const settings = yield* readSettings(ctx, playbook.id);
				const scope = yield* resolveScope(playbook, ctx);
				const limits = {
					maxTurns: settings.maxTurns ?? DEFAULT_MAX_TURNS,
					maxFindings: settings.maxFindings ?? DEFAULT_MAX_FINDINGS,
				};
				const model = resolveModel(ctx.options.model);
				const session = makeSession(playbook, ctx, scope, limits.maxFindings);
				const state: RunState = {
					started: false,
					skipReason: undefined,
					assistantError: undefined,
					result: undefined,
					thrown: undefined,
					stderr: [],
				};

				const mcpServers: Record<string, McpServerConfig> = {
					openaudit: reportingServer(session),
				};
				if (scope.browser && scope.url)
					mcpServers.playwright = {
						type: "stdio",
						command: "npx",
						args: [
							"-y",
							PLAYWRIGHT_MCP,
							"--headless",
							"--isolated",
							"--block-service-workers",
							// Advisory only (Playwright: "not a security boundary"); the
							// init-page origin guard below is what enforces the origin.
							`--allowed-origins=${new URL(scope.url).origin}`,
							`--init-page=${browserGuardFiles().initPage}`,
							`--config=${browserGuardFiles().config}`,
							...storageStateArgs(settings.storageState, scope.root),
						],
						env: browserEnv(new URL(scope.url).origin),
					};

				const tools = [...(scope.root ? ["Read", "Grep", "Glob"] : [])];
				const guard = makeToolGuard(scope);
				const options: Options = {
					model,
					systemPrompt: buildSystemPrompt(
						playbook,
						ctx,
						scope,
						settings,
						limits,
					),
					cwd: scope.root,
					tools,
					disallowedTools: [
						"Write",
						"Edit",
						"NotebookEdit",
						"Bash",
						"WebFetch",
						"WebSearch",
					],
					allowedTools: Object.keys(session.handlers).map(
						(name) => `mcp__openaudit__${name}`,
					),
					canUseTool: guard.canUseTool,
					hooks: { PreToolUse: [{ hooks: [guard.preToolUse] }] },
					permissionMode: "default",
					mcpServers,
					strictMcpConfig: true,
					// Isolation: ignore the user's CLAUDE.md, hooks, plugins and permission rules.
					settingSources: [],
					persistSession: false,
					maxTurns: limits.maxTurns,
					...(settings.maxBudgetUsd
						? { maxBudgetUsd: settings.maxBudgetUsd }
						: {}),
					effort: settings.effort ?? "high",
					abortController: new AbortController(),
					env: {
						...process.env,
						CLAUDE_AGENT_SDK_CLIENT_APP: `openaudit/${VERSION}`,
					},
					stderr: (data) => {
						state.stderr.push(data);
						if (state.stderr.length > 20) state.stderr.shift();
					},
				};
				const prompt = `Audit ${scope.url ?? scope.root} with the "${playbook.title}" playbook. Record findings with report_finding and call finish when done.`;

				yield* Effect.promise((signal) =>
					pump(
						runner,
						{ prompt, options, tools: session.handlers },
						state,
						signal,
					),
				);

				const findings = session.findings;
				const result = state.result;

				if (state.skipReason)
					return yield* new SkipAudit({ reason: state.skipReason });
				if (!state.started && findings.length === 0) {
					const detail =
						state.thrown !== undefined
							? errorText(state.thrown)
							: result?.subtype !== "success" && result?.errors.length
								? result.errors.join("; ")
								: (state.assistantError ?? state.stderr.join("").trim());
					if (state.assistantError === "model_not_found")
						return yield* new AuditorError({
							message: `Model ${model} is not available to this account. Set --model or OPENAUDIT_MODEL.`,
						});
					return yield* new SkipAudit({
						reason: `Claude Agent SDK could not start${detail ? `: ${truncate(detail, 300)}` : ""}. ${AUTH_HINT}`,
					});
				}
				if (state.thrown !== undefined && findings.length === 0)
					return yield* new AuditorError({
						message: `Agent run failed: ${errorText(state.thrown)}`,
						cause: state.thrown,
					});

				const extra: FindingInput[] = [];
				const category = playbook.categories[0] ?? "best-practices";
				if (scope.reducedCoverage)
					extra.push({
						ruleId: `${playbook.id}/reduced-coverage`,
						title: "Ran without a browser; journeys were not exercised",
						severity: "info",
						category,
						message: `${playbook.title} needs a real browser to walk user journeys. This run only reviewed served HTML and headers. Re-run with --browser for full coverage.`,
						location: { url: scope.url },
						confidence: "high",
						tags: ["agentic", "coverage"],
					});
				const stoppedEarly =
					state.thrown !== undefined ||
					(result !== undefined && result.subtype !== "success");
				if (stoppedEarly) {
					const why =
						state.thrown !== undefined
							? errorText(state.thrown)
							: result?.subtype === "error_max_turns"
								? `reached maxTurns (${limits.maxTurns})`
								: result?.subtype === "error_max_budget_usd"
									? `reached maxBudgetUsd (${settings.maxBudgetUsd})`
									: (result?.subtype ?? "unknown");
					extra.push({
						ruleId: `${playbook.id}/incomplete`,
						title: "Agentic review stopped before finishing",
						severity: "info",
						category,
						message: `The agent stopped early (${truncate(why, 300)}); findings are partial. Raise settings["${playbook.id}"].maxTurns or re-run.`,
						confidence: "high",
						tags: ["agentic", "coverage"],
					});
				}

				yield* ctx.log(
					`${playbook.id}: ${findings.length} finding(s), ${result?.num_turns ?? "?"} turns, ~$${result?.total_cost_usd?.toFixed(2) ?? "?"}. ${session.finished?.summary ?? ""} ${session.finished?.coverage ?? ""}`.trim(),
				);
				return [...findings, ...extra];
			}),
	});

/** One agentic auditor per playbook (engine `agentic`, opt-in). */
/** One agentic auditor per playbook. */
export const playbookAuditors: ReadonlyArray<Auditor> = playbooks.map((p) =>
	makeAgenticAuditor(p),
);
