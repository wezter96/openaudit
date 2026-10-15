import type { McpServerConfig, Options } from "@anthropic-ai/claude-agent-sdk";
import {
	type AuditContext,
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
import { type AgentLimits, buildSystemPrompt } from "./prompts";
import {
	makeSession,
	reportingServer,
	type Session,
	truncate,
} from "./reporting";
import {
	AUTH_HINT,
	type ClaudeRunner,
	defaultRunner,
	errorText,
	pump,
	type RunState,
} from "./runner";
import { resolveScope, type Scope } from "./scope";
import {
	type AgentSettings,
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

/** Everything one agent run is configured from. */
interface AgentRun {
	readonly playbook: Playbook;
	readonly ctx: AuditContext;
	readonly scope: Scope;
	readonly settings: AgentSettings;
	readonly limits: AgentLimits;
	readonly model: string;
	readonly session: Session;
	readonly state: RunState;
}

const newRunState = (): RunState => ({
	started: false,
	skipReason: undefined,
	assistantError: undefined,
	result: undefined,
	thrown: undefined,
	stderr: [],
});

const playwrightServer = (
	url: string,
	settings: AgentSettings,
	root: string | undefined,
): McpServerConfig => {
	const origin = new URL(url).origin;
	return {
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
			`--allowed-origins=${origin}`,
			`--init-page=${browserGuardFiles().initPage}`,
			`--config=${browserGuardFiles().config}`,
			...storageStateArgs(settings.storageState, root),
		],
		env: browserEnv(origin),
	};
};

const mcpServersFor = ({
	session,
	scope,
	settings,
}: AgentRun): Record<string, McpServerConfig> => {
	const mcpServers: Record<string, McpServerConfig> = {
		openaudit: reportingServer(session),
	};
	if (scope.browser && scope.url)
		mcpServers.playwright = playwrightServer(scope.url, settings, scope.root);
	return mcpServers;
};

/** Keeps the last 20 stderr chunks for error messages. */
const collectStderr = (state: RunState) => (data: string) => {
	state.stderr.push(data);
	if (state.stderr.length > 20) state.stderr.shift();
};

const agentOptions = (run: AgentRun): Options => {
	const { scope, settings, session } = run;
	const mcpServers = mcpServersFor(run);
	const guard = makeToolGuard(scope);
	return {
		model: run.model,
		systemPrompt: buildSystemPrompt(run),
		cwd: scope.root,
		tools: scope.root ? ["Read", "Grep", "Glob"] : [],
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
		maxTurns: run.limits.maxTurns,
		...(settings.maxBudgetUsd ? { maxBudgetUsd: settings.maxBudgetUsd } : {}),
		effort: settings.effort ?? "high",
		abortController: new AbortController(),
		env: {
			...process.env,
			CLAUDE_AGENT_SDK_CLIENT_APP: `openaudit/${VERSION}`,
		},
		stderr: collectStderr(run.state),
	};
};

/** Why the SDK could not start: a thrown error, result errors, or stderr. */
const startDetail = (state: RunState): string => {
	if (state.thrown !== undefined) return errorText(state.thrown);
	const result = state.result;
	if (result?.subtype !== "success" && result?.errors.length)
		return result.errors.join("; ");
	return state.assistantError ?? state.stderr.join("").trim();
};

const startFailure = (state: RunState, model: string) => {
	const detail = startDetail(state);
	if (state.assistantError === "model_not_found")
		return new AuditorError({
			message: `Model ${model} is not available to this account. Set --model or OPENAUDIT_MODEL.`,
		});
	return new SkipAudit({
		reason: `Claude Agent SDK could not start${detail ? `: ${truncate(detail, 300)}` : ""}. ${AUTH_HINT}`,
	});
};

/** The error a run ends with, or undefined when its findings stand. */
const runFailure = (
	state: RunState,
	model: string,
	found: number,
): SkipAudit | AuditorError | undefined => {
	if (state.skipReason) return new SkipAudit({ reason: state.skipReason });
	if (!state.started && found === 0) return startFailure(state, model);
	if (state.thrown !== undefined && found === 0)
		return new AuditorError({
			message: `Agent run failed: ${errorText(state.thrown)}`,
			cause: state.thrown,
		});
	return undefined;
};

/** Why the agent stopped before finishing, or undefined when it finished. */
const stopReason = ({ state, limits, settings }: AgentRun) => {
	if (state.thrown !== undefined) return errorText(state.thrown);
	const result = state.result;
	if (result === undefined || result.subtype === "success") return undefined;
	if (result.subtype === "error_max_turns")
		return `reached maxTurns (${limits.maxTurns})`;
	if (result.subtype === "error_max_budget_usd")
		return `reached maxBudgetUsd (${settings.maxBudgetUsd})`;
	return result.subtype ?? "unknown";
};

/** Info findings that flag reduced or partial coverage. */
const coverageFindings = (run: AgentRun): FindingInput[] => {
	const { playbook, scope } = run;
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
	const why = stopReason(run);
	if (why !== undefined)
		extra.push({
			ruleId: `${playbook.id}/incomplete`,
			title: "Agentic review stopped before finishing",
			severity: "info",
			category,
			message: `The agent stopped early (${truncate(why, 300)}); findings are partial. Raise settings["${playbook.id}"].maxTurns or re-run.`,
			confidence: "high",
			tags: ["agentic", "coverage"],
		});
	return extra;
};

const summaryLine = ({ playbook, session, state }: AgentRun) =>
	`${playbook.id}: ${session.findings.length} finding(s), ${state.result?.num_turns ?? "?"} turns, ~$${state.result?.total_cost_usd?.toFixed(2) ?? "?"}. ${session.finished?.summary ?? ""} ${session.finished?.coverage ?? ""}`.trim();

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
				const state = newRunState();
				const run: AgentRun = {
					playbook,
					ctx,
					scope,
					settings,
					limits,
					model,
					session,
					state,
				};
				const options = agentOptions(run);
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
				const failure = runFailure(state, model, findings.length);
				if (failure) return yield* Effect.fail(failure);
				const extra = coverageFindings(run);
				yield* ctx.log(summaryLine(run));
				return [...findings, ...extra];
			}),
	});

/** One agentic auditor per playbook (engine `agentic`, opt-in). */
/** One agentic auditor per playbook. */
export const playbookAuditors: ReadonlyArray<Auditor> = playbooks.map((p) =>
	makeAgenticAuditor(p),
);
