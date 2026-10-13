import {
	type Options,
	query,
	type SDKMessage,
	type SDKResultMessage,
} from "@anthropic-ai/claude-agent-sdk";
import type { ToolHandler } from "./reporting";

/* -------------------------------------------------------------------------- */
/*                                   Runner                                   */
/* -------------------------------------------------------------------------- */

export interface ClaudeRunInput {
	readonly prompt: string;
	readonly options: Options;
	/**
	 * Handlers behind the in-process `openaudit` MCP tools (`report_finding`,
	 * `finish`, `http_get`). The real SDK reaches them through
	 * `options.mcpServers.openaudit`; fake runners call them directly.
	 */
	readonly tools: Readonly<Record<string, ToolHandler>>;
}

/** Drives one agent session. Injectable so tests can script messages. */
export type ClaudeRunner = (input: ClaudeRunInput) => AsyncIterable<SDKMessage>;

export const defaultRunner: ClaudeRunner = ({ prompt, options }) =>
	query({ prompt, options });

/** Assistant errors that mean "cannot run here" rather than "audit failed". */
const SKIP_ERRORS = new Set([
	"authentication_failed",
	"oauth_org_not_allowed",
	"account_on_hold",
	"verification_required",
	"billing_error",
	"cloud_credential_error",
]);

export const AUTH_HINT =
	"Set ANTHROPIC_API_KEY or log in with Claude Code (`claude` then /login).";

export interface RunState {
	/** The model produced at least one successful turn. */
	started: boolean;
	skipReason: string | undefined;
	assistantError: string | undefined;
	result: SDKResultMessage | undefined;
	thrown: unknown;
	stderr: string[];
}

export const pump = async (
	runner: ClaudeRunner,
	input: ClaudeRunInput,
	state: RunState,
	signal: AbortSignal,
) => {
	const controller = input.options.abortController;
	const onAbort = () => controller?.abort();
	signal.addEventListener("abort", onAbort);
	try {
		for await (const message of runner(input)) {
			if (message.type === "assistant") {
				if (!message.error) state.started = true;
				else if (SKIP_ERRORS.has(message.error))
					state.skipReason = `Claude authentication failed (${message.error}). ${AUTH_HINT}`;
				else state.assistantError = message.error;
			} else if (message.type === "auth_status" && message.error) {
				state.skipReason = `Claude authentication failed: ${message.error}. ${AUTH_HINT}`;
			} else if (message.type === "result") {
				state.result = message;
			}
		}
	} catch (cause) {
		state.thrown = cause;
	} finally {
		signal.removeEventListener("abort", onAbort);
	}
};

export const errorText = (cause: unknown) =>
	cause instanceof Error ? cause.message : String(cause);
