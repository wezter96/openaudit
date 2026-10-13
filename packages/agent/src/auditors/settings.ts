import { realpathSync } from "node:fs";
import { resolve, sep } from "node:path";
import { type AuditContext, AuditorError } from "@openaudit/core";
import { Effect } from "effect";
import { z } from "zod";

import { ORIGIN_ENV } from "../browser-guard";

/** Default model for agentic auditors and AI insights. */
export const DEFAULT_MODEL = "claude-opus-5-5";

/** `options.model`, then `OPENAUDIT_MODEL`, then {@link DEFAULT_MODEL}. */
export const resolveModel = (model?: string): string =>
	model || process.env.OPENAUDIT_MODEL || DEFAULT_MODEL;

export const DEFAULT_MAX_TURNS = 40;
export const DEFAULT_MAX_FINDINGS = 40;
export const MAX_HTTP_CALLS = 150;
export const MAX_BODY_CHARS = 40_000;
export const MAX_EVIDENCE_CHARS = 2_000;

/* -------------------------------------------------------------------------- */
/*                                  Settings                                  */
/* -------------------------------------------------------------------------- */

/**
 * Per-auditor settings, read from `options.settings[<auditor id>]` merged over
 * `options.settings.agent` (shared by all agentic auditors).
 */
export const AgentSettings = z.object({
	maxTurns: z.number().int().positive().max(500).optional(),
	maxBudgetUsd: z.number().positive().optional(),
	effort: z.enum(["low", "medium", "high", "xhigh", "max"]).optional(),
	maxFindings: z.number().int().positive().max(500).optional(),
	/** Extra context for the agent: test accounts, scope limits, focus areas. */
	instructions: z.string().max(20_000).optional(),
	/**
	 * Playwright storage state (cookies/localStorage of a logged-in test
	 * account). Must resolve inside the project root, or the working directory
	 * for URL targets. Free-form Playwright args are deliberately not accepted:
	 * flags such as `--executable-path` or `--init-script` would run code.
	 */
	storageState: z.string().optional(),
});
export type AgentSettings = z.infer<typeof AgentSettings>;

/**
 * Environment for the Playwright MCP process: just enough to run npx and find
 * browsers, plus the allowed origin. API keys and other secrets stay out.
 */
export const browserEnv = (origin: string): Record<string, string> => {
	const env: Record<string, string> = { [ORIGIN_ENV]: origin };
	for (const key of [
		"PATH",
		"HOME",
		"TMPDIR",
		"PLAYWRIGHT_BROWSERS_PATH",
		"npm_config_cache",
	]) {
		const value = process.env[key];
		if (value) env[key] = value;
	}
	return env;
};

/** Pinned so a compromised or breaking release is never pulled implicitly. */
export const PLAYWRIGHT_MCP = "@playwright/mcp@0.0.83";

/** `--storage-state=<abs path>` when the file resolves inside `base`, else nothing. */
export const storageStateArgs = (
	path: string | undefined,
	root: string | undefined,
): string[] => {
	if (!path) return [];
	try {
		const base = realpathSync(root ?? process.cwd());
		const file = realpathSync(resolve(base, path));
		return file.startsWith(base + sep) ? [`--storage-state=${file}`] : [];
	} catch {
		return [];
	}
};

export const readSettings = (ctx: AuditContext, id: string) => {
	const parsed = AgentSettings.safeParse({
		...ctx.options.settings?.agent,
		...ctx.options.settings?.[id],
	});
	return parsed.success
		? Effect.succeed(parsed.data)
		: Effect.fail(
				new AuditorError({
					message: `Invalid settings for ${id}: ${z.prettifyError(parsed.error)}`,
				}),
			);
};
