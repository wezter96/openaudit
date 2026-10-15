import { type AuditContext, SkipAudit } from "@openaudit/core";
import { Effect } from "effect";
import type { Playbook } from "../playbook";

/* -------------------------------------------------------------------------- */
/*                                   Scope                                    */
/* -------------------------------------------------------------------------- */

export interface Scope {
	/** Project root the agent may read (its working directory). */
	readonly root: string | undefined;
	/** Live URL the agent may fetch. */
	readonly url: string | undefined;
	/** Playwright MCP attached. */
	readonly browser: boolean;
	/** The playbook wants a browser but the user did not opt in. */
	readonly reducedCoverage: boolean;
}

const CODE_KINDS = new Set(["codebase", "container", "iac", "mobile"]);
const WEB_KINDS = new Set(["url", "webapp"]);

/** True when the playbook and the target share one of `kinds`. */
const appliesTo = (
	playbook: Playbook,
	ctx: AuditContext,
	kinds: Set<string>,
): boolean =>
	playbook.targets.some((t) => kinds.has(t) && ctx.target.kinds.includes(t));

const unsupportedTarget = (playbook: Playbook, ctx: AuditContext) =>
	new SkipAudit({
		reason:
			ctx.target.type === "image"
				? "Container images are not unpacked for agentic review; run against the directory with the Dockerfile/IaC instead"
				: `${playbook.id} needs local files or a URL target`,
	});

const browserScope = (
	playbook: Playbook,
	ctx: AuditContext,
	url: string | undefined,
): Pick<Scope, "browser" | "reducedCoverage"> => {
	const wantsBrowser = playbook.needs.includes("browser") && url !== undefined;
	const browser = wantsBrowser && ctx.options.browser === true;
	return { browser, reducedCoverage: wantsBrowser && !browser };
};

export const resolveScope = (
	playbook: Playbook,
	ctx: AuditContext,
): Effect.Effect<Scope, SkipAudit> => {
	const url = appliesTo(playbook, ctx, WEB_KINDS) ? ctx.target.url : undefined;
	const root = appliesTo(playbook, ctx, CODE_KINDS)
		? ctx.workspace?.root
		: undefined;
	if (!url && !root) return Effect.fail(unsupportedTarget(playbook, ctx));
	return Effect.succeed({ root, url, ...browserScope(playbook, ctx, url) });
};
