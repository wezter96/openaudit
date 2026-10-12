import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { SDKMessage } from "@anthropic-ai/claude-agent-sdk";
import {
	type AuditContext,
	type AuditOptions,
	AuditorError,
	type HttpResponse,
	makeWorkspace,
	type TargetInfo,
} from "@openaudit/core";
import { Effect } from "effect";

/** A temp project with one source file. */
export const fixtureProject = (): string => {
	const root = mkdtempSync(join(tmpdir(), "openaudit-agent-"));
	mkdirSync(join(root, "src"));
	writeFileSync(
		join(root, "src/app.ts"),
		'app.get("/orders/:id", (req) => db.order.find(req.params.id));\n',
	);
	return root;
};

export const codebaseContext = (
	root: string,
	options: AuditOptions = {},
): AuditContext => ({
	target: {
		input: root,
		type: "directory",
		root,
		kinds: ["codebase"],
		technologies: ["node", "typescript"],
	},
	options,
	workspace: makeWorkspace(root),
	http: () => Effect.fail(new AuditorError({ message: "no network" })),
	exec: {
		which: () => Effect.succeed(undefined),
		run: () => Effect.fail(new AuditorError({ message: "no exec" })),
	},
	log: () => Effect.void,
});

export const urlContext = (
	url: string,
	options: AuditOptions = {},
	respond?: (url: string) => Partial<HttpResponse>,
): AuditContext & { requests: string[] } => {
	const requests: string[] = [];
	const target: TargetInfo = {
		input: url,
		type: "url",
		kinds: options.browser ? ["url", "webapp"] : ["url"],
		url,
		technologies: [],
	};
	return {
		requests,
		target,
		options,
		workspace: undefined,
		http: (u) => {
			requests.push(u);
			return Effect.succeed({
				url: u,
				status: 200,
				headers: new Headers({ "content-type": "text/html" }),
				cookies: [],
				body: "<html></html>",
				bytes: 13,
				redirected: false,
				ttfbMs: 1,
				totalMs: 2,
				...respond?.(u),
			});
		},
		exec: {
			which: () => Effect.succeed(undefined),
			run: () => Effect.fail(new AuditorError({ message: "no exec" })),
		},
		log: () => Effect.void,
	};
};

/** Loosely typed SDK messages for scripted runs. */
export const msg = (m: Record<string, unknown>): SDKMessage =>
	m as unknown as SDKMessage;

export const assistant = (error?: string) =>
	msg({
		type: "assistant",
		message: { content: [{ type: "text", text: "Looking around" }] },
		parent_tool_use_id: null,
		...(error ? { error } : {}),
	});

export const result = (subtype = "success", extra: object = {}) =>
	msg({
		type: "result",
		subtype,
		is_error: subtype !== "success",
		num_turns: 3,
		total_cost_usd: 0.12,
		errors: [],
		...extra,
	});
