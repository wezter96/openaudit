import { realpathSync } from "node:fs";
import {
	basename,
	dirname,
	isAbsolute,
	join,
	relative,
	resolve,
} from "node:path";
import type { CanUseTool, HookCallback } from "@anthropic-ai/claude-agent-sdk";
import type { Scope } from "./scope";

/* -------------------------------------------------------------------------- */
/*                                 Tool guard                                 */
/* -------------------------------------------------------------------------- */

/*
 * The audited code or site is untrusted and can prompt-inject the agent, so
 * every permission below must hold against an adversarial model:
 * - no shell (Bash), no WebFetch/WebSearch, no writes;
 * - Read/Grep/Glob only inside the project root, after resolving symlinks;
 * - network access only through `http_get` and the browser, both pinned to
 *   the target origin.
 * The guard runs as a PreToolUse hook (every call) and as `canUseTool`.
 */

export const within = (root: string, path: string) => {
	const rel = relative(root, resolve(root, path));
	return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
};

/** `path` resolved against `root` with symlinks in its longest existing prefix followed. */
export const realPath = (root: string, path: string): string => {
	let current = resolve(root, path);
	const rest: string[] = [];
	for (;;) {
		try {
			return join(realpathSync(current), ...[...rest].reverse());
		} catch {
			const parent = dirname(current);
			if (parent === current) return resolve(root, path);
			rest.push(basename(current));
			current = parent;
		}
	}
};

/** True when `url` parses as an absolute URL on exactly `origin`. */
const sameOrigin = (url: unknown, origin: string): boolean => {
	if (typeof url !== "string") return false;
	try {
		return new URL(url).origin === origin;
	} catch {
		return false;
	}
};

/**
 * True when a URL carries another URL in its path, query or fragment, e.g.
 * `/redirect?to=https://evil.example/?d=…`. Navigating there could turn an open
 * redirect on the target into a way to send data elsewhere, and the browser's
 * origin allowlist does not apply to redirects.
 */
export const embedsUrl = (url: unknown): boolean => {
	if (typeof url !== "string") return true;
	try {
		const u = new URL(url);
		let rest = `${u.pathname}${u.search}${u.hash}`;
		for (let i = 0; i < 3; i++) {
			try {
				const decoded = decodeURIComponent(rest);
				if (decoded === rest) break;
				rest = decoded;
			} catch {
				break;
			}
		}
		rest = rest.replace(/\\/g, "/");
		return /[a-z][a-z0-9+.-]*:\/\/|(^|[=&?#/])\/\/[^/]|\b(javascript|data):/i.test(
			rest,
		);
	} catch {
		return true;
	}
};

/** Literal directory prefix of a glob pattern (`src/**` → `src`). */
const globBase = (pattern: string) => {
	const parts = pattern.split("/");
	const index = parts.findIndex((p) => /[*?[{]/.test(p));
	return (index === -1 ? parts : parts.slice(0, index)).join("/") || ".";
};

/**
 * Playwright MCP tools an audit may use: observation and ordinary interaction.
 * An allowlist, so tools added in future releases (code evaluation, file
 * upload, installs, PDF/file output) stay unavailable until reviewed.
 */
const ALLOWED_BROWSER_TOOLS = new Set([
	"browser_navigate",
	"browser_navigate_back",
	"browser_snapshot",
	"browser_take_screenshot",
	"browser_click",
	"browser_hover",
	"browser_type",
	"browser_press_key",
	"browser_select_option",
	"browser_fill_form",
	"browser_drag",
	"browser_handle_dialog",
	"browser_wait_for",
	"browser_resize",
	"browser_tabs",
	"browser_close",
	"browser_console_messages",
	"browser_network_requests",
]);

/** Absolute paths, `~` and `..` (even via brace expansion) let a pattern reach outside the root. */
const escapesRoot = (pattern: unknown): boolean =>
	typeof pattern === "string" &&
	(isAbsolute(pattern) ||
		pattern.startsWith("~") ||
		// Any `..`, including inside braces (`{..,x}`) or character classes.
		pattern.includes("..") ||
		// Brace alternatives can start a new absolute or home path: `{/etc,x}`.
		/[{,]\s*[/\\~]/.test(pattern) ||
		/[{,]\s*[a-z]:/i.test(pattern));

export type ToolDecision =
	| { readonly allow: true }
	| { readonly allow: false; readonly message: string };

export interface ToolGuard {
	readonly decide: (toolName: string, input: unknown) => ToolDecision;
	readonly canUseTool: CanUseTool;
	readonly preToolUse: HookCallback;
}

export const makeToolGuard = (scope: Scope): ToolGuard => {
	const realRoot = scope.root ? realPath("/", scope.root) : undefined;
	const origin = scope.url ? new URL(scope.url).origin : undefined;
	const allow: ToolDecision = { allow: true };
	const deny = (message: string): ToolDecision => ({ allow: false, message });

	const insideRoot = (path: unknown): boolean => {
		if (!scope.root || !realRoot) return false;
		if (path === undefined) return true;
		if (typeof path !== "string" || path.startsWith("~")) return false;
		return within(realRoot, realPath(scope.root, path));
	};

	const decide = (toolName: string, rawInput: unknown): ToolDecision => {
		const input = (
			rawInput && typeof rawInput === "object" ? rawInput : {}
		) as Record<string, unknown>;
		if (toolName.startsWith("mcp__openaudit__")) return allow;
		if (toolName.startsWith("mcp__playwright__")) {
			const name = toolName.slice("mcp__playwright__".length);
			if (!scope.browser || !origin) return deny("No browser in this run.");
			if (!ALLOWED_BROWSER_TOOLS.has(name))
				return deny("This browser tool is disabled in read-only audits.");
			if ("url" in input && !sameOrigin(input.url, origin))
				return deny(`The browser may only navigate to ${origin}.`);
			if ("url" in input && embedsUrl(input.url))
				return deny(
					"URLs that embed another URL (e.g. redirect parameters) are not allowed in audits.",
				);
			return allow;
		}
		switch (toolName) {
			case "Read":
			case "Grep":
			case "Glob": {
				if (!scope.root) return deny("No local files in this run.");
				const paths = [input.file_path, input.path];
				if (toolName === "Glob" && typeof input.pattern === "string")
					paths.push(globBase(input.pattern));
				// The tools also accept patterns the path check would not see.
				const patterns =
					toolName === "Glob"
						? [input.pattern]
						: toolName === "Grep"
							? [input.glob]
							: [];
				return paths.every(insideRoot) && !patterns.some(escapesRoot)
					? allow
					: deny(
							`Access outside the audited project (${scope.root}) is not allowed, including through symlinks.`,
						);
			}
			default:
				return deny(
					`${toolName} is not available in read-only audits. Use Read/Grep/Glob for files and mcp__openaudit__http_get for the target URL.`,
				);
		}
	};

	return {
		decide,
		canUseTool: async (toolName, input) => {
			const decision = decide(toolName, input);
			return decision.allow
				? { behavior: "allow", updatedInput: input }
				: { behavior: "deny", message: decision.message };
		},
		preToolUse: async (hookInput) => {
			if (hookInput.hook_event_name !== "PreToolUse") return {};
			const decision = decide(hookInput.tool_name, hookInput.tool_input);
			return decision.allow
				? {}
				: {
						hookSpecificOutput: {
							hookEventName: "PreToolUse",
							permissionDecision: "deny",
							permissionDecisionReason: decision.message,
						},
					};
		},
	};
};
