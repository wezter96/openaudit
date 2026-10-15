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

/** A filesystem path (absolute, or relative to a root). */
type FsPath = string;
/** A URL origin such as `https://example.com`. */
type Origin = string;
/** A Claude Code or MCP tool name such as `Read` or `mcp__playwright__browser_click`. */
type ToolName = string;
/** A Glob tool pattern such as `src/**`. */
type GlobPattern = string;
/** Why a tool call was denied, shown to the agent. */
type DenyReason = string;

export const within = (root: FsPath, path: FsPath) => {
	const rel = relative(root, resolve(root, path));
	return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
};

/** `path` resolved against `root` with symlinks in its longest existing prefix followed. */
export const realPath = (root: FsPath, path: FsPath): string => {
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
const sameOrigin = (url: unknown, origin: Origin): boolean => {
	if (typeof url !== "string") return false;
	try {
		return new URL(url).origin === origin;
	} catch {
		return false;
	}
};

/** Path, query and fragment of `u`, percent-decoded up to three times. */
const decodedRest = (u: URL): string => {
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
	return rest;
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
		const rest = decodedRest(new URL(url)).replace(/\\/g, "/");
		return /[a-z][a-z0-9+.-]*:\/\/|(^|[=&?#/])\/\/[^/]|\b(javascript|data):/i.test(
			rest,
		);
	} catch {
		return true;
	}
};

/** Literal directory prefix of a glob pattern (`src/**` → `src`). */
const globBase = (pattern: GlobPattern) => {
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

/** Patterns, besides absolute paths, that let a pattern reach outside the root. */
const ROOT_ESCAPES: ReadonlyArray<RegExp> = [
	/^~/,
	// Any `..`, including inside braces (`{..,x}`) or character classes.
	/\.\./,
	// Brace alternatives can start a new absolute or home path: `{/etc,x}`.
	/[{,]\s*[/\\~]/,
	/[{,]\s*[a-z]:/i,
];

/** Absolute paths, `~` and `..` (even via brace expansion) let a pattern reach outside the root. */
const escapesRoot = (pattern: unknown): boolean =>
	typeof pattern === "string" &&
	(isAbsolute(pattern) || ROOT_ESCAPES.some((re) => re.test(pattern)));

export type ToolDecision =
	| { readonly allow: true }
	| { readonly allow: false; readonly message: string };

export interface ToolGuard {
	readonly decide: (toolName: ToolName, input: unknown) => ToolDecision;
	readonly canUseTool: CanUseTool;
	readonly preToolUse: HookCallback;
}

/** What the guard checks tool calls against, resolved once per run. */
interface GuardScope {
	readonly scope: Scope;
	readonly realRoot: FsPath | undefined;
	readonly origin: Origin | undefined;
}

type ToolInput = Record<string, unknown>;

const ALLOW: ToolDecision = { allow: true };
const deny = (message: DenyReason): ToolDecision => ({ allow: false, message });

const asToolInput = (rawInput: unknown): ToolInput =>
	(rawInput && typeof rawInput === "object" ? rawInput : {}) as ToolInput;

const insideRoot = (guard: GuardScope, path: unknown): boolean => {
	const { scope, realRoot } = guard;
	if (!scope.root || !realRoot) return false;
	if (path === undefined) return true;
	if (typeof path !== "string" || path.startsWith("~")) return false;
	return within(realRoot, realPath(scope.root, path));
};

const PLAYWRIGHT_PREFIX = "mcp__playwright__";

const decideNavigation = (url: unknown, origin: Origin): ToolDecision => {
	if (!sameOrigin(url, origin))
		return deny(`The browser may only navigate to ${origin}.`);
	if (embedsUrl(url))
		return deny(
			"URLs that embed another URL (e.g. redirect parameters) are not allowed in audits.",
		);
	return ALLOW;
};

const decideBrowser = (
	guard: GuardScope,
	name: ToolName,
	input: ToolInput,
): ToolDecision => {
	if (!guard.scope.browser || !guard.origin)
		return deny("No browser in this run.");
	if (!ALLOWED_BROWSER_TOOLS.has(name))
		return deny("This browser tool is disabled in read-only audits.");
	return "url" in input ? decideNavigation(input.url, guard.origin) : ALLOW;
};

const FILE_TOOLS = new Set(["Read", "Grep", "Glob"]);

/** Input fields holding patterns the path check would not see, per tool. */
const PATTERN_FIELDS: Readonly<Record<ToolName, string>> = {
	Glob: "pattern",
	Grep: "glob",
};

const pathsOf = (toolName: ToolName, input: ToolInput): unknown[] => {
	const paths = [input.file_path, input.path];
	if (toolName === "Glob" && typeof input.pattern === "string")
		paths.push(globBase(input.pattern));
	return paths;
};

const patternsOf = (toolName: ToolName, input: ToolInput): unknown[] => {
	const field = PATTERN_FIELDS[toolName];
	return field ? [input[field]] : [];
};

const decideFiles = (
	guard: GuardScope,
	toolName: ToolName,
	input: ToolInput,
): ToolDecision => {
	const root = guard.scope.root;
	if (!root) return deny("No local files in this run.");
	const paths = pathsOf(toolName, input);
	// The tools also accept patterns the path check would not see.
	const patterns = patternsOf(toolName, input);
	return paths.every((path) => insideRoot(guard, path)) &&
		!patterns.some(escapesRoot)
		? ALLOW
		: deny(
				`Access outside the audited project (${root}) is not allowed, including through symlinks.`,
			);
};

export const makeToolGuard = (scope: Scope): ToolGuard => {
	const guard: GuardScope = {
		scope,
		realRoot: scope.root ? realPath("/", scope.root) : undefined,
		origin: scope.url ? new URL(scope.url).origin : undefined,
	};

	const decide = (toolName: ToolName, rawInput: unknown): ToolDecision => {
		const input = asToolInput(rawInput);
		if (toolName.startsWith("mcp__openaudit__")) return ALLOW;
		if (toolName.startsWith(PLAYWRIGHT_PREFIX))
			return decideBrowser(
				guard,
				toolName.slice(PLAYWRIGHT_PREFIX.length),
				input,
			);
		if (FILE_TOOLS.has(toolName)) return decideFiles(guard, toolName, input);
		return deny(
			`${toolName} is not available in read-only audits. Use Read/Grep/Glob for files and mcp__openaudit__http_get for the target URL.`,
		);
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
