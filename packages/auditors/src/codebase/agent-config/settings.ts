import type { FindingInput } from "@openaudit/core";

import { isRecord, lineLocator, owaspLlmUrl, type SourceFile } from "../util";
import { fallbackServers } from "./fallback";
import {
	fields,
	type JsonEntry,
	type JsonNode,
	parseJsoncDetailed,
	stringItems,
	treeOf,
} from "./json";
import { type McpServer, scanServers } from "./mcp";
import {
	bestEffort,
	CLAUDE_PERMISSIONS,
	CODEX_CONFIG_DOCS,
	finding,
	locate,
	MCP_SECURITY,
	unparsed,
} from "./shared";

/* -------------------------------------------------------------------------- */
/*                             Permission settings                            */
/* -------------------------------------------------------------------------- */

const BROAD_RULE =
	/^(Bash|PowerShell|WebFetch)(?:\(\s*(\*|:\*|\*:\*|\*\*|domain:\*)?\s*\))?$/i;

/** Where a settings file's findings point. */
interface Settings {
	readonly path: string;
	readonly lineOf: (offset: number) => number;
}

/** A broad permission rule and the tool it pre-approves. */
interface BroadRule {
	readonly rule: string;
	readonly tool: string;
}

type StringNode = Extract<JsonNode, { kind: "string" }>;

const shellPermission = ({ rule, tool }: BroadRule) => ({
	title: `Every ${tool} command is pre-approved`,
	severity: "high" as const,
	category: "security" as const,
	message: `\`${rule}\` in permissions.allow lets Claude Code run any shell command without a prompt for everyone who uses this repository, so a prompt injection in a file, issue or web page goes straight to code execution.`,
	evidence: `permissions.allow: "${rule}"`,
	remediation: `Allow specific commands instead, e.g. \`${tool}(bun test *)\`, and keep anything broader as a per-user choice in .claude/settings.local.json.`,
});

const fetchPermission = ({ rule }: BroadRule) => ({
	title: "Every web fetch is pre-approved",
	severity: "medium" as const,
	category: "security" as const,
	message: `\`${rule}\` in permissions.allow lets Claude Code fetch any URL without a prompt, which is an easy exfiltration channel and a source of injected instructions.`,
	evidence: `permissions.allow: "${rule}"`,
	remediation:
		"Allow specific domains with `WebFetch(domain:docs.example.com)`.",
});

const broadPermission = (
	settings: Settings,
	item: StringNode,
): FindingInput[] => {
	const rule = item.value;
	const m = BROAD_RULE.exec(rule.trim());
	if (!m) return [];
	const tool = (m[1] ?? "").replace(/^\w/, (c) => c.toUpperCase());
	const shell = tool.toLowerCase() !== "webfetch";
	if (m[2] === "domain:*" && shell) return [];
	const broad = { rule, tool };
	return [
		finding("broad-permission", settings.path, settings.lineOf(item.offset), {
			...(shell ? shellPermission(broad) : fetchPermission(broad)),
			references: [owaspLlmUrl("llm06"), CLAUDE_PERMISSIONS],
			confidence: "high",
			tags: ["owasp-llm06"],
		}),
	];
};

const isBypassMode = (n: JsonNode): boolean =>
	n.kind === "string" && n.value.toLowerCase() === "bypasspermissions";

const bypassMode = (
	settings: Settings,
	permissions: ReadonlyArray<JsonNode>,
): FindingInput[] => {
	const bypass = permissions
		.flatMap((p) => fields(p, "defaultMode"))
		.find(isBypassMode);
	if (!bypass) return [];
	return [
		finding(
			"permission-bypass-mode",
			settings.path,
			settings.lineOf(bypass.offset),
			{
				title: "Claude Code project settings request bypassPermissions",
				severity: "low",
				category: "security",
				message:
					'`permissions.defaultMode: "bypassPermissions"` asks every session in this repository to skip all permission prompts. Claude Code 2.1.257 and later ignore it in project and local settings, but older versions honour it.',
				evidence: 'permissions.defaultMode: "bypassPermissions"',
				remediation:
					"Remove it from committed settings. Use bypassPermissions only per session, inside an isolated container or VM.",
				references: [owaspLlmUrl("llm06"), CLAUDE_PERMISSIONS],
				confidence: "high",
				tags: ["owasp-llm06"],
			},
		),
	];
};

const isTrue = (n: JsonNode): boolean =>
	n.kind === "scalar" && n.value === true;

const isAutoApprove = (e: JsonEntry): boolean =>
	e.key === "enableAllProjectMcpServers" && isTrue(e.value);

const autoApprove = (settings: Settings, root: JsonNode): FindingInput[] => {
	const entry =
		root.kind === "object" ? root.entries.find(isAutoApprove) : undefined;
	if (!entry) return [];
	return [
		finding(
			"mcp-auto-approve",
			settings.path,
			settings.lineOf(entry.keyOffset),
			{
				title: "Every project MCP server is approved without a prompt",
				severity: "medium",
				category: "security",
				message:
					"`enableAllProjectMcpServers: true` starts every server in the project's .mcp.json without asking, so a pull request that adds a server gets code execution on the machine of whoever next opens the repository with Claude Code.",
				evidence: "enableAllProjectMcpServers: true",
				remediation:
					"Remove it and approve servers by name with `enabledMcpjsonServers`, or let each user approve them interactively.",
				references: [
					owaspLlmUrl("llm06"),
					"https://code.claude.com/docs/en/mcp",
					`${MCP_SECURITY}#local-mcp-server-compromise`,
				],
				confidence: "high",
				tags: ["owasp-llm06"],
			},
		),
	];
};

export const scanClaudeSettings = (file: SourceFile): FindingInput[] => {
	const { path, text } = file;
	// Every duplicate key counts: clients disagree on which one wins.
	const parsed = parseJsoncDetailed(text);
	const lineOf = lineLocator(text);
	if (!parsed.ok) {
		if (text.trim() === "") return [];
		const line = lineOf(parsed.offset);
		return [
			unparsed(
				path,
				line,
				`is not valid JSON(C): ${parsed.reason} at line ${line}`,
			),
		];
	}
	const { root } = parsed;
	const settings: Settings = { path, lineOf };
	const permissions = fields(root, "permissions");
	return [
		...stringItems(permissions.flatMap((p) => fields(p, "allow"))).flatMap(
			(item) => broadPermission(settings, item),
		),
		...bypassMode(settings, permissions),
		...autoApprove(settings, root),
	];
};

const sandboxFinding = (
	path: string,
	line: number,
	never: boolean,
): FindingInput =>
	finding("permission-bypass-mode", path, line, {
		title: "Codex project config disables the sandbox",
		severity: never ? "high" : "medium",
		category: "security",
		message: `\`sandbox_mode = "danger-full-access"\` gives Codex unrestricted file and network access in this project${never ? ', and `approval_policy = "never"` means it never asks first' : ""}.`,
		evidence: `sandbox_mode = "danger-full-access"${never ? ', approval_policy = "never"' : ""}`,
		remediation:
			'Use `sandbox_mode = "workspace-write"` in committed config and leave full access to an explicit per-session choice.',
		references: [owaspLlmUrl("llm06"), CODEX_CONFIG_DOCS],
		confidence: "high",
		tags: ["owasp-llm06"],
	});

const parseToml = (text: string): Record<string, unknown> | undefined => {
	try {
		const doc: unknown = Bun.TOML.parse(text);
		return isRecord(doc) ? doc : undefined;
	} catch {
		return undefined;
	}
};

export const scanCodexConfig = (
	file: SourceFile,
	localPackages: ReadonlySet<string>,
): FindingInput[] => {
	const { path, text } = file;
	const toml = parseToml(text);
	if (!toml) {
		if (text.trim() === "") return [];
		// Bun's TOML errors quote the input, so only a generic reason is given.
		const bypass = /^[ \t]*sandbox_mode\s*=\s*["']danger-full-access["']/m.exec(
			text,
		);
		return [
			unparsed(path, 1, "is not valid TOML"),
			...bestEffort([
				...(bypass
					? [sandboxFinding(path, lineLocator(text)(bypass.index), false)]
					: []),
				...scanServers({ path, text }, fallbackServers(text, true), {
					localPackages,
					gemini: false,
				}),
			]),
		];
	}
	const lineOf = lineLocator(text);
	const findings: FindingInput[] = [];

	if (toml.sandbox_mode === "danger-full-access")
		findings.push(
			sandboxFinding(
				path,
				lineOf(locate(text, "sandbox_mode", 0)),
				toml.approval_policy === "never",
			),
		);

	// TOML forbids duplicate keys, so the parsed table is what Codex sees.
	const tableAt = Math.max(0, text.indexOf("mcp_servers"));
	const servers: McpServer[] = Object.entries(
		isRecord(toml.mcp_servers) ? toml.mcp_servers : {},
	).flatMap(([name, raw]) => {
		if (!isRecord(raw)) return [];
		const at = text.indexOf(name, tableAt);
		const anchor = at === -1 ? tableAt : at;
		return [
			{
				name,
				nameOffset: anchor,
				node: treeOf(raw, (needle) => locate(text, needle, anchor)),
			},
		];
	});
	findings.push(
		...scanServers(file, servers, { localPackages, gemini: false }),
	);
	return findings;
};
