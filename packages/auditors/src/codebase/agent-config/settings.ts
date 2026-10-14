import type { FindingInput } from "@openaudit/core";

import { isRecord, lineLocator, owaspLlmUrl, type SourceFile } from "../util";
import { fields, parseJsoncTree, stringItems, treeOf } from "./json";
import { type McpServer, scanServers } from "./mcp";
import {
	CLAUDE_PERMISSIONS,
	CODEX_CONFIG_DOCS,
	finding,
	locate,
	MCP_SECURITY,
} from "./shared";

/* -------------------------------------------------------------------------- */
/*                             Permission settings                            */
/* -------------------------------------------------------------------------- */

const BROAD_RULE =
	/^(Bash|PowerShell|WebFetch)(?:\(\s*(\*|:\*|\*:\*|\*\*|domain:\*)?\s*\))?$/i;

export const scanClaudeSettings = (file: SourceFile): FindingInput[] => {
	const { path, text } = file;
	// Every duplicate key counts: clients disagree on which one wins.
	const root = parseJsoncTree(text);
	const lineOf = lineLocator(text);
	const findings: FindingInput[] = [];
	const permissions = fields(root, "permissions");

	for (const item of stringItems(
		permissions.flatMap((p) => fields(p, "allow")),
	)) {
		const rule = item.value;
		const m = BROAD_RULE.exec(rule.trim());
		if (!m) continue;
		const tool = (m[1] ?? "").replace(/^\w/, (c) => c.toUpperCase());
		if (m[2] === "domain:*" && tool.toLowerCase() !== "webfetch") continue;
		const shell = tool.toLowerCase() !== "webfetch";
		findings.push(
			finding("broad-permission", path, lineOf(item.offset), {
				title: shell
					? `Every ${tool} command is pre-approved`
					: "Every web fetch is pre-approved",
				severity: shell ? "high" : "medium",
				category: "security",
				message: shell
					? `\`${rule}\` in permissions.allow lets Claude Code run any shell command without a prompt for everyone who uses this repository, so a prompt injection in a file, issue or web page goes straight to code execution.`
					: `\`${rule}\` in permissions.allow lets Claude Code fetch any URL without a prompt, which is an easy exfiltration channel and a source of injected instructions.`,
				evidence: `permissions.allow: "${rule}"`,
				remediation: shell
					? `Allow specific commands instead, e.g. \`${tool}(bun test *)\`, and keep anything broader as a per-user choice in .claude/settings.local.json.`
					: "Allow specific domains with `WebFetch(domain:docs.example.com)`.",
				references: [owaspLlmUrl("llm06"), CLAUDE_PERMISSIONS],
				confidence: "high",
				tags: ["owasp-llm06"],
			}),
		);
	}

	const bypass = permissions
		.flatMap((p) => fields(p, "defaultMode"))
		.find(
			(n) =>
				n.kind === "string" && n.value.toLowerCase() === "bypasspermissions",
		);
	if (bypass)
		findings.push(
			finding("permission-bypass-mode", path, lineOf(bypass.offset), {
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
			}),
		);

	const autoApprove =
		root?.kind === "object"
			? root.entries.find(
					(e) =>
						e.key === "enableAllProjectMcpServers" &&
						e.value.kind === "scalar" &&
						e.value.value === true,
				)
			: undefined;
	if (autoApprove)
		findings.push(
			finding("mcp-auto-approve", path, lineOf(autoApprove.keyOffset), {
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
			}),
		);
	return findings;
};

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
	if (!toml) return [];
	const lineOf = lineLocator(text);
	const findings: FindingInput[] = [];

	if (toml.sandbox_mode === "danger-full-access") {
		const never = toml.approval_policy === "never";
		findings.push(
			finding(
				"permission-bypass-mode",
				path,
				lineOf(locate(text, "sandbox_mode", 0)),
				{
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
				},
			),
		);
	}

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
	findings.push(...scanServers(path, text, servers, localPackages, false));
	return findings;
};
