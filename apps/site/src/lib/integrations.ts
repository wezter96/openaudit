/**
 * The ways to run openaudit, each built from the repository's own docs: the
 * lede is a paragraph from the section and the snippets are its code blocks.
 */
import type { Tokens } from "marked";
import { codeIn, inline, paragraphsIn, render } from "./markdown";
import { IMAGE } from "./site";

export interface Integration {
	readonly id: string;
	readonly name: string;
	/** Glyph name in components/Icon.astro. */
	readonly icon:
		| "terminal"
		| "workflow"
		| "container"
		| "pipeline"
		| "commit"
		| "plug"
		| "sarif"
		| "editor";
	readonly hint: string;
	readonly lede: string;
	readonly html: string;
	readonly more?: { readonly href: string; readonly label: string };
}

const CLI = "apps/cli/README.md";
const INT = "integrations/README.md";

const blocks = (from: string, code: ReadonlyArray<Tokens.Code>) =>
	render(
		code.map((c) => `\`\`\`${c.lang ?? ""}\n${c.text}\n\`\`\``).join("\n\n"),
		from,
	);

/** A paragraph that introduced a snippet ends in a colon; here it stands alone. */
const para = (file: string, heading: string, index = 0) =>
	inline(
		(paragraphsIn(file, heading)[index] ?? "")
			.replace(/\s*Results:$/, "")
			.replace(/:$/, "."),
		file,
	);

export const integrations: ReadonlyArray<Integration> = [
	{
		id: "cli",
		name: "CLI",
		icon: "terminal",
		hint: "bunx @openaudit/cli",
		lede: para("README.md", "Quick start"),
		html: blocks("README.md", codeIn("README.md", "Quick start")),
		more: { href: "/docs/cli/", label: "CLI reference" },
	},
	{
		id: "mcp",
		name: "MCP",
		icon: "plug",
		hint: "openaudit mcp",
		lede: para(CLI, "MCP server"),
		html: blocks(CLI, codeIn(CLI, "MCP server").slice(0, 1)),
		more: { href: "/docs/agents/", label: "MCP and agents" },
	},
	{
		id: "action",
		name: "GitHub Action",
		icon: "workflow",
		hint: "wezter96/openaudit",
		lede: para("README.md", "In CI"),
		html: blocks("README.md", codeIn("README.md", "In CI")),
		more: { href: "/docs/ci/", label: "Inputs and outputs" },
	},
	{
		id: "docker",
		name: "Docker",
		icon: "container",
		hint: IMAGE,
		lede: para(INT, "Docker"),
		html: blocks(INT, codeIn(INT, "Docker")),
		more: { href: "/docs/ci/#docker", label: "Tags and included scanners" },
	},
	{
		id: "gitlab",
		name: "GitLab CI",
		icon: "pipeline",
		hint: "include: remote",
		lede: para(INT, "GitLab CI"),
		html: blocks(INT, codeIn(INT, "GitLab CI")),
		more: { href: "/docs/ci/#gitlab-ci", label: "GitLab setup" },
	},
	{
		id: "pre-commit",
		name: "pre-commit",
		icon: "commit",
		hint: "id: openaudit",
		lede: para(INT, "pre-commit"),
		html: blocks(INT, codeIn(INT, "pre-commit").slice(0, 1)),
		more: { href: "/docs/ci/#pre-commit", label: "Hooks and stages" },
	},
	{
		id: "sarif",
		name: "SARIF",
		icon: "sarif",
		hint: "-f sarif",
		lede: para(CLI, "CI: GitHub code scanning", 2),
		html: blocks(CLI, codeIn(CLI, "CI: GitHub code scanning")),
		more: {
			href: "/docs/ci/#sarif-and-code-scanning",
			label: "Code scanning setup",
		},
	},
	{
		id: "ide",
		name: "IDEs",
		icon: "editor",
		hint: "mcp.json",
		lede: inline(
			'Cursor and VS Code start the same MCP server from a project\'s `mcp.json` (VS Code uses `"servers"` instead of `"mcpServers"`), so the agent in your editor can run audits and playbooks.',
			CLI,
		),
		html: blocks(CLI, codeIn(CLI, "MCP server").slice(1, 2)),
		more: { href: "/docs/agents/#mcp-server", label: "Editor and Codex setup" },
	},
];
