/**
 * The ways to run openaudit, each with snippets taken from the code blocks
 * of the repository's own docs.
 */
import type { Tokens } from "marked";
import { codeIn, render } from "./markdown";
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

export const integrations: ReadonlyArray<Integration> = [
	{
		id: "cli",
		name: "CLI",
		icon: "terminal",
		hint: "bunx @openaudit/cli",
		html: blocks("README.md", codeIn("README.md", "Quick start")),
		more: { href: "/docs/cli/", label: "CLI reference" },
	},
	{
		id: "mcp",
		name: "MCP",
		icon: "plug",
		hint: "openaudit mcp",
		html: blocks(CLI, codeIn(CLI, "MCP server").slice(0, 1)),
		more: { href: "/docs/agents/", label: "MCP and agents" },
	},
	{
		id: "action",
		name: "GitHub Action",
		icon: "workflow",
		hint: "wezter96/openaudit",
		html: blocks("README.md", codeIn("README.md", "In CI")),
		more: { href: "/docs/ci/", label: "Inputs and outputs" },
	},
	{
		id: "docker",
		name: "Docker",
		icon: "container",
		hint: IMAGE,
		html: blocks(INT, codeIn(INT, "Docker")),
		more: { href: "/docs/ci/#docker", label: "Tags and included scanners" },
	},
	{
		id: "gitlab",
		name: "GitLab CI",
		icon: "pipeline",
		hint: "include: remote",
		html: blocks(INT, codeIn(INT, "GitLab CI")),
		more: { href: "/docs/ci/#gitlab-ci", label: "GitLab setup" },
	},
	{
		id: "pre-commit",
		name: "pre-commit",
		icon: "commit",
		hint: "id: openaudit",
		html: blocks(INT, codeIn(INT, "pre-commit").slice(0, 1)),
		more: { href: "/docs/ci/#pre-commit", label: "Hooks and stages" },
	},
	{
		id: "sarif",
		name: "SARIF",
		icon: "sarif",
		hint: "-f sarif",
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
		html: blocks(CLI, codeIn(CLI, "MCP server").slice(1, 2)),
		more: { href: "/docs/agents/#mcp-server", label: "Editor and Codex setup" },
	},
];
