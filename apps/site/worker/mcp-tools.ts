/** The MCP tools: their definitions, with input schemas and annotations. */
import type { Schema } from "./mcp-schema";

export const LIMITS = {
	/** Largest request body accepted, in bytes. */
	maxBodyBytes: 64 * 1024,
	/** Most messages in one JSON-RPC batch. */
	maxBatch: 16,
	maxSearchResults: 10,
	maxListResults: 200,
} as const;

export interface ToolDefinition {
	readonly name: string;
	readonly title: string;
	readonly description: string;
	readonly inputSchema: Schema;
	readonly annotations: {
		readonly readOnlyHint: true;
		readonly destructiveHint: false;
		readonly idempotentHint: true;
		readonly openWorldHint: false;
	};
}

const READ_ONLY = {
	readOnlyHint: true,
	destructiveHint: false,
	idempotentHint: true,
	openWorldHint: false,
} as const;
const LOCAL =
	" Read-only data from openaudit.se; to run audits, use the local server (`bunx @openaudit/cli mcp`).";

export const TOOLS: ReadonlyArray<ToolDefinition> = [
	{
		name: "list_auditors",
		title: "List auditors",
		description: `List openaudit's auditors, optionally filtered by area, target kind, engine or text. Returns each auditor's id, title, areas, targets and whether it runs by default.${LOCAL}`,
		inputSchema: {
			type: "object",
			properties: {
				category: {
					type: "string",
					maxLength: 40,
					description:
						"Area, e.g. security, accessibility, performance, seo, privacy, supply-chain",
				},
				target: {
					type: "string",
					maxLength: 40,
					description:
						"Target kind: codebase, url, webapp, container, iac, mobile or cloud",
				},
				engine: {
					type: "string",
					maxLength: 40,
					description: "builtin, external (wraps a scanner) or agentic",
				},
				query: {
					type: "string",
					maxLength: 200,
					description:
						"Words that must all appear in the id, title, tool or description",
				},
				limit: {
					type: "integer",
					minimum: 1,
					maximum: LIMITS.maxListResults,
					description: "Most auditors to return (default 50)",
				},
			},
			additionalProperties: false,
		},
		annotations: READ_ONLY,
	},
	{
		name: "get_auditor",
		title: "Get an auditor",
		description: `One auditor by id (e.g. code.secrets, web.headers, agent.authz): what it checks, its targets and areas, the command that runs only it, and its full playbook when it is an agentic auditor.${LOCAL}`,
		inputSchema: {
			type: "object",
			properties: {
				id: {
					type: "string",
					minLength: 1,
					maxLength: 100,
					pattern: "^[a-z0-9][a-z0-9._-]*$",
					description: "Auditor id, as returned by list_auditors",
				},
			},
			required: ["id"],
			additionalProperties: false,
		},
		annotations: READ_ONLY,
	},
	{
		name: "search_docs",
		title: "Search the docs",
		description: `Full-text search over the openaudit docs (CLI, configuration, CI, MCP and agents, HTTP API, report and scoring, safety, contributing). Returns matching sections with a snippet and a link.${LOCAL}`,
		inputSchema: {
			type: "object",
			properties: {
				query: {
					type: "string",
					minLength: 2,
					maxLength: 200,
					description: "Words to look for, e.g. 'baseline suppressions'",
				},
				limit: {
					type: "integer",
					minimum: 1,
					maximum: LIMITS.maxSearchResults,
					description: `Most sections to return (default 5, at most ${LIMITS.maxSearchResults})`,
				},
			},
			required: ["query"],
			additionalProperties: false,
		},
		annotations: READ_ONLY,
	},
	{
		name: "get_config_schema",
		title: "Get the config schema",
		description: `The JSON Schema of openaudit.config.json (published at https://openaudit.se/schema/config.json): suppressions, auditor selection and per-auditor settings.${LOCAL}`,
		inputSchema: {
			type: "object",
			properties: {},
			additionalProperties: false,
		},
		annotations: READ_ONLY,
	},
	{
		name: "get_install_instructions",
		title: "Get install instructions",
		description: `How to install and run openaudit: the CLI, the local MCP server for Claude Code, Cursor, VS Code and Codex, MCP over HTTP, the GitHub Action, Docker, GitLab CI, pre-commit and the agent skill. Without a method, lists them all.${LOCAL}`,
		inputSchema: {
			type: "object",
			properties: {
				method: {
					type: "string",
					maxLength: 40,
					description:
						"cli, mcp, mcp-http, github-action, docker, gitlab-ci, pre-commit or skill",
				},
			},
			additionalProperties: false,
		},
		annotations: READ_ONLY,
	},
];
