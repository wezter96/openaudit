/**
 * The discovery files agents look for, written into dist/ by postbuild.ts.
 * Each describes something that exists: the read-only MCP server in
 * worker/mcp.ts, the agent skill in skills/, the self-hosted HTTP API's
 * OpenAPI document (prepare.ts) and the site's own Markdown and llms.txt.
 *
 * - .well-known/mcp/server-card.json (and server-cards.json, the draft's
 *   newer name): MCP Server Card, SEP-2127 fields plus the SEP-1649 ones
 *   older scanners read.
 * - .well-known/mcp/index.json: the SEP-1960 manifest; the Worker serves it
 *   at /.well-known/mcp, which cannot be a file next to the mcp/ directory.
 * - .well-known/agent-skills/index.json and <name>/SKILL.md (Agent Skills
 *   Discovery 0.2.0), with the digest of the exact bytes served.
 * - .well-known/api-catalog: RFC 9727 linkset.
 * - .well-known/ai-catalog.json: AI Catalog / ARD.
 * - auth.md: no credentials are needed for anything here.
 *
 * Returns the site paths the files link to, for the link check.
 */
import { createHash } from "node:crypto";
import { mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import {
	INSTRUCTIONS,
	PROTOCOL_VERSIONS,
	SERVER_INFO,
	TOOLS,
} from "../worker/mcp";

const REPO = "https://github.com/wezter96/openaudit";

/** The skills published under /.well-known/agent-skills/, from skills/. */
const SKILLS = ["openaudit"] as const;

const frontMatter = (md: string): Record<string, string> => {
	const block = /^---\n([\s\S]*?)\n---/.exec(md)?.[1] ?? "";
	return Object.fromEntries(
		[...block.matchAll(/^([a-z-]+):\s*(.*)$/gm)].map((m) => [
			m[1] ?? "",
			(m[2] ?? "").trim(),
		]),
	);
};

export const writeAgentFiles = async (options: {
	readonly dist: string;
	readonly repo: string;
	/** Origin plus base path, without a trailing slash. */
	readonly root: string;
	/** The base path, "" at the root. */
	readonly base: string;
}): Promise<string[]> => {
	const { dist, repo, root, base } = options;
	const at = (path: string) => `${root}${path}`;
	const write = async (path: string, body: string) => {
		const file = join(dist, path);
		await mkdir(dirname(file), { recursive: true });
		await Bun.write(file, body);
	};
	const json = (v: unknown) => `${JSON.stringify(v, null, "\t")}\n`;
	const mcpUrl = at("/mcp");
	const cliVersion = SERVER_INFO.version;
	const localServer = {
		description:
			"The full openaudit MCP server runs on your machine and runs audits: run_audit, get_report, get_finding, compare_reports and the playbook tools. Over stdio it needs no credentials.",
		transport: "stdio",
		command: "bunx @openaudit/cli mcp",
		package: {
			registryType: "npm",
			identifier: "@openaudit/cli",
			version: cliVersion,
		},
		documentation: at("/docs/agents/"),
	};

	/* ---------------------------------------------------------- MCP card */

	const card = {
		$schema:
			"https://static.modelcontextprotocol.io/schemas/v1/server-card.schema.json",
		name: "se.openaudit/catalogue",
		version: cliVersion,
		title: SERVER_INFO.title,
		description:
			"Read-only openaudit reference: the auditor catalogue, playbooks, docs search, config schema and install instructions. It cannot run audits; the local server (bunx @openaudit/cli mcp) does.",
		websiteUrl: at("/"),
		repository: { url: REPO, source: "github", subfolder: "apps/site/worker" },
		icons: [{ src: at("/favicon.svg"), mimeType: "image/svg+xml" }],
		remotes: [
			{
				type: "streamable-http",
				url: mcpUrl,
				supportedProtocolVersions: [...PROTOCOL_VERSIONS],
			},
		],
		// SEP-1649's earlier shape, still read by discovery scanners.
		serverInfo: {
			name: SERVER_INFO.name,
			title: SERVER_INFO.title,
			version: cliVersion,
		},
		protocolVersion: PROTOCOL_VERSIONS[0],
		transport: { type: "streamable-http", endpoint: mcpUrl },
		capabilities: { tools: { listChanged: false } },
		instructions: INSTRUCTIONS,
		authentication: { required: false },
		tools: TOOLS,
		_meta: { "se.openaudit/local-server": localServer },
	};
	await write("/.well-known/mcp/server-card.json", json(card));
	await write("/.well-known/mcp/server-cards.json", json(card));
	await write(
		"/.well-known/mcp/index.json",
		json({
			mcp_version: PROTOCOL_VERSIONS[0],
			server_name: SERVER_INFO.name,
			server_version: cliVersion,
			description: card.description,
			endpoints: { streamable_http: mcpUrl },
			server_card: at("/.well-known/mcp/server-card.json"),
			capabilities: {
				tools: true,
				resources: false,
				prompts: false,
				sampling: false,
				roots: false,
			},
			authentication: { required: false },
			security: {
				tls_required: true,
				security_policy: at("/.well-known/security.txt"),
			},
			documentation: at("/docs/agents/"),
			local_server: localServer,
		}),
	);

	/* ------------------------------------------------------------- skills */

	const skills: {
		name: string;
		type: "skill-md";
		description: string;
		url: string;
		digest: string;
	}[] = [];
	for (const name of SKILLS) {
		const text = await Bun.file(join(repo, "skills", name, "SKILL.md")).text();
		const meta = frontMatter(text);
		if (meta.name !== name)
			throw new Error(`skills/${name}/SKILL.md: name is not ${name}`);
		if (!meta.description)
			throw new Error(`skills/${name}/SKILL.md: no description`);
		const path = `/.well-known/agent-skills/${name}/SKILL.md`;
		await write(path, text);
		skills.push({
			name,
			type: "skill-md",
			description: meta.description,
			url: `${base}${path}`,
			digest: `sha256:${createHash("sha256").update(text).digest("hex")}`,
		});
	}
	await write(
		"/.well-known/agent-skills/index.json",
		json({
			$schema: "https://schemas.agentskills.io/discovery/0.2.0/schema.json",
			skills,
		}),
	);

	/* -------------------------------------------------------- API catalog */

	const openapi = (await Bun.file(join(dist, "openapi.json")).json()) as {
		servers: { url: string }[];
	};
	await write(
		"/.well-known/api-catalog",
		json({
			linkset: [
				{
					// Self-hosted only: the anchor is the default local server.
					anchor:
						openapi.servers[0]?.url ?? "http://localhost:3000/api-reference",
					"service-desc": [
						{ href: at("/openapi.json"), type: "application/json" },
					],
					"service-doc": [{ href: at("/docs/api/"), type: "text/html" }],
				},
				{
					anchor: mcpUrl,
					"service-desc": [
						{
							href: at("/.well-known/mcp/server-card.json"),
							type: "application/json",
						},
					],
					"service-doc": [{ href: at("/docs/agents/"), type: "text/html" }],
				},
			],
		}),
	);

	/* --------------------------------------------------------- AI catalog */

	const skillEntries = skills.map((s) => ({
		identifier: `urn:air:openaudit.se:skill:${s.name}`,
		displayName: `${s.name} agent skill`,
		type: "application/agent-skills+md",
		description: s.description,
		url: at(s.url.slice(base.length)),
		representativeQueries: [
			"audit this repository for security and accessibility issues",
			"check my website's security headers and SEO",
			"verify that my fixes removed the audit findings",
		],
	}));
	await write(
		"/.well-known/ai-catalog.json",
		json({
			specVersion: "1.0",
			host: {
				displayName: "openaudit",
				identifier: "did:web:openaudit.se",
				documentationUrl: at("/docs/"),
			},
			entries: [
				{
					identifier: "urn:air:openaudit.se:mcp:catalogue",
					displayName: SERVER_INFO.title,
					type: "application/mcp-server-card+json",
					description: card.description,
					url: at("/.well-known/mcp/server-card.json"),
					representativeQueries: [
						"which openaudit auditors check accessibility",
						"what does the code.secrets auditor do",
						"how do I install openaudit as an MCP server in Cursor",
						"search the openaudit docs for baselines",
					],
				},
				...skillEntries,
				{
					identifier: "urn:air:openaudit.se:api:http-api",
					displayName: "openaudit HTTP API (self-hosted)",
					type: "application/vnd.oai.openapi+json",
					description:
						"OpenAPI document of the HTTP API you run yourself from apps/server. openaudit.se does not host this API.",
					url: at("/openapi.json"),
					representativeQueries: [
						"run an openaudit URL audit over HTTP",
						"list openaudit auditors through a REST API",
					],
				},
			],
		}),
	);

	/* ------------------------------------------------------------ auth.md */

	await write(
		"/auth.md",
		`# openaudit auth.md

openaudit.se needs no registration and no credentials. Everything it offers agents is public and read-only, and is served the same way to everyone:

- the website, and the Markdown version of every page (${at("/llms.txt")} lists them);
- the read-only MCP server at ${mcpUrl}, with the auditor catalogue, playbooks and docs (it cannot run audits);
- the agent skills, the OpenAPI document and the discovery files under ${at("/.well-known/")}.

## Audience

Any agent, crawler or person. The content signals in ${at("/robots.txt")} say how the content may be used.

## Registration

None. There is no account, no API key, no OAuth server and no registration endpoint, so this site publishes no OAuth metadata.

## Methods

Anonymous only. Send requests without an \`Authorization\` header; one that is sent is ignored.

## Credential use

None is accepted or stored. The site keeps no state between requests.

## Elsewhere in openaudit

- **Self-hosted HTTP API** (${at("/docs/api/")}): not hosted on openaudit.se; you run it from apps/server. It has no authentication of its own. URL audits are rate limited per client and server-wide and refuse private-network targets unless the server sets \`ALLOW_PRIVATE_TARGETS\`. Keep it behind your own network controls if it should not be public.
- **Local MCP server** (\`bunx @openaudit/cli mcp\`): runs on your machine over stdio and needs no credentials. Served over HTTP (\`openaudit mcp --http\`) it requires a bearer token you choose (\`OPENAUDIT_MCP_TOKEN\`); on loopback one is generated for you. See ${at("/docs/agents/")}.
- **Agentic auditors** (\`--agentic\`) use your own \`ANTHROPIC_API_KEY\` or Claude Code login, on your machine.
`,
	);

	// Paths these files link to on this site; /mcp is the Worker's own.
	return [
		"/.well-known/mcp/server-card.json",
		"/.well-known/agent-skills/index.json",
		...skills.map((s) => s.url.slice(base.length)),
		"/openapi.json",
		"/docs/api/",
		"/docs/agents/",
		"/docs/",
		"/favicon.svg",
		"/llms.txt",
		"/robots.txt",
		"/.well-known/security.txt",
	];
};
