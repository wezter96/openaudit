/**
 * A read-only MCP server at https://openaudit.se/mcp: the auditor catalogue,
 * the playbooks, the docs, the config schema and install instructions, all
 * read from the site's own static build (env.ASSETS).
 *
 * Stateless MCP Streamable HTTP: JSON-RPC over POST, answered with plain JSON.
 * There are no sessions, no SSE stream (GET is 405), no state and no outbound
 * requests. The endpoint is public, so the body and batch sizes are capped,
 * arguments are validated against each tool's schema, and every reply is
 * JSON. It complements the full local server (`bunx @openaudit/cli mcp`),
 * which runs audits; this one cannot.
 */
import cli from "../../cli/package.json";

export interface Assets {
	readonly fetch: (request: Request) => Promise<Response>;
}

export const LIMITS = {
	/** Largest request body accepted, in bytes. */
	maxBodyBytes: 64 * 1024,
	/** Most messages in one JSON-RPC batch. */
	maxBatch: 16,
	maxSearchResults: 10,
	maxListResults: 200,
} as const;

/** Newest first; an unknown requested version gets the newest. */
export const PROTOCOL_VERSIONS = [
	"2025-11-25",
	"2025-06-18",
	"2025-03-26",
	"2024-11-05",
] as const;

export const SERVER_INFO = {
	name: "openaudit-site",
	title: "openaudit catalogue and docs (read-only)",
	version: cli.version,
	websiteUrl: "https://openaudit.se/",
} as const;

export const INSTRUCTIONS =
	"Read-only reference for openaudit, served from the openaudit.se website: look up auditors and their playbooks, search the docs, read the config schema and get install instructions. This server cannot run audits. To audit a codebase, URL, container or app, install the full local MCP server, which runs audits on the user's machine: `claude mcp add openaudit -- bunx @openaudit/cli mcp` (get_install_instructions has the setup for other clients).";

/** The subset of JSON Schema the tools use; validate() checks exactly this. */
interface Schema {
	readonly type: "object" | "string" | "integer";
	readonly description?: string;
	readonly properties?: Readonly<Record<string, Schema>>;
	readonly required?: ReadonlyArray<string>;
	readonly additionalProperties?: false;
	readonly minLength?: number;
	readonly maxLength?: number;
	readonly pattern?: string;
	readonly minimum?: number;
	readonly maximum?: number;
}

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

/* ------------------------------------------------------------------- data */

interface Auditor {
	readonly id: string;
	readonly title: string;
	readonly description: string;
	readonly engine: string;
	readonly tool: string | null;
	readonly categories: ReadonlyArray<string>;
	readonly targets: ReadonlyArray<string>;
	readonly network: boolean;
	readonly optIn: boolean;
	readonly command: string;
	readonly url: string;
}
interface Catalogue {
	readonly auditors: ReadonlyArray<Auditor>;
	readonly playbooks: ReadonlyArray<{
		readonly id: string;
		readonly title: string;
		readonly summary: string;
		readonly needs: ReadonlyArray<string>;
		readonly markdown: string;
	}>;
}
interface Docs {
	readonly sections: ReadonlyArray<{
		readonly page: string;
		readonly heading: string;
		readonly url: string;
		readonly text: string;
	}>;
	readonly install: Readonly<Record<string, string>>;
}

/** Build output is immutable per deployment, so each isolate reads it once. */
const cache = new WeakMap<Assets, Map<string, Promise<unknown>>>();
const asset = <T>(assets: Assets, path: string): Promise<T> => {
	let files = cache.get(assets);
	if (!files) {
		files = new Map();
		cache.set(assets, files);
	}
	let file = files.get(path);
	if (!file) {
		file = assets
			.fetch(new Request(`https://openaudit.se${path}`))
			.then((r) => {
				if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
				return r.json();
			});
		// A failed read is retried by the next request.
		file.catch(() => files?.delete(path));
		files.set(path, file);
	}
	return file as Promise<T>;
};

/* ------------------------------------------------------------- validation */

/** The first way `value` breaks `schema`, or undefined when it conforms. */
export const validate = (
	schema: Schema,
	value: unknown,
	at = "arguments",
): string | undefined => {
	if (schema.type === "object") {
		if (typeof value !== "object" || value === null || Array.isArray(value))
			return `${at} must be an object`;
		const record = value as Record<string, unknown>;
		const props = schema.properties ?? {};
		for (const key of schema.required ?? [])
			if (record[key] === undefined) return `${at}.${key} is required`;
		for (const [key, v] of Object.entries(record)) {
			const prop = props[key];
			if (!prop) {
				if (schema.additionalProperties === false)
					return `${at} has an unknown property "${key.slice(0, 40)}"; allowed: ${Object.keys(props).join(", ") || "none"}`;
				continue;
			}
			const problem = validate(prop, v, `${at}.${key}`);
			if (problem) return problem;
		}
		return undefined;
	}
	if (schema.type === "string") {
		if (typeof value !== "string") return `${at} must be a string`;
		if (schema.minLength !== undefined && value.length < schema.minLength)
			return `${at} must be at least ${schema.minLength} characters`;
		if (schema.maxLength !== undefined && value.length > schema.maxLength)
			return `${at} must be at most ${schema.maxLength} characters`;
		// The patterns are this module's own literals.
		// nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
		if (schema.pattern && !new RegExp(schema.pattern).test(value))
			return `${at} must match ${schema.pattern}`;
		return undefined;
	}
	if (typeof value !== "number" || !Number.isInteger(value))
		return `${at} must be an integer`;
	if (schema.minimum !== undefined && value < schema.minimum)
		return `${at} must be at least ${schema.minimum}`;
	if (schema.maximum !== undefined && value > schema.maximum)
		return `${at} must be at most ${schema.maximum}`;
	return undefined;
};

/* ------------------------------------------------------------------ tools */

interface ToolResult {
	readonly content: ReadonlyArray<{ type: "text"; text: string }>;
	readonly structuredContent?: Record<string, unknown>;
	readonly isError?: boolean;
}
const ok = (
	text: string,
	structured?: Record<string, unknown>,
): ToolResult => ({
	content: [{ type: "text", text }],
	...(structured ? { structuredContent: structured } : {}),
});
const fail = (text: string): ToolResult => ({
	content: [{ type: "text", text }],
	isError: true,
});

/** `value` must be one of `allowed`, which come from the data itself. */
const oneOf = (
	name: string,
	value: string | undefined,
	allowed: Iterable<string>,
) => {
	const set = [...new Set(allowed)].sort();
	return value === undefined || set.includes(value)
		? undefined
		: `Unknown ${name} "${value}". Use one of: ${set.join(", ")}.`;
};

const summary = (a: Auditor) => ({
	id: a.id,
	title: a.title,
	engine: a.engine,
	tool: a.tool,
	categories: a.categories,
	targets: a.targets,
	runsByDefault: !a.optIn,
	url: a.url,
});

type Args = Record<string, unknown>;
const RUN: Record<string, (args: Args, assets: Assets) => Promise<ToolResult>> =
	{
		async list_auditors(args, assets) {
			const { auditors } = await asset<Catalogue>(
				assets,
				"/data/catalogue.json",
			);
			const category = args.category as string | undefined;
			const target = args.target as string | undefined;
			const engine = args.engine as string | undefined;
			const problem =
				oneOf(
					"category",
					category,
					auditors.flatMap((a) => a.categories),
				) ??
				oneOf(
					"target",
					target,
					auditors.flatMap((a) => a.targets),
				) ??
				oneOf(
					"engine",
					engine,
					auditors.map((a) => a.engine),
				);
			if (problem) return fail(problem);
			const words = ((args.query as string | undefined) ?? "")
				.toLowerCase()
				.split(/\s+/)
				.filter(Boolean)
				.slice(0, 10);
			const hits = auditors.filter(
				(a) =>
					(!category || a.categories.includes(category)) &&
					(!target || a.targets.includes(target)) &&
					(!engine || a.engine === engine) &&
					words.every((w) =>
						`${a.id} ${a.title} ${a.tool ?? ""} ${a.description}`
							.toLowerCase()
							.includes(w),
					),
			);
			const shown = hits.slice(0, (args.limit as number | undefined) ?? 50);
			const text = hits.length
				? `${hits.length} auditor(s)${shown.length < hits.length ? `, showing ${shown.length}` : ""}:\n\n${shown
						.map(
							(a) =>
								`- \`${a.id}\` ${a.title} (${a.engine}${a.tool ? `, wraps ${a.tool}` : ""}; ${a.categories.join(", ")}; ${a.optIn ? "opt-in" : "runs by default"})`,
						)
						.join("\n")}`
				: "No auditors match.";
			return ok(text, { total: hits.length, auditors: shown.map(summary) });
		},

		async get_auditor(args, assets) {
			const { auditors, playbooks } = await asset<Catalogue>(
				assets,
				"/data/catalogue.json",
			);
			const id = args.id as string;
			const a = auditors.find((x) => x.id === id);
			if (!a)
				return fail(
					`No auditor with id "${id}". Use list_auditors to find one.`,
				);
			const playbook = playbooks.find((p) => p.id === a.id);
			const text = [
				`# ${a.title}`,
				`\`${a.id}\`: ${a.description}`,
				`- Engine: ${a.engine}${a.tool ? ` (wraps ${a.tool})` : ""}\n- Targets: ${a.targets.join(", ")}\n- Areas: ${a.categories.join(", ")}\n- Runs: ${a.optIn ? "opt-in, only with --only" : "by default when the target applies"}\n- Network: ${a.network ? "contacts services beyond the target" : "only the target itself"}`,
				`Run only this auditor:\n\n\`\`\`sh\n${a.command}\n\`\`\``,
				playbook ? `## Playbook\n\n${playbook.markdown}` : "",
				`Page: ${a.url}`,
			]
				.filter(Boolean)
				.join("\n\n");
			return ok(text, {
				...summary(a),
				description: a.description,
				network: a.network,
				command: a.command,
				...(playbook
					? {
							playbook: {
								title: playbook.title,
								summary: playbook.summary,
								needs: playbook.needs,
								markdown: playbook.markdown,
							},
						}
					: {}),
			});
		},

		async search_docs(args, assets) {
			const { sections } = await asset<Docs>(assets, "/data/docs.json");
			const terms = [
				...new Set(
					(args.query as string)
						.toLowerCase()
						.split(/[^\p{L}\p{N}._-]+/u)
						.filter((t) => t.length >= 2),
				),
			].slice(0, 8);
			if (!terms.length)
				return fail("The query needs a word of two or more letters.");
			const count = (haystack: string, term: string) => {
				let n = 0;
				for (
					let i = haystack.indexOf(term);
					i >= 0 && n < 20;
					i = haystack.indexOf(term, i + term.length)
				)
					n++;
				return n;
			};
			const scored = sections
				.map((s) => {
					const heading = s.heading.toLowerCase();
					const text = s.text.toLowerCase();
					let score = 0;
					let matched = 0;
					for (const t of terms) {
						const n = count(heading, t) * 3 + count(text, t);
						if (n) matched++;
						score += n;
					}
					// Sections that contain every term rank first.
					return {
						s,
						score: score + (matched === terms.length ? 100 : 0),
						matched,
					};
				})
				.filter((r) => r.matched > 0)
				.sort((a, b) => b.score - a.score)
				.slice(0, (args.limit as number | undefined) ?? 5);
			const results = scored.map(({ s }) => {
				const flat = s.text.replace(/\s+/g, " ");
				const at = Math.max(
					0,
					Math.min(
						...terms
							.map((t) => flat.toLowerCase().indexOf(t))
							.filter((i) => i >= 0),
					) - 80,
				);
				const snippet = `${at > 0 ? "…" : ""}${flat.slice(at, at + 280).trim()}${at + 280 < flat.length ? "…" : ""}`;
				return { page: s.page, heading: s.heading, url: s.url, snippet };
			});
			const text = results.length
				? results
						.map((r) => `## ${r.page}: ${r.heading}\n${r.url}\n\n${r.snippet}`)
						.join("\n\n")
				: `Nothing in the docs matches "${terms.join(" ")}".`;
			return ok(text, { results });
		},

		async get_config_schema(_args, assets) {
			const schema = await asset<Record<string, unknown>>(
				assets,
				"/schema/config.json",
			);
			return ok(
				`The JSON Schema of openaudit.config.json (https://openaudit.se/schema/config.json):\n\n\`\`\`json\n${JSON.stringify(schema, null, 2)}\n\`\`\``,
				{ url: "https://openaudit.se/schema/config.json", schema },
			);
		},

		async get_install_instructions(args, assets) {
			const { install } = await asset<Docs>(assets, "/data/docs.json");
			const method = args.method as string | undefined;
			const problem = oneOf("method", method, Object.keys(install));
			if (problem) return fail(problem);
			const picked = method
				? { [method]: install[method] ?? "" }
				: { ...install };
			return ok(
				Object.entries(picked)
					.map(([k, v]) => (method ? v : `<!-- ${k} -->\n${v}`))
					.join("\n\n"),
				{ instructions: picked },
			);
		},
	};

/* ---------------------------------------------------------------- JSON-RPC */

type Id = string | number;
interface Message {
	readonly jsonrpc: "2.0";
	readonly id?: Id;
	readonly method: string;
	readonly params?: unknown;
}
type Reply =
	| { jsonrpc: "2.0"; id: Id | null; result: unknown }
	| {
			jsonrpc: "2.0";
			id: Id | null;
			error: { code: number; message: string };
	  };

const error = (id: Id | null, code: number, message: string): Reply => ({
	jsonrpc: "2.0",
	id,
	error: { code, message },
});
const PARSE_ERROR = -32700;
const INVALID_REQUEST = -32600;
const METHOD_NOT_FOUND = -32601;
const INVALID_PARAMS = -32602;
const INTERNAL_ERROR = -32603;

const isId = (v: unknown): v is Id =>
	(typeof v === "string" && v.length <= 200) ||
	(typeof v === "number" && Number.isFinite(v));

const isObject = (v: unknown): v is Record<string, unknown> =>
	typeof v === "object" && v !== null && !Array.isArray(v);

/** One message's reply; undefined for notifications and client responses. */
const answer = async (
	raw: unknown,
	assets: Assets,
): Promise<Reply | undefined> => {
	if (!isObject(raw)) return error(null, INVALID_REQUEST, "Invalid request");
	const hasId = "id" in raw;
	const id = hasId && isId(raw.id) ? raw.id : null;
	if (raw.jsonrpc !== "2.0" || (hasId && id === null))
		return error(id, INVALID_REQUEST, "Invalid request");
	if (typeof raw.method !== "string") {
		// A response to a server request; this server sends none, so ignore it.
		if (!hasId || "result" in raw || "error" in raw) return undefined;
		return error(id, INVALID_REQUEST, "Invalid request");
	}
	const message = raw as unknown as Message;
	if (!hasId) return undefined; // notifications, e.g. notifications/initialized
	if (id === null) return error(null, INVALID_REQUEST, "Invalid request");
	if (message.params !== undefined && !isObject(message.params))
		return error(id, INVALID_PARAMS, "params must be an object");
	const params = message.params as Record<string, unknown> | undefined;

	switch (message.method) {
		case "initialize": {
			const asked = params?.protocolVersion;
			const protocolVersion =
				typeof asked === "string" &&
				(PROTOCOL_VERSIONS as ReadonlyArray<string>).includes(asked)
					? asked
					: PROTOCOL_VERSIONS[0];
			return {
				jsonrpc: "2.0",
				id,
				result: {
					protocolVersion,
					capabilities: { tools: { listChanged: false } },
					serverInfo: SERVER_INFO,
					instructions: INSTRUCTIONS,
				},
			};
		}
		case "ping":
			return { jsonrpc: "2.0", id, result: {} };
		case "tools/list":
			return { jsonrpc: "2.0", id, result: { tools: TOOLS } };
		case "tools/call": {
			const name = params?.name;
			const tool = TOOLS.find((t) => t.name === name);
			if (typeof name !== "string" || !tool)
				return error(
					id,
					INVALID_PARAMS,
					`Unknown tool${typeof name === "string" ? ` "${name.slice(0, 100)}"` : ""}. Tools: ${TOOLS.map((t) => t.name).join(", ")}`,
				);
			const args = params?.arguments ?? {};
			// Bad arguments are a tool error, so the model can correct itself.
			const problem = validate(tool.inputSchema, args);
			if (problem)
				return {
					jsonrpc: "2.0",
					id,
					result: fail(`Invalid arguments: ${problem}`),
				};
			const run = RUN[tool.name];
			if (!run) return error(id, INTERNAL_ERROR, "Tool not implemented");
			try {
				return { jsonrpc: "2.0", id, result: await run(args as Args, assets) };
			} catch {
				return {
					jsonrpc: "2.0",
					id,
					result: fail("The site's data could not be read. Try again later."),
				};
			}
		}
		default:
			return error(
				id,
				METHOD_NOT_FOUND,
				`Method not found: ${message.method.slice(0, 100)}`,
			);
	}
};

/* -------------------------------------------------------------------- HTTP */

export const CORS = {
	"Access-Control-Allow-Origin": "*",
	"Access-Control-Allow-Methods": "POST, GET, OPTIONS",
	"Access-Control-Allow-Headers":
		"Content-Type, Accept, Authorization, Mcp-Protocol-Version, Mcp-Session-Id, Last-Event-ID",
	"Access-Control-Max-Age": "86400",
} as const;

const respond = (status: number, body?: unknown, headers: HeadersInit = {}) =>
	new Response(body === undefined ? null : JSON.stringify(body), {
		status,
		headers: {
			...CORS,
			"Cache-Control": "no-store",
			"X-Content-Type-Options": "nosniff",
			...(body === undefined ? {} : { "Content-Type": "application/json" }),
			...headers,
		},
	});

/** The body as text, or undefined once it passes `max` bytes. */
const readCapped = async (
	request: Request,
	max: number,
): Promise<string | undefined> => {
	if (!request.body) return "";
	const reader = request.body.getReader();
	const chunks: Uint8Array[] = [];
	let size = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		size += value.byteLength;
		if (size > max) {
			await reader.cancel();
			return undefined;
		}
		chunks.push(value);
	}
	const all = new Uint8Array(size);
	let at = 0;
	for (const c of chunks) {
		all.set(c, at);
		at += c.byteLength;
	}
	return new TextDecoder().decode(all);
};

export const handleMcp = async (
	request: Request,
	assets: Assets,
): Promise<Response> => {
	if (request.method === "OPTIONS") return respond(204);
	if (request.method !== "POST")
		// No server-to-client stream and no sessions to delete.
		return respond(
			405,
			error(null, INVALID_REQUEST, "Use POST: this server has no SSE stream"),
			{ Allow: "POST, OPTIONS" },
		);
	const type = request.headers.get("content-type") ?? "";
	if (!/^application\/json\b/i.test(type))
		return respond(
			415,
			error(null, INVALID_REQUEST, "Content-Type must be application/json"),
		);
	const version = request.headers.get("mcp-protocol-version");
	if (
		version !== null &&
		!(PROTOCOL_VERSIONS as ReadonlyArray<string>).includes(version)
	)
		return respond(
			400,
			error(
				null,
				INVALID_REQUEST,
				`Unsupported MCP-Protocol-Version; supported: ${PROTOCOL_VERSIONS.join(", ")}`,
			),
		);
	const length = Number(request.headers.get("content-length") ?? "0");
	const tooLarge = () =>
		respond(
			413,
			error(
				null,
				INVALID_REQUEST,
				`Request body over ${LIMITS.maxBodyBytes} bytes`,
			),
		);
	if (length > LIMITS.maxBodyBytes) return tooLarge();
	const text = await readCapped(request, LIMITS.maxBodyBytes);
	if (text === undefined) return tooLarge();

	let body: unknown;
	try {
		body = JSON.parse(text);
	} catch {
		return respond(400, error(null, PARSE_ERROR, "Parse error"));
	}
	if (Array.isArray(body)) {
		if (body.length === 0)
			return respond(400, error(null, INVALID_REQUEST, "Empty batch"));
		if (body.length > LIMITS.maxBatch)
			return respond(
				400,
				error(null, INVALID_REQUEST, `Batch over ${LIMITS.maxBatch} messages`),
			);
		const replies: Reply[] = [];
		for (const m of body) {
			const r = await answer(m, assets);
			if (r) replies.push(r);
		}
		return replies.length ? respond(200, replies) : respond(202);
	}
	const reply = await answer(body, assets);
	return reply ? respond(200, reply) : respond(202);
};
