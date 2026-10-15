/** JSON-RPC for the MCP server: one message in, its reply out. */
import cli from "../../cli/package.json";
import { type Args, type Assets, fail, RUN } from "./mcp-run";
import { isObject, validate } from "./mcp-schema";
import { TOOLS } from "./mcp-tools";

/** Newest first; an unknown requested version gets the newest. */
export const PROTOCOL_VERSIONS = [
	"2025-11-25",
	"2025-06-18",
	"2025-03-26",
	"2024-11-05",
] as const;

export const isSupportedVersion = (version: string) =>
	(PROTOCOL_VERSIONS as ReadonlyArray<string>).includes(version);

export const SERVER_INFO = {
	name: "openaudit-site",
	title: "openaudit catalogue and docs (read-only)",
	version: cli.version,
	websiteUrl: "https://openaudit.se/",
} as const;

export const INSTRUCTIONS =
	"Read-only reference for openaudit, served from the openaudit.se website: look up auditors and their playbooks, search the docs, read the config schema and get install instructions. This server cannot run audits. To audit a codebase, URL, container or app, install the full local MCP server, which runs audits on the user's machine: `claude mcp add openaudit -- bunx @openaudit/cli mcp` (get_install_instructions has the setup for other clients).";

type Id = string | number;
export type Reply =
	| { jsonrpc: "2.0"; id: Id | null; result: unknown }
	| {
			jsonrpc: "2.0";
			id: Id | null;
			error: { code: number; message: string };
	  };

export const error = (id: Id | null, code: number, message: string): Reply => ({
	jsonrpc: "2.0",
	id,
	error: { code, message },
});
const result = (id: Id, value: unknown): Reply => ({
	jsonrpc: "2.0",
	id,
	result: value,
});
export const PARSE_ERROR = -32700;
export const INVALID_REQUEST = -32600;
const METHOD_NOT_FOUND = -32601;
const INVALID_PARAMS = -32602;
const INTERNAL_ERROR = -32603;

const invalid = (id: Id | null) =>
	error(id, INVALID_REQUEST, "Invalid request");

const isId = (v: unknown): v is Id =>
	(typeof v === "string" && v.length <= 200) ||
	(typeof v === "number" && Number.isFinite(v));

/* --------------------------------------------------------------- envelope */

/** A request this server answers. */
interface Call {
	readonly id: Id;
	readonly method: string;
	readonly params: Record<string, unknown> | undefined;
}
/** What to send instead of answering a message; undefined sends nothing. */
interface Instead {
	readonly reply: Reply | undefined;
}

/** The message's id: undefined when it has none, null when it is malformed. */
const idOf = (raw: Record<string, unknown>): Id | null | undefined => {
	if (!("id" in raw)) return undefined;
	return isId(raw.id) ? raw.id : null;
};

/** A response to a server request; this server sends none, so it is ignored. */
const isClientResponse = (raw: Record<string, unknown>) =>
	!("id" in raw) || "result" in raw || "error" in raw;

const isParams = (v: unknown): v is Record<string, unknown> | undefined =>
	v === undefined || isObject(v);

const toCall = (raw: unknown): Call | Instead => {
	if (!isObject(raw)) return { reply: invalid(null) };
	const id = idOf(raw);
	if (raw.jsonrpc !== "2.0" || id === null)
		return { reply: invalid(id ?? null) };
	if (typeof raw.method !== "string")
		return { reply: isClientResponse(raw) ? undefined : invalid(id ?? null) };
	// Notifications, e.g. notifications/initialized, get no reply.
	if (id === undefined) return { reply: undefined };
	if (!isParams(raw.params))
		return { reply: error(id, INVALID_PARAMS, "params must be an object") };
	return { id, method: raw.method, params: raw.params };
};

/* ---------------------------------------------------------------- methods */

const negotiate = (asked: unknown) =>
	typeof asked === "string" && isSupportedVersion(asked)
		? asked
		: PROTOCOL_VERSIONS[0];

const unknownTool = (name: unknown) =>
	`Unknown tool${typeof name === "string" ? ` "${name.slice(0, 100)}"` : ""}. Tools: ${TOOLS.map((t) => t.name).join(", ")}`;

const callTool = async (
	{ id, params }: Call,
	assets: Assets,
): Promise<Reply> => {
	const name = params?.name;
	const tool = TOOLS.find((t) => t.name === name);
	if (!tool) return error(id, INVALID_PARAMS, unknownTool(name));
	const args = params?.arguments ?? {};
	// Bad arguments are a tool error, so the model can correct itself.
	const problem = validate(tool.inputSchema, args);
	if (problem) return result(id, fail(`Invalid arguments: ${problem}`));
	const run = RUN[tool.name];
	if (!run) return error(id, INTERNAL_ERROR, "Tool not implemented");
	try {
		return result(id, await run(args as Args, assets));
	} catch {
		return result(
			id,
			fail("The site's data could not be read. Try again later."),
		);
	}
};

const METHODS = new Map<
	string,
	(call: Call, assets: Assets) => Reply | Promise<Reply>
>([
	[
		"initialize",
		({ id, params }) =>
			result(id, {
				protocolVersion: negotiate(params?.protocolVersion),
				capabilities: { tools: { listChanged: false } },
				serverInfo: SERVER_INFO,
				instructions: INSTRUCTIONS,
			}),
	],
	["ping", ({ id }) => result(id, {})],
	["tools/list", ({ id }) => result(id, { tools: TOOLS })],
	["tools/call", callTool],
]);

/** One message's reply; undefined for notifications and client responses. */
export const answer = async (
	raw: unknown,
	assets: Assets,
): Promise<Reply | undefined> => {
	const call = toCall(raw);
	if ("reply" in call) return call.reply;
	const method = METHODS.get(call.method);
	if (!method)
		return error(
			call.id,
			METHOD_NOT_FOUND,
			`Method not found: ${call.method.slice(0, 100)}`,
		);
	return method(call, assets);
};
