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

import {
	answer,
	error,
	INVALID_REQUEST,
	isSupportedVersion,
	PARSE_ERROR,
	PROTOCOL_VERSIONS,
	type Reply,
} from "./mcp-rpc";
import type { Assets } from "./mcp-run";
import { LIMITS } from "./mcp-tools";

export {
	INSTRUCTIONS,
	PROTOCOL_VERSIONS,
	SERVER_INFO,
} from "./mcp-rpc";
export type { Assets } from "./mcp-run";
export { validate } from "./mcp-schema";
export { LIMITS, TOOLS, type ToolDefinition } from "./mcp-tools";

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

const badRequest = (status: number, code: number, message: string) =>
	respond(status, error(null, code, message));

const tooLarge = () =>
	badRequest(
		413,
		INVALID_REQUEST,
		`Request body over ${LIMITS.maxBodyBytes} bytes`,
	);

/** The response to a request refused before its body is read, if any. */
const refuse = (request: Request): Response | undefined => {
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
		return badRequest(
			415,
			INVALID_REQUEST,
			"Content-Type must be application/json",
		);
	const version = request.headers.get("mcp-protocol-version");
	if (version !== null && !isSupportedVersion(version))
		return badRequest(
			400,
			INVALID_REQUEST,
			`Unsupported MCP-Protocol-Version; supported: ${PROTOCOL_VERSIONS.join(", ")}`,
		);
	return undefined;
};

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

/** The parsed JSON body, or the response for one too large or not JSON. */
const readBody = async (
	request: Request,
): Promise<{ readonly json: unknown } | Response> => {
	const length = Number(request.headers.get("content-length") ?? "0");
	if (length > LIMITS.maxBodyBytes) return tooLarge();
	const text = await readCapped(request, LIMITS.maxBodyBytes);
	if (text === undefined) return tooLarge();
	try {
		return { json: JSON.parse(text) };
	} catch {
		return badRequest(400, PARSE_ERROR, "Parse error");
	}
};

const answerBatch = async (
	batch: ReadonlyArray<unknown>,
	assets: Assets,
): Promise<Response> => {
	if (batch.length === 0)
		return badRequest(400, INVALID_REQUEST, "Empty batch");
	if (batch.length > LIMITS.maxBatch)
		return badRequest(
			400,
			INVALID_REQUEST,
			`Batch over ${LIMITS.maxBatch} messages`,
		);
	const replies: Reply[] = [];
	for (const m of batch) {
		const r = await answer(m, assets);
		if (r) replies.push(r);
	}
	return replies.length ? respond(200, replies) : respond(202);
};

export const handleMcp = async (
	request: Request,
	assets: Assets,
): Promise<Response> => {
	const refused = refuse(request);
	if (refused) return refused;
	const body = await readBody(request);
	if (body instanceof Response) return body;
	if (Array.isArray(body.json)) return answerBatch(body.json, assets);
	const reply = await answer(body.json, assets);
	return reply ? respond(200, reply) : respond(202);
};
