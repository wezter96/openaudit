/**
 * The site is static (dist/, with dist/_headers applied by the assets
 * binding). This Worker runs first on every request to:
 *
 * - send www.openaudit.se to the apex (static assets cannot redirect by host);
 * - answer the read-only MCP endpoint at /mcp (worker/mcp.ts);
 * - serve a page's Markdown version when `Accept` prefers text/markdown;
 * - add discovery Link headers and `Vary: Accept` to HTML;
 * - give the agent-facing files (llms.txt, .well-known/*, *.md, /data/*,
 *   /openapi.json) their content types and open CORS (worker/agents.ts);
 * - count page and Markdown views anonymously (worker/visits.ts).
 */
import {
	agentFile,
	estimateTokens,
	linkHeader,
	markdownFor,
	PUBLIC_READ,
	prefersMarkdown,
} from "./agents";
import { type Assets, CORS, handleMcp } from "./mcp";
import { recordVisit, type Visits } from "./visits";

export interface Env {
	readonly ASSETS: Assets;
	/** Analytics Engine dataset for page views; absent in tests and local dev. */
	readonly VISITS?: Visits;
}

const SERVER_CARD = "/.well-known/mcp/server-card.json";
/** /.well-known/mcp is also a directory (the server card), so it lives here. */
const MCP_MANIFEST = "/.well-known/mcp/index.json";

const asset = (env: Env, request: Request, path: string) =>
	env.ASSETS.fetch(
		new Request(new URL(path, request.url), {
			method: "GET",
			headers: request.headers,
		}),
	);

const withHeaders = (res: Response, headers: Record<string, string>) => {
	const out = new Response(res.body, res);
	for (const [k, v] of Object.entries(headers)) out.headers.set(k, v);
	return out;
};

const preflight = () =>
	new Response(null, {
		status: 204,
		headers: {
			...PUBLIC_READ,
			"Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
			"Access-Control-Allow-Headers": "Accept, If-None-Match",
			"Access-Control-Max-Age": "86400",
		},
	});

/** A public file with its declared type and CORS, or `res` untouched on error. */
const publicFile = (res: Response, type: string, head: boolean) =>
	res.ok
		? withHeaders(head ? new Response(null, res) : res, {
				...PUBLIC_READ,
				"Content-Type": type,
			})
		: res;

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);
		if (url.hostname.startsWith("www.")) {
			url.hostname = url.hostname.slice(4);
			return Response.redirect(url.toString(), 301);
		}
		const path = url.pathname;
		const head = request.method === "HEAD";
		const read = request.method === "GET" || head;

		if (path === "/mcp" || path === "/mcp/")
			return handleMcp(request, env.ASSETS);
		// The recommended Server Card location: <streamable-http-url>/server-card.
		if (path === "/mcp/server-card") {
			if (request.method === "OPTIONS")
				return new Response(null, { status: 204, headers: CORS });
			if (!read)
				return new Response(null, {
					status: 405,
					headers: { Allow: "GET, HEAD, OPTIONS" },
				});
			return publicFile(
				await asset(env, request, SERVER_CARD),
				"application/mcp-server-card+json",
				head,
			);
		}
		if (path === "/.well-known/mcp" || path === "/.well-known/mcp/") {
			if (request.method === "OPTIONS") return preflight();
			return publicFile(
				await asset(env, request, MCP_MANIFEST),
				"application/json",
				head,
			);
		}

		const file = agentFile(path);
		if (file && request.method === "OPTIONS") return preflight();

		if (read && !file && prefersMarkdown(request.headers.get("accept"))) {
			const md = markdownFor(path);
			const res = md ? await asset(env, request, md) : undefined;
			if (res?.ok) {
				const text = await res.text();
				const out = new Response(head ? null : text, res);
				out.headers.set("Content-Type", "text/markdown; charset=utf-8");
				out.headers.set("x-markdown-tokens", String(estimateTokens(text)));
				out.headers.set("Vary", "Accept");
				out.headers.set(
					"Link",
					`<${path}>; rel="alternate"; type="text/html", ${linkHeader()}`,
				);
				out.headers.delete("Content-Length");
				out.headers.delete("ETag");
				recordVisit(env.VISITS, request, path, "markdown");
				return out;
			}
		}

		const res = await env.ASSETS.fetch(request);
		if (file) {
			if (res.ok && path.endsWith(".md"))
				recordVisit(env.VISITS, request, path, "markdown");
			return publicFile(res, file.type, false);
		}
		if ((res.headers.get("content-type") ?? "").startsWith("text/html")) {
			if (res.status === 200) recordVisit(env.VISITS, request, path, "page");
			const md = res.status === 200 ? markdownFor(path) : undefined;
			const out = withHeaders(res, { Link: linkHeader(md) });
			out.headers.append("Vary", "Accept");
			return out;
		}
		return res;
	},
};
