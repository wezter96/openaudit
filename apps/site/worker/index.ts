/**
 * The site is static (dist/, with dist/_headers applied by the assets
 * binding). This Worker runs first on every request to:
 *
 * - send www.openaudit.se to the apex (static assets cannot redirect by host);
 * - send the retired architecture page to the auditor catalogue;
 * - answer the read-only MCP endpoint at /mcp (worker/mcp.ts);
 * - serve the verified badges: their JSON API, SVGs, verification pages and
 *   stored reports (worker/badge/);
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
import type { BadgeBindings } from "./badge/env";
import { badgeRoute } from "./badge/routes";
import { type Assets, CORS, handleMcp } from "./mcp";
import { recordVisit, type Visits } from "./visits";

export interface Env extends BadgeBindings {
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

/** One request as the routes below see it. */
interface Visit {
	readonly request: Request;
	readonly env: Env;
	readonly path: string;
	readonly head: boolean;
	/** GET or HEAD. */
	readonly read: boolean;
}

/** Redirects for the www host and the retired architecture page. */
const redirectFor = (url: URL): Response | undefined => {
	if (url.hostname.startsWith("www.")) {
		url.hostname = url.hostname.slice(4);
		return Response.redirect(url.toString(), 301);
	}
	// Retired: README links and search results still point at it.
	if (/^\/architecture(?:\/|\.html$|$)/.test(url.pathname))
		return Response.redirect(new URL("/auditors/", url).toString(), 301);
	return undefined;
};

const serverCard = async ({ request, env, head, read }: Visit) => {
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
};

const mcpManifest = async ({ request, env, head }: Visit) => {
	if (request.method === "OPTIONS") return preflight();
	return publicFile(
		await asset(env, request, MCP_MANIFEST),
		"application/json",
		head,
	);
};

const mcp = ({ request, env }: Visit) => handleMcp(request, env.ASSETS);

/** Paths the Worker answers itself rather than from the static build. */
const ROUTES = new Map<string, (visit: Visit) => Promise<Response>>([
	["/mcp", mcp],
	["/mcp/", mcp],
	// The recommended Server Card location: <streamable-http-url>/server-card.
	["/mcp/server-card", serverCard],
	["/.well-known/mcp", mcpManifest],
	["/.well-known/mcp/", mcpManifest],
	// Where some clients and scanners look for the same manifest.
	["/.well-known/mcp.json", mcpManifest],
]);

type AgentFile = ReturnType<typeof agentFile>;

const wantsMarkdown = (visit: Visit, file: AgentFile) =>
	visit.read && !file && prefersMarkdown(visit.request.headers.get("accept"));

/** The page's Markdown version, or undefined when it has none. */
const markdownPage = async ({ request, env, path, head }: Visit) => {
	const md = markdownFor(path);
	const res = md ? await asset(env, request, md) : undefined;
	if (!res?.ok) return undefined;
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
};

const agentFileResponse = (
	{ request, env, path }: Visit,
	res: Response,
	type: string,
) => {
	if (res.ok && path.endsWith(".md"))
		recordVisit(env.VISITS, request, path, "markdown");
	return publicFile(res, type, false);
};

const htmlResponse = ({ request, env, path }: Visit, res: Response) => {
	if (res.status === 200) recordVisit(env.VISITS, request, path, "page");
	const md = res.status === 200 ? markdownFor(path) : undefined;
	const out = withHeaders(res, { Link: linkHeader(md) });
	out.headers.append("Vary", "Accept");
	return out;
};

const isHtml = (res: Response) =>
	(res.headers.get("content-type") ?? "").startsWith("text/html");

/** The static build's response, with agent-file or HTML headers added. */
const staticResponse = async (visit: Visit, file: AgentFile) => {
	const res = await visit.env.ASSETS.fetch(visit.request);
	if (file) return agentFileResponse(visit, res, file.type);
	if (isHtml(res)) return htmlResponse(visit, res);
	return res;
};

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);
		const redirect = redirectFor(url);
		if (redirect) return redirect;
		const badge = badgeRoute(request, env);
		if (badge) return badge;
		const head = request.method === "HEAD";
		const visit: Visit = {
			request,
			env,
			path: url.pathname,
			head,
			read: request.method === "GET" || head,
		};
		const route = ROUTES.get(visit.path);
		if (route) return route(visit);

		const file = agentFile(visit.path);
		if (file && request.method === "OPTIONS") return preflight();
		const markdown = wantsMarkdown(visit, file)
			? await markdownPage(visit)
			: undefined;
		return markdown ?? staticResponse(visit, file);
	},
};
