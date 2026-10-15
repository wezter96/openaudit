/**
 * Routes for the verified badges (see packages/badge): the JSON API under
 * /api/badges and /api/scanner, and the public /badge/* and /v/* pages.
 */
import type { ScanId } from "@openaudit/badge";
import { apiRoute, type Path } from "./api-route";
import type { BadgeBindings } from "./env";
import { reportResponse, svgResponse, verifyPage } from "./pages";

/** Path plus query string, in characters. */
const MAX_URL = 512;

const ID = "([a-z0-9][a-z0-9-]{0,159})";
const SVG = new RegExp(`^/badge/${ID}(\\.svg|/card\\.svg)$`);
const PAGE = new RegExp(`^/v/${ID}/?$`);
const REPORT = new RegExp(`^/v/${ID}/(report|site-report)$`);
const SCAN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const isApi = (path: Path) =>
	path.startsWith("/api/badges") || path.startsWith("/api/scanner/");

const isPublic = (path: Path) =>
	[SVG, PAGE, REPORT].some((pattern) => pattern.test(path));

const tooLong = (url: URL) => url.pathname.length + url.search.length > MAX_URL;

const uriTooLong = async () => new Response("URL too long.\n", { status: 414 });

const notAllowed = async () =>
	new Response(null, { status: 405, headers: { Allow: "GET, HEAD" } });

const scanParam = (url: URL): ScanId | null => {
	const scan = url.searchParams.get("scan");
	return scan && SCAN.test(scan) ? scan : null;
};

const withoutBody = async (res: Promise<Response>, head: boolean) => {
	const out = await res;
	return head ? new Response(null, out) : out;
};

const svgPage = (path: string, env: BadgeBindings) => {
	const svg = SVG.exec(path);
	if (!svg?.[1]) return undefined;
	return svgResponse(env, svg[1], svg[2] === ".svg" ? "badge" : "card");
};

const reportPage = (url: URL, env: BadgeBindings) => {
	const report = REPORT.exec(url.pathname);
	if (!report?.[1]) return undefined;
	const target = report[2] === "report" ? "codebase" : "site";
	return reportResponse(env, { id: report[1], target, scan: scanParam(url) });
};

const page = (url: URL, env: BadgeBindings): Promise<Response> | undefined => {
	const verify = PAGE.exec(url.pathname);
	if (verify?.[1]) return verifyPage(env, verify[1], url.origin);
	return svgPage(url.pathname, env) ?? reportPage(url, env);
};

const kindOf = (path: Path) => {
	if (isApi(path)) return "api";
	return isPublic(path) ? "public" : undefined;
};

const isRead = (method: string) => method === "GET" || method === "HEAD";

const publicRoute = (url: URL, env: BadgeBindings, head: boolean) => {
	const res = page(url, env);
	return res && withoutBody(res, head);
};

/** The badge service's response, or undefined when the path isn't its own. */
export const badgeRoute = (
	request: Request,
	env: BadgeBindings,
): Promise<Response> | undefined => {
	const url = new URL(request.url);
	const kind = kindOf(url.pathname);
	if (!kind) return undefined;
	if (tooLong(url)) return uriTooLong();
	if (kind === "api") return apiRoute(request, env, url.pathname);
	if (!isRead(request.method)) return notAllowed();
	return publicRoute(url, env, request.method === "HEAD");
};
