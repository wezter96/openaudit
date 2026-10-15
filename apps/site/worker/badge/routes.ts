/**
 * Routes for the verified badges (see packages/badge): the JSON API under
 * /api/badges and /api/scanner, and the public /badge/* and /v/* pages.
 */
import { MAX_REPORT_BYTES, type ScanId } from "@openaudit/badge";
import { readUpTo } from "./bytes";
import { type BadgeBindings, nowSeconds } from "./env";
import { reportResponse, svgResponse, verifyPage } from "./pages";
import { handleApi } from "./server";

/** Request bodies the public API accepts (the scanner's reports excepted). */
const MAX_FORM_BYTES = 16 * 1024;

const ID = "([a-z0-9][a-z0-9-]{0,159})";
const SVG = new RegExp(`^/badge/${ID}(\\.svg|/card\\.svg)$`);
const PAGE = new RegExp(`^/v/${ID}/?$`);
const REPORT = new RegExp(`^/v/${ID}/(report|site-report)$`);
const SCAN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const isApi = (path: string) =>
	path.startsWith("/api/badges") || path.startsWith("/api/scanner/");

const tooLarge = () =>
	new Response("Request body too large.\n", { status: 413 });

const declaredTooLarge = (request: Request, limit: number) =>
	Number(request.headers.get("content-length") ?? 0) > limit;

/** Buffers the body under its limit, then hands the request to the API. */
const api = async (request: Request, env: BadgeBindings, path: string) => {
	const limit = path.startsWith("/api/scanner/")
		? MAX_REPORT_BYTES
		: MAX_FORM_BYTES;
	if (declaredTooLarge(request, limit)) return tooLarge();
	const { bytes: body, over } = await readUpTo(request.body, limit);
	if (over) return tooLarge();
	const hasBody = request.method !== "GET" && request.method !== "HEAD";
	const buffered = new Request(request, { body: hasBody ? body : null });
	return handleApi(buffered, {
		env,
		now: nowSeconds(),
		ip: request.headers.get("cf-connecting-ip") ?? "",
	});
};

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

/** The badge service's response, or undefined when the path isn't its own. */
export const badgeRoute = (
	request: Request,
	env: BadgeBindings,
): Promise<Response> | undefined => {
	const url = new URL(request.url);
	if (isApi(url.pathname)) return api(request, env, url.pathname);
	const head = request.method === "HEAD";
	if (request.method !== "GET" && !head) return undefined;
	const res = page(url, env);
	return res && withoutBody(res, head);
};
