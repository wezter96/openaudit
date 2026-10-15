/**
 * The JSON API's entry. Every limit is enforced here, on the raw request,
 * before the HttpApi handler parses, routes or touches D1:
 *
 * - the scanner's routes refuse a wrong bearer token before reading a byte,
 *   so only the scanner can send its 25 MB uploads;
 * - a declared Content-Length over the limit is refused unread, and the
 *   stream is cut as soon as it passes the limit;
 * - only then is a Request rebuilt from the bounded bytes for the handler.
 */
import { MAX_REPORT_BYTES } from "@openaudit/badge";
import { type Bytes, readUpTo } from "./bytes";
import { constantTimeEqual } from "./crypto";
import { type BadgeBindings, nowSeconds } from "./env";
import { handleApi } from "./server";

/** Request bodies the public API accepts (the scanner's reports excepted). */
const MAX_FORM_BYTES: Bytes = 4 * 1024;

/** A URL path. */
export type Path = string;

const plain = (status: number, text: string) =>
	new Response(`${text}\n`, {
		status,
		headers: { "Content-Type": "text/plain; charset=utf-8" },
	});

const unauthorized = () =>
	Response.json(
		{ _tag: "Unauthorized", message: "Missing or wrong bearer token." },
		{ status: 401 },
	);

const isScanner = (path: Path) => path.startsWith("/api/scanner/");

/** The scanner's token, compared in constant time; never logged. */
const isScannerCall = (request: Request, env: BadgeBindings) => {
	const expected = env.SCANNER_TOKEN ?? "";
	const header = request.headers.get("authorization") ?? "";
	return expected !== "" && constantTimeEqual(header, `Bearer ${expected}`);
};

/** The declared length: a number, null when absent, NaN when malformed. */
const declaredLength = (request: Request) => {
	const header = request.headers.get("content-length");
	return header === null
		? null
		: /^\d{1,12}$/.test(header)
			? Number(header)
			: Number.NaN;
};

const hasBody = (request: Request) =>
	request.method !== "GET" && request.method !== "HEAD";

/** The body, bounded, or the response that refuses it. */
const boundedBody = async (request: Request, limit: Bytes) => {
	const declared = declaredLength(request);
	if (Number.isNaN(declared)) return plain(400, "Bad Content-Length.");
	if ((declared ?? 0) > limit) return plain(413, "Request body too large.");
	const { bytes, over } = await readUpTo(request.body, limit);
	return over ? plain(413, "Request body too large.") : bytes;
};

export const apiRoute = async (
	request: Request,
	env: BadgeBindings,
	path: Path,
) => {
	const scanner = isScanner(path);
	if (scanner && !isScannerCall(request, env)) return unauthorized();
	const limit = scanner ? MAX_REPORT_BYTES : MAX_FORM_BYTES;
	const body = hasBody(request) ? await boundedBody(request, limit) : null;
	if (body instanceof Response) return body;
	const rebuilt = new Request(request.url, {
		method: request.method,
		headers: request.headers,
		body,
	});
	return handleApi(rebuilt, {
		env,
		now: nowSeconds(),
		ip: request.headers.get("cf-connecting-ip") ?? "",
	});
};
