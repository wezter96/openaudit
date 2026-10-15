/** The JSON API's entry: body limits, then the HttpApi web handler. */
import { MAX_REPORT_BYTES } from "@openaudit/badge";
import { type Bytes, readUpTo } from "./bytes";
import { type BadgeBindings, nowSeconds } from "./env";
import { handleApi } from "./server";

/** Request bodies the public API accepts (the scanner's reports excepted). */
const MAX_FORM_BYTES: Bytes = 4 * 1024;

/** A URL path. */
export type Path = string;

const tooLarge = () =>
	new Response("Request body too large.\n", { status: 413 });

const declaredTooLarge = (request: Request, limit: Bytes) =>
	Number(request.headers.get("content-length") ?? 0) > limit;

/** Buffers the body under its limit, then hands the request to the API. */
export const apiRoute = async (
	request: Request,
	env: BadgeBindings,
	path: Path,
) => {
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
