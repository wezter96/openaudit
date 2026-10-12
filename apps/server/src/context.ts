import type { Context as ApiContext } from "@openaudit/api/context";
import type { Context as HonoContext } from "hono";
import { getConnInfo } from "hono/bun";

import { ENV } from "./env.server";

export type CreateContextOptions = {
	context: HonoContext;
};

/**
 * Client IP for rate limiting. X-Forwarded-For is client-controlled, so it is
 * only honoured behind a trusted proxy, and then only the entry that proxy
 * appended (the last one).
 */
function clientIp(c: HonoContext): string | undefined {
	if (ENV.TRUST_PROXY) {
		const forwarded = c.req
			.header("x-forwarded-for")
			?.split(",")
			.at(-1)
			?.trim();
		if (forwarded) return forwarded;
	}
	try {
		return getConnInfo(c).remote.address;
	} catch {
		return undefined;
	}
}

export async function createContext({
	context,
}: CreateContextOptions): Promise<ApiContext> {
	return {
		clientIp: clientIp(context),
		allowPrivateTargets: ENV.ALLOW_PRIVATE_TARGETS,
	};
}

export type Context = Awaited<ReturnType<typeof createContext>>;
