import { ORPCError } from "@orpc/server";
import { z } from "zod";

import { AuditTimeout, runUrlAudit, URL_AUDIT_LIMITS } from "../audit";
import { publicProcedure } from "../index";
import { ReportSchema } from "../schemas";
import {
	clientKey,
	createRateLimiter,
	type ResolvedUrl,
	resolvePublicUrl,
	SsrfError,
} from "../ssrf";

/** 10 audits per client (IPv4 address or IPv6 /64) per minute. */
const limiter = createRateLimiter({ limit: 10, windowMs: 60_000 });

/** Server-wide budget, so many clients together cannot keep the host busy. */
const globalLimiter = createRateLimiter({ limit: 120, windowMs: 60_000 });

/** Server-wide cap so a burst from many clients cannot exhaust the host. */
const MAX_CONCURRENT_AUDITS = 4;
let inFlight = 0;

/** Refuses the request when the client's or the server's budget is spent. */
const checkRateLimits = (clientIp: string | undefined): void => {
	// Per-client first: requests a client is already refused must not drain
	// the shared budget, or one noisy client could lock everyone out.
	const own = limiter.hit(clientKey(clientIp));
	const rate = own.ok ? globalLimiter.hit("*") : own;
	if (!rate.ok)
		throw new ORPCError("TOO_MANY_REQUESTS", {
			message: `Rate limit reached. Try again in ${Math.ceil(rate.retryAfterMs / 1000)}s.`,
			data: { retryAfterMs: rate.retryAfterMs },
		});
};

type Guard = { readonly allowPrivate: boolean };

/** The validated target, with SSRF refusals as bad requests. */
const resolveTarget = async (
	url: string,
	guard: Guard,
): Promise<ResolvedUrl> => {
	try {
		return await resolvePublicUrl(url, guard);
	} catch (e) {
		if (e instanceof SsrfError)
			throw new ORPCError("BAD_REQUEST", {
				message: e.message,
				data: { reason: e.reason },
			});
		throw e;
	}
};

/** The engine's TargetError: the target could not be audited. */
const isTargetError = (
	e: unknown,
): e is { readonly _tag: "TargetError"; readonly message?: unknown } =>
	typeof e === "object" &&
	e !== null &&
	"_tag" in e &&
	e._tag === "TargetError";

const auditError = (e: unknown) => {
	if (e instanceof AuditTimeout)
		return new ORPCError("GATEWAY_TIMEOUT", { message: e.message });
	const message = isTargetError(e)
		? String(e.message)
		: "The audit failed unexpectedly";
	return new ORPCError("UNPROCESSABLE_CONTENT", { message });
};

/** Runs one audit within the server-wide concurrency cap. */
const auditWithinCap = async (
	target: ResolvedUrl,
	maxPages: number | undefined,
	guard: Guard,
): Promise<z.infer<typeof ReportSchema>> => {
	if (inFlight >= MAX_CONCURRENT_AUDITS)
		throw new ORPCError("SERVICE_UNAVAILABLE", {
			message: "The server is busy running other audits. Try again shortly.",
		});
	inFlight++;
	try {
		const report = await runUrlAudit({
			url: target.url.toString(),
			address: target.address,
			maxPages,
			guard,
		});
		// Mirrors the engine's own report shape; copy to drop readonly.
		return structuredClone(report) as z.infer<typeof ReportSchema>;
	} catch (e) {
		throw auditError(e);
	} finally {
		inFlight--;
	}
};

export const auditRouter = {
	url: publicProcedure
		.route({
			method: "POST",
			path: "/audit/url",
			summary: "Audit a URL",
			description: `Runs the built-in web auditors (security headers, TLS, SEO, accessibility markup, privacy…) against a public URL without a browser. Crawls at most ${URL_AUDIT_LIMITS.maxPages} pages and stops after ${URL_AUDIT_LIMITS.timeoutMs / 1000}s. Private, loopback and link-local targets are refused. Rate limited to 10 requests per minute per client.`,
			tags: ["Audit"],
		})
		.input(
			z.object({
				url: z
					.string()
					.trim()
					.min(1)
					.max(2048)
					.describe("http(s) URL of a site you own or are authorised to test"),
				maxPages: z
					.number()
					.int()
					.min(1)
					.max(URL_AUDIT_LIMITS.maxPages)
					.optional()
					.describe("Pages to crawl, 1–5 (default 5)"),
			}),
		)
		.output(ReportSchema)
		.handler(async ({ input, context }) => {
			checkRateLimits(context.clientIp);
			const guard = { allowPrivate: context.allowPrivateTargets === true };
			const target = await resolveTarget(input.url, guard);
			return auditWithinCap(target, input.maxPages, guard);
		}),
};
