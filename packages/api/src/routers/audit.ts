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
			const global = globalLimiter.hit("*");
			const rate = global.ok
				? limiter.hit(clientKey(context.clientIp))
				: global;
			if (!rate.ok)
				throw new ORPCError("TOO_MANY_REQUESTS", {
					message: `Rate limit reached. Try again in ${Math.ceil(rate.retryAfterMs / 1000)}s.`,
					data: { retryAfterMs: rate.retryAfterMs },
				});

			const guard = { allowPrivate: context.allowPrivateTargets === true };
			let target: ResolvedUrl;
			try {
				target = await resolvePublicUrl(input.url, guard);
			} catch (e) {
				if (e instanceof SsrfError)
					throw new ORPCError("BAD_REQUEST", {
						message: e.message,
						data: { reason: e.reason },
					});
				throw e;
			}

			if (inFlight >= MAX_CONCURRENT_AUDITS)
				throw new ORPCError("SERVICE_UNAVAILABLE", {
					message:
						"The server is busy running other audits. Try again shortly.",
				});
			inFlight++;
			try {
				const report = await runUrlAudit({
					url: target.url.toString(),
					address: target.address,
					maxPages: input.maxPages,
					guard,
				});
				// Mirrors the engine's own report shape; copy to drop readonly.
				return structuredClone(report) as z.infer<typeof ReportSchema>;
			} catch (e) {
				if (e instanceof AuditTimeout)
					throw new ORPCError("GATEWAY_TIMEOUT", { message: e.message });
				const message =
					e && typeof e === "object" && "_tag" in e && e._tag === "TargetError"
						? String((e as { message?: unknown }).message)
						: "The audit failed unexpectedly";
				throw new ORPCError("UNPROCESSABLE_CONTENT", { message });
			} finally {
				inFlight--;
			}
		}),
};
