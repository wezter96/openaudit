import { isIP } from "node:net";
import { builtinAuditors } from "@openaudit/auditors";
import {
	type Auditor,
	AuditorError,
	Exec,
	Http,
	type HttpRequest,
	type HttpResponse,
	type Report,
	runAudit,
	USER_AGENT,
	type Workspace,
	Workspaces,
} from "@openaudit/core";
import { Duration, Effect, Layer } from "effect";

import { type GuardOptions, resolvePublicUrl } from "./ssrf";

/** Hard limits for audits triggered over the public API. */
export const URL_AUDIT_LIMITS = {
	maxPages: 5,
	/** Whole-audit deadline. */
	timeoutMs: 60_000,
	/** Per-auditor deadline (inside the whole-audit one). */
	auditorTimeoutMs: 45_000,
	/** Per-request deadline, including redirects. */
	requestTimeoutMs: 15_000,
	maxRedirects: 5,
	maxResponseBytes: 2 * 1024 * 1024,
} as const;

/**
 * Auditors that open network connections we cannot pin to a validated IP: a
 * real browser and Lighthouse resolve DNS themselves. Listed explicitly even
 * though the engine/target filter below already excludes them.
 */
const UNPINNABLE = new Set(["webapp.browser", "web.lighthouse"]);

/**
 * Auditors the public API may run: deterministic `web.*` URL auditors only.
 * External-tool wrappers are excluded because those binaries make their own
 * network requests, which would bypass the SSRF-guarded HTTP layer below.
 * A built-in auditor that dials its own sockets must accept a pinned address
 * (as `web.tls` does via its `connectHost` setting) or join UNPINNABLE.
 */
export const urlAuditors = (
	all: ReadonlyArray<Auditor> = builtinAuditors,
): ReadonlyArray<Auditor> =>
	all.filter(
		(a) =>
			a.id.startsWith("web.") &&
			a.engine === "builtin" &&
			a.targets.includes("url") &&
			!UNPINNABLE.has(a.id),
	);

const readLimited = async (
	res: Response,
	maxBytes: number,
): Promise<{ body: string; bytes: number }> => {
	if (!res.body) return { body: "", bytes: 0 };
	const reader = res.body.getReader();
	const chunks: Uint8Array[] = [];
	let bytes = 0;
	while (bytes < maxBytes) {
		const { done, value } = await reader.read();
		if (done) break;
		chunks.push(value);
		bytes += value.byteLength;
	}
	await reader.cancel().catch(() => {});
	const buf = new Uint8Array(Math.min(bytes, maxBytes));
	let offset = 0;
	for (const chunk of chunks) {
		const part = chunk.subarray(0, buf.byteLength - offset);
		buf.set(part, offset);
		offset += part.byteLength;
		if (offset >= buf.byteLength) break;
	}
	return { body: new TextDecoder().decode(buf), bytes };
};

const SENSITIVE_HEADERS = ["authorization", "cookie", "proxy-authorization"];

/** The URL to dial: the validated literal IP in place of the hostname. */
const pinnedUrl = (url: URL, address: string): string => {
	const pinned = new URL(url);
	pinned.hostname = address.includes(":") ? `[${address}]` : address;
	return pinned.toString();
};

/**
 * Fetch options that send the request to the pinned IP while the server still
 * sees the original hostname: `Host` header, TLS SNI, and certificate
 * verification against the hostname (Bun's `tls.serverName`; covered by the
 * "verifies certificates against the hostname" test).
 */
const pinnedInit = (
	url: URL,
	headers: Record<string, string>,
): RequestInit & { tls?: { serverName?: string } } => {
	const sansHost = Object.fromEntries(
		Object.entries(headers).filter(([k]) => k.toLowerCase() !== "host"),
	);
	const hostname = url.hostname.replace(/^\[|\]$/g, "");
	return {
		headers: { ...sansHost, host: url.host },
		// A pooled connection opened for another hostname on the same IP would
		// skip the certificate check for this one.
		keepalive: false,
		...(url.protocol === "https:" && !isIP(hostname)
			? { tls: { serverName: hostname } }
			: {}),
	};
};

/**
 * `fetch` that only ever connects to addresses the SSRF guard validated.
 * Each hop (the initial URL and every redirect) is resolved once, every
 * resolved address is checked, and the connection goes to the checked literal
 * IP, so a DNS answer that changes between check and connect (rebinding) has
 * no effect. Redirects are followed manually for that reason.
 */
export const guardedFetch = async (
	input: string,
	init: HttpRequest,
	guard: GuardOptions & {
		/** Injectable for tests. */
		readonly fetch?: (url: string, init: RequestInit) => Promise<Response>;
	},
	signal?: AbortSignal,
): Promise<HttpResponse> => {
	const doFetch = guard.fetch ?? fetch;
	const controller = new AbortController();
	signal?.addEventListener("abort", () => controller.abort());
	const timer = setTimeout(
		() => controller.abort(),
		Math.min(
			init.timeoutMs ?? URL_AUDIT_LIMITS.requestTimeoutMs,
			URL_AUDIT_LIMITS.requestTimeoutMs,
		),
	);
	const maxBytes = Math.min(
		init.maxBytes ?? URL_AUDIT_LIMITS.maxResponseBytes,
		URL_AUDIT_LIMITS.maxResponseBytes,
	);
	const started = performance.now();
	try {
		let current = input;
		let method = init.method ?? "GET";
		let body = init.body;
		let headers: Record<string, string> = {
			"user-agent": USER_AGENT,
			...init.headers,
		};

		for (let hop = 0; ; hop++) {
			const { url, address } = await resolvePublicUrl(current, guard);
			current = url.toString();
			const res = await doFetch(
				address === undefined ? current : pinnedUrl(url, address),
				{
					method,
					body,
					redirect: "manual",
					signal: controller.signal,
					...(address === undefined ? { headers } : pinnedInit(url, headers)),
				},
			);
			const location = res.headers.get("location");
			const isRedirect = res.status >= 300 && res.status < 400 && location;
			if (isRedirect && init.redirect !== "manual") {
				await res.body?.cancel().catch(() => {});
				if (hop >= URL_AUDIT_LIMITS.maxRedirects)
					throw new Error(
						`Too many redirects (>${URL_AUDIT_LIMITS.maxRedirects})`,
					);
				// Resolved, validated and pinned at the top of the next iteration.
				const next = new URL(location, current);
				if (next.origin !== url.origin) {
					headers = Object.fromEntries(
						Object.entries(headers).filter(
							([k]) => !SENSITIVE_HEADERS.includes(k.toLowerCase()),
						),
					);
				}
				if (
					res.status === 303 ||
					((res.status === 301 || res.status === 302) && method === "POST")
				) {
					method = "GET";
					body = undefined;
				}
				current = next.toString();
				continue;
			}

			const ttfbMs = performance.now() - started;
			const read = await readLimited(res, maxBytes);
			return {
				url: current,
				status: res.status,
				headers: res.headers,
				cookies: res.headers.getSetCookie(),
				body: read.body,
				bytes: read.bytes,
				redirected: hop > 0,
				ttfbMs,
				totalMs: performance.now() - started,
			};
		}
	} finally {
		clearTimeout(timer);
	}
};

const guardedHttpLayer = (guard: GuardOptions) =>
	Layer.succeed(Http, {
		request: (url, init = {}) =>
			Effect.tryPromise({
				try: (signal) => guardedFetch(url, init, guard, signal),
				catch: (cause) =>
					new AuditorError({
						message: `Request to ${url} failed: ${cause instanceof Error ? cause.message : String(cause)}`,
						cause,
					}),
			}),
	});

const disabled = (what: string) =>
	new AuditorError({ message: `${what} is disabled on the hosted API` });

/** No subprocesses: `which` finds nothing, so external auditors skip. */
const noExecLayer = Layer.succeed(Exec, {
	which: () => Effect.succeed(undefined),
	run: () => Effect.fail(disabled("Running external tools")),
});

/** No filesystem: URL targets never need one, and nothing may read server files. */
const noWorkspacesLayer = Layer.succeed(Workspaces, {
	open: (root): Workspace => ({
		root,
		absolute: (p) => p,
		files: Effect.fail(disabled("File access")),
		glob: () => Effect.fail(disabled("File access")),
		readText: () => Effect.fail(disabled("File access")),
		readBytes: () => Effect.fail(disabled("File access")),
		size: () => Effect.fail(disabled("File access")),
		exists: () => Effect.succeed(false),
	}),
});

export class AuditTimeout extends Error {
	readonly _tag = "AuditTimeout";
}

/**
 * Runs a URL-only audit with sandboxed infrastructure. The caller must already
 * have validated `url` with `resolvePublicUrl`; every request is resolved,
 * validated and pinned again.
 */
export const runUrlAudit = (input: {
	readonly url: string;
	/**
	 * The validated address of the target host. `web.tls` opens its own TLS
	 * socket outside `ctx.http`, so it is told to dial this IP rather than
	 * resolving the hostname again.
	 */
	readonly address: string | undefined;
	readonly maxPages?: number;
	readonly guard: GuardOptions;
	readonly auditors?: ReadonlyArray<Auditor>;
}): Promise<Report> =>
	Effect.runPromise(
		runAudit({
			target: input.url,
			auditors: input.auditors ?? urlAuditors(),
			options: {
				browser: false,
				agentic: false,
				settings: input.address
					? { "web.tls": { connectHost: input.address } }
					: undefined,
				maxPages: Math.max(
					1,
					Math.min(
						input.maxPages ?? URL_AUDIT_LIMITS.maxPages,
						URL_AUDIT_LIMITS.maxPages,
					),
				),
			},
			timeoutMs: URL_AUDIT_LIMITS.auditorTimeoutMs,
			concurrency: 4,
		}).pipe(
			Effect.timeoutOrElse({
				duration: Duration.millis(URL_AUDIT_LIMITS.timeoutMs),
				orElse: () =>
					Effect.die(
						new AuditTimeout(
							`Audit exceeded ${URL_AUDIT_LIMITS.timeoutMs / 1000}s`,
						),
					),
			}),
			Effect.provide(
				Layer.mergeAll(
					guardedHttpLayer(input.guard),
					noExecLayer,
					noWorkspacesLayer,
				),
			),
		),
	);
