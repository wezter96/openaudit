import { builtinAuditors } from "@openaudit/auditors";
import {
	type Auditor,
	AuditorError,
	guardedFetch as coreGuardedFetch,
	guardedHttpLayer as coreGuardedHttpLayer,
	Exec,
	type GuardOptions,
	type HttpRequest,
	type HttpResponse,
	isPinnableUrlAuditor,
	type Report,
	runAudit,
	type Workspace,
	Workspaces,
} from "@openaudit/core";
import { Duration, Effect, Layer } from "effect";

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
 * Auditors the public API may run: deterministic `web.*` URL auditors only.
 * External-tool wrappers are excluded because those binaries make their own
 * network requests, which would bypass the SSRF-guarded HTTP layer below.
 * A built-in auditor that dials its own sockets must accept a pinned address
 * (as `web.tls` does via its `connectHost` setting) or join UNPINNABLE in core's ssrf.ts.
 */
export const urlAuditors = (
	all: ReadonlyArray<Auditor> = builtinAuditors,
): ReadonlyArray<Auditor> => all.filter(isPinnableUrlAuditor);

/**
 * `fetch` that only ever connects to addresses the SSRF guard validated (see
 * `guardedFetch` in core), with the hosted API's limits.
 */
export const guardedFetch = (
	input: string,
	init: HttpRequest,
	guard: GuardOptions & {
		/** Injectable for tests. */
		readonly fetch?: (url: string, init: RequestInit) => Promise<Response>;
	},
	signal?: AbortSignal,
): Promise<HttpResponse> =>
	coreGuardedFetch(input, init, { guard, limits: URL_AUDIT_LIMITS, signal });

const guardedHttpLayer = (guard: GuardOptions) =>
	coreGuardedHttpLayer(guard, URL_AUDIT_LIMITS);

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
		ignored: Effect.succeed([]),
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
