import {
	createHash,
	randomBytes,
	randomUUID,
	timingSafeEqual,
} from "node:crypto";
import { mkdir, realpath, rename, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";

import {
	type GuardOptions,
	resolvePublicUrl,
	SsrfError,
} from "@openaudit/core";

import { createServer, type ServerOptions } from "./server";

export const DEFAULT_HTTP_HOST = "127.0.0.1";
export const DEFAULT_HTTP_PORT = 7337;
const MCP_PATH = "/mcp";
const MIN_REMOTE_TOKEN_LENGTH = 16;

/** A hostname or IP address, optionally with a port. */
type Host = string;
/** The bearer token clients must send. */
type BearerToken = string;
/** An OCI image reference such as `ghcr.io/org/repo:tag`. */
type ImageRef = string;
type SessionId = string;
type ByteCount = number;

export interface HttpServerOptions {
	/** Interface to bind. Defaults to loopback. */
	readonly host?: string;
	/** Port to bind; 0 picks an ephemeral one. */
	readonly port?: number;
	/** Bearer token. Required (not generated) when `host` is not loopback; generated on loopback. */
	readonly token?: string;
	/** Browser origins allowed to call the server. Requests without Origin always pass. */
	readonly allowOrigins?: ReadonlyArray<string>;
	/** Extra Host header values (hostname or host:port) accepted besides the bind address. */
	readonly allowHosts?: ReadonlyArray<string>;
	/** Directories that file and directory targets must resolve inside. */
	readonly roots?: ReadonlyArray<string>;
	/** Permit `cloud:<provider>` targets, which use the server's own credentials. */
	readonly allowCloud?: boolean;
	/**
	 * Accept `image:` targets while the URL guard is active (non-loopback bind
	 * without --allow-private-targets). The registry host is still checked.
	 */
	readonly allowImages?: boolean;
	/** Let clients run agentic auditors, which spend the server's ANTHROPIC_API_KEY. */
	readonly allowAgentic?: boolean;
	/**
	 * Save reports under `<root>/.openaudit/reports` as stdio does. Off by
	 * default over HTTP: remote clients should not write into served roots.
	 */
	readonly persistReports?: boolean;
	/**
	 * Skip the private-address guard for URL targets. The guard only applies to
	 * non-loopback binds, where clients are remote; on loopback the user is
	 * auditing their own machine.
	 */
	readonly allowPrivateTargets?: boolean;
	readonly maxBodyBytes?: number;
	readonly maxSessions?: number;
	readonly sessionIdleMs?: number;
	/** Options for each per-session MCP server (auditors, playbooks, ...). */
	readonly server?: Omit<
		ServerOptions,
		| "resolveInput"
		| "allowAgentic"
		| "urlGuard"
		| "registryImagesOnly"
		| "store"
		| "persistReports"
	>;
}

export interface HttpServerHandle {
	readonly url: string;
	readonly host: string;
	readonly port: number;
	/** Set only when no token was supplied and one was generated. */
	readonly generatedToken?: string;
	readonly roots: ReadonlyArray<string>;
	sessionCount(): number;
	close(): Promise<void>;
}

export const isLoopbackHost = (host: Host): boolean => {
	const h = host.replace(/^\[|\]$/g, "").toLowerCase();
	return h === "localhost" || h === "::1" || /^127(\.\d{1,3}){3}$/.test(h);
};

/** Constant-time comparison: hash both sides so length differences leak nothing. */
export const tokenMatches = (
	given: BearerToken,
	expected: BearerToken,
): boolean => {
	const a = createHash("sha256").update(given).digest();
	const b = createHash("sha256").update(expected).digest();
	return timingSafeEqual(a, b);
};

const DOMAIN_LABEL = "[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?";
const PATH_COMPONENT = "[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*";
const REGISTRY_REF = new RegExp(
	// A leading component is a host only with a dot, a port or "localhost".
	`^(?:(?:${DOMAIN_LABEL}(?:\\.${DOMAIN_LABEL})+(?::\\d{1,5})?|${DOMAIN_LABEL}:\\d{1,5}|localhost)/)?` +
		`${PATH_COMPONENT}(?:/${PATH_COMPONENT})*` +
		"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?" +
		"(?:@sha256:[a-f0-9]{64})?$",
);
/** Tool transports that make a ref mean a local path or daemon, not a registry. */
const IMAGE_TRANSPORT =
	/^(?:dir|file|docker-archive|oci-archive|oci-dir|oci|singularity|docker|podman|registry|containerd)(?::|$)/i;

/**
 * True only for an OCI registry reference: optional host[:port], lowercase
 * path, optional tag and/or sha256 digest. Anything a scanner could read as a
 * local archive, directory or daemon (`docker-archive:/x`, `oci-dir:…`) fails.
 * Note `registry:2` is refused too; write `docker.io/library/registry:2`.
 */
export const isRegistryImageRef = (ref: ImageRef): boolean =>
	ref.length <= 255 &&
	// `registry:5000/x` is a host with a port, not the registry transport.
	(!IMAGE_TRANSPORT.test(ref) || /^[^:/]+:\d{1,5}\//.test(ref)) &&
	REGISTRY_REF.test(ref);

/** A leading path component names a host only with a dot, a port or "localhost". */
const isHostComponent = (component: Host): boolean =>
	/[.:]/.test(component) || component === "localhost";

/** Registry host[:port] of a validated reference; Docker Hub when none is given. */
export const registryHost = (ref: ImageRef): Host => {
	const first = ref.split("/")[0] ?? "";
	return ref.includes("/") && isHostComponent(first)
		? first
		: "registry-1.docker.io";
};

const within = (path: string, root: string) =>
	path === root || path.startsWith(root.endsWith(sep) ? root : root + sep);

/** Refuses `url` unless it resolves to public addresses, with the SSRF reason as the message. */
const assertPublic = async (
	url: string,
	guard: GuardOptions,
): Promise<void> => {
	try {
		await resolvePublicUrl(url, guard);
	} catch (error) {
		if (error instanceof SsrfError) throw new Error(error.message);
		throw error;
	}
};

/** Optional settings of `makeTargetPolicy`. */
export interface TargetPolicyOptions {
	/** Base directory for relative paths. Defaults to the first root. */
	readonly cwd?: string;
	/** When set, URL targets and image registries must resolve to public addresses. */
	readonly urlGuard?: GuardOptions;
	/** Accept `image:` targets while `urlGuard` is set. */
	readonly allowImages?: boolean;
}

interface TargetPolicy {
	readonly roots: ReadonlyArray<string>;
	readonly allowCloud: boolean;
	readonly base: string;
	readonly urlGuard?: GuardOptions;
	readonly allowImages: boolean;
}

type TargetCheck = (target: string, policy: TargetPolicy) => Promise<string>;

const checkUrl: TargetCheck = async (target, policy) => {
	if (policy.urlGuard) await assertPublic(target, policy.urlGuard);
	return target;
};

const checkImage: TargetCheck = async (target, policy) => {
	const ref = target.slice("image:".length);
	// Registry references only: never a local tarball, directory or daemon.
	if (!isRegistryImageRef(ref))
		throw new Error(
			"image: targets must be OCI registry references such as nginx:1.27 or ghcr.io/org/repo:tag",
		);
	if (!policy.urlGuard) return target;
	// Scanners pull images themselves, so the registry cannot be pinned.
	if (!policy.allowImages)
		throw new Error(
			"image: targets are disabled on this server (start it with --allow-images)",
		);
	await assertPublic(`https://${registryHost(ref)}/`, policy.urlGuard);
	return target;
};

const checkCloud: TargetCheck = async (target, policy) => {
	if (!policy.allowCloud)
		throw new Error(
			"cloud: targets are disabled on this server (start it with --allow-cloud)",
		);
	return target;
};

const checkPath: TargetCheck = async (target, policy) => {
	if (policy.roots.length === 0)
		throw new Error(
			"Local paths are disabled on this server; only URL and image: targets are accepted. Start it with --root <dir> to allow directories.",
		);
	const real = await realpath(resolve(policy.base, target)).catch(
		() => undefined,
	);
	// Same message for missing and forbidden paths: no filesystem probing.
	if (!real || !policy.roots.some((r) => within(real, r)))
		throw new Error("Target is not inside an allowed root");
	return real;
};

/** Checks by target prefix; anything else is a local path. */
const TARGET_CHECKS: ReadonlyArray<readonly [RegExp, TargetCheck]> = [
	[/^https?:\/\//i, checkUrl],
	[/^image:/i, checkImage],
	[/^cloud:/i, checkCloud],
];

/**
 * Target policy for remote clients. URLs and (safe) image refs pass; local
 * paths must realpath inside an allowed root, which defeats `..` and symlinks.
 * The resolved real path is returned so a later symlink swap cannot escape.
 */
export const makeTargetPolicy = (
	roots: ReadonlyArray<string>,
	allowCloud: boolean,
	options: TargetPolicyOptions = {},
) => {
	const policy: TargetPolicy = {
		roots,
		allowCloud,
		base: options.cwd ?? roots[0] ?? process.cwd(),
		urlGuard: options.urlGuard,
		allowImages: options.allowImages ?? false,
	};
	return async (target: string): Promise<string> => {
		const check =
			TARGET_CHECKS.find(([prefix]) => prefix.test(target))?.[1] ?? checkPath;
		return check(target, policy);
	};
};

interface Session {
	readonly transport: WebStandardStreamableHTTPServerTransport;
	readonly server: McpServer;
	lastSeen: number;
	/** In-flight POST responses (long run_audit calls keep a session alive). */
	active: number;
}

/** Live sessions by id, plus the closes still in flight. */
class SessionTable {
	private readonly sessions = new Map<SessionId, Session>();
	private readonly closing = new Set<Promise<unknown>>();

	get size(): number {
		return this.sessions.size;
	}

	set(id: SessionId, session: Session): void {
		this.sessions.set(id, session);
	}

	delete(id: SessionId): void {
		this.sessions.delete(id);
	}

	/** The session for `id`, marked as just used. */
	touch(id: SessionId): Session | undefined {
		const s = this.sessions.get(id);
		if (s) s.lastSeen = Date.now();
		return s;
	}

	/** Forgets a session and closes its transport and server in the background. */
	drop(id: SessionId): void {
		const s = this.sessions.get(id);
		if (!s) return;
		this.sessions.delete(id);
		const p = Promise.allSettled([s.transport.close(), s.server.close()]);
		this.closing.add(p);
		void p.finally(() => this.closing.delete(p));
	}

	/** Drops sessions with no request in flight that have been idle over `idleMs`. */
	sweep(idleMs: number): void {
		const now = Date.now();
		for (const [id, s] of this.sessions)
			if (s.active === 0 && now - s.lastSeen > idleMs) this.drop(id);
	}

	async closeAll(): Promise<void> {
		for (const id of this.sessions.keys()) this.drop(id);
		await Promise.allSettled(this.closing);
	}
}

const json = (
	status: number,
	body: unknown,
	headers: Record<string, string> = {},
) =>
	new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json", ...headers },
	});

const rpcError = (status: number, code: number, message: string) =>
	json(status, { jsonrpc: "2.0", error: { code, message }, id: null });

const missingSession = () =>
	rpcError(400, -32000, "Missing Mcp-Session-Id header");

const unknownSession = () =>
	rpcError(404, -32001, "Unknown or expired session");

class BodyTooLarge extends Error {}

const declaredTooLarge = (req: Request, max: ByteCount): boolean => {
	const declared = Number(req.headers.get("content-length"));
	return Number.isFinite(declared) && declared > max;
};

/** Reads a body to the end, cancelling it once it passes `max` bytes. */
const readChunks = async (
	body: ReadableStream<Uint8Array>,
	max: ByteCount,
): Promise<Uint8Array[]> => {
	const reader = body.getReader();
	const chunks: Uint8Array[] = [];
	let size = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) return chunks;
		size += value.byteLength;
		if (size > max) {
			await reader.cancel();
			throw new BodyTooLarge();
		}
		chunks.push(value);
	}
};

const readLimited = async (req: Request, max: ByteCount): Promise<string> => {
	if (declaredTooLarge(req, max)) throw new BodyTooLarge();
	if (!req.body) return "";
	return Buffer.concat(await readChunks(req.body, max)).toString("utf8");
};

/** The parsed JSON body, or the JSON-RPC error answering a bad one. */
const readJson = async (
	req: Request,
	max: ByteCount,
): Promise<{ readonly body: unknown } | { readonly error: Response }> => {
	try {
		return { body: JSON.parse(await readLimited(req, max)) };
	} catch (e) {
		return {
			error:
				e instanceof BodyTooLarge
					? rpcError(413, -32000, "Request body too large")
					: rpcError(400, -32700, "Parse error: invalid JSON"),
		};
	}
};

/** Counts a response as in flight until its body has been fully sent. */
const track = (session: Session, res: Response): Response => {
	session.active++;
	let finished = false;
	const done = () => {
		if (finished) return;
		finished = true;
		session.active--;
		session.lastSeen = Date.now();
	};
	if (!res.body) {
		done();
		return res;
	}
	const ts = new TransformStream<Uint8Array, Uint8Array>({ flush: done });
	res.body.pipeTo(ts.writable).catch(done);
	// A client abort cancels ts.readable, which rejects the pipe above.
	return new Response(ts.readable, {
		status: res.status,
		headers: res.headers,
	});
};

/** What the MCP endpoint needs to route requests to sessions. */
interface Endpoint {
	readonly sessions: SessionTable;
	readonly maxBody: ByteCount;
	readonly maxSessions: number;
	/** A new MCP server for one session. */
	readonly createSessionServer: () => McpServer;
}

const newSession = async (
	ep: Endpoint,
	req: Request,
	body: unknown,
): Promise<Response> => {
	if (ep.sessions.size >= ep.maxSessions)
		return rpcError(503, -32000, "Too many sessions; try again later");
	let id: string | undefined;
	const server = ep.createSessionServer();
	const transport = new WebStandardStreamableHTTPServerTransport({
		sessionIdGenerator: randomUUID,
		keepAliveMs: 15_000,
		maxRequestBodySize: ep.maxBody,
		onsessioninitialized: (sid) => {
			id = sid;
			ep.sessions.set(sid, session);
		},
	});
	const session: Session = {
		transport,
		server,
		lastSeen: Date.now(),
		active: 0,
	};
	transport.onclose = () => {
		if (id) ep.sessions.delete(id);
	};
	await server.connect(transport);
	const res = await transport.handleRequest(req, { parsedBody: body });
	if (!id) {
		// Initialization failed: nothing registered, release the pair.
		void Promise.allSettled([transport.close(), server.close()]);
		return res;
	}
	return track(session, res);
};

/** A POST without a session id must be an initialize request, which opens one. */
const initialize = async (
	ep: Endpoint,
	req: Request,
	body: unknown,
): Promise<Response> => {
	const first = Array.isArray(body) ? body[0] : body;
	if (!isInitializeRequest(first)) return missingSession();
	return newSession(ep, req, body);
};

const handlePost = async (
	ep: Endpoint,
	req: Request,
	sid: SessionId | null,
): Promise<Response> => {
	const parsed = await readJson(req, ep.maxBody);
	if ("error" in parsed) return parsed.error;
	if (!sid) return initialize(ep, req, parsed.body);
	const s = ep.sessions.touch(sid);
	if (!s) return unknownSession();
	return track(
		s,
		await s.transport.handleRequest(req, { parsedBody: parsed.body }),
	);
};

/** GET opens the server-to-client stream; DELETE ends the session. */
const handleStream = async (
	ep: Endpoint,
	req: Request,
	sid: SessionId | null,
): Promise<Response> => {
	if (!sid) return missingSession();
	const s = ep.sessions.touch(sid);
	if (!s) return unknownSession();
	const res = await s.transport.handleRequest(req);
	if (req.method === "DELETE") ep.sessions.drop(sid);
	return res;
};

const handleMcp = async (ep: Endpoint, req: Request): Promise<Response> => {
	const sid = req.headers.get("mcp-session-id");
	if (req.method === "POST") return handlePost(ep, req, sid);
	if (req.method === "GET" || req.method === "DELETE")
		return handleStream(ep, req, sid);
	return json(
		405,
		{ error: "Method not allowed" },
		{ allow: "POST, GET, DELETE" },
	);
};

/** What the Host header may name besides the configured extra hosts. */
interface HostRule {
	readonly host: Host;
	readonly loopback: boolean;
	readonly port: number;
	readonly allowHosts?: ReadonlyArray<string>;
}

const hostAllowed = (header: Host | null, rule: HostRule): boolean => {
	if (!header) return false;
	const h = header.toLowerCase();
	const extra = (rule.allowHosts ?? []).map((x) => x.toLowerCase());
	if (extra.includes(h) || extra.includes(h.replace(/:\d+$/, ""))) return true;
	// A non-loopback bind is token-gated and reached by arbitrary names.
	if (!rule.loopback) return extra.length === 0;
	const names = new Set(["localhost", "127.0.0.1", "[::1]", rule.host]);
	return [...names].some((n) => h === `${n}:${rule.port}`);
};

const authorized = (req: Request, token: BearerToken): boolean => {
	const m = /^Bearer ([^\s]+)$/i.exec(req.headers.get("authorization") ?? "");
	return m?.[1] !== undefined && tokenMatches(m[1], token);
};

const pathOf = (url: string): string | undefined => {
	try {
		return new URL(url).pathname;
	} catch {
		return undefined;
	}
};

/** Answers requests that never reach MCP: bad URLs, /health, other paths, no token. */
const routeResponse = (
	req: Request,
	token: BearerToken,
): Response | undefined => {
	const path = pathOf(req.url);
	if (path === undefined) return json(400, { error: "Bad request" });
	if (path === "/health" && req.method === "GET")
		return json(200, { status: "ok" });
	if (path !== MCP_PATH) return json(404, { error: "Not found" });
	if (!authorized(req, token))
		return json(
			401,
			{ error: "Unauthorized" },
			{ "www-authenticate": 'Bearer realm="openaudit"' },
		);
	return undefined;
};

/** Refuses tokens the Authorization check cannot match, and missing or short ones on remote binds. */
const checkToken = (
	host: Host,
	supplied: BearerToken | undefined,
	loopback: boolean,
): void => {
	// The Authorization check matches a whitespace-free token exactly.
	if (supplied && /\s/.test(supplied))
		throw new Error("The bearer token must not contain whitespace.");
	if (loopback) return;
	if (!supplied)
		throw new Error(
			`Refusing to bind ${host} without a bearer token. Pass --token or set OPENAUDIT_MCP_TOKEN, or bind 127.0.0.1.`,
		);
	if (supplied.length < MIN_REMOTE_TOKEN_LENGTH)
		throw new Error(
			`Bearer token must be at least ${MIN_REMOTE_TOKEN_LENGTH} characters when binding a non-loopback host.`,
		);
};

const realRoots = (roots: ReadonlyArray<string>): Promise<string[]> =>
	Promise.all(
		roots.map(async (r) => {
			const real = await realpath(resolve(r)).catch(() => undefined);
			if (!real) throw new Error(`--root does not exist: ${r}`);
			return real;
		}),
	);

/** Default location for a generated token: readable by the current user only. */
export const defaultTokenFile = (): string =>
	join(
		process.env.XDG_CONFIG_HOME || join(homedir(), ".config"),
		"openaudit",
		"mcp-token",
	);

/** Writes the token to a 0600 file (0700 directory), replacing it atomically. */
export const writeTokenFile = async (
	token: BearerToken,
	path: string = defaultTokenFile(),
): Promise<string> => {
	await mkdir(dirname(path), { recursive: true, mode: 0o700 });
	const tmp = `${path}.${randomBytes(6).toString("hex")}.tmp`;
	try {
		await writeFile(tmp, `${token}\n`, { flag: "wx", mode: 0o600 });
		await rename(tmp, path);
	} catch (error) {
		await rm(tmp, { force: true });
		throw error;
	}
	return path;
};

export const startHttpServer = async (
	options: HttpServerOptions = {},
): Promise<HttpServerHandle> => {
	const host = options.host ?? DEFAULT_HTTP_HOST;
	const supplied = options.token || undefined;
	// Loopback is reachable by other local users too: always require a token.
	const token = supplied ?? randomBytes(32).toString("base64url");
	const loopback = isLoopbackHost(host);
	checkToken(host, supplied, loopback);
	const idleMs = options.sessionIdleMs ?? 30 * 60_000;
	const allowOrigins = new Set(options.allowOrigins ?? []);
	const roots = await realRoots(options.roots ?? []);
	const urlGuard: GuardOptions | undefined =
		loopback || options.allowPrivateTargets ? undefined : {};
	const resolveInput = makeTargetPolicy(roots, options.allowCloud ?? false, {
		cwd: options.server?.cwd,
		urlGuard,
		allowImages: options.allowImages ?? false,
	});
	const sessions = new SessionTable();
	const endpoint: Endpoint = {
		sessions,
		maxBody: options.maxBodyBytes ?? 4 * 1024 * 1024,
		maxSessions: options.maxSessions ?? 32,
		createSessionServer: () =>
			createServer({
				...options.server,
				resolveInput,
				// Reports are per session: never share a store between clients.
				store: undefined,
				allowAgentic: options.allowAgentic ?? false,
				registryImagesOnly: true,
				persistReports: options.persistReports ?? false,
				urlGuard,
			}),
	};

	let boundPort = 0;
	const callerRefusal = (req: Request): Response | undefined => {
		const rule = {
			host,
			loopback,
			port: boundPort,
			allowHosts: options.allowHosts,
		};
		if (!hostAllowed(req.headers.get("host"), rule))
			return json(403, { error: "Host not allowed" });
		const origin = req.headers.get("origin");
		if (origin !== null && !allowOrigins.has(origin))
			return json(403, { error: "Origin not allowed" });
		return undefined;
	};

	const bun = Bun.serve({
		hostname: host,
		port: options.port ?? DEFAULT_HTTP_PORT,
		idleTimeout: 120,
		async fetch(req) {
			const early = callerRefusal(req) ?? routeResponse(req, token);
			if (early) return early;
			try {
				return await handleMcp(endpoint, req);
			} catch {
				return rpcError(500, -32603, "Internal server error");
			}
		},
	});
	boundPort = bun.port ?? options.port ?? DEFAULT_HTTP_PORT;

	const sweep = setInterval(
		() => sessions.sweep(idleMs),
		Math.max(50, Math.min(30_000, Math.floor(idleMs / 4))),
	);
	sweep.unref();

	let closed: Promise<void> | undefined;
	const close = () =>
		(closed ??= (async () => {
			clearInterval(sweep);
			await bun.stop(true);
			await sessions.closeAll();
		})());

	const shownHost = host.includes(":") ? `[${host}]` : host;
	return {
		url: `http://${shownHost}:${boundPort}${MCP_PATH}`,
		host,
		port: boundPort,
		...(supplied ? {} : { generatedToken: token }),
		roots,
		sessionCount: () => sessions.size,
		close,
	};
};
