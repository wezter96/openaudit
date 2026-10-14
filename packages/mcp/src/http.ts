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

export const isLoopbackHost = (host: string): boolean => {
	const h = host.replace(/^\[|\]$/g, "").toLowerCase();
	return h === "localhost" || h === "::1" || /^127(\.\d{1,3}){3}$/.test(h);
};

/** Constant-time comparison: hash both sides so length differences leak nothing. */
export const tokenMatches = (given: string, expected: string): boolean => {
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
export const isRegistryImageRef = (ref: string): boolean =>
	ref.length <= 255 &&
	// `registry:5000/x` is a host with a port, not the registry transport.
	(!IMAGE_TRANSPORT.test(ref) || /^[^:/]+:\d{1,5}\//.test(ref)) &&
	REGISTRY_REF.test(ref);

/** Registry host[:port] of a validated reference; Docker Hub when none is given. */
export const registryHost = (ref: string): string => {
	const first = ref.split("/")[0] ?? "";
	return ref.includes("/") &&
		(first.includes(".") || first.includes(":") || first === "localhost")
		? first
		: "registry-1.docker.io";
};

const within = (path: string, root: string) =>
	path === root || path.startsWith(root.endsWith(sep) ? root : root + sep);

/**
 * Target policy for remote clients. URLs and (safe) image refs pass; local
 * paths must realpath inside an allowed root, which defeats `..` and symlinks.
 * The resolved real path is returned so a later symlink swap cannot escape.
 */
export const makeTargetPolicy = (
	roots: ReadonlyArray<string>,
	allowCloud: boolean,
	cwd?: string,
	urlGuard?: GuardOptions,
	allowImages = false,
) => {
	const base = cwd ?? roots[0] ?? process.cwd();
	return async (target: string): Promise<string> => {
		if (/^https?:\/\//i.test(target)) {
			if (urlGuard) {
				try {
					await resolvePublicUrl(target, urlGuard);
				} catch (error) {
					if (error instanceof SsrfError) throw new Error(error.message);
					throw error;
				}
			}
			return target;
		}
		if (/^image:/i.test(target)) {
			const ref = target.slice("image:".length);
			// Registry references only: never a local tarball, directory or daemon.
			if (!isRegistryImageRef(ref))
				throw new Error(
					"image: targets must be OCI registry references such as nginx:1.27 or ghcr.io/org/repo:tag",
				);
			if (urlGuard) {
				// Scanners pull images themselves, so the registry cannot be pinned.
				if (!allowImages)
					throw new Error(
						"image: targets are disabled on this server (start it with --allow-images)",
					);
				try {
					await resolvePublicUrl(`https://${registryHost(ref)}/`, urlGuard);
				} catch (error) {
					if (error instanceof SsrfError) throw new Error(error.message);
					throw error;
				}
			}
			return target;
		}
		if (/^cloud:/i.test(target)) {
			if (!allowCloud)
				throw new Error(
					"cloud: targets are disabled on this server (start it with --allow-cloud)",
				);
			return target;
		}
		if (roots.length === 0)
			throw new Error(
				"Local paths are disabled on this server; only URL and image: targets are accepted. Start it with --root <dir> to allow directories.",
			);
		const real = await realpath(resolve(base, target)).catch(() => undefined);
		// Same message for missing and forbidden paths: no filesystem probing.
		if (!real || !roots.some((r) => within(real, r)))
			throw new Error("Target is not inside an allowed root");
		return real;
	};
};

interface Session {
	readonly transport: WebStandardStreamableHTTPServerTransport;
	readonly server: McpServer;
	lastSeen: number;
	/** In-flight POST responses (long run_audit calls keep a session alive). */
	active: number;
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

class BodyTooLarge extends Error {}

const readLimited = async (req: Request, max: number): Promise<string> => {
	const declared = Number(req.headers.get("content-length"));
	if (Number.isFinite(declared) && declared > max) throw new BodyTooLarge();
	if (!req.body) return "";
	const reader = req.body.getReader();
	const chunks: Uint8Array[] = [];
	let size = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		size += value.byteLength;
		if (size > max) {
			await reader.cancel();
			throw new BodyTooLarge();
		}
		chunks.push(value);
	}
	return Buffer.concat(chunks).toString("utf8");
};

/** Default location for a generated token: readable by the current user only. */
export const defaultTokenFile = (): string =>
	join(
		process.env.XDG_CONFIG_HOME || join(homedir(), ".config"),
		"openaudit",
		"mcp-token",
	);

/** Writes the token to a 0600 file (0700 directory), replacing it atomically. */
export const writeTokenFile = async (
	token: string,
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
	// The Authorization check matches a whitespace-free token exactly.
	if (supplied && /\s/.test(supplied))
		throw new Error("The bearer token must not contain whitespace.");
	if (!loopback) {
		if (!supplied)
			throw new Error(
				`Refusing to bind ${host} without a bearer token. Pass --token or set OPENAUDIT_MCP_TOKEN, or bind 127.0.0.1.`,
			);
		if (supplied.length < MIN_REMOTE_TOKEN_LENGTH)
			throw new Error(
				`Bearer token must be at least ${MIN_REMOTE_TOKEN_LENGTH} characters when binding a non-loopback host.`,
			);
	}
	const maxBody = options.maxBodyBytes ?? 4 * 1024 * 1024;
	const maxSessions = options.maxSessions ?? 32;
	const idleMs = options.sessionIdleMs ?? 30 * 60_000;
	const allowOrigins = new Set(options.allowOrigins ?? []);
	const roots = await Promise.all(
		(options.roots ?? []).map(async (r) => {
			const real = await realpath(resolve(r)).catch(() => undefined);
			if (!real) throw new Error(`--root does not exist: ${r}`);
			return real;
		}),
	);
	const urlGuard: GuardOptions | undefined =
		loopback || options.allowPrivateTargets ? undefined : {};
	const resolveInput = makeTargetPolicy(
		roots,
		options.allowCloud ?? false,
		options.server?.cwd,
		urlGuard,
		options.allowImages ?? false,
	);
	const sessions = new Map<string, Session>();
	const closing = new Set<Promise<unknown>>();

	let boundPort = 0;
	const hostAllowed = (header: string | null): boolean => {
		if (!header) return false;
		const h = header.toLowerCase();
		const extra = (options.allowHosts ?? []).map((x) => x.toLowerCase());
		if (extra.includes(h) || extra.includes(h.replace(/:\d+$/, "")))
			return true;
		// A non-loopback bind is token-gated and reached by arbitrary names.
		if (!loopback) return extra.length === 0;
		const names = new Set(["localhost", "127.0.0.1", "[::1]", host]);
		return [...names].some((n) => h === `${n}:${boundPort}`);
	};

	const authorized = (req: Request): boolean => {
		const m = /^Bearer ([^\s]+)$/i.exec(req.headers.get("authorization") ?? "");
		return m?.[1] !== undefined && tokenMatches(m[1], token);
	};

	const dropSession = (id: string) => {
		const s = sessions.get(id);
		if (!s) return;
		sessions.delete(id);
		const p = Promise.allSettled([s.transport.close(), s.server.close()]);
		closing.add(p);
		void p.finally(() => closing.delete(p));
	};

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

	const newSession = async (req: Request, body: unknown): Promise<Response> => {
		if (sessions.size >= maxSessions)
			return rpcError(503, -32000, "Too many sessions; try again later");
		let id: string | undefined;
		const server = createServer({
			...options.server,
			resolveInput,
			// Reports are per session: never share a store between clients.
			store: undefined,
			allowAgentic: options.allowAgentic ?? false,
			registryImagesOnly: true,
			persistReports: options.persistReports ?? false,
			urlGuard,
		});
		const transport = new WebStandardStreamableHTTPServerTransport({
			sessionIdGenerator: randomUUID,
			keepAliveMs: 15_000,
			maxRequestBodySize: maxBody,
			onsessioninitialized: (sid) => {
				id = sid;
				sessions.set(sid, session);
			},
		});
		const session: Session = {
			transport,
			server,
			lastSeen: Date.now(),
			active: 0,
		};
		transport.onclose = () => {
			if (id) sessions.delete(id);
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

	const handleMcp = async (req: Request): Promise<Response> => {
		const sid = req.headers.get("mcp-session-id");
		if (req.method === "POST") {
			let body: unknown;
			try {
				const text = await readLimited(req, maxBody);
				body = JSON.parse(text);
			} catch (e) {
				return e instanceof BodyTooLarge
					? rpcError(413, -32000, "Request body too large")
					: rpcError(400, -32700, "Parse error: invalid JSON");
			}
			if (!sid) {
				const first = Array.isArray(body) ? body[0] : body;
				if (!isInitializeRequest(first))
					return rpcError(400, -32000, "Missing Mcp-Session-Id header");
				return newSession(req, body);
			}
			const s = sessions.get(sid);
			if (!s) return rpcError(404, -32001, "Unknown or expired session");
			s.lastSeen = Date.now();
			return track(
				s,
				await s.transport.handleRequest(req, { parsedBody: body }),
			);
		}
		if (req.method === "GET" || req.method === "DELETE") {
			if (!sid) return rpcError(400, -32000, "Missing Mcp-Session-Id header");
			const s = sessions.get(sid);
			if (!s) return rpcError(404, -32001, "Unknown or expired session");
			s.lastSeen = Date.now();
			const res = await s.transport.handleRequest(req);
			if (req.method === "DELETE") dropSession(sid);
			return res;
		}
		return json(
			405,
			{ error: "Method not allowed" },
			{ allow: "POST, GET, DELETE" },
		);
	};

	const bun = Bun.serve({
		hostname: host,
		port: options.port ?? DEFAULT_HTTP_PORT,
		idleTimeout: 120,
		async fetch(req) {
			if (!hostAllowed(req.headers.get("host")))
				return json(403, { error: "Host not allowed" });
			const origin = req.headers.get("origin");
			if (origin !== null && !allowOrigins.has(origin))
				return json(403, { error: "Origin not allowed" });
			let path: string;
			try {
				path = new URL(req.url).pathname;
			} catch {
				return json(400, { error: "Bad request" });
			}
			if (path === "/health" && req.method === "GET")
				return json(200, { status: "ok" });
			if (path !== MCP_PATH) return json(404, { error: "Not found" });
			if (!authorized(req))
				return json(
					401,
					{ error: "Unauthorized" },
					{ "www-authenticate": 'Bearer realm="openaudit"' },
				);
			try {
				return await handleMcp(req);
			} catch {
				return rpcError(500, -32603, "Internal server error");
			}
		},
	});
	boundPort = bun.port ?? options.port ?? DEFAULT_HTTP_PORT;

	const sweep = setInterval(
		() => {
			const now = Date.now();
			for (const [id, s] of sessions)
				if (s.active === 0 && now - s.lastSeen > idleMs) dropSession(id);
		},
		Math.max(50, Math.min(30_000, Math.floor(idleMs / 4))),
	);
	sweep.unref();

	let closed: Promise<void> | undefined;
	const close = () =>
		(closed ??= (async () => {
			clearInterval(sweep);
			await bun.stop(true);
			for (const id of sessions.keys()) dropSession(id);
			await Promise.allSettled(closing);
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
