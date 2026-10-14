import { lstat, readdir, realpath, stat } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
import { Context, Effect, Layer } from "effect";

import { AuditorError } from "./errors";
import { GIT_HARDENING_ENV } from "./git";

/* -------------------------------------------------------------------------- */
/*                                  Workspace                                 */
/* -------------------------------------------------------------------------- */

/** Directories never worth scanning. */
export const DEFAULT_IGNORES = [
	"node_modules",
	".git",
	"dist",
	"build",
	"out",
	".next",
	".nuxt",
	".output",
	".svelte-kit",
	".turbo",
	".vercel",
	".cache",
	"coverage",
	"vendor",
	"target",
	"Pods",
	"DerivedData",
	".gradle",
	"__pycache__",
	".venv",
	"venv",
	".terraform",
	".openaudit",
];

const MAX_FILES = 50_000;
/** Files larger than this are listed but never read as text. */
export const MAX_TEXT_BYTES = 2 * 1024 * 1024;

/** Read-only view over a project directory. Paths are POSIX, relative to root. */
export interface Workspace {
	readonly root: string;
	/** All non-ignored files (respects .gitignore inside git repos). Cached. */
	readonly files: Effect.Effect<ReadonlyArray<string>, AuditorError>;
	/**
	 * Untracked paths that .gitignore excludes, directories with a trailing
	 * `/`. Tracked files are never in it, so a target can't hide committed
	 * code by ignoring it. Empty outside a git repo. Cached.
	 */
	readonly ignored: Effect.Effect<ReadonlyArray<string>, AuditorError>;
	/** Files matching a glob such as `**\/*.{ts,tsx}` (Bun.Glob syntax). */
	readonly glob: (
		pattern: string,
	) => Effect.Effect<ReadonlyArray<string>, AuditorError>;
	readonly readText: (path: string) => Effect.Effect<string, AuditorError>;
	readonly readBytes: (path: string) => Effect.Effect<Uint8Array, AuditorError>;
	readonly size: (path: string) => Effect.Effect<number, AuditorError>;
	readonly exists: (path: string) => Effect.Effect<boolean>;
	readonly absolute: (path: string) => string;
}

const toPosix = (p: string) => p.split(sep).join("/");

const walk = async (root: string): Promise<string[]> => {
	const out: string[] = [];
	const ignored = new Set(DEFAULT_IGNORES);
	const visit = async (dir: string): Promise<void> => {
		if (out.length >= MAX_FILES) return;
		const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
		for (const entry of entries) {
			if (out.length >= MAX_FILES) return;
			const full = join(dir, entry.name);
			if (entry.isDirectory()) {
				if (!ignored.has(entry.name)) await visit(full);
			} else if (entry.isFile()) {
				out.push(toPosix(relative(root, full)));
			}
		}
	};
	await visit(root);
	return out;
};

/** Variables that would point git at another repository than the target. */
const GIT_LOCATION_VARS = [
	"GIT_DIR",
	"GIT_WORK_TREE",
	"GIT_INDEX_FILE",
	"GIT_OBJECT_DIRECTORY",
	"GIT_ALTERNATE_OBJECT_DIRECTORIES",
	"GIT_COMMON_DIR",
	"GIT_CEILING_DIRECTORIES",
];

/**
 * Runs `git ls-files` in the target and returns its NUL-separated paths, or
 * undefined when the target isn't a git repo. The target may be untrusted,
 * so it runs with the hardened environment, and no inherited variable can
 * point it at another repository.
 */
const lsFiles = async (
	root: string,
	args: ReadonlyArray<string>,
): Promise<string[] | undefined> => {
	try {
		const env: Record<string, string | undefined> = {
			...process.env,
			...GIT_HARDENING_ENV,
		};
		for (const name of GIT_LOCATION_VARS) delete env[name];
		const proc = Bun.spawn(
			[
				"git",
				"-c",
				"core.untrackedCache=false",
				"-c",
				`core.hooksPath=${devNull}`,
				"ls-files",
				...args,
				"--exclude-standard",
				"-z",
			],
			{ cwd: root, stdout: "pipe", stderr: "ignore", env },
		);
		const text = await new Response(proc.stdout).text();
		if ((await proc.exited) !== 0) return undefined;
		return text.split("\0").filter(Boolean);
	} catch {
		return undefined;
	}
};

/** Lists files via git so .gitignore is honoured. */
const gitFiles = async (root: string): Promise<string[] | undefined> => {
	try {
		const listed = await lsFiles(root, ["-co"]);
		if (!listed) return undefined;
		const ignored = new Set(DEFAULT_IGNORES);
		const files = listed.filter(
			(f) => !f.split("/").some((part) => ignored.has(part)),
		);
		const regular: string[] = [];
		for (const f of files.slice(0, MAX_FILES)) {
			// Skip symlinks: they can point outside the workspace.
			const info = await lstat(join(root, f)).catch(() => undefined);
			if (info?.isFile()) regular.push(f);
		}
		return regular;
	} catch {
		return undefined;
	}
};

const devNull = process.platform === "win32" ? "NUL" : "/dev/null";

/**
 * A test for root-relative paths against `Workspace.ignored`: true for an
 * ignored file or anything inside an ignored directory. Paths may start with
 * `./` or be absolute under `root`.
 */
export const ignoredPathMatcher = (
	root: string,
	ignored: ReadonlyArray<string>,
): ((path: string) => boolean) => {
	const files = new Set<string>();
	const dirs: string[] = [];
	for (const p of ignored) {
		if (p.endsWith("/")) dirs.push(p);
		else files.add(p);
	}
	const prefix = toPosix(resolve(root)) + "/";
	return (path) => {
		let p = toPosix(path);
		if (p.startsWith(prefix)) p = p.slice(prefix.length);
		while (p.startsWith("./")) p = p.slice(2);
		return files.has(p) || dirs.some((d) => p.startsWith(d));
	};
};

/** Max bytes `readBytes` will load (mobile artifacts can be large). */
export const MAX_BINARY_BYTES = 512 * 1024 * 1024;

export const makeWorkspace = (rootInput: string): Workspace => {
	const root = resolve(rootInput);
	const absolute = (p: string) => join(root, p);
	let realRoot: Promise<string> | undefined;

	/**
	 * Resolves a workspace-relative path and refuses anything that escapes the
	 * root, either lexically (`../`) or through a symlink.
	 */
	const safePath = async (p: string): Promise<string> => {
		const full = resolve(root, p);
		if (full !== root && !full.startsWith(root + sep))
			throw new Error(`Path escapes workspace: ${p}`);
		realRoot ??= realpath(root);
		const [rr, rf] = await Promise.all([realRoot, realpath(full)]);
		if (rf !== rr && !rf.startsWith(rr + sep))
			throw new Error(`Path resolves outside workspace: ${p}`);
		return rf;
	};

	let ignoredCache: Promise<string[]> | undefined;
	const ignored = Effect.tryPromise({
		try: () => {
			ignoredCache ??= lsFiles(root, ["-oi", "--directory"]).then((paths) =>
				(paths ?? []).slice(0, MAX_FILES),
			);
			return ignoredCache;
		},
		catch: (cause) =>
			new AuditorError({
				message: `Failed to list ignored files in ${root}`,
				cause,
			}),
	});

	let cache: Promise<string[]> | undefined;
	const listFiles = () => {
		cache ??= gitFiles(root).then((files) => files ?? walk(root));
		return cache;
	};
	const files = Effect.tryPromise({
		try: listFiles,
		catch: (cause) =>
			new AuditorError({ message: `Failed to list files in ${root}`, cause }),
	});
	const readFile = <A>(
		p: string,
		max: number,
		read: (file: ReturnType<typeof Bun.file>) => Promise<A>,
	) =>
		Effect.tryPromise({
			try: async () => {
				const file = Bun.file(await safePath(p));
				if (file.size > max)
					throw new Error(`File too large (${file.size} bytes)`);
				return read(file);
			},
			catch: (cause) =>
				new AuditorError({ message: `Failed to read ${p}`, cause }),
		});
	return {
		root,
		absolute,
		files,
		ignored,
		glob: (pattern) =>
			Effect.map(files, (all) => {
				const g = new Bun.Glob(pattern);
				return all.filter((f) => g.match(f));
			}),
		readText: (p) => readFile(p, MAX_TEXT_BYTES, (f) => f.text()),
		readBytes: (p) =>
			readFile(
				p,
				MAX_BINARY_BYTES,
				async (f) => new Uint8Array(await f.arrayBuffer()),
			),
		size: (p) =>
			Effect.tryPromise({
				try: async () => (await stat(await safePath(p))).size,
				catch: (cause) =>
					new AuditorError({ message: `Failed to stat ${p}`, cause }),
			}),
		exists: (p) =>
			Effect.promise(() =>
				safePath(p).then(
					() => true,
					() => false,
				),
			),
	};
};

/** Opens workspaces. A service so tests can substitute in-memory fixtures. */
export class Workspaces extends Context.Service<
	Workspaces,
	{ readonly open: (root: string) => Workspace }
>()("openaudit/Workspaces") {
	static readonly layer = Layer.succeed(this, { open: makeWorkspace });
}

/* -------------------------------------------------------------------------- */
/*                                    Http                                    */
/* -------------------------------------------------------------------------- */

export const USER_AGENT =
	"openaudit/0.1 (+https://github.com/openaudit/openaudit)";

export interface HttpRequest {
	readonly method?: string;
	readonly headers?: Record<string, string>;
	readonly body?: string;
	/** `manual` returns 3xx responses instead of following them. */
	readonly redirect?: "follow" | "manual";
	readonly timeoutMs?: number;
	/** Max body bytes to buffer; the rest is discarded (default 5 MB). */
	readonly maxBytes?: number;
}

export interface HttpResponse {
	readonly url: string;
	readonly status: number;
	readonly headers: Headers;
	/** Raw `set-cookie` header values (Headers merges them otherwise). */
	readonly cookies: ReadonlyArray<string>;
	readonly body: string;
	readonly bytes: number;
	readonly redirected: boolean;
	/** Time until response headers arrived. */
	readonly ttfbMs: number;
	/** Time until the body was fully read. */
	readonly totalMs: number;
}

const MAX_REDIRECTS = 10;

/** Reads at most `max` bytes, cancelling the stream beyond that. */
const readCapped = async (res: Response, max: number) => {
	const chunks: Uint8Array[] = [];
	let total = 0;
	const reader = res.body?.getReader();
	if (!reader) return { bytes: new Uint8Array(), total: 0 };
	while (true) {
		const { done, value } = await reader.read();
		if (done) break;
		total += value.byteLength;
		if (total > max) {
			chunks.push(value.subarray(0, value.byteLength - (total - max)));
			await reader.cancel();
			break;
		}
		chunks.push(value);
	}
	return { bytes: Buffer.concat(chunks), total };
};

const httpRequest = (
	url: string,
	init: HttpRequest = {},
): Effect.Effect<HttpResponse, AuditorError> =>
	Effect.tryPromise({
		try: async (signal) => {
			const controller = new AbortController();
			signal.addEventListener("abort", () => controller.abort());
			const timer = setTimeout(
				() => controller.abort(),
				init.timeoutMs ?? 15_000,
			);
			const started = performance.now();
			try {
				// Redirects are followed manually. Caller headers may carry
				// credentials under any name (X-Api-Key, custom tokens), so once a
				// redirect leaves the original origin only the user agent is kept.
				const baseHeaders = { "user-agent": USER_AGENT };
				let current = url;
				let headers: Record<string, string> = {
					...baseHeaders,
					...init.headers,
				};
				let method = init.method ?? "GET";
				let body = init.body;
				let redirected = false;
				let res: Response;
				for (let hop = 0; ; hop++) {
					res = await fetch(current, {
						method,
						headers,
						body,
						redirect: "manual",
						signal: controller.signal,
					});
					const location = res.headers.get("location");
					if (
						init.redirect === "manual" ||
						res.status < 300 ||
						res.status >= 400 ||
						!location
					)
						break;
					if (hop >= MAX_REDIRECTS) throw new Error("Too many redirects");
					await res.body?.cancel();
					const next = new URL(location, current);
					if (next.protocol !== "http:" && next.protocol !== "https:")
						throw new Error(`Refusing redirect to ${next.protocol}`);
					if (next.origin !== new URL(url).origin) headers = baseHeaders;
					// Per the fetch spec, 301/302 after POST and every 303 become GET.
					if (
						res.status === 303 ||
						((res.status === 301 || res.status === 302) && method === "POST")
					) {
						method = "GET";
						body = undefined;
					}
					current = next.toString();
					redirected = true;
				}
				const ttfbMs = performance.now() - started;
				const { bytes, total } = await readCapped(
					res,
					init.maxBytes ?? 5 * 1024 * 1024,
				);
				return {
					url: current,
					status: res.status,
					headers: res.headers,
					cookies: res.headers.getSetCookie(),
					body: new TextDecoder().decode(bytes),
					bytes: total,
					redirected,
					ttfbMs,
					totalMs: performance.now() - started,
				};
			} finally {
				clearTimeout(timer);
			}
		},
		catch: (cause) =>
			new AuditorError({
				message: `Request to ${url} failed: ${cause instanceof Error ? cause.message : String(cause)}`,
				cause,
			}),
	});

export class Http extends Context.Service<
	Http,
	{
		readonly request: (
			url: string,
			init?: HttpRequest,
		) => Effect.Effect<HttpResponse, AuditorError>;
	}
>()("openaudit/Http") {
	static readonly layer = Layer.succeed(this, { request: httpRequest });
}

/* -------------------------------------------------------------------------- */
/*                                    Exec                                    */
/* -------------------------------------------------------------------------- */

export interface ExecResult {
	readonly code: number;
	readonly stdout: string;
	readonly stderr: string;
}

export interface ExecOptions {
	readonly cwd?: string;
	readonly timeoutMs?: number;
	readonly env?: Record<string, string>;
}

/** Runs external tools (gitleaks, semgrep, trivy, lighthouse, ...). */
export class Exec extends Context.Service<
	Exec,
	{
		/** Absolute path of a binary on PATH, or undefined. */
		readonly which: (bin: string) => Effect.Effect<string | undefined>;
		readonly run: (
			cmd: ReadonlyArray<string>,
			options?: ExecOptions,
		) => Effect.Effect<ExecResult, AuditorError>;
	}
>()("openaudit/Exec") {
	static readonly layer = Layer.succeed(this, {
		which: (bin) => Effect.sync(() => Bun.which(bin) ?? undefined),
		run: (cmd, options = {}) =>
			Effect.tryPromise({
				try: async () => {
					const proc = Bun.spawn([...cmd], {
						cwd: options.cwd,
						env: { ...process.env, ...options.env },
						stdout: "pipe",
						stderr: "pipe",
						stdin: "ignore",
					});
					const timer = setTimeout(
						() => proc.kill(),
						options.timeoutMs ?? 300_000,
					);
					try {
						const [stdout, stderr, code] = await Promise.all([
							new Response(proc.stdout).text(),
							new Response(proc.stderr).text(),
							proc.exited,
						]);
						return { code, stdout, stderr };
					} finally {
						clearTimeout(timer);
					}
				},
				catch: (cause) =>
					new AuditorError({
						message: `Failed to run ${cmd[0]}`,
						cause,
					}),
			}),
	});
}

/** All live infrastructure needed by the engine. */
export const CoreLive = Layer.mergeAll(
	Workspaces.layer,
	Http.layer,
	Exec.layer,
);
