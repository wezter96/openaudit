import { truncate } from "../util";

/**
 * Hosts of the public npm registry. Registries where anyone can publish
 * under their own namespace (GitHub Packages) are not on the list.
 */
export const DEFAULT_REGISTRY_HOSTS = new Set([
	"registry.npmjs.org",
	"registry.yarnpkg.com",
]);

/**
 * Default download locations of pnpm `runtime:` dependencies, by runtime.
 * Prefixes of the parsed URL: github.com serves anyone's release assets.
 */
const RUNTIME_DOWNLOADS: Readonly<Record<string, ReadonlyArray<string>>> = {
	node: ["https://nodejs.org/download/"],
	bun: ["https://github.com/oven-sh/bun/releases/download/"],
	deno: [
		"https://github.com/denoland/deno/releases/download/",
		"https://dl.deno.land/",
	],
};

export const isOfficialRuntime = (name: string, raw: string): boolean => {
	const prefixes = Object.hasOwn(RUNTIME_DOWNLOADS, name)
		? RUNTIME_DOWNLOADS[name]
		: undefined;
	if (!prefixes) return false;
	try {
		const url = new URL(raw);
		const href = `${url.protocol}//${url.host}${url.pathname}`;
		return !url.username && prefixes.some((p) => href.startsWith(p));
	} catch {
		return false;
	}
};

/** Hosts of the Python Package Index. */
const PYPI_HOSTS = new Set(["pypi.org", "files.pythonhosted.org"]);

/** Git hosts whose repositories have a known owner namespace. */
export const KNOWN_GIT_HOSTS = new Set([
	"github.com",
	"codeload.github.com",
	"gist.github.com",
	"gitlab.com",
	"bitbucket.org",
]);

export type Source =
	| { readonly kind: "registry" }
	/** Workspaces, patches and other sources that are part of the project. */
	| { readonly kind: "ignored" }
	| { readonly kind: "path"; readonly path: string }
	| {
			readonly kind: "git";
			readonly url: string;
			readonly host: string;
			readonly ref?: string;
			/** The ref is a commit id. */
			readonly pinned: boolean;
			readonly insecure: boolean;
	  }
	| {
			readonly kind: "tarball";
			readonly url: string;
			readonly host: string;
			readonly insecure: boolean;
	  }
	/** Anything else: reported, never assumed safe. */
	| { readonly kind: "unknown" };

const REGISTRY: Source = { kind: "registry" };

const IGNORED: Source = { kind: "ignored" };

const UNKNOWN: Source = { kind: "unknown" };

const COMMIT = /^[0-9a-f]{7,40}$/i;

const GIT_SHORTHANDS: ReadonlyArray<readonly [string, string]> = [
	["github:", "github.com"],
	["gitlab:", "gitlab.com"],
	["bitbucket:", "bitbucket.org"],
	["gist:", "gist.github.com"],
];

const GIT_PREFIXES = ["git+", "git:", "git@", "ssh:"];

/** `owner/repo` or `owner/repo#ref`: npm's GitHub shorthand. */
const GITHUB_SHORTHAND = /^[\w.-]+\/[\w.-]+(#.*)?$/;

/** The ref of a git fragment, including Yarn Berry's `commit=<sha>&…` form. */
const gitRef = (fragment: string | undefined): string | undefined => {
	if (!fragment) return undefined;
	if (!fragment.includes("=")) return fragment;
	const params = new URLSearchParams(fragment);
	return (
		params.get("commit") ??
		params.get("tag") ??
		params.get("head") ??
		params.get("semver") ??
		fragment
	);
};

/** The host of a git spec: URL, scp-like `user@host:path` or shorthand. */
export const gitHost = (spec: string): string => {
	const lower = spec.toLowerCase();
	for (const [prefix, host] of GIT_SHORTHANDS)
		if (lower.startsWith(prefix)) return host;
	if (GITHUB_SHORTHAND.test(spec)) return "github.com";
	const bare = spec.replace(/^git\+/i, "");
	try {
		const host = new URL(bare).hostname.toLowerCase();
		if (host) return host;
	} catch {
		// scp-like `git@host:owner/repo.git`.
	}
	const at = bare.indexOf("@");
	const colon = bare.indexOf(":", at + 1);
	return at !== -1 && colon > at ? bare.slice(at + 1, colon).toLowerCase() : "";
};

/** The ref of a GitHub/GitLab/Bitbucket source archive URL. */
const archiveRef = (url: URL): string | undefined => {
	const host = url.hostname.toLowerCase();
	const parts = url.pathname.split("/").filter(Boolean);
	const stripExt = (s: string) =>
		s.replace(/\.(tar\.gz|tgz|zip|tar\.bz2)$/, "");
	if (host === "codeload.github.com" && parts.length >= 4)
		return parts.slice(3).join("/");
	if (host === "github.com" && parts[2] === "archive" && parts.length >= 4)
		return stripExt(parts.slice(3).join("/"));
	if (host === "gitlab.com") {
		const i = parts.indexOf("archive");
		if (i > 0 && parts[i - 1] === "-" && parts[i + 1]) return parts[i + 1];
	}
	if (host === "bitbucket.org" && parts[2] === "get" && parts[3])
		return stripExt(parts[3]);
	return undefined;
};

const gitSource = (
	spec: string,
	fragment: string | undefined,
	insecure: boolean,
): Source => {
	const hash = spec.indexOf("#");
	const ref = gitRef(fragment);
	return {
		kind: "git",
		url: hash === -1 ? spec : spec.slice(0, hash),
		host: gitHost(spec),
		...(ref ? { ref } : {}),
		pinned: ref !== undefined && COMMIT.test(ref),
		insecure,
	};
};

/**
 * Classifies where a lockfile entry is fetched from. URLs are parsed, never
 * prefix-matched, so `https://registry.npmjs.org@evil.example/` is evil.example.
 */
export const classifySource = (raw: string | undefined): Source => {
	const s = (raw ?? "").trim();
	if (!s) return REGISTRY;
	const lower = s.toLowerCase();
	if (lower.startsWith("npm:")) return REGISTRY;
	if (
		["workspace:", "patch:", "exec:", "catalog:"].some((p) =>
			lower.startsWith(p),
		)
	)
		return IGNORED;
	if (["file:", "link:", "portal:"].some((p) => lower.startsWith(p)))
		return { kind: "path", path: s.slice(s.indexOf(":") + 1) };
	// Protocol-relative: whatever fetches it picks the scheme, so judge the host.
	if (s.startsWith("//")) return classifySource(`https:${s}`);
	const hash = s.indexOf("#");
	const fragment = hash === -1 ? undefined : s.slice(hash + 1);
	// `http:host/x` and `https:\\host` are URLs too, as npm and pnpm parse them.
	if (/^https?:/i.test(s)) {
		let url: URL;
		try {
			url = new URL(s);
		} catch {
			return UNKNOWN;
		}
		const insecure = url.protocol === "http:";
		if (url.pathname.toLowerCase().endsWith(".git"))
			return gitSource(s, fragment, insecure);
		const ref = archiveRef(url);
		if (ref !== undefined)
			return {
				kind: "git",
				url: `${url.origin}${url.pathname}`,
				host: url.hostname.toLowerCase(),
				ref,
				pinned: COMMIT.test(ref),
				insecure,
			};
		return {
			kind: "tarball",
			url: s,
			host: url.hostname.toLowerCase(),
			insecure,
		};
	}
	if (
		GIT_PREFIXES.some((p) => lower.startsWith(p)) ||
		GIT_SHORTHANDS.some(([p]) => lower.startsWith(p)) ||
		GITHUB_SHORTHAND.test(s)
	)
		return gitSource(
			s,
			fragment,
			lower.startsWith("git://") || lower.startsWith("git+http://"),
		);
	return UNKNOWN;
};

/**
 * The repository path of `rel` relative to the repository directory `dir`
 * (`""` for the root), or undefined if either leaves the repository. With
 * `urlDots`, `%2e` counts as a dot, as it does where a path is resolved as a
 * URL (npm-package-arg).
 */
const resolvePath = (
	dir: string,
	rel: string,
	urlDots: boolean,
): string | undefined => {
	const out: string[] = [];
	for (const part of [dir, rel]) {
		const p = part.replace(/\\/g, "/");
		if (p.startsWith("/") || p.startsWith("~") || /^[a-z]:/i.test(p))
			return undefined;
		for (const raw of p.split("/")) {
			const seg = urlDots ? raw.replace(/%2e/gi, ".") : raw;
			if (!seg || seg === ".") continue;
			if (seg === "..") {
				if (!out.length) return undefined;
				out.pop();
			} else out.push(raw);
		}
	}
	return out.join("/");
};

/** A repository path for `rel` relative to `dir`, or undefined if it leaves the repository. */
export const resolveInRepo = (dir: string, rel: string) =>
	resolvePath(dir, rel, false);

/**
 * Whether `path`, relative to the repository directory `base` (`""` for the
 * root), points outside the repository. `base` comes from the lockfile too,
 * so a base that leaves the repository counts.
 */
export const escapesRoot = (base: string, path: string): boolean =>
	resolvePath(base, path, true) === undefined;

/** A URL without credentials or query string, safe to show as evidence. */
export const displayUrl = (raw: string): string => {
	try {
		const url = new URL(raw);
		if (url.protocol === "http:" || url.protocol === "https:")
			return truncate(`${url.protocol}//${url.host}${url.pathname}`, 120);
	} catch {
		// Not a URL: git shorthands and scp-like `git@host:path` specs.
	}
	const scheme = raw.indexOf("://");
	const hostEnd = scheme === -1 ? -1 : raw.indexOf("/", scheme + 3);
	const at = raw.lastIndexOf("@", hostEnd === -1 ? undefined : hostEnd);
	const withoutUser =
		scheme !== -1 && at > scheme
			? raw.slice(0, scheme + 3) + raw.slice(at + 1)
			: raw;
	const q = withoutUser.indexOf("?");
	return truncate(q === -1 ? withoutUser : withoutUser.slice(0, q), 120);
};

/** A dependency spec safe to show: URL specs lose credentials and query strings. */
export const displaySpec = (spec: string): string =>
	spec.includes("://") ? displayUrl(spec) : truncate(spec, 120);

/** The host of a registry URL, or `undefined` when it does not parse. */
export const hostOf = (url: string): string | undefined => {
	try {
		return new URL(
			url.startsWith("//") ? `https:${url}` : url,
		).hostname.toLowerCase();
	} catch {
		return undefined;
	}
};

/** How well an integrity value protects the download. */
export type IntegrityStrength = "none" | "weak" | "strong";

const SRI = /^(sha1|sha256|sha384|sha512)-[A-Za-z0-9+/=_-]+$/i;

/**
 * Strength of an SRI string (`sha512-… sha1-…`). Values that are not a hash
 * count as none: package managers skip verification they cannot parse.
 */
export const integrityStrength = (
	integrity: string | undefined,
): IntegrityStrength => {
	const valid = (integrity ?? "")
		.split(/\s+/)
		.filter((t) => SRI.test(t))
		.map((t) => t.slice(0, t.indexOf("-")).toLowerCase());
	if (!valid.length) return "none";
	return valid.some((a) => a !== "sha1") ? "strong" : "weak";
};

/**
 * The host Python's urllib.parse.urlsplit sees, which pip uses for auth and
 * trusted hosts: the authority ends at the first `/`, `?` or `#` (not a backslash),
 * and the host follows its last `@`.
 */
const pythonHost = (url: string): string | undefined => {
	const authority = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(url)?.[1];
	if (authority === undefined) return undefined;
	const host = authority.slice(authority.lastIndexOf("@") + 1);
	const end = host.startsWith("[") ? host.indexOf("]") + 1 : host.indexOf(":");
	return (end > 0 ? host.slice(0, end) : host).toLowerCase();
};

/** A PyPI URL by both WHATWG's and Python's reading; one they disagree on is not. */
export const onPypi = (url: string): boolean => {
	const host = hostOf(url);
	return host !== undefined && PYPI_HOSTS.has(host) && pythonHost(url) === host;
};

export const isInsecureUrl = (s: string) => {
	const l = s.toLowerCase();
	return (
		l.startsWith("http://") ||
		l.startsWith("git://") ||
		l.startsWith("svn://") ||
		/^[a-z]+\+http:\/\//.test(l)
	);
};
