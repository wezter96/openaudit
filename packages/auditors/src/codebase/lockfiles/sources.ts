import { redact } from "@openaudit/core";

import { truncate } from "../util";
import { scrubText } from "./scrub";
import type {
	FilePath,
	Host,
	Integrity,
	PackageName,
	SourceSpec,
	Url,
} from "./types";

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

export const isOfficialRuntime = (name: PackageName, raw: Url): boolean => {
	const prefixes = Object.hasOwn(RUNTIME_DOWNLOADS, name)
		? RUNTIME_DOWNLOADS[name]
		: undefined;
	if (!prefixes) return false;
	const url = parseUrl(raw);
	if (!url) return false;
	const href = `${url.protocol}//${url.host}${url.pathname}`;
	return !url.username && prefixes.some((p) => href.startsWith(p));
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

const GIT_SHORTHANDS: ReadonlyArray<readonly [string, Host]> = [
	["github:", "github.com"],
	["gitlab:", "gitlab.com"],
	["bitbucket:", "bitbucket.org"],
	["gist:", "gist.github.com"],
];

const GIT_PREFIXES = ["git+", "git:", "git@", "ssh:"];

/** Prefixes of sources that are part of the project. */
const IGNORED_PREFIXES = ["workspace:", "patch:", "exec:", "catalog:"];

/** Prefixes of local path sources. */
const PATH_PREFIXES = ["file:", "link:", "portal:"];

/** `owner/repo` or `owner/repo#ref`: npm's GitHub shorthand. */
const GITHUB_SHORTHAND = /^[\w.-]+\/[\w.-]+(#.*)?$/;

/** The parsed URL, or undefined when it does not parse. */
export const parseUrl = (raw: Url): URL | undefined => {
	try {
		return new URL(raw);
	} catch {
		return undefined;
	}
};

/** The ref of a git fragment, including Yarn Berry's `commit=<sha>&…` form. */
const gitRef = (fragment: SourceSpec | undefined): string | undefined => {
	if (!fragment) return undefined;
	if (!fragment.includes("=")) return fragment;
	// Other parameters are not a ref and may be a token (`#access_token=`).
	const params = new URLSearchParams(fragment);
	return (
		params.get("commit") ??
		params.get("tag") ??
		params.get("head") ??
		params.get("semver") ??
		undefined
	);
};

/** The host of a scp-like `git@host:owner/repo.git` spec, or `""`. */
const scpHost = (bare: SourceSpec): Host => {
	const at = bare.indexOf("@");
	const colon = bare.indexOf(":", at + 1);
	return at !== -1 && colon > at ? bare.slice(at + 1, colon).toLowerCase() : "";
};

/** The host of a git spec: URL, scp-like `user@host:path` or shorthand. */
export const gitHost = (spec: SourceSpec): Host => {
	const lower = spec.toLowerCase();
	const shorthand = GIT_SHORTHANDS.find(([prefix]) => lower.startsWith(prefix));
	if (shorthand) return shorthand[1];
	if (GITHUB_SHORTHAND.test(spec)) return "github.com";
	const bare = spec.replace(/^git\+/i, "");
	const host = parseUrl(bare)?.hostname.toLowerCase();
	return host || scpHost(bare);
};

/** The ref named by the path segments of a source archive URL, if it is one. */
type ArchiveRef = (parts: ReadonlyArray<string>) => string | undefined;

const stripArchiveExt = (file: FilePath): FilePath =>
	file.replace(/\.(tar\.gz|tgz|zip|tar\.bz2)$/, "");

/** `/<owner>/<repo>/-/archive/<ref>/…` */
const gitlabArchiveRef: ArchiveRef = (parts) => {
	const i = parts.indexOf("archive");
	const isArchive = i > 0 && parts[i - 1] === "-";
	return isArchive ? parts[i + 1] : undefined;
};

/** Source archive URL layouts of GitHub, GitLab and Bitbucket, by host. */
const ARCHIVE_REFS = new Map<Host, ArchiveRef>([
	[
		"codeload.github.com",
		(parts) => (parts.length >= 4 ? parts.slice(3).join("/") : undefined),
	],
	[
		"github.com",
		(parts) =>
			parts[2] === "archive" && parts.length >= 4
				? stripArchiveExt(parts.slice(3).join("/"))
				: undefined,
	],
	["gitlab.com", gitlabArchiveRef],
	[
		"bitbucket.org",
		(parts) =>
			parts[2] === "get" && parts[3] ? stripArchiveExt(parts[3]) : undefined,
	],
]);

/** The ref of a GitHub/GitLab/Bitbucket source archive URL. */
const archiveRef = (url: URL): string | undefined => {
	const parts = url.pathname.split("/").filter(Boolean);
	return ARCHIVE_REFS.get(url.hostname.toLowerCase())?.(parts);
};

const gitSource = (
	spec: SourceSpec,
	fragment: SourceSpec | undefined,
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

/** Sources recognised by their protocol prefix alone: registry, project and path. */
const prefixSource = (s: SourceSpec, lower: SourceSpec): Source | undefined => {
	if (lower.startsWith("npm:")) return REGISTRY;
	if (IGNORED_PREFIXES.some((p) => lower.startsWith(p))) return IGNORED;
	if (PATH_PREFIXES.some((p) => lower.startsWith(p)))
		return { kind: "path", path: s.slice(s.indexOf(":") + 1) };
	return undefined;
};

/** An `http:`/`https:` source: a git repository, a source archive or a tarball. */
const httpSource = (s: Url, fragment: SourceSpec | undefined): Source => {
	const url = parseUrl(s);
	if (!url) return UNKNOWN;
	const insecure = url.protocol === "http:";
	if (url.pathname.toLowerCase().endsWith(".git"))
		return gitSource(s, fragment, insecure);
	const host = url.hostname.toLowerCase();
	const ref = archiveRef(url);
	if (ref === undefined) return { kind: "tarball", url: s, host, insecure };
	return {
		kind: "git",
		url: `${url.origin}${url.pathname}`,
		host,
		ref,
		pinned: COMMIT.test(ref),
		insecure,
	};
};

const isGitSpec = (s: SourceSpec, lower: SourceSpec): boolean =>
	GIT_PREFIXES.some((p) => lower.startsWith(p)) ||
	GIT_SHORTHANDS.some(([p]) => lower.startsWith(p)) ||
	GITHUB_SHORTHAND.test(s);

const isInsecureGit = (lower: SourceSpec): boolean =>
	lower.startsWith("git://") || lower.startsWith("git+http://");

/** The text after the first `#`, if any. */
const fragmentOf = (s: SourceSpec): SourceSpec | undefined => {
	const hash = s.indexOf("#");
	return hash === -1 ? undefined : s.slice(hash + 1);
};

/**
 * Classifies where a lockfile entry is fetched from. URLs are parsed, never
 * prefix-matched, so `https://registry.npmjs.org@evil.example/` is evil.example.
 */
export const classifySource = (raw: SourceSpec | undefined): Source => {
	const s = (raw ?? "").trim();
	if (!s) return REGISTRY;
	const lower = s.toLowerCase();
	const known = prefixSource(s, lower);
	if (known) return known;
	// Protocol-relative: whatever fetches it picks the scheme, so judge the host.
	if (s.startsWith("//")) return classifySource(`https:${s}`);
	const fragment = fragmentOf(s);
	// `http:host/x` and `https:\\host` are URLs too, as npm and pnpm parse them.
	if (/^https?:/i.test(s)) return httpSource(s, fragment);
	if (isGitSpec(s, lower)) return gitSource(s, fragment, isInsecureGit(lower));
	return UNKNOWN;
};

const isAbsolutePath = (p: FilePath): boolean =>
	p.startsWith("/") || p.startsWith("~") || /^[a-z]:/i.test(p);

/**
 * Applies one path segment to the resolved segments `out`; false when `..`
 * climbs above the repository root.
 */
const applySegment = (
	out: string[],
	raw: FilePath,
	urlDots: boolean,
): boolean => {
	const seg = urlDots ? raw.replace(/%2e/gi, ".") : raw;
	if (!seg || seg === ".") return true;
	if (seg !== "..") {
		out.push(raw);
		return true;
	}
	if (!out.length) return false;
	out.pop();
	return true;
};

/**
 * The repository path of `rel` relative to the repository directory `dir`
 * (`""` for the root), or undefined if either leaves the repository. With
 * `urlDots`, `%2e` counts as a dot, as it does where a path is resolved as a
 * URL (npm-package-arg).
 */
const resolvePath = (
	dir: FilePath,
	rel: FilePath,
	urlDots: boolean,
): FilePath | undefined => {
	const out: string[] = [];
	for (const part of [dir, rel]) {
		const p = part.replace(/\\/g, "/");
		if (isAbsolutePath(p)) return undefined;
		const inside = p.split("/").every((raw) => applySegment(out, raw, urlDots));
		if (!inside) return undefined;
	}
	return out.join("/");
};

/** A repository path for `rel` relative to `dir`, or undefined if it leaves the repository. */
export const resolveInRepo = (dir: FilePath, rel: FilePath) =>
	resolvePath(dir, rel, false);

/**
 * Whether `path`, relative to the repository directory `base` (`""` for the
 * root), points outside the repository. `base` comes from the lockfile too,
 * so a base that leaves the repository counts.
 */
export const escapesRoot = (base: FilePath, path: FilePath): boolean =>
	resolvePath(base, path, true) === undefined;

/** Where the authority of `raw` starts: after `://`, or at 0 without a scheme. */
const authorityStart = (raw: Url): number => {
	const scheme = raw.indexOf("://");
	return scheme === -1 ? 0 : scheme + 3;
};

/** The first `/`, `?` or `#` from `start`, or the end of `raw`. */
const lenientAuthorityEnd = (raw: Url, start: number): number => {
	const ends = [..."/?#"]
		.map((c) => raw.indexOf(c, start))
		.filter((i) => i !== -1);
	return Math.min(raw.length, ...ends);
};

/**
 * The userinfo of a URL up to the last `@` of its authority, read leniently:
 * the authority ends only at `/`, `?` or `#`, so text before a backslash
 * (where WHATWG ends a special URL's authority) counts. Without a scheme,
 * only scp-like `user:password@host` counts, not `git@host` or `npm:@scope`.
 */
const lenientUserinfo = (raw: Url): string => {
	const start = authorityStart(raw);
	const at = raw.lastIndexOf("@", lenientAuthorityEnd(raw, start) - 1);
	const userinfo = at >= start ? raw.slice(start, at) : "";
	const hasScheme = raw.includes("://");
	return hasScheme || /^[^:@]+:[^@]+$/.test(userinfo) ? userinfo : "";
};

/** `input` with its lenient userinfo and the `@` after it removed. */
const withoutLenientUserinfo = (input: Url): Url => {
	const userinfo = lenientUserinfo(input);
	if (!userinfo) return input;
	const start = authorityStart(input);
	return input.slice(0, start) + input.slice(start + userinfo.length + 1);
};

const WEB_PROTOCOLS = new Set(["http:", "https:"]);

/** Scheme, host and path of an `http(s)` URL; undefined for anything else. */
const webUrl = (raw: Url): Url | undefined => {
	const url = parseUrl(raw);
	if (!url || !WEB_PROTOCOLS.has(url.protocol)) return undefined;
	return `${url.protocol}//${url.host}${url.pathname}`;
};

/** Git shorthands and scp-like `git@host:path` specs: userinfo and query dropped by hand. */
const looseUrl = (raw: Url): Url => {
	const scheme = raw.indexOf("://");
	const hostEnd = scheme === -1 ? -1 : raw.indexOf("/", scheme + 3);
	const at = raw.lastIndexOf("@", hostEnd === -1 ? undefined : hostEnd);
	const withoutUser =
		scheme !== -1 && at > scheme
			? raw.slice(0, scheme + 3) + raw.slice(at + 1)
			: raw;
	const q = withoutUser.indexOf("?");
	return q === -1 ? withoutUser : withoutUser.slice(0, q);
};

/**
 * A URL without credentials or query string, safe to show as evidence.
 * Userinfo is dropped up to the last `@`, however a parser splits it.
 */
export const displayUrl = (input: Url): string => {
	const raw = withoutLenientUserinfo(input);
	return truncate(scrubText(webUrl(raw) ?? looseUrl(raw)), 120);
};

/**
 * A host to show for `raw`. A host WHATWG took from what another parser
 * reads as userinfo (`https://token\@host`) may be a credential, so it is
 * masked.
 */
export const displayHost = (raw: Url, host: Host): string =>
	host && lenientUserinfo(raw).toLowerCase().includes(host.toLowerCase())
		? redact(host)
		: host;

/** A dependency spec safe to show: URL specs lose credentials and query strings. */
export const displaySpec = (spec: SourceSpec): string =>
	spec.includes("://") ? displayUrl(spec) : truncate(spec, 120);

/** The host of a registry URL, or `undefined` when it does not parse. */
export const hostOf = (url: Url): Host | undefined =>
	parseUrl(url.startsWith("//") ? `https:${url}` : url)?.hostname.toLowerCase();

/** How well an integrity value protects the download. */
export type IntegrityStrength = "none" | "weak" | "strong";

const SRI = /^(sha1|sha256|sha384|sha512)-[A-Za-z0-9+/=_-]+$/i;

/**
 * Strength of an SRI string (`sha512-… sha1-…`). Values that are not a hash
 * count as none: package managers skip verification they cannot parse.
 */
export const integrityStrength = (
	integrity: Integrity | undefined,
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
const pythonHost = (url: Url): Host | undefined => {
	const authority = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(url)?.[1];
	if (authority === undefined) return undefined;
	const host = authority.slice(authority.lastIndexOf("@") + 1);
	const end = host.startsWith("[") ? host.indexOf("]") + 1 : host.indexOf(":");
	return (end > 0 ? host.slice(0, end) : host).toLowerCase();
};

/** A PyPI URL by both WHATWG's and Python's reading; one they disagree on is not. */
export const onPypi = (url: Url): boolean => {
	const host = hostOf(url);
	return host !== undefined && PYPI_HOSTS.has(host) && pythonHost(url) === host;
};

export const isInsecureUrl = (s: Url) => {
	const l = s.toLowerCase();
	return (
		l.startsWith("http://") ||
		l.startsWith("git://") ||
		l.startsWith("svn://") ||
		/^[a-z]+\+http:\/\//.test(l)
	);
};
