import {
	defineAuditor,
	type FindingInput,
	requireWorkspace,
	type Severity,
	severityRank,
	skip,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import {
	baseName,
	cweUrl,
	isFixturePath,
	isRecord,
	lineLocator,
	owaspUrl,
	parseJsonc,
	type SourceFile,
	truncate,
} from "./util";

/*
 * Lockfile integrity and install-time risk, in the spirit of lockfile-lint and
 * Socket's install-script signal. Everything is read offline from lockfiles
 * and package-manager configs; nothing is installed or executed.
 *
 * Every file read here is controlled by whoever controls the target, configs
 * included. A config can explain a finding (a private registry, an allow-list
 * for install scripts) but never makes it disappear: settings are only
 * honoured where the package manager itself reads and enforces them, and what
 * they allow is still reported.
 */

export const LOCKFILES_ID = "code.lockfiles";

/**
 * Per-entry findings of one rule per file; the rest are summarised in one
 * more finding of the same rule. Every entry is still checked.
 */
export const MAX_FINDINGS_PER_RULE = 100;
/** Lockfiles above this size are reported as unchecked. */
const MAX_LOCKFILE_BYTES = 20 * 1024 * 1024;
/** Text searches for a location per file; later findings get no line. */
const MAX_LINE_SEARCHES = 50;

/** Hosts every JavaScript package manager treats as the public registry. */
const DEFAULT_REGISTRY_HOSTS = new Set([
	"registry.npmjs.org",
	"registry.yarnpkg.com",
	"npm.pkg.github.com",
]);

/** Default download hosts of pnpm `runtime:` dependencies (Node.js, Bun, Deno). */
const RUNTIME_HOSTS = new Set(["nodejs.org", "github.com", "dl.deno.land"]);

/** Hosts of the Python Package Index. */
const PYPI_HOSTS = new Set(["pypi.org", "files.pythonhosted.org"]);

/** Git hosts whose repositories have a known owner namespace. */
const KNOWN_GIT_HOSTS = new Set([
	"github.com",
	"codeload.github.com",
	"gist.github.com",
	"gitlab.com",
	"bitbucket.org",
]);

/* -------------------------------------------------------------------------- */
/*                                  Sources                                   */
/* -------------------------------------------------------------------------- */

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
const gitHost = (spec: string): string => {
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
	if (lower.startsWith("http://") || lower.startsWith("https://")) {
		const insecure = lower.startsWith("http://");
		let url: URL;
		try {
			url = new URL(s);
		} catch {
			return UNKNOWN;
		}
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
 * Whether `path`, relative to the repository directory `base` (`""` for the
 * root), points outside the repository.
 */
export const escapesRoot = (base: string, path: string): boolean => {
	const p = path.replace(/\\/g, "/");
	if (p.startsWith("/") || p.startsWith("~") || /^[a-z]:/i.test(p)) return true;
	let depth = base.split("/").filter((s) => s && s !== ".").length;
	for (const seg of p.split("/")) {
		if (seg === "..") {
			depth--;
			if (depth < 0) return true;
		} else if (seg && seg !== ".") depth++;
	}
	return false;
};

const dirOf = (path: string) => {
	const i = path.lastIndexOf("/");
	return i === -1 ? "" : path.slice(0, i);
};

const joinDir = (a: string, b: string) =>
	[a, b].filter((s) => s && s !== ".").join("/");

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

/** The host of a registry URL, or `undefined` when it does not parse. */
const hostOf = (url: string): string | undefined => {
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

/* -------------------------------------------------------------------------- */
/*                                  Parsing                                   */
/* -------------------------------------------------------------------------- */

export type Manager = "npm" | "bun" | "pnpm" | "yarn" | "yarn-berry";

export interface LockedPackage {
	readonly name: string;
	readonly version?: string;
	/** Where it is fetched from; `undefined` for the configured registry. */
	readonly source?: string;
	/** Directory a relative path source is relative to (lockfile-relative). */
	readonly base?: string;
	readonly integrity?: string;
	readonly installScript?: boolean;
	/** Shipped inside its parent's tarball (npm `inBundle`). */
	readonly bundled?: boolean;
	/** A Node.js/Bun/Deno runtime download (pnpm `runtime:` dependencies). */
	readonly runtime?: boolean;
	readonly line?: number;
}

/** Dependency name → specs the lockfile accepts (`undefined`: any spec). */
type Importer = Map<string, ReadonlyArray<string> | undefined>;

export interface Lockfile {
	readonly path: string;
	readonly manager: Manager;
	readonly packages: ReadonlyArray<LockedPackage>;
	/** Recorded dependencies per workspace directory, relative to the lockfile. */
	readonly importers: ReadonlyMap<string, Importer>;
	/** The format marks packages that run install scripts. */
	readonly recordsInstallScripts: boolean;
	/** bun.lock `trustedDependencies`. */
	readonly trusted?: ReadonlyArray<string>;
}

const str = (v: unknown): string | undefined =>
	typeof v === "string" ? v : undefined;

/** A YAML or Yarn scalar as text (js-yaml's FAILSAFE schema keeps every scalar a string). */
const scalar = (v: unknown): string | undefined =>
	typeof v === "string" || typeof v === "number" || typeof v === "boolean"
		? String(v)
		: undefined;

const strings = (v: unknown): string[] =>
	Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];

/** Every package manager here ignores a leading byte-order mark. */
const stripBom = (text: string) =>
	text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;

const parseJson = (text: string): unknown => {
	const t = stripBom(text);
	try {
		return JSON.parse(t);
	} catch {
		return parseJsonc(t);
	}
};

/** Strips quotes; double-quoted strings are JSON-decoded like Yarn does. */
const unquote = (s: string) => {
	if (s.length < 2) return s;
	if (s[0] === '"' && s.endsWith('"')) {
		try {
			const v: unknown = JSON.parse(s);
			if (typeof v === "string") return v;
		} catch {
			// Not valid JSON: fall back to the raw contents.
		}
		return s.slice(1, -1);
	}
	return s[0] === "'" && s.endsWith("'") ? s.slice(1, -1) : s;
};

const DEP_FIELDS = [
	"dependencies",
	"devDependencies",
	"optionalDependencies",
] as const;

/** `dependencies` + `devDependencies` + `optionalDependencies` specs. */
const declaredSpecs = (pkg: Record<string, unknown>): Importer => {
	const out: Importer = new Map();
	for (const field of DEP_FIELDS) {
		const deps = pkg[field];
		if (!isRecord(deps)) continue;
		for (const [name, spec] of Object.entries(deps))
			if (typeof spec === "string") out.set(name, [spec]);
	}
	return out;
};

/**
 * 1-based lines of `"key":` lines after the top-level `"section"` key (first
 * occurrence wins). Linear: no regex backtracking. Minified files get none.
 */
const jsonKeyLines = (text: string, section: string): Map<string, number> => {
	const out = new Map<string, number>();
	const lines = text.split("\n");
	let started = false;
	for (let i = 0; i < lines.length; i++) {
		const line = lines[i] ?? "";
		const t = line.trimStart();
		if (!started) {
			started =
				line.length - t.length === 2 &&
				(t[0] === '"' || t[0] === "'") &&
				t.startsWith(`${section}${t[0]}`, 1);
			continue;
		}
		const quote = t[0];
		if (quote !== '"' && quote !== "'") continue;
		let end = 1;
		while (end < t.length && t[end] !== quote) end += t[end] === "\\" ? 2 : 1;
		if (t[end + 1] !== ":") continue;
		const key = unquote(t.slice(0, end + 1));
		if (!out.has(key)) out.set(key, i + 1);
	}
	return out;
};

/**
 * npm package-lock.json / npm-shrinkwrap.json, v1 to v3. A v2 lockfile has
 * both `packages` (npm 7+) and `dependencies` (npm 6); both are checked.
 */
export const parseNpmLock = (file: SourceFile): Lockfile | undefined => {
	const json = parseJson(file.text);
	if (!isRecord(json)) return undefined;
	const packages: LockedPackage[] = [];
	const importers = new Map<string, Importer>();
	if (isRecord(json.packages)) {
		const lines = jsonKeyLines(file.text, "packages");
		for (const [key, value] of Object.entries(json.packages)) {
			if (!isRecord(value)) continue;
			const line = lines.get(key);
			const nm = key.lastIndexOf("node_modules/");
			if (nm === -1) {
				// The root, a workspace or a `file:` directory dependency.
				importers.set(key, declaredSpecs(value));
				if (key)
					packages.push({
						name: str(value.name) ?? baseName(key),
						source: `file:${key}`,
						line,
					});
				continue;
			}
			const name = str(value.name) ?? key.slice(nm + "node_modules/".length);
			if (value.link) {
				packages.push({
					name,
					source: `file:${str(value.resolved) ?? ""}`,
					line,
				});
				continue;
			}
			packages.push({
				name,
				version: str(value.version),
				source: str(value.resolved),
				integrity: str(value.integrity),
				installScript: value.hasInstallScript === true,
				bundled: value.inBundle === true,
				line,
			});
		}
	}
	if (isRecord(json.dependencies)) {
		const lines = jsonKeyLines(file.text, "dependencies");
		const visit = (deps: Record<string, unknown>, depth: number) => {
			if (depth > 64) return;
			for (const [name, value] of Object.entries(deps)) {
				if (!isRecord(value)) continue;
				const version = str(value.version);
				// v1 records git and file dependencies in `version`.
				const spec = version && !/^\d/.test(version) ? version : undefined;
				packages.push({
					name,
					version: spec ? undefined : version,
					source: str(value.resolved) ?? spec,
					integrity: str(value.integrity),
					bundled: value.bundled === true,
					line: lines.get(name),
				});
				if (isRecord(value.dependencies)) visit(value.dependencies, depth + 1);
			}
		};
		visit(json.dependencies, 0);
	}
	return {
		path: file.path,
		manager: "npm",
		packages,
		importers,
		recordsInstallScripts: isRecord(json.packages),
	};
};

/** bun.lock (JSONC): `"key": ["name@spec", registry?, info, integrity?]`. */
export const parseBunLock = (file: SourceFile): Lockfile | undefined => {
	let json: unknown;
	try {
		// Bun's own parser: comments, trailing commas, single quotes and a BOM.
		json = Bun.JSONC.parse(file.text);
	} catch {
		return undefined;
	}
	if (!isRecord(json) || !isRecord(json.packages)) return undefined;
	const lines = jsonKeyLines(file.text, "packages");
	const packages: LockedPackage[] = [];
	for (const [key, value] of Object.entries(json.packages)) {
		if (!Array.isArray(value) || typeof value[0] !== "string") continue;
		const ident = value[0];
		const at = ident.indexOf("@", 1);
		if (at === -1) continue;
		const name = ident.slice(0, at);
		const spec = ident.slice(at + 1);
		const registryVersion = /^\d/.test(spec);
		packages.push({
			name,
			...(registryVersion ? { version: spec } : {}),
			// Registry entries carry the tarball URL ("" for registry.npmjs.org).
			source: registryVersion ? str(value[1]) || undefined : spec,
			integrity: str(value[value.length - 1]),
			line: lines.get(key),
		});
	}
	const importers = new Map<string, Importer>();
	if (isRecord(json.workspaces))
		for (const [dir, ws] of Object.entries(json.workspaces))
			if (isRecord(ws)) importers.set(dir, declaredSpecs(ws));
	return {
		path: file.path,
		manager: "bun",
		packages,
		importers,
		recordsInstallScripts: false,
		trusted: strings(json.trustedDependencies),
	};
};

/** `name` from a pnpm package key (v5 `/a/1.0.0`, v6 `/a@1.0.0`, v9 `a@1.0.0`). */
const pnpmName = (key: string): string => {
	const k = key.startsWith("/") ? key.slice(1) : key;
	const at = k.indexOf("@", 1);
	if (at > 0) return k.slice(0, at);
	const parts = k.split("/");
	return k.startsWith("@") ? parts.slice(0, 2).join("/") : (parts[0] ?? k);
};

/**
 * Lines of block-style `key:` lines: the first indentation level under the
 * top-level `section`, or top-level keys when `section` is undefined.
 */
const yamlKeyLines = (
	text: string,
	section: string | undefined,
): Map<string, number> => {
	const out = new Map<string, number>();
	const lines = text.split("\n");
	let current = "";
	let keyIndent = -1;
	for (let i = 0; i < lines.length; i++) {
		const line = (lines[i] ?? "").trimEnd();
		const t = line.trimStart();
		if (!t || t.startsWith("#")) continue;
		const indent = line.length - t.length;
		if (section !== undefined) {
			if (indent === 0) {
				current = line;
				keyIndent = -1;
				continue;
			}
			if (current !== `${section}:`) continue;
			if (keyIndent === -1) keyIndent = indent;
		} else keyIndent = 0;
		if (indent !== keyIndent || !t.endsWith(":")) continue;
		const key = unquote(t.slice(0, -1));
		if (!out.has(key)) out.set(key, i + 1);
	}
	return out;
};

/** Shifts entry lines, for documents parsed out of a larger file. */
const shiftLines = (
	lock: Lockfile,
	map: (line: number) => number,
): Lockfile => ({
	...lock,
	packages: lock.packages.map((p) =>
		p.line === undefined ? p : { ...p, line: map(p.line) },
	),
});

/** One lockfile from several parses of the same file (documents, conflict sides). */
const mergeLockfiles = (
	locks: ReadonlyArray<Lockfile>,
): Lockfile | undefined => {
	const [first] = locks;
	if (!first || locks.length === 1) return first;
	const importers = new Map<string, Importer>();
	for (const lock of locks)
		for (const [dir, importer] of lock.importers) {
			const into: Importer = importers.get(dir) ?? new Map();
			for (const [name, specs] of importer) {
				const prev = into.get(name);
				into.set(
					name,
					!into.has(name)
						? specs
						: prev === undefined || specs === undefined
							? undefined
							: [...prev, ...specs],
				);
			}
			importers.set(dir, into);
		}
	return {
		path: first.path,
		manager: locks.some((l) => l.manager === "yarn-berry")
			? "yarn-berry"
			: first.manager,
		packages: locks.flatMap((l) => l.packages),
		importers,
		recordsInstallScripts: locks.some((l) => l.recordsInstallScripts),
		trusted: [...new Set(locks.flatMap((l) => l.trusted ?? []))],
	};
};

interface ConflictSide {
	readonly text: string;
	/** Line in the file of each line of `text`. */
	readonly lines: ReadonlyArray<number>;
}

/**
 * Both sides of git merge conflicts in a lockfile. npm (parse-conflict-json),
 * pnpm and Yarn resolve a conflicted lockfile by reading both sides and
 * merging them, so code.lockfiles checks both.
 */
export const conflictSides = (text: string): ConflictSide[] => {
	if (
		!text.includes("<<<<<<<") ||
		!text.includes("=======") ||
		!text.includes(">>>>>>>")
	)
		return [];
	const ours: string[] = [];
	const theirs: string[] = [];
	const oursLines: number[] = [];
	const theirsLines: number[] = [];
	let state: "top" | "ours" | "parent" | "theirs" = "top";
	text.split(/\r\n|\r|\n/).forEach((line, i) => {
		if (line.startsWith("<<<<<<<")) state = "ours";
		else if (line.startsWith("|||||||")) state = "parent";
		else if (line === "=======") state = "theirs";
		else if (line.startsWith(">>>>>>>")) state = "top";
		else {
			if (state === "top" || state === "ours") {
				ours.push(line);
				oursLines.push(i + 1);
			}
			if (state === "top" || state === "theirs") {
				theirs.push(line);
				theirsLines.push(i + 1);
			}
		}
	});
	return [
		{ text: ours.join("\n"), lines: oursLines },
		{ text: theirs.join("\n"), lines: theirsLines },
	];
};

/**
 * One YAML document, parsed with Bun's YAML parser: it applies `<<` merge
 * keys like pnpm's js-yaml and lets a repeated key override the earlier one
 * like Yarn 2+ (js-yaml with `json: true`), and it is fast on large lockfiles.
 * Values that js-yaml's FAILSAFE schema keeps as strings (Yarn) may come back
 * as numbers or booleans, so callers compare them as strings. A stream of
 * several documents is an error, as it is for js-yaml's `load`.
 */
const parseYaml = (text: string): unknown => {
	const doc: unknown = Bun.YAML.parse(text);
	if (Array.isArray(doc) && /^---|\n---/.test(text))
		throw new Error("Expected a single YAML document");
	return doc;
};

/** pnpm's `removeSuffix`: `a@1.0.0(peer@2.0.0)` → `a@1.0.0`. */
const withoutPeerSuffix = (depPath: string) => {
	if (!depPath.endsWith(")")) return depPath;
	const i = depPath.indexOf("(", 1);
	return i === -1 ? depPath : depPath.slice(0, i);
};

interface Fetch {
	readonly source?: string;
	readonly integrity?: string;
	readonly runtime?: boolean;
}

/**
 * What a pnpm `resolution` downloads: a registry or tarball URL, a git commit,
 * a directory, or one archive per platform of a `runtime:` dependency.
 * Unknown shapes become an unknown source, which is reported.
 */
const pnpmFetches = (res: unknown, depth = 0): Fetch[] => {
	if (!isRecord(res)) return [{}];
	const integrity = str(res.integrity);
	switch (res.type) {
		case undefined:
			return [
				{
					source:
						typeof res.directory === "string"
							? `file:${res.directory}`
							: str(res.tarball),
					integrity,
				},
			];
		case "directory":
			return [{ source: `file:${str(res.directory) ?? ""}` }];
		case "git":
			return [
				{ source: `git+${str(res.repo) ?? ""}#${str(res.commit) ?? ""}` },
			];
		case "binary":
			return [{ source: str(res.url) ?? "binary:", integrity, runtime: true }];
		case "variations":
			if (depth > 2 || !Array.isArray(res.variants))
				return [{ source: "variations:" }];
			return res.variants.flatMap((v) =>
				pnpmFetches(isRecord(v) ? v.resolution : undefined, depth + 1).map(
					(f) => ({ ...f, runtime: true }),
				),
			);
		default:
			return [{ source: `${String(res.type)}:`, integrity }];
	}
};

/** One YAML document of a pnpm lockfile. */
const parsePnpmDocument = (file: SourceFile): Lockfile | undefined => {
	let doc: unknown;
	try {
		doc = parseYaml(file.text);
	} catch {
		return undefined;
	}
	if (!isRecord(doc)) return undefined;
	const major = Number.parseInt(String(doc.lockfileVersion ?? "0"), 10);
	const packages: LockedPackage[] = [];
	const importers = new Map<string, Importer>();
	const rawImporters = isRecord(doc.importers) ? doc.importers : { ".": doc };
	const lineOf = lineFinder(file.text);
	// pnpm records an overridden dependency with the override as its specifier.
	const overridden = new Set(
		Object.keys(isRecord(doc.overrides) ? doc.overrides : {})
			.filter((k) => !k.includes(">"))
			.map(pnpmName),
	);
	for (const [rawDir, importer] of Object.entries(rawImporters)) {
		if (!isRecord(importer)) continue;
		const dir = rawDir === "." ? "" : rawDir;
		const specifiers = isRecord(importer.specifiers) ? importer.specifiers : {};
		const recorded: Importer = new Map();
		for (const field of DEP_FIELDS) {
			const deps = importer[field];
			if (!isRecord(deps)) continue;
			for (const [name, value] of Object.entries(deps)) {
				const spec = isRecord(value)
					? str(value.specifier)
					: str(specifiers[name]);
				const version = isRecord(value) ? str(value.version) : str(value);
				recorded.set(
					name,
					spec === undefined || overridden.has(name) ? undefined : [spec],
				);
				if (version?.startsWith("link:") || version?.startsWith("file:"))
					packages.push({
						name,
						source: version,
						base: dir,
						line: lineOf(version),
					});
			}
		}
		if (recorded.size || isRecord(doc.importers)) importers.set(dir, recorded);
	}
	const add = (key: string, value: Record<string, unknown>, line?: number) => {
		const name = str(value.name) ?? pnpmName(key);
		const at = key.lastIndexOf("@");
		const keyVersion = at > 0 ? key.slice(at + 1).split("(")[0] : undefined;
		const version =
			str(value.version) ??
			(keyVersion && /^\d/.test(keyVersion) ? keyVersion : undefined);
		for (const f of pnpmFetches(value.resolution))
			packages.push({
				name,
				version,
				source: f.source,
				integrity: f.integrity,
				...(f.runtime ? { runtime: true } : {}),
				installScript: value.requiresBuild === true,
				line: line ?? lineOf(key),
			});
	};
	const declared = isRecord(doc.packages) ? doc.packages : {};
	const packageLines = yamlKeyLines(file.text, "packages");
	for (const [key, value] of Object.entries(declared))
		if (isRecord(value)) add(key, value, packageLines.get(key));
	// v9 lockfiles install what `snapshots` lists; pnpm fills each snapshot in
	// from `packages`, so a snapshot without a package (or a package without a
	// resolution) brings its own fields.
	if (isRecord(doc.snapshots)) {
		const snapshotLines = yamlKeyLines(file.text, "snapshots");
		for (const [key, snapshot] of Object.entries(doc.snapshots)) {
			if (!isRecord(snapshot)) continue;
			const id = withoutPeerSuffix(key);
			const pkg = declared[id];
			if (isRecord(pkg) && pkg.resolution !== undefined) continue;
			add(
				id,
				{ ...snapshot, ...(isRecord(pkg) ? pkg : {}) },
				snapshotLines.get(key),
			);
		}
	}
	return {
		path: file.path,
		manager: "pnpm",
		packages,
		importers,
		recordsInstallScripts: major > 0 && major < 9,
	};
};

/**
 * pnpm-lock.yaml v5, v6 and v9. pnpm 10 may put an env lockfile document
 * first (`---\n<env>\n---\n<main>`); both are installed, so both are checked.
 */
export const parsePnpmLock = (file: SourceFile): Lockfile | undefined => {
	const text = file.text;
	const sep = text.startsWith("---\n") ? text.indexOf("\n---\n", 4) : -1;
	if (sep === -1) return parsePnpmDocument(file);
	const mainStart = sep + "\n---\n".length;
	const offset = text.slice(0, mainStart).split("\n").length - 1;
	const env = parsePnpmDocument({ path: file.path, text: text.slice(4, sep) });
	const main = parsePnpmDocument({
		path: file.path,
		text: text.slice(mainStart),
	});
	if (!env || !main) return undefined;
	return mergeLockfiles([
		shiftLines(env, (l) => l + 1),
		shiftLines(main, (l) => l + offset),
	]);
};

const nameOfSpec = (spec: string) => {
	const at = spec.indexOf("@", 1);
	return at === -1 ? spec : spec.slice(0, at);
};

/** Workspace directory from Berry's `::locator=name%40workspace%3Adir`. */
const berryLocatorDir = (params: string): string => {
	for (const pair of params.split("&")) {
		if (!pair.startsWith("locator=")) continue;
		let locator: string;
		try {
			locator = decodeURIComponent(pair.slice("locator=".length));
		} catch {
			return "";
		}
		const i = locator.indexOf("@workspace:");
		return i === -1 ? "" : locator.slice(i + "@workspace:".length);
	}
	return "";
};

/* --------------------------- Classic yarn.lock ---------------------------- */

/*
 * A port of Yarn 1's lockfile parser (src/lockfile/parse.js), so that what is
 * checked is exactly what Yarn reads: comments run to the next \n, a lone \r
 * is a newline but does not start an indent, only even runs of spaces indent,
 * quoted strings are JSON, and a repeated key overrides the earlier one.
 */

type YarnToken =
	| {
			readonly type:
				| "newline"
				| "colon"
				| "comma"
				| "comment"
				| "eof"
				| "invalid";
			readonly line: number;
	  }
	| { readonly type: "indent"; readonly value: number; readonly line: number }
	| {
			readonly type: "string" | "number" | "boolean";
			readonly value: string | number | boolean;
			readonly line: number;
	  };

class YarnLexer {
	private i = 0;
	private line = 1;
	private lastNewline = false;
	constructor(private readonly s: string) {}

	next(): YarnToken {
		const s = this.s;
		for (;;) {
			const i = this.i;
			if (i >= s.length) return { type: "eof", line: this.line };
			const c = s[i] as string;
			const line = this.line;
			let chop = 1;
			let token: YarnToken | undefined;
			if (c === "\n" || c === "\r") {
				if (c === "\r" && s[i + 1] === "\n") chop = 2;
				this.line++;
				token = { type: "newline", line };
			} else if (c === "#") {
				const nl = s.indexOf("\n", i + 1);
				chop = (nl === -1 ? s.length : nl) - i;
				token = { type: "comment", line };
			} else if (c === " ") {
				if (this.lastNewline) {
					let n = 1;
					while (s[i + n] === " ") n++;
					if (n % 2) throw new Error("Invalid number of spaces");
					chop = n;
					token = { type: "indent", value: n / 2, line };
				}
			} else if (c === '"') {
				let j = i + 1;
				for (; j < s.length; j++)
					if (s[j] === '"' && !(s[j - 1] === "\\" && s[j - 2] !== "\\")) {
						j++;
						break;
					}
				chop = j - i;
				try {
					token = { type: "string", value: JSON.parse(s.slice(i, j)), line };
				} catch {
					token = { type: "invalid", line };
				}
			} else if (c >= "0" && c <= "9") {
				let j = i;
				while (
					s[j] !== undefined &&
					(s[j] as string) >= "0" &&
					(s[j] as string) <= "9"
				)
					j++;
				chop = j - i;
				token = { type: "number", value: Number(s.slice(i, j)), line };
			} else if (s.startsWith("true", i)) {
				chop = 4;
				token = { type: "boolean", value: true, line };
			} else if (s.startsWith("false", i)) {
				chop = 5;
				token = { type: "boolean", value: false, line };
			} else if (c === ":") token = { type: "colon", line };
			else if (c === ",") token = { type: "comma", line };
			else if (/[a-zA-Z/.-]/.test(c)) {
				let j = i;
				for (; j < s.length; j++) {
					const ch = s[j];
					if (
						ch === ":" ||
						ch === " " ||
						ch === "\n" ||
						ch === "\r" ||
						ch === ","
					)
						break;
				}
				chop = j - i;
				token = { type: "string", value: s.slice(i, j), line };
			} else token = { type: "invalid", line };
			this.lastNewline = c === "\n" || (c === "\r" && s[i + 1] === "\n");
			this.i += chop;
			if (token) return token;
		}
	}
}

/** Yarn 1's grammar; throws where Yarn throws. Records top-level key lines. */
const yarnGrammar = (
	text: string,
): {
	readonly obj: Record<string, unknown>;
	readonly lines: Map<string, number>;
} => {
	const lexer = new YarnLexer(text);
	const lines = new Map<string, number>();
	let token = lexer.next();
	const next = () => {
		token = lexer.next();
		return token;
	};
	const parse = (indent: number): Record<string, unknown> => {
		const obj: Record<string, unknown> = Object.create(null);
		for (;;) {
			const t = token;
			if (t.type === "newline") {
				const n = next();
				if (!indent) continue;
				if (n.type !== "indent") break;
				if (n.value === indent) next();
				else break;
			} else if (t.type === "indent") {
				if (t.value === indent) next();
				else break;
			} else if (t.type === "eof") break;
			else if (t.type === "string") {
				if (!t.value) throw new Error("Expected a key");
				const keys = [String(t.value)];
				next();
				while (token.type === "comma") {
					const k = next();
					if (k.type !== "string") throw new Error("Expected string");
					keys.push(String(k.value));
					next();
				}
				const wasColon = token.type === "colon";
				if (wasColon) next();
				const v = token;
				const plain =
					v.type === "string" || v.type === "number" || v.type === "boolean";
				if (!plain && !wasColon) throw new Error("Invalid value type");
				let value: unknown;
				if (plain) {
					value = v.value;
					next();
				} else value = parse(indent + 1);
				for (const k of keys) {
					obj[k] = value;
					if (!indent) lines.set(k, t.line);
				}
				if (!plain && indent && token.type !== "indent") break;
			} else if (t.type === "comment") next();
			else throw new Error("Unknown token");
		}
		return obj;
	};
	return { obj: parse(0), lines };
};

/** Yarn 1 reads lockfiles and .yarnrc with its grammar, falling back to YAML. */
const parseYarnClassic = (
	text: string,
):
	| {
			readonly obj: Record<string, unknown>;
			readonly lines: Map<string, number>;
	  }
	| undefined => {
	try {
		return yarnGrammar(text);
	} catch {
		// Yarn 1 retries with js-yaml (FAILSAFE schema).
	}
	try {
		const doc: unknown = parseYaml(text);
		if (isRecord(doc))
			return { obj: doc, lines: yamlKeyLines(text, undefined) };
	} catch {
		// Neither parses: Yarn 1 cannot read it either.
	}
	return undefined;
};

/** Yarn 2+ treats files with this header as classic lockfiles. */
const YARN_V1_HEADER = /^(#.*(\r?\n))*?#\s+yarn\s+lockfile\s+v1\r?\n/i;

/**
 * yarn.lock, read the way both Yarn 1 (its grammar, then YAML) and Yarn 2+
 * (YAML unless the file has the classic header) read it. Which Yarn installs
 * is not known, so entries from either reading are checked: Berry's
 * `resolution`/`checksum` and Yarn 1's `resolved`/`integrity`.
 */
export const parseYarnLock = (file: SourceFile): Lockfile | undefined => {
	const text = file.text;
	const docs: Array<{
		readonly obj: Record<string, unknown>;
		readonly lines: Map<string, number>;
	}> = [];
	let classic: ReturnType<typeof parseYarnClassic>;
	try {
		classic = yarnGrammar(text);
		docs.push(classic);
	} catch {
		classic = undefined;
	}
	if (!YARN_V1_HEADER.test(text))
		try {
			const doc: unknown = parseYaml(text);
			if (isRecord(doc))
				docs.push({ obj: doc, lines: yamlKeyLines(text, undefined) });
		} catch {
			// Not YAML: Yarn 2+ cannot read it either.
		}
	if (!docs.length) {
		classic = parseYarnClassic(text);
		if (classic) docs.push(classic);
	}
	if (!docs.length) return undefined;

	const lineOf = lineFinder(text);
	const packages: LockedPackage[] = [];
	const workspaces = new Map<string, Importer>();
	const rootSpecs: Importer = new Map();
	let berry = false;
	for (const { obj, lines } of docs) {
		if (isRecord(obj.__metadata)) berry = true;
		for (const [key, value] of Object.entries(obj)) {
			if (key === "__metadata" || !isRecord(value)) continue;
			const line = lines.get(key) ?? lineOf(key);
			const resolution = scalar(value.resolution);
			if (resolution !== undefined) {
				const name = nameOfSpec(resolution);
				const spec = resolution.slice(name.length + 1);
				if (spec.startsWith("workspace:")) {
					const dir = spec.slice("workspace:".length);
					const deps = isRecord(value.dependencies) ? value.dependencies : {};
					workspaces.set(
						dir === "." ? "" : dir,
						new Map(Object.keys(deps).map((n) => [n, undefined])),
					);
				} else {
					const params = spec.indexOf("::");
					const bare = params === -1 ? spec : spec.slice(0, params);
					const isPath = /^(file|link|portal):/.test(bare);
					const checksum = scalar(value.checksum);
					packages.push({
						name,
						version: scalar(value.version),
						source: isPath ? bare.split("#")[0] : bare,
						...(isPath && params !== -1
							? { base: berryLocatorDir(spec.slice(params + 2)) }
							: {}),
						// Berry checksums are SHA-512 digests of the package archive.
						integrity: checksum ? `sha512-${checksum}` : undefined,
						line,
					});
				}
			}
			if (resolution !== undefined && value.resolved === undefined) continue;
			// Yarn 1's reading of the entry.
			const first = key.split(",")[0]?.trim() ?? key;
			const name = nameOfSpec(first);
			if (obj === classic?.obj)
				rootSpecs.set(name, [
					...(rootSpecs.get(name) ?? []),
					first.slice(name.length + 1),
				]);
			const declared = first.slice(name.length + 1);
			let resolved = scalar(value.resolved);
			let integrity = scalar(value.integrity);
			const source = classifySource(resolved);
			const hash = resolved?.indexOf("#") ?? -1;
			const sha1 = resolved && hash !== -1 ? resolved.slice(hash + 1) : "";
			// Classic yarn appends the archive's SHA-1 to registry, tarball and
			// codeload URLs; for those the fragment is a checksum, not a git ref.
			const archive =
				source.kind === "tarball" ||
				(source.kind === "git" && /^https?:/i.test(resolved ?? ""));
			if (resolved && archive && /^[0-9a-f]{40}$/i.test(sha1)) {
				resolved = resolved.slice(0, hash);
				integrity ??= `sha1-${sha1}`;
			}
			packages.push({
				name,
				version:
					value.version === undefined ? undefined : String(value.version),
				source:
					resolved ?? (/^(file|link):/.test(declared) ? declared : undefined),
				integrity,
				line,
			});
		}
	}
	return {
		path: file.path,
		manager: berry ? "yarn-berry" : "yarn",
		packages,
		importers: berry ? workspaces : new Map([["", rootSpecs]]),
		recordsInstallScripts: false,
	};
};

const LOCKFILE_PARSERS: Readonly<
	Record<string, (file: SourceFile) => Lockfile | undefined>
> = {
	"package-lock.json": parseNpmLock,
	"npm-shrinkwrap.json": parseNpmLock,
	"bun.lock": parseBunLock,
	"pnpm-lock.yaml": parsePnpmLock,
	"yarn.lock": parseYarnLock,
};

/* -------------------------------------------------------------------------- */
/*                         Package-manager configuration                      */
/* -------------------------------------------------------------------------- */

/** A setting found in a config file, with where it was found. */
interface Setting {
	readonly file: string;
	readonly line?: number;
	readonly evidence: string;
}

interface Registry extends Setting {
	readonly url: string;
	/** `@scope` for a scoped registry. */
	readonly scope?: string;
}

/** What one package-manager config file declares. */
export interface FileConfig {
	readonly file: string;
	readonly registries: Registry[];
	ignoreScripts?: Setting;
	strictSslOff?: Setting;
	/** pnpm `onlyBuiltDependencies` (allow-list). */
	onlyBuilt?: string[];
	/** pnpm `neverBuiltDependencies` (deny-list). */
	neverBuilt?: string[];
	/** pnpm `dangerouslyAllowAllBuilds`, or a wildcard in its allow-list. */
	allowAllBuilds?: Setting;
	/** package.json `trustedDependencies` (Bun's allow-list). */
	trusted?: string[];
}

/**
 * Config files each package manager reads for the project whose lockfile is
 * in a directory: `here` only in that directory, `inherited` also in its
 * parents. Settings in other files do not affect that install.
 */
const MANAGER_CONFIGS: Readonly<
	Record<
		Manager,
		{
			readonly here: ReadonlyArray<string>;
			readonly inherited: ReadonlyArray<string>;
		}
	>
> = {
	npm: { here: [".npmrc", "package.json"], inherited: [] },
	pnpm: {
		here: [".npmrc", "pnpm-workspace.yaml", "package.json"],
		inherited: [],
	},
	bun: { here: ["bunfig.toml", ".npmrc", "package.json"], inherited: [] },
	yarn: { here: [], inherited: [".yarnrc", ".npmrc"] },
	"yarn-berry": { here: [], inherited: [".yarnrc.yml"] },
};

/** The line of the first occurrence of `needle`, within a search budget. */
const lineFinder = (text: string) => {
	let budget = MAX_LINE_SEARCHES;
	let locate: ((i: number) => number) | undefined;
	return (needle: string): number | undefined => {
		if (budget <= 0 || !needle) return undefined;
		budget--;
		const i = text.indexOf(needle);
		if (i === -1) return undefined;
		locate ??= lineLocator(text);
		return locate(i);
	};
};

const scopeOf = (key: string) => {
	const scope = key.startsWith("@") ? key : `@${key}`;
	return scope.length > 1 ? scope : undefined;
};

/** A value as the `ini` package (npm's .npmrc parser) unescapes it. */
const iniValue = (raw: string): unknown => {
	let val = raw.trim();
	const quoted =
		val.length > 1 &&
		((val[0] === '"' && val.endsWith('"')) ||
			(val[0] === "'" && val.endsWith("'")));
	if (quoted) {
		if (val[0] === "'") val = val.slice(1, -1);
		try {
			return JSON.parse(val);
		} catch {
			return val;
		}
	}
	let out = "";
	let escaped = false;
	for (const c of val) {
		if (escaped) {
			out += ";#".includes(c) ? c : `\\${c}`;
			escaped = false;
		} else if (c === ";" || c === "#") break;
		else if (c === "\\") escaped = true;
		else out += c;
	}
	if (escaped) out += "\\";
	return out.trim();
};

const INI_LINE = /^\[([^\]]*)\]\s*$|^([^=]+)(=(.*))?$/;

/**
 * `.npmrc`, read like npm's `ini` parser: `\r` and `\n` end lines, `;` and `#`
 * start comments (also after a value), keys after a `[section]` header are not
 * npm config, and the last value of a key wins.
 */
const readNpmrc = (file: SourceFile, config: FileConfig) => {
	const values = new Map<
		string,
		{ readonly value: unknown; readonly line: number; readonly raw: string }
	>();
	let inSection = false;
	stripBom(file.text)
		.split(/\r\n|\r|\n/)
		.forEach((line, i) => {
			if (/^\s*([;#]|$)/.test(line)) return;
			const m = INI_LINE.exec(line);
			if (!m) return;
			if (m[1] !== undefined) {
				inSection = true;
				return;
			}
			if (inSection) return;
			const key = String(iniValue(m[2] ?? ""));
			if (key.length > 2 && key.endsWith("[]")) return;
			const raw = m[3] ? iniValue(m[4] ?? "") : true;
			const value =
				raw === "true"
					? true
					: raw === "false"
						? false
						: raw === "null"
							? null
							: raw;
			values.set(key, { value, line: i + 1, raw: line.trim() });
		});
	for (const [key, { value, line, raw }] of values) {
		const at = { file: file.path, line };
		if (
			typeof value === "string" &&
			(key === "registry" || key.endsWith(":registry"))
		) {
			const scope =
				key === "registry"
					? undefined
					: scopeOf(key.slice(0, -":registry".length));
			config.registries.push({
				...at,
				url: value,
				...(scope ? { scope } : {}),
				evidence: `${key}=${displayUrl(value)}`,
			});
		} else if (key === "ignore-scripts" && value === true)
			config.ignoreScripts = { ...at, evidence: raw };
		else if (key === "strict-ssl" && value === false)
			config.strictSslOff = { ...at, evidence: raw };
	}
};

/** Classic `.yarnrc`, read with Yarn 1's lockfile grammar like Yarn does. */
const readYarnrc = (file: SourceFile, config: FileConfig) => {
	const parsed = parseYarnClassic(stripBom(file.text));
	if (!parsed) return;
	for (const [key, value] of Object.entries(parsed.obj)) {
		const at = { file: file.path, line: parsed.lines.get(key) };
		if (
			typeof value === "string" &&
			(key === "registry" || key.endsWith(":registry"))
		) {
			const scope =
				key === "registry"
					? undefined
					: scopeOf(key.slice(0, -":registry".length));
			config.registries.push({
				...at,
				url: value,
				...(scope ? { scope } : {}),
				evidence: `${key} ${displayUrl(value)}`,
			});
		} else if (key === "strict-ssl" && String(value) === "false")
			config.strictSslOff = { ...at, evidence: "strict-ssl false" };
	}
};

/** `.yarnrc.yml` (YAML as Yarn reads it): registries and `enableStrictSsl`. */
const readYarnrcYml = (file: SourceFile, config: FileConfig) => {
	let doc: unknown;
	try {
		doc = parseYaml(stripBom(file.text));
	} catch {
		return;
	}
	if (!isRecord(doc)) return;
	const lineOf = lineFinder(file.text);
	const registry = (value: unknown, scope?: string) => {
		if (typeof value !== "string") return;
		config.registries.push({
			file: file.path,
			line: lineOf(value),
			url: value,
			...(scope ? { scope } : {}),
			evidence: `${scope ? `npmScopes.${scope.slice(1)}.` : ""}npmRegistryServer: ${displayUrl(value)}`,
		});
	};
	registry(doc.npmRegistryServer);
	if (isRecord(doc.npmScopes))
		for (const [scope, value] of Object.entries(doc.npmScopes))
			if (isRecord(value)) registry(value.npmRegistryServer, scopeOf(scope));
	if (String(doc.enableStrictSsl) === "false")
		config.strictSslOff = {
			file: file.path,
			line: lineOf("enableStrictSsl"),
			evidence: "enableStrictSsl: false",
		};
};

/** bunfig.toml, parsed with Bun's TOML parser: `install.registry` and `install.scopes`. */
const readBunfig = (file: SourceFile, config: FileConfig) => {
	let doc: unknown;
	try {
		doc = Bun.TOML.parse(stripBom(file.text));
	} catch {
		return;
	}
	const install = isRecord(doc) && isRecord(doc.install) ? doc.install : {};
	const lineOf = lineFinder(file.text);
	const registry = (value: unknown, scope?: string) => {
		const url = isRecord(value) ? str(value.url) : str(value);
		if (!url || !/^(https?:)?\/\//i.test(url)) return;
		config.registries.push({
			file: file.path,
			line: lineOf(url),
			url,
			...(scope ? { scope } : {}),
			evidence: `${scope ?? "registry"} = ${displayUrl(url)}`,
		});
	};
	registry(install.registry);
	if (isRecord(install.scopes))
		for (const [scope, value] of Object.entries(install.scopes))
			registry(value, scopeOf(scope));
};

/** pnpm build settings, from pnpm-workspace.yaml or package.json `pnpm`. */
const readPnpmBuildSettings = (
	settings: Record<string, unknown>,
	file: SourceFile,
	config: FileConfig,
) => {
	const lineOf = lineFinder(file.text);
	if (Array.isArray(settings.onlyBuiltDependencies)) {
		config.onlyBuilt = strings(settings.onlyBuiltDependencies);
		// Treated as allowing everything, whether or not pnpm expands it.
		if (config.onlyBuilt.some((n) => n.includes("*")))
			config.allowAllBuilds = {
				file: file.path,
				line: lineOf("onlyBuiltDependencies"),
				evidence: `onlyBuiltDependencies: ${truncate(config.onlyBuilt.join(", "), 100)}`,
			};
	}
	if (Array.isArray(settings.neverBuiltDependencies))
		config.neverBuilt = strings(settings.neverBuiltDependencies);
	if (settings.dangerouslyAllowAllBuilds === true)
		config.allowAllBuilds = {
			file: file.path,
			line: lineOf("dangerouslyAllowAllBuilds"),
			evidence: "dangerouslyAllowAllBuilds: true",
		};
};

const readPnpmWorkspace = (file: SourceFile, config: FileConfig) => {
	let doc: unknown;
	try {
		doc = parseYaml(stripBom(file.text));
	} catch {
		return;
	}
	if (isRecord(doc)) readPnpmBuildSettings(doc, file, config);
};

/** package.json: `pnpm.*` build settings and Bun's `trustedDependencies`. */
const readPackageJson = (file: SourceFile, config: FileConfig) => {
	const json = parseJson(file.text);
	if (!isRecord(json)) return;
	if (isRecord(json.pnpm)) readPnpmBuildSettings(json.pnpm, file, config);
	if (Array.isArray(json.trustedDependencies))
		config.trusted = strings(json.trustedDependencies);
};

const CONFIG_READERS: Readonly<
	Record<string, (file: SourceFile, config: FileConfig) => void>
> = {
	".npmrc": readNpmrc,
	".yarnrc": readYarnrc,
	".yarnrc.yml": readYarnrcYml,
	"bunfig.toml": readBunfig,
	"pnpm-workspace.yaml": readPnpmWorkspace,
	"package.json": readPackageJson,
};

/** Configs the lockfile's package manager reads, nearest first. */
const configsFor = (
	configs: ReadonlyMap<string, FileConfig>,
	lock: Lockfile,
): FileConfig[] => {
	const { here, inherited } = MANAGER_CONFIGS[lock.manager];
	const out: FileConfig[] = [];
	const lockDir = dirOf(lock.path);
	let d = lockDir;
	for (;;) {
		for (const name of d === lockDir ? [...here, ...inherited] : inherited) {
			const c = configs.get(joinDir(d, name));
			if (c) out.push(c);
		}
		if (!d) return out;
		d = dirOf(d);
	}
};

const scopeOfPackage = (name: string) =>
	name.startsWith("@") ? name.slice(0, name.indexOf("/")) : undefined;

/** The registry a package manager would fetch `name` from, if configured. */
const registryFor = (
	configs: ReadonlyArray<FileConfig>,
	name: string,
): Registry | undefined => {
	const scope = scopeOfPackage(name);
	const all = configs.flatMap((c) => c.registries);
	return (
		(scope ? all.find((r) => r.scope === scope) : undefined) ??
		all.find((r) => r.scope === undefined)
	);
};

/* -------------------------------------------------------------------------- */
/*                                  Findings                                  */
/* -------------------------------------------------------------------------- */

const LOCKFILE_LINT = "https://github.com/lirantal/lockfile-lint";
const NPM_LOCKFILE =
	"https://docs.npmjs.com/cli/configuring-npm/package-lock-json";
const NPM_SCRIPTS = "https://docs.npmjs.com/cli/using-npm/scripts";
const NPM_IGNORE_SCRIPTS =
	"https://docs.npmjs.com/cli/using-npm/config#ignore-scripts";
const NPM_REGISTRY = "https://docs.npmjs.com/cli/using-npm/registry";
const PNPM_BUILDS = "https://pnpm.io/settings#onlybuiltdependencies";
const BUN_LIFECYCLE = "https://bun.sh/docs/install/lifecycle";
const SOCKET_INSTALL_SCRIPTS = "https://socket.dev/npm/issue/installScripts";
const PIP_INSTALL = "https://pip.pypa.io/en/stable/cli/pip_install/";
const PIP_CONFUSION = "https://github.com/pypa/pip/issues/8606";
const COMPOSER_CONFIG = "https://getcomposer.org/doc/06-config.md#secure-http";
const COMPOSER_REPOS = "https://getcomposer.org/doc/05-repositories.md";

const rule = (name: string) => `${LOCKFILES_ID}/${name}`;

const base = {
	category: "supply-chain",
	confidence: "high",
} as const;

const label = (p: LockedPackage) =>
	p.version ? `${p.name}@${p.version}` : p.name;

/** Names, at most `max`, joined for a message. */
const listNames = (names: ReadonlyArray<string>, max = 10) =>
	`${names.slice(0, max).join(", ")}${names.length > max ? `, … (${names.length - max} more)` : ""}`;

const unique = (xs: ReadonlyArray<string>) => [...new Set(xs)];

const insecureFinding = (
	file: string,
	line: number | undefined,
	what: string,
	evidence: string,
	severity: Severity = "high",
): FindingInput => ({
	...base,
	ruleId: rule("insecure-protocol"),
	title: truncate(`${what} is fetched over an unencrypted connection`, 120),
	severity,
	message: truncate(
		`${what} is downloaded over ${evidence.toLowerCase().includes("git://") ? "the unencrypted git:// protocol" : "plain HTTP"}, so anyone on the network path can substitute the code that gets installed.`,
		500,
	),
	location: { file, line },
	evidence: truncate(evidence),
	remediation:
		"Use https:// (or git+https:// / git+ssh://) URLs for registries and dependencies, then regenerate the lockfile.",
	references: [LOCKFILE_LINT, cweUrl(319), cweUrl(494), owaspUrl("a08")],
	tags: ["cwe-319", "cwe-494", "owasp-a08"],
});

const pathFinding = (
	file: string,
	line: number | undefined,
	name: string,
	evidence: string,
): FindingInput => ({
	...base,
	ruleId: rule("path-outside-workspace"),
	title: truncate(
		`${name} is installed from a path outside the repository`,
		120,
	),
	severity: "medium",
	message: truncate(
		`${name} resolves to a local path that leaves the repository. Installs then depend on whatever happens to be at that path on the machine, which a clean checkout cannot reproduce or review.`,
		500,
	),
	location: { file, line },
	evidence: truncate(evidence),
	remediation:
		"Move the package into the repository (as a workspace) or publish it to a registry, and depend on it from there.",
	references: [LOCKFILE_LINT, cweUrl(829)],
	tags: ["cwe-829"],
});

const gitFinding = (
	file: string,
	line: number | undefined,
	name: string,
	evidence: string,
	pinned: boolean,
	how: string,
	host: string,
): FindingInput => {
	const knownHost = KNOWN_GIT_HOSTS.has(host);
	return {
		...base,
		ruleId: rule("git-dependency"),
		title: truncate(
			`${name} is installed from a git host instead of a registry`,
			120,
		),
		severity: pinned && knownHost ? "low" : "medium",
		message: truncate(
			`${name} is installed from ${how}. It bypasses the registry's integrity metadata, advisories and malware scanning${pinned ? "." : ", and the lockfile does not pin its content to a commit or hash, so the same lockfile can install different code tomorrow."}${knownHost ? "" : ` ${host || "The host"} is not one of the well-known git hosts (GitHub, GitLab, Bitbucket).`}`,
			600,
		),
		location: { file, line },
		evidence: truncate(evidence),
		remediation: pinned
			? "Prefer a published registry version. If the git dependency is needed, keep it pinned to a full commit SHA on a host you trust and review updates."
			: "Pin the dependency to a full commit SHA (or publish it to a registry) and regenerate the lockfile.",
		references: [LOCKFILE_LINT, cweUrl(829), ...(pinned ? [] : [cweUrl(1357)])],
		tags: ["cwe-829", ...(pinned ? [] : ["cwe-1357"])],
	};
};

const unexpectedHostFinding = (
	lock: Lockfile,
	p: LockedPackage,
	host: string,
	shown: string,
	why: string,
): FindingInput => ({
	...base,
	ruleId: rule("unexpected-host"),
	title: truncate(
		`${p.name} is downloaded from ${host || "an unrecognised source"}`,
		120,
	),
	severity: "medium",
	message: truncate(
		`${label(p)} resolves to ${shown}, ${why}. A lockfile that points a package at another host is a known way to slip in a modified package${integrityStrength(p.integrity) === "none" ? ", and this entry has no integrity hash either" : ""}.`,
		600,
	),
	location: { file: lock.path, line: p.line },
	evidence: `${label(p)}: ${shown}`,
	remediation:
		"If the host is your private registry, configure it for the package's scope in .npmrc, .yarnrc.yml or bunfig.toml next to the lockfile. Otherwise reinstall the package from the registry and regenerate the lockfile.",
	references: [LOCKFILE_LINT, NPM_REGISTRY, cweUrl(829), owaspUrl("a08")],
	tags: ["cwe-829", "owasp-a08"],
});

/** Packages served by a registry that a config in the target declares. */
interface CustomSource {
	readonly registry: Registry;
	readonly host: string;
	readonly packages: LockedPackage[];
}

/**
 * One finding for an entry's source, or none. Packages from a registry the
 * target configures are collected in `custom` and reported together.
 */
const sourceFinding = (
	lock: Lockfile,
	p: LockedPackage,
	configs: ReadonlyArray<FileConfig>,
	custom: Map<string, CustomSource>,
): FindingInput | undefined => {
	const source = classifySource(p.source);
	const file = lock.path;
	const evidence = (s: string) => `${label(p)}: ${s}`;
	const fromRegistry = (host: string, registry: Registry) => {
		const entry = custom.get(host) ?? { registry, host, packages: [] };
		entry.packages.push(p);
		custom.set(host, entry);
	};
	switch (source.kind) {
		case "ignored":
			return undefined;
		case "registry": {
			// No URL recorded: the package comes from the configured registry.
			const registry = registryFor(configs, p.name);
			const host = registry && hostOf(registry.url);
			if (
				registry &&
				host &&
				!DEFAULT_REGISTRY_HOSTS.has(host) &&
				!registry.url.toLowerCase().startsWith("http:")
			)
				fromRegistry(host, registry);
			return undefined;
		}
		case "unknown":
			return unexpectedHostFinding(
				lock,
				p,
				"",
				displayUrl(p.source ?? ""),
				"a source that is not a registry, a URL, git or a local path",
			);
		case "path": {
			const from = joinDir(dirOf(lock.path), p.base ?? "");
			return escapesRoot(from, source.path)
				? pathFinding(
						file,
						p.line,
						p.name,
						evidence(truncate(source.path, 120)),
					)
				: undefined;
		}
		case "git": {
			const shown = displayUrl(p.source ?? "");
			if (source.insecure)
				return insecureFinding(file, p.line, p.name, evidence(shown));
			const pinned = source.pinned || integrityStrength(p.integrity) !== "none";
			return gitFinding(
				file,
				p.line,
				p.name,
				evidence(shown),
				pinned,
				source.ref
					? `${displayUrl(source.url)} at "${truncate(source.ref, 60)}"`
					: displayUrl(source.url),
				source.host,
			);
		}
		case "tarball": {
			const shown = displayUrl(source.url);
			if (source.insecure)
				return insecureFinding(file, p.line, p.name, evidence(shown));
			if (DEFAULT_REGISTRY_HOSTS.has(source.host)) return undefined;
			if (p.runtime && RUNTIME_HOSTS.has(source.host)) return undefined;
			// A scoped registry only serves its own scope.
			const scope = scopeOfPackage(p.name);
			const registry = configs
				.flatMap((c) => c.registries)
				.find(
					(r) =>
						hostOf(r.url) === source.host &&
						(r.scope === undefined || r.scope === scope),
				);
			if (registry) {
				fromRegistry(source.host, registry);
				return undefined;
			}
			return unexpectedHostFinding(
				lock,
				p,
				source.host,
				shown,
				"which is neither the public npm registry nor a registry configured for this package next to the lockfile",
			);
		}
	}
};

const customSourceFinding = (
	lock: Lockfile,
	{ registry, host, packages }: CustomSource,
): FindingInput => {
	const names = unique(packages.map(label));
	const declared = `${registry.file}:${registry.line ?? "?"}`;
	return {
		...base,
		ruleId: rule("custom-registry-source"),
		title: truncate(
			`${names.length} ${names.length === 1 ? "package" : "packages"} in ${baseName(lock.path)} ${names.length === 1 ? "comes" : "come"} from ${host}`,
			120,
		),
		severity: "low",
		message: truncate(
			`${listNames(names)} ${names.length === 1 ? "is" : "are"} downloaded from ${host}, which ${declared} configures as ${registry.scope ? `the registry for ${registry.scope}` : "the default registry"} instead of the public npm registry. The lockfile's integrity hashes for them come from that registry too, so it decides what gets installed. The setting is part of the repository, so check that ${host} is your organisation's registry.`,
			800,
		),
		location: { file: lock.path, line: packages[0]?.line },
		evidence: truncate(`${host}: ${names.join(", ")}`),
		remediation:
			"If this is your private registry, suppress the finding by fingerprint. Otherwise remove the registry setting, reinstall from the public registry and regenerate the lockfile.",
		references: [NPM_REGISTRY, LOCKFILE_LINT, cweUrl(829), owaspUrl("a08")],
		tags: ["cwe-829", "owasp-a08"],
	};
};

const integrityFindings = (
	lock: Lockfile,
	packages: ReadonlyArray<LockedPackage>,
): FindingInput[] => {
	const missing: string[] = [];
	const weak: string[] = [];
	let missingLine: number | undefined;
	let weakLine: number | undefined;
	for (const p of packages) {
		if (p.bundled) continue;
		const kind = classifySource(p.source).kind;
		if (kind !== "registry" && kind !== "tarball") continue;
		// npm workspaces and the root are not downloaded.
		if (lock.manager === "npm" && !p.version && !p.source) continue;
		const strength = integrityStrength(p.integrity);
		if (strength === "none") {
			missing.push(label(p));
			missingLine ??= p.line;
		} else if (strength === "weak") {
			weak.push(label(p));
			weakLine ??= p.line;
		}
	}
	const out: FindingInput[] = [];
	const m = unique(missing);
	const w = unique(weak);
	if (m.length)
		out.push({
			...base,
			ruleId: rule("missing-integrity"),
			title: `${m.length} ${m.length === 1 ? "entry" : "entries"} in ${baseName(lock.path)} ${m.length === 1 ? "has" : "have"} no integrity hash`,
			severity: "low",
			message: truncate(
				`The lockfile records no valid integrity hash for ${listNames(m)}. The package manager cannot detect a tarball that was changed on the server or in transit.`,
				600,
			),
			location: { file: lock.path, line: missingLine },
			evidence: truncate(m.join(", ")),
			remediation:
				"Delete the affected entries (or the lockfile) and reinstall with a current package manager so it records integrity hashes; then commit the lockfile.",
			references: [LOCKFILE_LINT, NPM_LOCKFILE, cweUrl(494), owaspUrl("a08")],
			tags: ["cwe-494", "owasp-a08"],
		});
	if (w.length)
		out.push({
			...base,
			ruleId: rule("weak-integrity"),
			title: `${w.length} ${w.length === 1 ? "entry" : "entries"} in ${baseName(lock.path)} ${w.length === 1 ? "is" : "are"} only checked with SHA-1`,
			severity: "low",
			message: truncate(
				`The only integrity hash recorded for ${listNames(w)} is SHA-1, which is no longer collision resistant.`,
				600,
			),
			location: { file: lock.path, line: weakLine },
			evidence: truncate(w.join(", ")),
			remediation:
				"Regenerate the lockfile with a current package manager so it records sha512 integrity hashes.",
			references: [LOCKFILE_LINT, NPM_LOCKFILE, cweUrl(328)],
			tags: ["cwe-328"],
		});
	return out;
};

/** How the lockfile's package manager gates install scripts. */
interface ScriptPolicy {
	/** Packages known to run install scripts (marked in the lockfile or allow-listed). */
	readonly scripted: ReadonlyArray<LockedPackage>;
	/** Of those, the ones that run without explicit approval. */
	readonly ungated: ReadonlyArray<LockedPackage>;
	/** Sentence describing how scripts are gated. */
	readonly gate: string;
	readonly references: ReadonlyArray<string>;
	/** A setting that lets every package run scripts. */
	readonly allowAll?: Setting;
}

const uniqueByName = (ps: ReadonlyArray<LockedPackage>) => {
	const seen = new Set<string>();
	return ps.filter((p) => !seen.has(p.name) && seen.add(p.name));
};

const scriptPolicy = (
	lock: Lockfile,
	packages: ReadonlyArray<LockedPackage>,
	configs: ReadonlyArray<FileConfig>,
): ScriptPolicy | undefined => {
	const find = <K extends keyof FileConfig>(key: K) =>
		configs.find((c) => c[key] !== undefined)?.[key];
	const marked = uniqueByName(packages.filter((p) => p.installScript));
	const ignore = find("ignoreScripts");
	const byName = new Map(uniqueByName(packages).map((p) => [p.name, p]));
	const listed = (names: ReadonlyArray<string>) =>
		unique(names).map((n) => byName.get(n) ?? { name: n });
	switch (lock.manager) {
		case "npm": {
			const other = find("onlyBuilt") ?? find("trusted");
			const note = other
				? " package.json declares an install-script allow-list for pnpm or Bun, which npm ignores."
				: "";
			return {
				scripted: marked,
				ungated: ignore ? [] : marked,
				gate: ignore
					? `${ignore.file} sets ignore-scripts, so npm runs none of them.`
					: `npm runs every one of them on install because ignore-scripts is not set in the project's .npmrc.${note}`,
				references: [NPM_SCRIPTS, NPM_IGNORE_SCRIPTS, SOCKET_INSTALL_SCRIPTS],
			};
		}
		case "pnpm": {
			const onlyBuilt = find("onlyBuilt");
			const never = new Set(find("neverBuilt") ?? []);
			const allowAll = find("allowAllBuilds");
			const references = [
				PNPM_BUILDS,
				NPM_IGNORE_SCRIPTS,
				SOCKET_INSTALL_SCRIPTS,
			];
			if (ignore)
				return {
					scripted: marked,
					ungated: [],
					gate: `${ignore.file} sets ignore-scripts, so pnpm runs none of them.`,
					references,
				};
			if (allowAll)
				return {
					scripted: marked,
					ungated: marked,
					gate: `${allowAll.file} allows every package to build (${allowAll.evidence}), so pnpm runs every install script.`,
					references,
					allowAll,
				};
			if (onlyBuilt) {
				const allowed = new Set(onlyBuilt);
				return {
					scripted: uniqueByName([
						...marked,
						...listed(onlyBuilt.filter((n) => byName.has(n))),
					]),
					ungated: [],
					gate: `pnpm only runs the scripts of packages in onlyBuiltDependencies: ${listNames(onlyBuilt)}.${marked.some((p) => !allowed.has(p.name)) ? " The others are blocked." : ""}`,
					references,
				};
			}
			return {
				scripted: marked,
				// Lockfiles that record requiresBuild come from pnpm 8 and older,
				// which run every install script unless an allow-list is set.
				ungated: marked.filter((p) => !never.has(p.name)),
				gate: `pnpm 8 and older run them on install because no onlyBuiltDependencies allow-list is configured${never.size ? ` (neverBuiltDependencies excludes ${listNames([...never])})` : ""}.`,
				references,
			};
		}
		case "bun": {
			// Bun enforces package.json's list; bun.lock keeps a copy. Either
			// can be edited on its own, so both are listed.
			const trusted = unique([
				...(lock.trusted ?? []),
				...(find("trusted") ?? []),
			]);
			const wildcard = trusted.find((n) => n.includes("*"));
			return {
				scripted: listed(trusted),
				ungated: [],
				gate: "Bun only runs the lifecycle scripts of packages in trustedDependencies (and of its built-in default allow-list); bun.lock does not record which packages actually have scripts.",
				references: [BUN_LIFECYCLE, SOCKET_INSTALL_SCRIPTS],
				...(wildcard
					? {
							allowAll: {
								file: lock.path,
								evidence: `trustedDependencies: ${wildcard}`,
							},
						}
					: {}),
			};
		}
		default:
			return undefined;
	}
};

const installScriptFindings = (
	lock: Lockfile,
	packages: ReadonlyArray<LockedPackage>,
	configs: ReadonlyArray<FileConfig>,
): FindingInput[] => {
	const policy = scriptPolicy(lock, packages, configs);
	if (!policy) return [];
	const out: FindingInput[] = [];
	const names = policy.scripted.map((p) => p.name).sort();
	const firstLine = (ps: ReadonlyArray<LockedPackage>) =>
		ps.map((p) => p.line).find((l) => l !== undefined);
	if (names.length) {
		const one = names.length === 1;
		// Bun and pnpm 9+ lockfiles do not mark packages with scripts; only
		// the allow-list says which packages may run them.
		const verb = lock.recordsInstallScripts
			? one
				? "runs"
				: "run"
			: `${one ? "is" : "are"} allowed to run`;
		out.push({
			...base,
			ruleId: rule("install-scripts"),
			title: `${names.length} ${one ? "package" : "packages"} in ${baseName(lock.path)} ${verb} install scripts`,
			severity: "info",
			message: truncate(
				`${listNames(names, 20)} ${verb} code (preinstall, install or postinstall scripts) when dependencies are installed. That is not a vulnerability on its own, but it is the most common way malicious packages execute. ${policy.gate}`,
				1000,
			),
			location: { file: lock.path, line: firstLine(policy.scripted) },
			evidence: truncate(names.join(", ")),
			remediation:
				"Review which dependencies need install scripts and keep the list short: use pnpm's onlyBuiltDependencies, Bun's trustedDependencies, or npm with ignore-scripts=true plus an allow-list such as @lavamoat/allow-scripts.",
			references: policy.references,
			tags: ["install-scripts"],
		});
	}
	const ungated = policy.ungated.map((p) => p.name).sort();
	if (ungated.length || policy.allowAll) {
		const shown = ungated.length ? ungated : ["(every dependency)"];
		const allowAllOnly = policy.allowAll && !ungated.length;
		out.push({
			...base,
			ruleId: rule("ungated-install-scripts"),
			title: ungated.length
				? `${ungated.length} install ${ungated.length === 1 ? "script runs" : "scripts run"} without an allow-list`
				: "Every dependency may run install scripts",
			severity: "low",
			message: truncate(
				`${listNames(shown, 20)} ${shown.length === 1 ? "runs" : "run"} code on install without being approved by an allow-list. ${allowAllOnly ? `${policy.allowAll?.file} allows every package (${policy.allowAll?.evidence}). ` : ""}${policy.gate} A compromised version of any of them runs on every developer machine and CI runner that installs dependencies.`,
				1000,
			),
			location: allowAllOnly
				? { file: policy.allowAll?.file, line: policy.allowAll?.line }
				: { file: lock.path, line: firstLine(policy.ungated) },
			evidence: truncate(
				allowAllOnly ? (policy.allowAll?.evidence ?? "") : ungated.join(", "),
			),
			remediation:
				"Gate install scripts: with npm set ignore-scripts=true in .npmrc and allow the few packages that need them (for example with @lavamoat/allow-scripts); with pnpm list them by name in onlyBuiltDependencies; with Bun in trustedDependencies.",
			references: policy.references,
			tags: ["install-scripts", "owasp-a08"],
		});
	}
	return out;
};

/** package.json dependencies the lockfile does not record (or records differently). */
const driftFinding = (
	lock: Lockfile,
	manifest: SourceFile,
	importer: Importer,
): FindingInput | undefined => {
	const json = parseJson(manifest.text);
	if (!isRecord(json)) return undefined;
	const drifted: Array<{ name: string; text: string; evidence: string }> = [];
	for (const [name, specs] of declaredSpecs(json)) {
		const spec = specs?.[0] ?? "";
		if (!importer.has(name))
			drifted.push({
				name,
				text: `${name} is missing`,
				evidence: `${name}: ${spec} (not locked)`,
			});
		else {
			const locked = importer.get(name);
			if (locked && !locked.includes(spec))
				drifted.push({
					name,
					text: `${name} is "${spec}" but locked as "${locked[0]}"`,
					evidence: `${name}: ${spec} (locked ${locked[0]})`,
				});
		}
	}
	const first = drifted[0];
	if (!first) return undefined;
	const lineOf = lineFinder(manifest.text);
	return {
		...base,
		ruleId: rule("lockfile-drift"),
		title: `${baseName(lock.path)} is out of date with ${manifest.path}`,
		severity: "low",
		message: truncate(
			`${manifest.path} declares ${drifted.length} ${drifted.length === 1 ? "dependency" : "dependencies"} that ${lock.path} does not match: ${drifted
				.slice(0, 10)
				.map((d) => d.text)
				.join(
					"; ",
				)}${drifted.length > 10 ? "; …" : ""}. A frozen install (npm ci, --frozen-lockfile) fails, and a plain install resolves the versions anew instead of using reviewed ones.`,
			1000,
		),
		location: { file: manifest.path, line: lineOf(`"${first.name}"`) },
		evidence: truncate(drifted.map((d) => d.evidence).join("; ")),
		remediation:
			"Run the package manager's install to update the lockfile, review the diff, and commit both files together. Use frozen installs in CI.",
		references: [NPM_LOCKFILE, LOCKFILE_LINT],
		confidence: lock.manager === "yarn" ? "medium" : "high",
		tags: ["lockfile-drift"],
	};
};

/** A lockfile that was not checked at all (too large or unparseable). */
const uncheckedFinding = (
	ruleName: "truncated" | "unparseable-lockfile",
	file: string,
	message: string,
): FindingInput => ({
	...base,
	ruleId: rule(ruleName),
	title: `${baseName(file)} was not checked`,
	// A lockfile the package manager may read but openaudit cannot is a
	// place to hide entries; an oversized one is more likely just large.
	severity: ruleName === "unparseable-lockfile" ? "medium" : "low",
	message: `${message} Its entries were not checked, but the package manager may still install from it.`,
	location: { file },
	evidence: file,
	remediation:
		"Regenerate the lockfile with the package manager and check it with lockfile-lint.",
	references: [LOCKFILE_LINT],
	tags: ["lockfile"],
});

/**
 * Keeps the first `MAX_FINDINGS_PER_RULE` findings of each rule per file and
 * folds the rest into one finding of that rule at their highest severity.
 */
export const capPerRule = (
	findings: ReadonlyArray<FindingInput>,
): FindingInput[] => {
	const byRule = new Map<string, FindingInput[]>();
	for (const f of findings) {
		const key = `${f.ruleId}|${f.location?.file ?? ""}`;
		const group = byRule.get(key);
		if (group) group.push(f);
		else byRule.set(key, [f]);
	}
	const out: FindingInput[] = [];
	for (const group of byRule.values()) {
		out.push(...group.slice(0, MAX_FINDINGS_PER_RULE));
		const rest = group.slice(MAX_FINDINGS_PER_RULE);
		const first = rest[0];
		if (!first) continue;
		const severity = rest.reduce<Severity>(
			(s, f) => (severityRank(f.severity) < severityRank(s) ? f.severity : s),
			first.severity,
		);
		const items = rest.map((f) => f.evidence ?? f.title);
		out.push({
			...first,
			title: truncate(
				`${rest.length} more ${first.ruleId.split("/")[1]} findings in ${baseName(first.location?.file ?? "")}`,
				120,
			),
			severity,
			message: truncate(
				`Only the first ${MAX_FINDINGS_PER_RULE} findings of this rule are listed one by one. ${rest.length} more entries have the same problem: ${listNames(items)}.`,
				1000,
			),
			evidence: truncate(`${rest.length} more: ${items.join(", ")}`),
		});
	}
	return out;
};

/** All findings for one parsed lockfile. */
export const lockfileFindings = (
	lock: Lockfile,
	configs: ReadonlyArray<FileConfig>,
	manifests: ReadonlyMap<string, SourceFile>,
): FindingInput[] => {
	const perEntry: FindingInput[] = [];
	const custom = new Map<string, CustomSource>();
	for (const p of lock.packages) {
		const f = sourceFinding(lock, p, configs, custom);
		if (f) perEntry.push(f);
	}
	const findings = capPerRule(perEntry);
	for (const c of custom.values()) findings.push(customSourceFinding(lock, c));
	findings.push(...integrityFindings(lock, lock.packages));
	findings.push(...installScriptFindings(lock, lock.packages, configs));
	const lockDir = dirOf(lock.path);
	for (const [dir, importer] of lock.importers) {
		if (escapesRoot(lockDir, dir)) continue;
		const manifest = manifests.get(
			joinDir(joinDir(lockDir, dir), "package.json"),
		);
		const drift = manifest && driftFinding(lock, manifest, importer);
		if (drift) findings.push(drift);
	}
	return findings;
};

/** Registries (custom or insecure) and disabled TLS checks in a config file. */
const configFindings = (config: FileConfig): FindingInput[] => {
	const out: FindingInput[] = [];
	for (const r of config.registries) {
		const host = hostOf(r.url);
		if (r.url.toLowerCase().startsWith("http:"))
			out.push(
				insecureFinding(
					r.file,
					r.line,
					`The registry ${displayUrl(r.url)}`,
					r.evidence,
				),
			);
		else if (host && !DEFAULT_REGISTRY_HOSTS.has(host))
			out.push({
				...base,
				ruleId: rule("custom-registry"),
				title: truncate(
					`${baseName(r.file)} installs ${r.scope ? `${r.scope} packages` : "packages"} from ${host}`,
					120,
				),
				severity: "info",
				message: truncate(
					`${r.file} sets ${displayUrl(r.url)} as ${r.scope ? `the registry for ${r.scope} packages` : "the default registry"}. Whoever runs that registry decides what gets installed, and the setting lives in the repository, so a change to it deserves the same review as a change to the code.`,
					600,
				),
				location: { file: r.file, line: r.line },
				evidence: truncate(r.evidence),
				remediation:
					"Confirm the host is your organisation's registry. Keep registry settings in CI or user configuration where possible, and review changes to them.",
				references: [NPM_REGISTRY, LOCKFILE_LINT],
				tags: ["registry"],
			});
	}
	if (config.strictSslOff)
		out.push(tlsFinding(config.strictSslOff, "the package manager"));
	return out;
};

const tlsFinding = (s: Setting, who: string): FindingInput => ({
	...base,
	ruleId: rule("tls-verification-disabled"),
	title: `TLS certificate checks are disabled for ${who}`,
	severity: "medium",
	message: truncate(
		`${s.file} turns off certificate verification for ${who}, so a machine-in-the-middle can serve modified packages over a connection that still looks encrypted.`,
		500,
	),
	location: { file: s.file, line: s.line },
	evidence: truncate(s.evidence),
	remediation:
		"Remove the setting. For a private registry with an internal CA, trust that CA instead (npm cafile, NODE_EXTRA_CA_CERTS, pip --cert).",
	references: [cweUrl(295), LOCKFILE_LINT],
	tags: ["cwe-295"],
});

/* -------------------------------------------------------------------------- */
/*                               Python, Composer                             */
/* -------------------------------------------------------------------------- */

/** Long options pip accepts in requirements files (optparse also takes unique prefixes). */
const PIP_LONG_OPTIONS = [
	"--index-url",
	"--extra-index-url",
	"--no-index",
	"--find-links",
	"--trusted-host",
	"--requirement",
	"--constraint",
	"--editable",
	"--no-binary",
	"--only-binary",
	"--prefer-binary",
	"--require-hashes",
	"--pre",
	"--use-feature",
	"--global-option",
	"--config-settings",
	"--hash",
];

const PIP_SHORT_OPTIONS: Readonly<Record<string, string>> = {
	"-i": "--index-url",
	"-f": "--find-links",
	"-r": "--requirement",
	"-c": "--constraint",
	"-e": "--editable",
};

/** Options whose value is a source or file. */
const PIP_VALUE_OPTIONS = new Set([
	"--index-url",
	"--extra-index-url",
	"--find-links",
	"--trusted-host",
	"--requirement",
	"--constraint",
	"--editable",
	"--no-binary",
	"--only-binary",
	"--use-feature",
	"--global-option",
	"--config-settings",
	"--hash",
]);

/** optparse's long-option matching: exact, else a unique prefix. */
const pipLongOption = (name: string): string | undefined => {
	if (PIP_LONG_OPTIONS.includes(name)) return name;
	const matches = PIP_LONG_OPTIONS.filter((o) => o.startsWith(name));
	return matches.length === 1 ? matches[0] : undefined;
};

const isInsecureUrl = (s: string) => {
	const l = s.toLowerCase();
	return (
		l.startsWith("http://") ||
		l.startsWith("git://") ||
		l.startsWith("svn://") ||
		/^[a-z]+\+http:\/\//.test(l)
	);
};

/** Logical lines of a requirements file (`\` continuations joined), with start lines. */
const logicalLines = (text: string): Array<readonly [string, number]> => {
	const out: Array<readonly [string, number]> = [];
	let buffer = "";
	let start = 0;
	text.split(/\r\n|\r|\n/).forEach((line, i) => {
		if (!buffer) start = i + 1;
		if (line.endsWith("\\")) {
			buffer += `${line.slice(0, -1)} `;
			return;
		}
		out.push([buffer + line, start]);
		buffer = "";
	});
	if (buffer) out.push([buffer, start]);
	return out;
};

/** A repository path for `rel` relative to `dir`, or undefined if it leaves the repository. */
const resolveInRepo = (dir: string, rel: string): string | undefined => {
	const p = rel.replace(/\\/g, "/");
	if (p.startsWith("/") || p.startsWith("~") || /^[a-z]:/i.test(p))
		return undefined;
	const out = dir ? dir.split("/") : [];
	for (const seg of p.split("/")) {
		if (!seg || seg === ".") continue;
		if (seg === "..") {
			if (!out.length) return undefined;
			out.pop();
		} else out.push(seg);
	}
	return out.join("/");
};

const pipSourceFinding = (
	file: string,
	line: number,
	what: string,
	url: string,
	why: string,
): FindingInput => {
	const shown = displayUrl(url);
	const host = hostOf(url) ?? "an unknown host";
	return {
		...base,
		ruleId: rule("unexpected-host"),
		title: truncate(`${what} is downloaded from ${host}`, 120),
		severity: "medium",
		message: truncate(
			`${file} makes pip download ${what} from ${shown}, ${why}. It bypasses the package index, so the index's provenance and any --require-hashes pinning of index packages do not cover it.`,
			600,
		),
		location: { file, line },
		evidence: truncate(`${what}: ${shown}`),
		remediation:
			"Publish the package to PyPI or your private index and require it by version, or pin the download with --hash.",
		references: [PIP_INSTALL, cweUrl(829), owaspUrl("a08")],
		tags: ["cwe-829", "owasp-a08"],
	};
};

/** A VCS, URL or path requirement (`name @ url`, a bare URL, `-e url`). */
const pipDirectReference = (
	file: SourceFile,
	line: number,
	name: string,
	url: string,
): FindingInput | undefined => {
	const lower = url.toLowerCase();
	const what = name || "a direct reference";
	const evidence = `${what}: ${displayUrl(url)}`;
	if (isInsecureUrl(url))
		return insecureFinding(file.path, line, what, evidence);
	const vcs = /^(git|hg|svn|bzr)\+/.exec(lower);
	if (vcs) {
		const bare = url.slice(vcs[0].length);
		const host = hostOf(bare) ?? "";
		let path = bare;
		try {
			path = new URL(bare).pathname;
		} catch {
			// scp-like spec: keep it whole.
		}
		const hash = path.indexOf("#");
		const at = path.lastIndexOf("@");
		const ref =
			at === -1
				? undefined
				: path.slice(at + 1, hash === -1 ? undefined : hash);
		return gitFinding(
			file.path,
			line,
			what,
			evidence,
			ref !== undefined && /^[0-9a-f]{40}$/i.test(ref),
			ref ? `${displayUrl(url)} at "${truncate(ref, 60)}"` : displayUrl(url),
			host,
		);
	}
	if (lower.startsWith("https://")) {
		const host = hostOf(url);
		return host && PYPI_HOSTS.has(host)
			? undefined
			: pipSourceFinding(
					file.path,
					line,
					what,
					url,
					"not the Python Package Index",
				);
	}
	if (lower.startsWith("file:")) {
		const path = url.replace(/^file:(\/\/)?/i, "");
		return escapesRoot(dirOf(file.path), path)
			? pathFinding(file.path, line, what, evidence)
			: undefined;
	}
	return undefined;
};

/**
 * pip requirements and constraints files: index and link options, included
 * files, and direct references. `includes` lists local `-r`/`-c` files for
 * the caller to read and check too.
 */
export const requirementsFindings = (
	file: SourceFile,
): { readonly findings: FindingInput[]; readonly includes: string[] } => {
	const out: FindingInput[] = [];
	const includes: string[] = [];
	for (const [raw, line] of logicalLines(stripBom(file.text))) {
		const hash = raw.search(/(^|\s)#/);
		const tokens = (hash === -1 ? raw : raw.slice(0, hash))
			.trim()
			.split(/\s+/)
			.filter(Boolean);
		for (let t = 0; t < tokens.length; t++) {
			const token = tokens[t] ?? "";
			let option: string | undefined;
			let value: string | undefined;
			if (token.startsWith("--")) {
				const eq = token.indexOf("=");
				option = pipLongOption(eq === -1 ? token : token.slice(0, eq));
				if (eq !== -1) value = token.slice(eq + 1);
				else if (option && PIP_VALUE_OPTIONS.has(option)) value = tokens[++t];
			} else if (
				token.startsWith("-") &&
				PIP_SHORT_OPTIONS[token.slice(0, 2)]
			) {
				option = PIP_SHORT_OPTIONS[token.slice(0, 2)];
				value = token.length > 2 ? token.slice(2) : tokens[++t];
			}
			if (option === undefined) {
				// A requirement: `name @ url`, `name@url`, `@ url` or a bare URL.
				if (token === "@" || !token.includes("://")) continue;
				const scheme = token.indexOf("://");
				const at = token.lastIndexOf("@", scheme);
				const url = at === -1 ? token : token.slice(at + 1);
				const name =
					at > 0
						? token.slice(0, at)
						: at === 0 || tokens[t - 1] === "@"
							? (tokens[t - (at === 0 ? 1 : 2)] ?? "")
							: "";
				const f = pipDirectReference(file, line, name, url);
				if (f) out.push(f);
				continue;
			}
			if (value === undefined) continue;
			const evidence = `${option} ${displayUrl(value)}`;
			const isUrl = /^[a-z][a-z0-9+.-]*:\/\//i.test(value);
			switch (option) {
				case "--trusted-host":
					out.push(
						tlsFinding(
							{ file: file.path, line, evidence },
							`pip (host ${truncate(value, 60)})`,
						),
					);
					break;
				case "--index-url":
				case "--extra-index-url":
				case "--find-links": {
					if (isInsecureUrl(value))
						out.push(
							insecureFinding(
								file.path,
								line,
								`The package source ${displayUrl(value)}`,
								evidence,
							),
						);
					const host = hostOf(value);
					if (option === "--index-url") {
						if (host && !PYPI_HOSTS.has(host) && !isInsecureUrl(value))
							out.push({
								...base,
								ruleId: rule("custom-registry"),
								title: truncate(
									`${baseName(file.path)} installs packages from ${host}`,
									120,
								),
								severity: "info",
								message: truncate(
									`${file.path} sets ${displayUrl(value)} as pip's package index. Whoever runs that index decides what gets installed, and the setting lives in the repository, so a change to it deserves the same review as a change to the code.`,
									600,
								),
								location: { file: file.path, line },
								evidence,
								remediation:
									"Confirm the host is your organisation's index. Keep index settings in pip.conf or CI where possible, and review changes to them.",
								references: [PIP_INSTALL],
								tags: ["registry"],
							});
					} else if (option === "--extra-index-url" || isUrl)
						out.push({
							...base,
							ruleId: rule("extra-index-url"),
							title:
								option === "--find-links"
									? "pip searches extra package links"
									: "pip searches an extra package index",
							severity: "medium",
							message: truncate(
								`${file.path} adds ${displayUrl(value)} with ${option}. pip treats every index and link page as equal and installs the highest version it finds on any of them, so a public package with the same name as an internal one (dependency confusion) can win.`,
								500,
							),
							location: { file: file.path, line },
							evidence,
							remediation:
								"Use a single --index-url that proxies PyPI and your private packages (devpi, Artifactory, Nexus, CodeArtifact), or pin every package with --require-hashes.",
							references: [PIP_INSTALL, PIP_CONFUSION, cweUrl(427)],
							tags: ["cwe-427", "owasp-a08"],
						});
					break;
				}
				case "--requirement":
				case "--constraint":
					if (isInsecureUrl(value))
						out.push(
							insecureFinding(
								file.path,
								line,
								`The ${option.slice(2)} file ${displayUrl(value)}`,
								evidence,
							),
						);
					else if (isUrl)
						out.push(
							pipSourceFinding(
								file.path,
								line,
								`the ${option.slice(2)} file`,
								value,
								"a remote file whose contents can change between installs",
							),
						);
					else includes.push(value);
					break;
				case "--editable": {
					const f = isUrl
						? pipDirectReference(file, line, "", value)
						: undefined;
					if (f) out.push(f);
					break;
				}
			}
		}
	}
	return { findings: capPerRule(out), includes };
};

/** Pipfile `[[source]]` blocks. */
export const pipfileFindings = (file: SourceFile): FindingInput[] => {
	const out: FindingInput[] = [];
	let inSource = false;
	file.text.split("\n").forEach((raw, i) => {
		const t = raw.trim();
		if (t.startsWith("[")) {
			inSource = t.replace(/\s+/g, "") === "[[source]]";
			return;
		}
		if (!inSource) return;
		const eq = t.indexOf("=");
		if (eq === -1) return;
		const key = t.slice(0, eq).trim();
		const value = unquote(t.slice(eq + 1).trim());
		if (key === "url" && isInsecureUrl(value))
			out.push(
				insecureFinding(
					file.path,
					i + 1,
					`The package index ${displayUrl(value)}`,
					`url = ${displayUrl(value)}`,
				),
			);
		else if (key === "verify_ssl" && value.toLowerCase() === "false")
			out.push(
				tlsFinding({ file: file.path, line: i + 1, evidence: t }, "pipenv"),
			);
	});
	return out;
};

const GIT_REPOSITORY_TYPES = new Set([
	"vcs",
	"git",
	"github",
	"gitlab",
	"bitbucket",
	"hg",
	"svn",
	"fossil",
	"perforce",
]);

/** composer.json `repositories` and `config.secure-http`. */
export const composerJsonFindings = (file: SourceFile): FindingInput[] => {
	const json = parseJson(file.text);
	if (!isRecord(json)) return [];
	const lineOf = lineFinder(file.text);
	const out: FindingInput[] = [];
	const repos = Array.isArray(json.repositories)
		? json.repositories
		: isRecord(json.repositories)
			? Object.values(json.repositories)
			: [];
	for (const repo of repos) {
		if (!isRecord(repo)) continue;
		const type = (str(repo.type) ?? "").toLowerCase();
		const url = str(repo.url);
		if (!url) continue;
		const line = lineOf(`"${url}"`);
		const evidence = `${type}: ${displayUrl(url)}`;
		if (isInsecureUrl(url))
			out.push(
				insecureFinding(
					file.path,
					line,
					`The ${type} repository ${displayUrl(url)}`,
					evidence,
				),
			);
		else if (type === "path" && escapesRoot(dirOf(file.path), url))
			out.push(
				pathFinding(
					file.path,
					line,
					`The path repository ${truncate(url, 60)}`,
					`path: ${truncate(url, 120)}`,
				),
			);
		else if (GIT_REPOSITORY_TYPES.has(type))
			out.push(
				gitFinding(
					file.path,
					line,
					`The ${type} repository ${displayUrl(url)}`,
					evidence,
					true,
					`${displayUrl(url)} (composer.lock pins the commit)`,
					gitHost(url),
				),
			);
	}
	if (isRecord(json.config) && json.config["secure-http"] === false)
		out.push({
			...insecureFinding(
				file.path,
				lineOf('"secure-http"'),
				"Composer",
				"secure-http: false",
				"medium",
			),
			title: "Composer is allowed to download over plain HTTP",
			message:
				"config.secure-http is false, so Composer accepts http:// repository and package URLs, which anyone on the network path can tamper with.",
			remediation:
				"Remove secure-http: false and serve every repository over https://.",
			references: [COMPOSER_CONFIG, cweUrl(319)],
		});
	return out.map((f) => ({
		...f,
		references: [...(f.references ?? []), COMPOSER_REPOS],
	}));
};

/** composer.lock `dist`/`source` URLs over plain HTTP. */
export const composerLockFindings = (file: SourceFile): FindingInput[] => {
	const json = parseJson(file.text);
	if (!isRecord(json)) return [];
	const lineOf = lineFinder(file.text);
	const out: FindingInput[] = [];
	const list = [
		...(Array.isArray(json.packages) ? json.packages : []),
		...(Array.isArray(json["packages-dev"]) ? json["packages-dev"] : []),
	];
	for (const p of list) {
		if (!isRecord(p)) continue;
		const name = str(p.name) ?? "a package";
		for (const field of ["dist", "source"] as const) {
			const url = isRecord(p[field])
				? str((p[field] as Record<string, unknown>).url)
				: undefined;
			if (url && isInsecureUrl(url))
				out.push(
					insecureFinding(
						file.path,
						lineOf(url),
						name,
						`${name}: ${displayUrl(url)}`,
					),
				);
		}
	}
	return capPerRule(out);
};

/* -------------------------------------------------------------------------- */
/*                                  Auditor                                   */
/* -------------------------------------------------------------------------- */

const isRequirements = (path: string) =>
	/^requirements[\w.-]*\.txt$/.test(baseName(path)) ||
	/(^|\/)requirements\/[^/]+\.txt$/.test(path);

const OTHER_READERS: Readonly<
	Record<string, (file: SourceFile) => FindingInput[]>
> = {
	Pipfile: pipfileFindings,
	"composer.json": composerJsonFindings,
	"composer.lock": composerLockFindings,
};

/** Lockfiles in binary formats that package managers install from but cannot be read here. */
const BINARY_LOCKFILES = new Set(["bun.lockb"]);

/** Requirements files read in total, including those reached through `-r`/`-c`. */
const MAX_REQUIREMENTS_FILES = 200;

const isRelevant = (path: string) => {
	if (isFixturePath(path)) return false;
	const name = baseName(path);
	return (
		name in LOCKFILE_PARSERS ||
		BINARY_LOCKFILES.has(name) ||
		name in CONFIG_READERS ||
		name in OTHER_READERS ||
		isRequirements(path)
	);
};

/**
 * Parses a lockfile as a whole and, when it has merge conflicts, each side of
 * them (package managers merge both sides), then combines what parsed.
 */
export const parseLockfile = (file: SourceFile): Lockfile | undefined => {
	const parse = LOCKFILE_PARSERS[baseName(file.path)];
	if (!parse) return undefined;
	const text = stripBom(file.text);
	const whole = parse({ path: file.path, text });
	const sides = conflictSides(text).flatMap((side) => {
		const lock = parse({ path: file.path, text: side.text });
		return lock ? [shiftLines(lock, (l) => side.lines[l - 1] ?? l)] : [];
	});
	return mergeLockfiles([...(whole ? [whole] : []), ...sides]);
};

/** Reads a file up to `MAX_LOCKFILE_BYTES` (Workspace.readText stops at 2 MB). */
const readLarge = (
	ws: Workspace,
	path: string,
): Effect.Effect<
	SourceFile | { readonly path: string; readonly size: number } | undefined
> =>
	Effect.gen(function* () {
		const size = yield* ws.size(path);
		if (size === 0) return undefined;
		if (size > MAX_LOCKFILE_BYTES) return { path, size };
		const bytes = yield* ws.readBytes(path);
		const text = new TextDecoder().decode(bytes);
		return text.includes("\u0000") ? undefined : { path, text };
	}).pipe(Effect.orElseSucceed(() => undefined));

export const lockfiles = defineAuditor({
	id: LOCKFILES_ID,
	title: "Lockfile integrity and install scripts",
	description:
		"Checks npm, pnpm, Bun and Yarn lockfiles offline, in the spirit of lockfile-lint: packages resolved over plain HTTP, from unexpected or repository-configured registries, git or local paths outside the repository, entries without (or with SHA-1-only) integrity hashes, dependencies that run install scripts without an allow-list, and lockfiles out of date with package.json. Also flags insecure registries and pip/Composer index settings.",
	categories: ["supply-chain"],
	targets: ["codebase"],
	engine: "builtin",
	network: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const paths = (yield* ws.files).filter(isRelevant).sort();
			const findings: FindingInput[] = paths
				.filter((p) => BINARY_LOCKFILES.has(baseName(p)))
				.map((p) =>
					uncheckedFinding(
						"unparseable-lockfile",
						p,
						`${p} is a binary lockfile, which openaudit cannot read. Run \`bun install --save-text-lockfile\` to migrate to bun.lock.`,
					),
				);
			const read = yield* Effect.forEach(
				paths.filter((p) => !BINARY_LOCKFILES.has(baseName(p))),
				(p) => readLarge(ws, p),
				{ concurrency: 16 },
			);
			const files: SourceFile[] = [];
			for (const f of read) {
				if (!f) continue;
				if ("text" in f) files.push(f);
				else
					findings.push(
						uncheckedFinding(
							"truncated",
							f.path,
							`${f.path} is ${(f.size / 1024 / 1024).toFixed(1)} MB, above the ${MAX_LOCKFILE_BYTES / 1024 / 1024} MB limit.`,
						),
					);
			}
			const lockfileList = files.filter(
				(f) => baseName(f.path) in LOCKFILE_PARSERS,
			);
			if (
				!lockfileList.length &&
				!findings.length &&
				!files.some((f) => baseName(f.path) !== "package.json")
			)
				return yield* skip(
					"No lockfiles, package-manager configs, requirements files or composer.json found",
				);

			const configs = new Map<string, FileConfig>();
			const manifests = new Map<string, SourceFile>();
			for (const f of files) {
				const name = baseName(f.path);
				const reader = CONFIG_READERS[name];
				if (reader) {
					const config: FileConfig = { file: f.path, registries: [] };
					reader(f, config);
					configs.set(f.path, config);
					findings.push(...configFindings(config));
				}
				if (name === "package.json") manifests.set(f.path, f);
				const other = OTHER_READERS[name];
				if (other) findings.push(...other(f));
			}

			// pip follows -r/-c includes, whatever their names, so do we.
			const queue = files.filter((f) => isRequirements(f.path));
			const seen = new Set(queue.map((f) => f.path));
			for (let f = queue.shift(); f; f = queue.shift()) {
				const result = requirementsFindings(f);
				findings.push(...result.findings);
				for (const include of result.includes) {
					const path = resolveInRepo(dirOf(f.path), include);
					if (!path || seen.has(path) || seen.size >= MAX_REQUIREMENTS_FILES)
						continue;
					seen.add(path);
					const included = yield* readLarge(ws, path);
					if (included && "text" in included) queue.push(included);
				}
			}

			for (const f of lockfileList) {
				const lock = parseLockfile(f);
				if (!lock) {
					findings.push(
						uncheckedFinding(
							"unparseable-lockfile",
							f.path,
							`${f.path} could not be parsed.`,
						),
					);
					continue;
				}
				findings.push(
					...lockfileFindings(lock, configsFor(configs, lock), manifests),
				);
			}
			return findings;
		}),
});
