import {
	defineAuditor,
	type FindingInput,
	requireWorkspace,
	type Severity,
	skip,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";
import { parse as parseYaml } from "yaml";

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
 */

export const LOCKFILES_ID = "code.lockfiles";

/** Lockfile entries checked per lockfile; the rest are disclosed, not checked. */
export const MAX_LOCKFILE_ENTRIES = 5000;
/** Lockfiles above this size are disclosed and skipped. */
const MAX_LOCKFILE_BYTES = 20 * 1024 * 1024;
/** Text searches for a location per file; later findings get no line. */
const MAX_LINE_SEARCHES = 50;

/** Hosts every JavaScript package manager treats as the public registry. */
const DEFAULT_REGISTRY_HOSTS = [
	"registry.npmjs.org",
	"registry.yarnpkg.com",
	"npm.pkg.github.com",
];

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
	  };

const REGISTRY: Source = { kind: "registry" };
const IGNORED: Source = { kind: "ignored" };

const COMMIT = /^[0-9a-f]{7,40}$/i;

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

/** Classifies where a lockfile entry is fetched from. */
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
	const hash = s.indexOf("#");
	const base = hash === -1 ? s : s.slice(0, hash);
	const fragment = hash === -1 ? undefined : s.slice(hash + 1);
	if (
		[
			"git+",
			"git:",
			"git@",
			"ssh:",
			"github:",
			"gitlab:",
			"bitbucket:",
			"gist:",
		].some((p) => lower.startsWith(p)) ||
		base.toLowerCase().endsWith(".git")
	) {
		const ref = gitRef(fragment);
		return {
			kind: "git",
			url: base,
			...(ref ? { ref } : {}),
			pinned: ref !== undefined && COMMIT.test(ref),
			insecure: lower.startsWith("git://") || lower.startsWith("git+http://"),
		};
	}
	if (lower.startsWith("http://") || lower.startsWith("https://")) {
		const insecure = lower.startsWith("http://");
		let url: URL;
		try {
			url = new URL(s);
		} catch {
			return { kind: "tarball", url: s, host: "", insecure };
		}
		const ref = archiveRef(url);
		if (ref !== undefined)
			return {
				kind: "git",
				url: base,
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
	return IGNORED;
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

/* -------------------------------------------------------------------------- */
/*                                  Parsing                                   */
/* -------------------------------------------------------------------------- */

export type Manager = "npm" | "bun" | "pnpm" | "yarn" | "yarn-berry";

export interface LockedPackage {
	readonly name: string;
	readonly version?: string;
	/** Where it is fetched from; `undefined` for the default registry. */
	readonly source?: string;
	/** Directory a relative path source is relative to (lockfile-relative). */
	readonly base?: string;
	readonly integrity?: string;
	readonly installScript?: boolean;
	/** Shipped inside its parent's tarball (npm `inBundle`). */
	readonly bundled?: boolean;
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

const strings = (v: unknown): string[] =>
	Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];

const parseJson = (text: string): unknown => {
	try {
		return JSON.parse(text);
	} catch {
		return parseJsonc(text);
	}
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
 * 1-based lines of `"key":` lines after the first line that starts with
 * `section` (first occurrence wins). Linear: no regex backtracking.
 */
const jsonKeyLines = (text: string, section: string): Map<string, number> => {
	const out = new Map<string, number>();
	const lines = text.split("\n");
	let started = false;
	for (let i = 0; i < lines.length; i++) {
		const t = (lines[i] ?? "").trimStart();
		if (!started) {
			started = t.startsWith(section);
			continue;
		}
		if (!t.startsWith('"')) continue;
		const end = t.indexOf('"', 1);
		if (end === -1 || t[end + 1] !== ":") continue;
		const key = t.slice(1, end);
		if (!out.has(key)) out.set(key, i + 1);
	}
	return out;
};

/** npm package-lock.json / npm-shrinkwrap.json, lockfile v1 to v3. */
export const parseNpmLock = (file: SourceFile): Lockfile | undefined => {
	const json = parseJson(file.text);
	if (!isRecord(json)) return undefined;
	const packages: LockedPackage[] = [];
	const importers = new Map<string, Importer>();
	if (isRecord(json.packages)) {
		const lines = jsonKeyLines(file.text, '"packages"');
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
	} else if (isRecord(json.dependencies)) {
		const lines = jsonKeyLines(file.text, '"dependencies"');
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
	const json = parseJsonc(file.text);
	if (!isRecord(json) || !isRecord(json.packages)) return undefined;
	const lines = jsonKeyLines(file.text, '"packages"');
	const packages: LockedPackage[] = [];
	for (const [key, value] of Object.entries(json.packages)) {
		if (!Array.isArray(value) || typeof value[0] !== "string") continue;
		const ident = value[0];
		const at = ident.indexOf("@", 1);
		if (at === -1) continue;
		const name = ident.slice(0, at);
		const spec = ident.slice(at + 1);
		const last = value[value.length - 1];
		const integrity =
			typeof last === "string" && /^sha\d+-/.test(last) ? last : undefined;
		const registryVersion = /^\d/.test(spec);
		packages.push({
			name,
			...(registryVersion ? { version: spec } : {}),
			// Registry entries carry the registry URL ("" for the default).
			source: registryVersion ? str(value[1]) || undefined : spec,
			integrity,
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

/** Lines of two-space-indented `key:` lines in pnpm's `packages:` section. */
const pnpmKeyLines = (text: string): Map<string, number> => {
	const out = new Map<string, number>();
	const lines = text.split("\n");
	let section = "";
	for (let i = 0; i < lines.length; i++) {
		const line = (lines[i] ?? "").trimEnd();
		if (line && line[0] !== " ") {
			section = line;
			continue;
		}
		if (section !== "packages:" || !line.startsWith("  ") || line[2] === " ")
			continue;
		if (!line.endsWith(":")) continue;
		let key = line.slice(2, -1);
		if (key.length > 1 && (key[0] === "'" || key[0] === '"'))
			key = key.slice(1, -1);
		if (!out.has(key)) out.set(key, i + 1);
	}
	return out;
};

/** pnpm-lock.yaml v5, v6 and v9. */
export const parsePnpmLock = (file: SourceFile): Lockfile | undefined => {
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
	// pnpm records an overridden dependency with the override as its specifier.
	const overridden = new Set(
		Object.keys(isRecord(doc.overrides) ? doc.overrides : {})
			.filter((k) => !k.includes(">"))
			.map(pnpmName),
	);
	const lineOf = lineFinder(file.text);
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
	if (isRecord(doc.packages)) {
		const lines = pnpmKeyLines(file.text);
		for (const [key, value] of Object.entries(doc.packages)) {
			if (!isRecord(value)) continue;
			const res = isRecord(value.resolution) ? value.resolution : {};
			const source =
				typeof res.directory === "string"
					? `file:${res.directory}`
					: res.type === "git" && typeof res.repo === "string"
						? `git+${res.repo}#${str(res.commit) ?? ""}`
						: str(res.tarball);
			const name = str(value.name) ?? pnpmName(key);
			const at = key.lastIndexOf("@");
			const keyVersion = at > 0 ? key.slice(at + 1).split("(")[0] : undefined;
			packages.push({
				name,
				version:
					str(value.version) ??
					(keyVersion && /^\d/.test(keyVersion) ? keyVersion : undefined),
				source,
				integrity: str(res.integrity),
				installScript: value.requiresBuild === true,
				line: lines.get(key),
			});
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

const unquote = (s: string) =>
	s.length >= 2 && (s[0] === '"' || s[0] === "'") && s.endsWith(s[0])
		? s.slice(1, -1)
		: s;

interface YarnEntry {
	readonly specs: string[];
	readonly line: number;
	readonly fields: Map<string, string>;
	readonly dependencies: Map<string, string>;
}

/** Line parser shared by yarn.lock v1 and Berry (YAML) lockfiles. */
const yarnEntries = (text: string): YarnEntry[] => {
	const out: YarnEntry[] = [];
	let current: YarnEntry | undefined;
	let block = "";
	const lines = text.split("\n");
	for (let i = 0; i < lines.length; i++) {
		const line = (lines[i] ?? "").trimEnd();
		if (!line || line.startsWith("#")) continue;
		if (line[0] !== " ") {
			current = undefined;
			if (!line.endsWith(":") || line.startsWith("__metadata")) continue;
			current = {
				specs: line
					.slice(0, -1)
					.split(",")
					.map((s) => unquote(s.trim()))
					.filter(Boolean),
				line: i + 1,
				fields: new Map(),
				dependencies: new Map(),
			};
			out.push(current);
			continue;
		}
		if (!current) continue;
		const indented4 = line.startsWith("    ") && line[4] !== " ";
		const indented2 = line.startsWith("  ") && line[2] !== " ";
		const t = line.trim();
		const sp = t.indexOf(" ");
		const key = unquote((sp === -1 ? t : t.slice(0, sp)).replace(/:$/, ""));
		const value = sp === -1 ? "" : unquote(t.slice(sp + 1).trim());
		if (indented2) {
			block = key;
			if (value) current.fields.set(key, value);
		} else if (indented4 && block === "dependencies" && value)
			current.dependencies.set(key, value);
	}
	return out;
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

/** yarn.lock: classic v1 and Berry (v2+, recognised by `__metadata`). */
export const parseYarnLock = (file: SourceFile): Lockfile => {
	const berry =
		file.text.includes("\n__metadata:") || file.text.startsWith("__metadata:");
	const packages: LockedPackage[] = [];
	const importers = new Map<string, Importer>();
	const rootSpecs: Importer = new Map();
	for (const entry of yarnEntries(file.text)) {
		const version = entry.fields.get("version");
		if (berry) {
			const resolution = entry.fields.get("resolution") ?? entry.specs[0] ?? "";
			const name = nameOfSpec(resolution);
			const spec = resolution.slice(name.length + 1);
			if (spec.startsWith("workspace:")) {
				const dir = spec.slice("workspace:".length);
				importers.set(
					dir === "." ? "" : dir,
					new Map([...entry.dependencies.keys()].map((n) => [n, undefined])),
				);
				continue;
			}
			const params = spec.indexOf("::");
			const bare = params === -1 ? spec : spec.slice(0, params);
			const isPath = /^(file|link|portal):/.test(bare);
			const checksum = entry.fields.get("checksum");
			packages.push({
				name,
				version,
				source: isPath ? bare.split("#")[0] : bare,
				...(isPath && params !== -1
					? { base: berryLocatorDir(spec.slice(params + 2)) }
					: {}),
				// Berry checksums are SHA-512 digests of the package archive.
				integrity: checksum ? `sha512-${checksum}` : undefined,
				line: entry.line,
			});
			continue;
		}
		for (const spec of entry.specs) {
			const name = nameOfSpec(spec);
			rootSpecs.set(name, [
				...(rootSpecs.get(name) ?? []),
				spec.slice(name.length + 1),
			]);
		}
		const first = entry.specs[0] ?? "";
		const name = nameOfSpec(first);
		const declared = first.slice(name.length + 1);
		let resolved = entry.fields.get("resolved");
		let integrity = entry.fields.get("integrity");
		const source = classifySource(resolved);
		// Classic yarn appends the tarball's SHA-1 to registry and tarball URLs.
		if (resolved && source.kind === "tarball") {
			const hash = resolved.indexOf("#");
			if (hash !== -1) {
				const sha1 = resolved.slice(hash + 1);
				resolved = resolved.slice(0, hash);
				if (!integrity && /^[0-9a-f]{40}$/i.test(sha1))
					integrity = `sha1-${sha1}`;
			}
		}
		if (resolved && source.kind === "git") {
			const hash = resolved.indexOf("#");
			const sha1 = hash === -1 ? "" : resolved.slice(hash + 1);
			// codeload archives carry the archive's SHA-1, not a ref.
			if (
				!integrity &&
				/^https?:/.test(resolved) &&
				/^[0-9a-f]{40}$/i.test(sha1)
			) {
				integrity = `sha1-${sha1}`;
				resolved = resolved.slice(0, hash);
			}
		}
		packages.push({
			name,
			version,
			source:
				resolved ?? (/^(file|link):/.test(declared) ? declared : undefined),
			integrity,
			line: entry.line,
		});
	}
	if (!berry) importers.set("", rootSpecs);
	return {
		path: file.path,
		manager: berry ? "yarn-berry" : "yarn",
		packages,
		importers,
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
}

/** What one directory's package-manager configs declare. */
export interface DirConfig {
	registries: Registry[];
	ignoreScripts?: Setting;
	strictSslOff?: Setting;
	/** pnpm `onlyBuiltDependencies` (allow-list). */
	onlyBuilt?: string[];
	/** pnpm `neverBuiltDependencies` (deny-list). */
	neverBuilt?: string[];
	/** pnpm `dangerouslyAllowAllBuilds`. */
	allowAllBuilds?: Setting;
	/** package.json `trustedDependencies` (Bun's allow-list). */
	trusted?: string[];
	/** Source of `onlyBuilt` / `trusted`, for messages. */
	allowListFile?: string;
}

const newConfig = (): DirConfig => ({ registries: [] });

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

/** `.npmrc`: `registry`, `@scope:registry`, `ignore-scripts`, `strict-ssl`. */
const readNpmrc = (file: SourceFile, config: DirConfig) => {
	file.text.split("\n").forEach((raw, i) => {
		const t = raw.trim();
		if (!t || t[0] === "#" || t[0] === ";") return;
		const eq = t.indexOf("=");
		if (eq === -1) return;
		const key = t.slice(0, eq).trim();
		const value = unquote(t.slice(eq + 1).trim());
		const at = { file: file.path, line: i + 1 };
		if (key === "registry" || key.endsWith(":registry"))
			config.registries.push({
				...at,
				url: value,
				evidence: `${key}=${displayUrl(value)}`,
			});
		else if (key === "ignore-scripts" && value === "true")
			config.ignoreScripts = { ...at, evidence: t };
		else if (key === "strict-ssl" && value === "false")
			config.strictSslOff = { ...at, evidence: t };
	});
};

/** Classic `.yarnrc`: `registry "url"`, `"@scope:registry" "url"`, … */
const readYarnrc = (file: SourceFile, config: DirConfig) => {
	file.text.split("\n").forEach((raw, i) => {
		const t = raw.trim();
		if (!t || t[0] === "#") return;
		const sp = t.search(/\s/);
		if (sp === -1) return;
		const key = unquote(t.slice(0, sp));
		const value = unquote(t.slice(sp + 1).trim());
		const at = { file: file.path, line: i + 1 };
		if (key === "registry" || key.endsWith(":registry"))
			config.registries.push({
				...at,
				url: value,
				evidence: `${key} ${displayUrl(value)}`,
			});
		else if (key === "ignore-scripts" && value === "true")
			config.ignoreScripts = { ...at, evidence: t };
		else if (key === "strict-ssl" && value === "false")
			config.strictSslOff = { ...at, evidence: t };
	});
};

/** `.yarnrc.yml`: `npmRegistryServer`, `npmScopes.*`, `enableStrictSsl`, `enableScripts`. */
const readYarnrcYml = (file: SourceFile, config: DirConfig) => {
	let doc: unknown;
	try {
		doc = parseYaml(file.text);
	} catch {
		return;
	}
	if (!isRecord(doc)) return;
	const lineOf = lineFinder(file.text);
	const registry = (value: unknown) => {
		if (typeof value !== "string") return;
		config.registries.push({
			file: file.path,
			line: lineOf(value),
			url: value,
			evidence: `npmRegistryServer: ${displayUrl(value)}`,
		});
	};
	registry(doc.npmRegistryServer);
	if (isRecord(doc.npmScopes))
		for (const scope of Object.values(doc.npmScopes))
			if (isRecord(scope)) registry(scope.npmRegistryServer);
	if (doc.enableStrictSsl === false)
		config.strictSslOff = {
			file: file.path,
			line: lineOf("enableStrictSsl"),
			evidence: "enableStrictSsl: false",
		};
	if (doc.enableScripts === false)
		config.ignoreScripts = {
			file: file.path,
			line: lineOf("enableScripts"),
			evidence: "enableScripts: false",
		};
};

/** bunfig.toml: `[install] registry` and `[install.scopes]` URLs. */
const readBunfig = (file: SourceFile, config: DirConfig) => {
	let section = "";
	file.text.split("\n").forEach((raw, i) => {
		const t = raw.trim();
		if (t.startsWith("[")) {
			section = t;
			return;
		}
		const isRegistry =
			(section === "[install]" && t.startsWith("registry")) ||
			section === "[install.scopes]";
		if (!isRegistry) return;
		const start = t.indexOf('"http');
		if (start === -1) return;
		const end = t.indexOf('"', start + 1);
		if (end === -1) return;
		const url = t.slice(start + 1, end);
		config.registries.push({
			file: file.path,
			line: i + 1,
			url,
			evidence: `registry = ${displayUrl(url)}`,
		});
	});
};

/** pnpm-workspace.yaml build settings. */
const readPnpmWorkspace = (file: SourceFile, config: DirConfig) => {
	let doc: unknown;
	try {
		doc = parseYaml(file.text);
	} catch {
		return;
	}
	if (!isRecord(doc)) return;
	readPnpmBuildSettings(doc, file, config);
};

const readPnpmBuildSettings = (
	settings: Record<string, unknown>,
	file: SourceFile,
	config: DirConfig,
) => {
	if (Array.isArray(settings.onlyBuiltDependencies)) {
		config.onlyBuilt = strings(settings.onlyBuiltDependencies);
		config.allowListFile = file.path;
	}
	if (Array.isArray(settings.neverBuiltDependencies))
		config.neverBuilt = strings(settings.neverBuiltDependencies);
	if (settings.dangerouslyAllowAllBuilds === true)
		config.allowAllBuilds = {
			file: file.path,
			line: lineFinder(file.text)("dangerouslyAllowAllBuilds"),
			evidence: "dangerouslyAllowAllBuilds: true",
		};
};

/** package.json: `pnpm.*` build settings and Bun's `trustedDependencies`. */
const readPackageJson = (file: SourceFile, config: DirConfig) => {
	const json = parseJson(file.text);
	if (!isRecord(json)) return;
	if (isRecord(json.pnpm)) readPnpmBuildSettings(json.pnpm, file, config);
	if (Array.isArray(json.trustedDependencies)) {
		config.trusted = strings(json.trustedDependencies);
		config.allowListFile ??= file.path;
	}
};

const CONFIG_READERS: Readonly<
	Record<string, (file: SourceFile, config: DirConfig) => void>
> = {
	".npmrc": readNpmrc,
	".yarnrc": readYarnrc,
	".yarnrc.yml": readYarnrcYml,
	"bunfig.toml": readBunfig,
	"pnpm-workspace.yaml": readPnpmWorkspace,
	"package.json": readPackageJson,
};

/** Configs of `dir` and its ancestors, nearest first. */
const configsFor = (
	configs: ReadonlyMap<string, DirConfig>,
	dir: string,
): DirConfig[] => {
	const out: DirConfig[] = [];
	let d = dir;
	for (;;) {
		const c = configs.get(d);
		if (c) out.push(c);
		if (!d) return out;
		d = dirOf(d);
	}
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
		`${what} is downloaded over ${evidence.includes("git://") ? "the unencrypted git:// protocol" : "plain HTTP"}, so anyone on the network path can substitute the code that gets installed.`,
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
): FindingInput => ({
	...base,
	ruleId: rule("git-dependency"),
	title: truncate(
		`${name} is installed from a git host instead of a registry`,
		120,
	),
	severity: pinned ? "low" : "medium",
	message: truncate(
		`${name} is installed from ${how}. It bypasses the registry's integrity metadata, advisories and malware scanning${pinned ? "." : ", and the lockfile does not pin its content to a commit or hash, so the same lockfile can install different code tomorrow."}`,
		500,
	),
	location: { file, line },
	evidence: truncate(evidence),
	remediation: pinned
		? "Prefer a published registry version. If the git dependency is needed, keep it pinned to a full commit SHA and review updates."
		: "Pin the dependency to a full commit SHA (or publish it to a registry) and regenerate the lockfile.",
	references: [LOCKFILE_LINT, cweUrl(829), ...(pinned ? [] : [cweUrl(1357)])],
	tags: ["cwe-829", ...(pinned ? [] : ["cwe-1357"])],
});

/** One finding for an entry's source, or none. */
const sourceFinding = (
	lock: Lockfile,
	p: LockedPackage,
	allowedHosts: ReadonlySet<string>,
): FindingInput | undefined => {
	const source = classifySource(p.source);
	const file = lock.path;
	const evidence = (s: string) => `${label(p)}: ${s}`;
	switch (source.kind) {
		case "registry":
		case "ignored":
			return undefined;
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
			const pinned = source.pinned || p.integrity !== undefined;
			return gitFinding(
				file,
				p.line,
				p.name,
				evidence(shown),
				pinned,
				source.ref
					? `${displayUrl(source.url)} at "${truncate(source.ref, 60)}"`
					: displayUrl(source.url),
			);
		}
		case "tarball": {
			const shown = displayUrl(source.url);
			if (source.insecure)
				return insecureFinding(file, p.line, p.name, evidence(shown));
			if (allowedHosts.has(source.host)) return undefined;
			return {
				...base,
				ruleId: rule("unexpected-host"),
				title: truncate(
					`${p.name} is downloaded from ${source.host || "an unknown host"}`,
					120,
				),
				severity: "medium",
				message: truncate(
					`${label(p)} resolves to ${shown}, which is neither the public npm registry nor a registry configured in .npmrc, .yarnrc(.yml) or bunfig.toml. A lockfile that points a package at another host is a known way to slip in a modified package${p.integrity ? "" : ", and this entry has no integrity hash either"}.`,
					500,
				),
				location: { file, line: p.line },
				evidence: evidence(shown),
				remediation:
					"If the host is your private registry, configure it in .npmrc (registry= or @scope:registry=), .yarnrc.yml (npmRegistryServer) or bunfig.toml. Otherwise reinstall the package from the registry and regenerate the lockfile.",
				references: [LOCKFILE_LINT, cweUrl(829), owaspUrl("a08")],
				tags: ["cwe-829", "owasp-a08"],
			};
		}
	}
};

/** SRI algorithms in an integrity string (`sha512-… sha1-…`). */
const algorithms = (integrity: string) =>
	integrity
		.split(/\s+/)
		.filter(Boolean)
		.map((t) => t.slice(0, t.indexOf("-")).toLowerCase());

const integrityFindings = (
	lock: Lockfile,
	checked: ReadonlyArray<LockedPackage>,
): FindingInput[] => {
	const missing: LockedPackage[] = [];
	const weak: LockedPackage[] = [];
	for (const p of checked) {
		if (p.bundled) continue;
		const kind = classifySource(p.source).kind;
		if (kind !== "registry" && kind !== "tarball") continue;
		// npm workspaces and the root are not downloaded.
		if (lock.manager === "npm" && !p.version && !p.source) continue;
		if (!p.integrity) missing.push(p);
		else if (algorithms(p.integrity).every((a) => a === "sha1")) weak.push(p);
	}
	const out: FindingInput[] = [];
	const names = (ps: ReadonlyArray<LockedPackage>) => ps.map(label);
	if (missing.length)
		out.push({
			...base,
			ruleId: rule("missing-integrity"),
			title: `${missing.length} ${missing.length === 1 ? "entry" : "entries"} in ${baseName(lock.path)} ${missing.length === 1 ? "has" : "have"} no integrity hash`,
			severity: "low",
			message: truncate(
				`The lockfile records no integrity hash for ${listNames(names(missing))}. The package manager cannot detect a tarball that was changed on the server or in transit.`,
				600,
			),
			location: { file: lock.path, line: missing[0]?.line },
			evidence: truncate(names(missing).join(", ")),
			remediation:
				"Delete the affected entries (or the lockfile) and reinstall with a current package manager so it records integrity hashes; then commit the lockfile.",
			references: [LOCKFILE_LINT, NPM_LOCKFILE, cweUrl(494), owaspUrl("a08")],
			tags: ["cwe-494", "owasp-a08"],
		});
	if (weak.length)
		out.push({
			...base,
			ruleId: rule("weak-integrity"),
			title: `${weak.length} ${weak.length === 1 ? "entry" : "entries"} in ${baseName(lock.path)} ${weak.length === 1 ? "is" : "are"} only checked with SHA-1`,
			severity: "low",
			message: truncate(
				`The only integrity hash recorded for ${listNames(names(weak))} is SHA-1, which is no longer collision resistant.`,
				600,
			),
			location: { file: lock.path, line: weak[0]?.line },
			evidence: truncate(names(weak).join(", ")),
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
	/** A setting that lets every package run scripts (pnpm allow-all). */
	readonly allowAll?: Setting;
}

const uniqueByName = (ps: ReadonlyArray<LockedPackage>) => {
	const seen = new Set<string>();
	return ps.filter((p) => !seen.has(p.name) && seen.add(p.name));
};

const scriptPolicy = (
	lock: Lockfile,
	checked: ReadonlyArray<LockedPackage>,
	configs: ReadonlyArray<DirConfig>,
): ScriptPolicy | undefined => {
	const find = <K extends keyof DirConfig>(key: K) =>
		configs.find((c) => c[key] !== undefined);
	const marked = uniqueByName(checked.filter((p) => p.installScript));
	const ignore = find("ignoreScripts")?.ignoreScripts;
	const byName = new Map(uniqueByName(checked).map((p) => [p.name, p]));
	const listed = (names: ReadonlyArray<string>) =>
		names.map((n) => byName.get(n) ?? { name: n });
	switch (lock.manager) {
		case "npm": {
			const other = find("onlyBuilt") ?? find("trusted");
			const note = other
				? ` ${other.allowListFile ?? "package.json"} declares an install-script allow-list for pnpm or Bun, which npm ignores.`
				: "";
			return {
				scripted: marked,
				ungated: ignore ? [] : marked,
				gate: ignore
					? `${ignore.file} sets ignore-scripts, so npm runs none of them.`
					: `npm runs every one of them on install because ignore-scripts is not set.${note}`,
				references: [NPM_SCRIPTS, NPM_IGNORE_SCRIPTS, SOCKET_INSTALL_SCRIPTS],
			};
		}
		case "pnpm": {
			const cfg = find("onlyBuilt");
			const never = new Set(find("neverBuilt")?.neverBuilt ?? []);
			const allowAll = find("allowAllBuilds")?.allowAllBuilds;
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
					gate: `${allowAll.file} sets dangerouslyAllowAllBuilds, so pnpm runs every install script.`,
					references,
					allowAll,
				};
			if (cfg?.onlyBuilt) {
				const allowed = new Set(cfg.onlyBuilt);
				return {
					scripted: uniqueByName([
						...marked,
						...listed(cfg.onlyBuilt.filter((n) => byName.has(n))),
					]),
					ungated: [],
					gate: `pnpm only runs the scripts of packages in onlyBuiltDependencies (${cfg.allowListFile}): ${listNames(cfg.onlyBuilt)}.${marked.some((p) => !allowed.has(p.name)) ? " The others are blocked." : ""}`,
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
			const trusted = lock.trusted?.length
				? lock.trusted
				: (find("trusted")?.trusted ?? []);
			return {
				scripted: listed(trusted),
				ungated: [],
				gate: "Bun only runs the lifecycle scripts of packages in trustedDependencies (and of its built-in default allow-list); bun.lock does not record which packages actually have scripts.",
				references: [BUN_LIFECYCLE, SOCKET_INSTALL_SCRIPTS],
			};
		}
		default:
			return undefined;
	}
};

const installScriptFindings = (
	lock: Lockfile,
	checked: ReadonlyArray<LockedPackage>,
	configs: ReadonlyArray<DirConfig>,
): FindingInput[] => {
	const policy = scriptPolicy(lock, checked, configs);
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
		out.push({
			...base,
			ruleId: rule("ungated-install-scripts"),
			title: ungated.length
				? `${ungated.length} install ${ungated.length === 1 ? "script runs" : "scripts run"} without an allow-list`
				: "Every dependency may run install scripts",
			severity: "low",
			message: truncate(
				`${listNames(shown, 20)} ${shown.length === 1 ? "runs" : "run"} code on install without being approved by an allow-list. ${policy.gate} A compromised version of any of them runs on every developer machine and CI runner that installs dependencies.`,
				1000,
			),
			location:
				policy.allowAll && !ungated.length
					? { file: policy.allowAll.file, line: policy.allowAll.line }
					: { file: lock.path, line: firstLine(policy.ungated) },
			evidence: truncate(
				policy.allowAll && !ungated.length
					? policy.allowAll.evidence
					: ungated.join(", "),
			),
			remediation:
				"Gate install scripts: with npm set ignore-scripts=true in .npmrc and allow the few packages that need them (for example with @lavamoat/allow-scripts); with pnpm list them in onlyBuiltDependencies; with Bun in trustedDependencies.",
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

const truncatedFinding = (
	file: string,
	message: string,
	evidence: string,
): FindingInput => ({
	...base,
	ruleId: rule("truncated"),
	title: `${baseName(file)} was only partly checked`,
	severity: "info",
	message,
	location: { file },
	evidence,
	remediation:
		"Audit large monorepo packages separately, or check the lockfile with lockfile-lint.",
	references: [LOCKFILE_LINT],
	tags: ["lockfile"],
});

/** All findings for one parsed lockfile. */
export const lockfileFindings = (
	lock: Lockfile,
	configs: ReadonlyArray<DirConfig>,
	manifests: ReadonlyMap<string, SourceFile>,
): FindingInput[] => {
	const allowedHosts = new Set(DEFAULT_REGISTRY_HOSTS);
	for (const c of configs)
		for (const r of c.registries)
			try {
				allowedHosts.add(new URL(r.url).hostname.toLowerCase());
			} catch {
				// Not a URL: nothing to allow.
			}
	const checked = lock.packages.slice(0, MAX_LOCKFILE_ENTRIES);
	const findings: FindingInput[] = [];
	for (const p of checked) {
		const f = sourceFinding(lock, p, allowedHosts);
		if (f) findings.push(f);
	}
	findings.push(...integrityFindings(lock, checked));
	findings.push(...installScriptFindings(lock, checked, configs));
	const lockDir = dirOf(lock.path);
	for (const [dir, importer] of lock.importers) {
		if (escapesRoot(lockDir, dir)) continue;
		const manifest = manifests.get(
			joinDir(joinDir(lockDir, dir), "package.json"),
		);
		const drift = manifest && driftFinding(lock, manifest, importer);
		if (drift) findings.push(drift);
	}
	if (lock.packages.length > MAX_LOCKFILE_ENTRIES)
		findings.push(
			truncatedFinding(
				lock.path,
				`${lock.path} lists ${lock.packages.length} entries; the first ${MAX_LOCKFILE_ENTRIES} were checked and the rest were skipped.`,
				`${lock.packages.length} entries, ${MAX_LOCKFILE_ENTRIES} checked`,
			),
		);
	return findings;
};

/** http registries and disabled TLS verification in package-manager configs. */
const configFindings = (config: DirConfig): FindingInput[] => {
	const out: FindingInput[] = [];
	for (const r of config.registries)
		if (r.url.toLowerCase().startsWith("http://"))
			out.push(
				insecureFinding(
					r.file,
					r.line,
					`The registry ${displayUrl(r.url)}`,
					r.evidence,
				),
			);
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

const PIP_VALUE_OPTIONS = new Set([
	"-i",
	"--index-url",
	"--extra-index-url",
	"-f",
	"--find-links",
	"--trusted-host",
]);

const isInsecureUrl = (s: string) => {
	const l = s.toLowerCase();
	return (
		l.startsWith("http://") ||
		l.startsWith("git://") ||
		l.startsWith("git+http://")
	);
};

/** pip requirements files: index options and plain-HTTP sources. */
export const requirementsFindings = (file: SourceFile): FindingInput[] => {
	const out: FindingInput[] = [];
	file.text.split("\n").forEach((raw, i) => {
		const hash = raw.search(/(^|\s)#/);
		const tokens = (hash === -1 ? raw : raw.slice(0, hash))
			.trim()
			.split(/\s+/)
			.filter(Boolean);
		const line = i + 1;
		for (let t = 0; t < tokens.length; t++) {
			const token = tokens[t] ?? "";
			const eq = token.indexOf("=");
			let option = token;
			let value: string | undefined;
			if (token.startsWith("--") && eq !== -1) {
				option = token.slice(0, eq);
				value = token.slice(eq + 1);
			} else if (PIP_VALUE_OPTIONS.has(token)) {
				value = tokens[t + 1];
				t++;
			}
			if (value === undefined) {
				if (isInsecureUrl(token))
					out.push(
						insecureFinding(
							file.path,
							line,
							"A requirement",
							displayUrl(token),
						),
					);
				continue;
			}
			const evidence = `${option} ${displayUrl(value)}`;
			if (option === "--trusted-host")
				out.push(
					tlsFinding(
						{ file: file.path, line, evidence },
						`pip (host ${truncate(value, 60)})`,
					),
				);
			else if (isInsecureUrl(value))
				out.push(
					insecureFinding(
						file.path,
						line,
						`The package index ${displayUrl(value)}`,
						evidence,
					),
				);
			if (option === "--extra-index-url")
				out.push({
					...base,
					ruleId: rule("extra-index-url"),
					title: "pip searches an extra package index",
					severity: "medium",
					message: truncate(
						`${file.path} adds ${displayUrl(value)} with --extra-index-url. pip treats every index as equal and installs the highest version it finds on any of them, so a public package with the same name as an internal one (dependency confusion) can win.`,
						500,
					),
					location: { file: file.path, line },
					evidence,
					remediation:
						"Use a single --index-url that proxies PyPI and your private packages (devpi, Artifactory, Nexus, CodeArtifact), or pin every package with --require-hashes.",
					references: [PIP_INSTALL, PIP_CONFUSION, cweUrl(427)],
					tags: ["cwe-427", "owasp-a08"],
				});
		}
	});
	return out;
};

/** Pipfile `[[source]]` blocks. */
export const pipfileFindings = (file: SourceFile): FindingInput[] => {
	const out: FindingInput[] = [];
	let inSource = false;
	file.text.split("\n").forEach((raw, i) => {
		const t = raw.trim();
		if (t.startsWith("[")) {
			inSource = t === "[[source]]";
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
		else if (key === "verify_ssl" && value === "false")
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
		const type = str(repo.type) ?? "";
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
	].slice(0, MAX_LOCKFILE_ENTRIES);
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
	return out;
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

const isRelevant = (path: string) => {
	if (isFixturePath(path)) return false;
	const name = baseName(path);
	return (
		name in LOCKFILE_PARSERS ||
		name in CONFIG_READERS ||
		name in OTHER_READERS ||
		isRequirements(path)
	);
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
		"Checks npm, pnpm, Bun and Yarn lockfiles offline, in the spirit of lockfile-lint: packages resolved over plain HTTP, from unexpected hosts, git or local paths outside the repository, entries without (or with SHA-1-only) integrity hashes, dependencies that run install scripts without an allow-list, and lockfiles out of date with package.json. Also flags insecure registries and pip/Composer index settings.",
	categories: ["supply-chain"],
	targets: ["codebase"],
	engine: "builtin",
	network: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const paths = (yield* ws.files).filter(isRelevant).sort();
			const read = yield* Effect.forEach(paths, (p) => readLarge(ws, p), {
				concurrency: 16,
			});
			const files: SourceFile[] = [];
			const findings: FindingInput[] = [];
			for (const f of read) {
				if (!f) continue;
				if ("text" in f) files.push(f);
				else
					findings.push(
						truncatedFinding(
							f.path,
							`${f.path} is ${(f.size / 1024 / 1024).toFixed(1)} MB, above the ${MAX_LOCKFILE_BYTES / 1024 / 1024} MB limit, and was not checked.`,
							`${f.size} bytes`,
						),
					);
			}
			const lockfileList = files.filter(
				(f) => baseName(f.path) in LOCKFILE_PARSERS,
			);
			if (
				!lockfileList.length &&
				!files.some((f) => baseName(f.path) !== "package.json")
			)
				return yield* skip(
					"No lockfiles, package-manager configs, requirements files or composer.json found",
				);

			const configs = new Map<string, DirConfig>();
			const manifests = new Map<string, SourceFile>();
			for (const f of files) {
				const name = baseName(f.path);
				const reader = CONFIG_READERS[name];
				if (reader) {
					const dir = dirOf(f.path);
					const config = configs.get(dir) ?? newConfig();
					configs.set(dir, config);
					reader(f, config);
				}
				if (name === "package.json") manifests.set(f.path, f);
				const other = OTHER_READERS[name];
				if (other) findings.push(...other(f));
				if (isRequirements(f.path)) findings.push(...requirementsFindings(f));
			}
			for (const config of configs.values())
				findings.push(...configFindings(config));

			for (const f of lockfileList) {
				const lock = LOCKFILE_PARSERS[baseName(f.path)]?.(f);
				if (!lock) continue;
				findings.push(
					...lockfileFindings(
						lock,
						configsFor(configs, dirOf(f.path)),
						manifests,
					),
				);
			}
			return findings;
		}),
});
