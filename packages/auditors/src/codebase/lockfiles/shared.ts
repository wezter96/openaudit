import type { Severity } from "@openaudit/core";

import { isRecord, lineLocator, parseJsonc } from "../util";

export const LOCKFILES_ID = "code.lockfiles";

/**
 * Per-entry findings of one rule per file; the rest are summarised in one
 * more finding of the same rule. Every entry is still checked.
 */
export const MAX_FINDINGS_PER_RULE = 100;

/** Lockfiles above this size are reported as unchecked. */
export const MAX_LOCKFILE_BYTES = 20 * 1024 * 1024;

/** Text searches for a location per file; later findings get no line. */
const MAX_LINE_SEARCHES = 50;

export const dirOf = (path: string) => {
	const i = path.lastIndexOf("/");
	return i === -1 ? "" : path.slice(0, i);
};

export const joinDir = (a: string, b: string) =>
	[a, b].filter((s) => s && s !== ".").join("/");

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
export type Importer = Map<string, ReadonlyArray<string> | undefined>;

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
	/** Parts of the file that could not be checked. */
	readonly problems?: ReadonlyArray<Problem>;
}

/** Why part of a lockfile was not checked. */
export interface Problem {
	readonly severity: Severity;
	/** A few words for the evidence, distinct per kind of problem. */
	readonly what: string;
	readonly reason: string;
}

export const str = (v: unknown): string | undefined =>
	typeof v === "string" ? v : undefined;

const typeName = (v: unknown) =>
	v === null ? "null" : Array.isArray(v) ? "array" : typeof v;

/**
 * A field that names where a package comes from. A value that is not a
 * string becomes a marker that classifies as an unknown source, so it is
 * reported instead of being read as "no URL, so the registry".
 */
export const sourceField = (v: unknown): string | undefined =>
	v === undefined || v === null
		? undefined
		: typeof v === "string"
			? v
			: `(${typeName(v)} value)`;

/** A lockfile entry that is not the shape the format defines. */
export const malformedEntry = (
	name: string,
	value: unknown,
	line: number | undefined,
): LockedPackage => ({ name, source: `(${typeName(value)} entry)`, line });

/** A problem for a `lockfileVersion` outside `known`, or none. */
export const versionProblem = (
	version: unknown,
	known: ReadonlyArray<number>,
): Problem[] => {
	const v = Number.parseInt(String(version ?? ""), 10);
	// Only a version number is echoed; anything else is file content.
	const raw = String(version ?? "none");
	const shown = /^\d{1,6}(\.\d{1,6})?$/.test(raw) ? raw : "not a number";
	return known.includes(v)
		? []
		: [
				{
					severity: "low",
					what: `format version ${shown}`,
					reason: `Its format version (${shown}) is not one openaudit recognises, so entries may have been missed.`,
				},
			];
};

/** A YAML or Yarn scalar as text (js-yaml's FAILSAFE schema keeps every scalar a string). */
export const scalar = (v: unknown): string | undefined =>
	typeof v === "string" || typeof v === "number" || typeof v === "boolean"
		? String(v)
		: undefined;

export const strings = (v: unknown): string[] =>
	Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];

/** Every package manager here ignores a leading byte-order mark. */
export const stripBom = (text: string) =>
	text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;

export const parseJson = (text: string): unknown => {
	const t = stripBom(text);
	try {
		return JSON.parse(t);
	} catch {
		return parseJsonc(t);
	}
};

/** Strips quotes; double-quoted strings are JSON-decoded like Yarn does. */
export const unquote = (s: string) => {
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

export const DEP_FIELDS = [
	"dependencies",
	"devDependencies",
	"optionalDependencies",
] as const;

/** `dependencies` + `devDependencies` + `optionalDependencies` specs. */
export const declaredSpecs = (pkg: Record<string, unknown>): Importer => {
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
export const jsonKeyLines = (
	text: string,
	section: string,
): Map<string, number> => {
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
 * Lines of block-style `key:` lines: the first indentation level under the
 * top-level `section`, or top-level keys when `section` is undefined.
 */
export const yamlKeyLines = (
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
export const shiftLines = (
	lock: Lockfile,
	map: (line: number) => number,
): Lockfile => ({
	...lock,
	packages: lock.packages.map((p) =>
		p.line === undefined ? p : { ...p, line: map(p.line) },
	),
});

/** One lockfile from several parses of the same file (documents, conflict sides). */
export const mergeLockfiles = (
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
		problems: uniqueProblems(locks.flatMap((l) => l.problems ?? [])),
	};
};

export const uniqueProblems = (problems: ReadonlyArray<Problem>): Problem[] => {
	const seen = new Set<string>();
	return problems.filter((p) => !seen.has(p.what) && seen.add(p.what));
};

/**
 * One YAML document, parsed with Bun's YAML parser: it applies `<<` merge
 * keys like pnpm's js-yaml and lets a repeated key override the earlier one
 * like Yarn 2+ (js-yaml with `json: true`), and it is fast on large lockfiles.
 * Values that js-yaml's FAILSAFE schema keeps as strings (Yarn) may come back
 * as numbers or booleans, so callers compare them as strings. A stream of
 * several documents is an error, as it is for js-yaml's `load`.
 */
export const parseYaml = (text: string): unknown => {
	const doc: unknown = Bun.YAML.parse(text);
	if (Array.isArray(doc) && /^---|\n---/.test(text))
		throw new Error("Expected a single YAML document");
	return doc;
};

/** The line of the first occurrence of `needle`, within a search budget. */
export const lineFinder = (text: string) => {
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
