import { isRecord, type SourceFile } from "../util";
import {
	DEP_FIELDS,
	type Importer,
	type LockedPackage,
	type Lockfile,
	lineFinder,
	malformedEntry,
	mergeLockfiles,
	parseYaml,
	shiftLines,
	sourceField,
	str,
	versionProblem,
	yamlKeyLines,
} from "./shared";
import type { FilePath, FileText, PackageName, SourceSpec } from "./types";

/** A key of `packages` or `snapshots` (`/a/1.0.0`, `a@1.0.0(peer@2.0.0)`). */
type PackageKey = string;

/** `name` from a pnpm package key (v5 `/a/1.0.0`, v6 `/a@1.0.0`, v9 `a@1.0.0`). */
const pnpmName = (key: PackageKey): string => {
	const k = key.startsWith("/") ? key.slice(1) : key;
	const at = k.indexOf("@", 1);
	if (at > 0) return k.slice(0, at);
	const parts = k.split("/");
	return k.startsWith("@") ? parts.slice(0, 2).join("/") : (parts[0] ?? k);
};

/** pnpm's `removeSuffix`: `a@1.0.0(peer@2.0.0)` → `a@1.0.0`. */
const withoutPeerSuffix = (depPath: PackageKey) => {
	if (!depPath.endsWith(")")) return depPath;
	const i = depPath.indexOf("(", 1);
	return i === -1 ? depPath : depPath.slice(0, i);
};

interface Fetch {
	readonly source?: string;
	readonly integrity?: string;
	readonly runtime?: boolean;
}

type Resolution = Record<string, unknown>;

/** The fetches of one `resolution` shape, by its `type`. */
type FetchesOf = (
	res: Resolution,
	integrity: string | undefined,
	depth: number,
) => Fetch[];

/** A registry or tarball URL, or a directory (no `type`). */
const untypedFetches: FetchesOf = (res, integrity) => [
	{
		source:
			typeof res.directory === "string"
				? `file:${res.directory}`
				: (sourceField(res.directory) ?? sourceField(res.tarball)),
		integrity,
	},
];

/** One archive per platform of a `runtime:` dependency. */
const variationFetches: FetchesOf = (res, _integrity, depth) => {
	if (depth > 2 || !Array.isArray(res.variants))
		return [{ source: "variations:" }];
	return res.variants.flatMap((v) =>
		pnpmFetches(isRecord(v) ? v.resolution : undefined, depth + 1).map((f) => ({
			...f,
			runtime: true,
		})),
	);
};

const FETCHES = new Map<unknown, FetchesOf>([
	[undefined, untypedFetches],
	["directory", (res) => [{ source: `file:${str(res.directory) ?? ""}` }]],
	[
		"git",
		(res) => [
			{ source: `git+${str(res.repo) ?? ""}#${str(res.commit) ?? ""}` },
		],
	],
	[
		"binary",
		(res, integrity) => [
			{ source: sourceField(res.url) ?? "binary:", integrity, runtime: true },
		],
	],
	["variations", variationFetches],
]);

/**
 * What a pnpm `resolution` downloads: a registry or tarball URL, a git commit,
 * a directory, or one archive per platform of a `runtime:` dependency.
 * Unknown shapes become an unknown source, which is reported.
 */
const pnpmFetches = (res: unknown, depth = 0): Fetch[] => {
	if (!isRecord(res))
		return [{ source: res === undefined ? undefined : sourceField(res) }];
	const integrity = str(res.integrity);
	const fetches = FETCHES.get(res.type);
	if (fetches) return fetches(res, integrity, depth);
	return [{ source: `${String(res.type)}:`, integrity }];
};

/** One pnpm lockfile document being read. */
interface PnpmDoc {
	readonly packages: LockedPackage[];
	readonly lineOf: (needle: string) => number | undefined;
}

const parseDocument = (text: FileText): unknown => {
	try {
		return parseYaml(text);
	} catch {
		return undefined;
	}
};

/** pnpm records an overridden dependency with the override as its specifier. */
const overriddenNames = (doc: Record<string, unknown>) =>
	new Set(
		Object.keys(isRecord(doc.overrides) ? doc.overrides : {})
			.filter((k) => !k.includes(">"))
			.map(pnpmName),
	);

const isLocalVersion = (version: SourceSpec) =>
	version.startsWith("link:") || version.startsWith("file:");

/** One importer being read. */
interface ImporterRead {
	readonly dir: FilePath;
	readonly specifiers: Record<string, unknown>;
	readonly overridden: ReadonlySet<string>;
	readonly recorded: Importer;
}

/** v6+ records `{ specifier, version }`; v5 a bare version plus `specifiers`. */
const dependencyFields = (
	at: ImporterRead,
	name: PackageName,
	value: unknown,
): { spec: string | undefined; version: string | undefined } =>
	isRecord(value)
		? { spec: str(value.specifier), version: str(value.version) }
		: { spec: str(at.specifiers[name]), version: str(value) };

/** One importer's dependency: its accepted spec, and a `link:`/`file:` package. */
const recordDependency = (
	ctx: PnpmDoc,
	at: ImporterRead,
	[name, value]: [string, unknown],
) => {
	const { spec, version } = dependencyFields(at, name, value);
	at.recorded.set(
		name,
		spec === undefined || at.overridden.has(name) ? undefined : [spec],
	);
	if (version && isLocalVersion(version))
		ctx.packages.push({
			name,
			source: version,
			base: at.dir,
			line: ctx.lineOf(version),
		});
};

const readImporter = (
	ctx: PnpmDoc,
	importer: Record<string, unknown>,
	at: Omit<ImporterRead, "specifiers" | "recorded">,
): Importer => {
	const specifiers = isRecord(importer.specifiers) ? importer.specifiers : {};
	const read: ImporterRead = { ...at, specifiers, recorded: new Map() };
	for (const field of DEP_FIELDS) {
		const deps = importer[field];
		if (!isRecord(deps)) continue;
		for (const entry of Object.entries(deps))
			recordDependency(ctx, read, entry);
	}
	return read.recorded;
};

/** Importers by directory; v5 lockfiles without `importers` describe the root. */
const rawImportersOf = (doc: Record<string, unknown>) =>
	isRecord(doc.importers) ? doc.importers : { ".": doc };

const importerDir = (rawDir: FilePath) => (rawDir === "." ? "" : rawDir);

const readImporters = (
	ctx: PnpmDoc,
	doc: Record<string, unknown>,
): Map<string, Importer> => {
	const importers = new Map<string, Importer>();
	const overridden = overriddenNames(doc);
	for (const [rawDir, importer] of Object.entries(rawImportersOf(doc))) {
		if (!isRecord(importer)) continue;
		const dir = importerDir(rawDir);
		const recorded = readImporter(ctx, importer, { dir, overridden });
		if (recorded.size || isRecord(doc.importers)) importers.set(dir, recorded);
	}
	return importers;
};

/** The version in a package key (`a@1.0.0(peer@2.0.0)`), if it is one. */
const keyVersion = (key: PackageKey) => {
	const at = key.lastIndexOf("@");
	const version = at > 0 ? key.slice(at + 1).split("(")[0] : undefined;
	return version && /^\d/.test(version) ? version : undefined;
};

/** The packages a `packages` or `snapshots` entry installs. */
const addPackage = (
	ctx: PnpmDoc,
	key: PackageKey,
	value: Record<string, unknown>,
	line?: number,
) => {
	const name = str(value.name) ?? pnpmName(key);
	const version = str(value.version) ?? keyVersion(key);
	for (const f of pnpmFetches(value.resolution))
		ctx.packages.push({
			name,
			version,
			source: f.source,
			integrity: f.integrity,
			...(f.runtime ? { runtime: true } : {}),
			installScript: value.requiresBuild === true,
			line: line ?? ctx.lineOf(key),
		});
};

const readPackages = (
	ctx: PnpmDoc,
	text: FileText,
	declared: Record<string, unknown>,
) => {
	const packageLines = yamlKeyLines(text, "packages");
	for (const [key, value] of Object.entries(declared))
		if (isRecord(value)) addPackage(ctx, key, value, packageLines.get(key));
		else
			ctx.packages.push(
				malformedEntry(pnpmName(key), value, packageLines.get(key)),
			);
};

/**
 * A snapshot filled in from its package, or undefined when the package has a
 * resolution of its own and so is already installed from `packages`.
 */
const snapshotEntry = (
	snapshot: Record<string, unknown>,
	pkg: unknown,
): Record<string, unknown> | undefined => {
	if (!isRecord(pkg)) return { ...snapshot };
	return pkg.resolution === undefined ? { ...snapshot, ...pkg } : undefined;
};

/**
 * v9 lockfiles install what `snapshots` lists; pnpm fills each snapshot in
 * from `packages`, so a snapshot without a package (or a package without a
 * resolution) brings its own fields.
 */
const readSnapshots = (
	ctx: PnpmDoc,
	text: FileText,
	snapshots: Record<string, unknown>,
	declared: Record<string, unknown>,
) => {
	const snapshotLines = yamlKeyLines(text, "snapshots");
	for (const [key, snapshot] of Object.entries(snapshots)) {
		if (!isRecord(snapshot)) {
			ctx.packages.push(
				malformedEntry(pnpmName(key), snapshot, snapshotLines.get(key)),
			);
			continue;
		}
		const id = withoutPeerSuffix(key);
		const entry = snapshotEntry(snapshot, declared[id]);
		if (entry) addPackage(ctx, id, entry, snapshotLines.get(key));
	}
};

/** One YAML document of a pnpm lockfile. */
const parsePnpmDocument = (file: SourceFile): Lockfile | undefined => {
	const doc = parseDocument(file.text);
	if (!isRecord(doc)) return undefined;
	const major = Number.parseInt(String(doc.lockfileVersion ?? "0"), 10);
	const ctx: PnpmDoc = { packages: [], lineOf: lineFinder(file.text) };
	const importers = readImporters(ctx, doc);
	const declared = isRecord(doc.packages) ? doc.packages : {};
	readPackages(ctx, file.text, declared);
	if (isRecord(doc.snapshots))
		readSnapshots(ctx, file.text, doc.snapshots, declared);
	return {
		path: file.path,
		manager: "pnpm",
		packages: ctx.packages,
		importers,
		recordsInstallScripts: major > 0 && major < 9,
		problems: versionProblem(doc.lockfileVersion, [5, 6, 9]),
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
