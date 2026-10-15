import { isRecord, type SourceFile } from "../util";
import {
	type Importer,
	type LockedPackage,
	type Lockfile,
	lineFinder,
	type Problem,
	scalar,
	sourceField,
	uniqueProblems,
	versionProblem,
} from "./shared";
import { classifySource } from "./sources";
import {
	grammarDocument,
	parseYarnClassic,
	type YarnDocument,
	yamlDocument,
} from "./yarn-grammar";

export { parseYarnClassic };

/** A Yarn descriptor or locator, such as `name@^1.0.0` or `name@npm:1.0.0`. */
type Descriptor = string;

/** The query after a Berry locator's `::`, such as `locator=name%40workspace%3Adir`. */
type LocatorParams = string;

const nameOfSpec = (spec: Descriptor) => {
	const at = spec.indexOf("@", 1);
	return at === -1 ? spec : spec.slice(0, at);
};

/** Workspace directory from Berry's `::locator=name%40workspace%3Adir`. */
const berryLocatorDir = (params: LocatorParams): string => {
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

/** Yarn 2+ treats files with this header as classic lockfiles. */
const YARN_V1_HEADER = /^(#.*(\r?\n))*?#\s+yarn\s+lockfile\s+v1\r?\n/i;

/** What the entries of every reading of the file add up to. */
interface YarnLock {
	readonly packages: LockedPackage[];
	readonly workspaces: Map<string, Importer>;
	readonly rootSpecs: Map<string, string[]>;
	readonly problems: Problem[];
	berry: boolean;
}

/** One entry of one reading of the file. */
interface YarnEntry {
	readonly key: Descriptor;
	readonly value: Record<string, unknown>;
	readonly line: number | undefined;
	/** From the reading Yarn 1 uses. */
	readonly classic: boolean;
}

/**
 * Yarn 1's reading (its grammar) and Yarn 2+'s (YAML unless the file has the
 * classic header); where neither reads it, Yarn 1's YAML fallback.
 */
const readDocs = (
	text: string,
): {
	readonly docs: ReadonlyArray<YarnDocument>;
	readonly classic: YarnDocument | undefined;
} => {
	const classic = grammarDocument(text);
	// Not YAML: Yarn 2+ cannot read it either.
	const berry = YARN_V1_HEADER.test(text) ? undefined : yamlDocument(text);
	const docs = [classic, berry].filter(
		(doc): doc is YarnDocument => doc !== undefined,
	);
	if (docs.length) return { docs, classic };
	const fallback = parseYarnClassic(text);
	return { docs: fallback ? [fallback] : [], classic: fallback };
};

/** A locator split at its `::` parameters. */
const splitParams = (
	spec: Descriptor,
): readonly [Descriptor, LocatorParams | undefined] => {
	const at = spec.indexOf("::");
	return at === -1
		? [spec, undefined]
		: [spec.slice(0, at), spec.slice(at + 2)];
};

/**
 * npm: packages outside the registry's usual tarball path are downloaded
 * from the URL in their locator. Several values: which one Yarn uses is not
 * modelled.
 */
const archiveUrl = (params: LocatorParams | undefined) => {
	if (params === undefined) return undefined;
	const urls = new URLSearchParams(params).getAll("__archiveUrl");
	return urls.length > 1 ? "(several __archiveUrl values)" : urls[0];
};

const berryPackage = (
	entry: YarnEntry,
	name: string,
	spec: Descriptor,
): LockedPackage => {
	const [bare, params] = splitParams(spec);
	const isPath = /^(file|link|portal):/.test(bare);
	const checksum = scalar(entry.value.checksum);
	return {
		name,
		version: scalar(entry.value.version),
		source: archiveUrl(params) ?? (isPath ? bare.split("#")[0] : bare),
		...(isPath && params !== undefined
			? { base: berryLocatorDir(params) }
			: {}),
		// Berry checksums are SHA-512 digests of the package archive.
		integrity: checksum ? `sha512-${checksum}` : undefined,
		line: entry.line,
	};
};

const workspaceImporter = (
	spec: Descriptor,
	value: Record<string, unknown>,
): readonly [string, Importer] => {
	const dir = spec.slice("workspace:".length);
	const deps = isRecord(value.dependencies) ? value.dependencies : {};
	return [
		dir === "." ? "" : dir,
		new Map(Object.keys(deps).map((n) => [n, undefined])),
	];
};

/** Yarn 2+'s `resolution`; a malformed one is kept to be reported. */
const berryResolution = ({ key, value }: YarnEntry) => {
	const malformed = sourceField(value.resolution);
	return (
		scalar(value.resolution) ?? (malformed && `${nameOfSpec(key)}@${malformed}`)
	);
};

const readBerryEntry = (
	lock: YarnLock,
	entry: YarnEntry,
	resolution: Descriptor,
) => {
	const name = nameOfSpec(resolution);
	const spec = resolution.slice(name.length + 1);
	if (spec.startsWith("workspace:"))
		lock.workspaces.set(...workspaceImporter(spec, entry.value));
	else lock.packages.push(berryPackage(entry, name, spec));
};

const isArchive = (resolved: string) => {
	const { kind } = classifySource(resolved);
	if (kind === "tarball") return true;
	return kind === "git" && /^https?:/i.test(resolved);
};

/**
 * Classic yarn appends the archive's SHA-1 to registry, tarball and codeload
 * URLs; for those the fragment is a checksum, not a git ref.
 */
const sha1Fragment = (resolved: string | undefined) => {
	if (!resolved) return undefined;
	const hash = resolved.indexOf("#");
	const sha1 = hash === -1 ? "" : resolved.slice(hash + 1);
	if (!isArchive(resolved) || !/^[0-9a-f]{40}$/i.test(sha1)) return undefined;
	return { url: resolved.slice(0, hash), sha1 };
};

/** Yarn 1's `resolved` and `integrity`, with an archive's SHA-1 moved over. */
const classicFetch = (value: Record<string, unknown>) => {
	const resolved = scalar(value.resolved) ?? sourceField(value.resolved);
	const integrity = scalar(value.integrity);
	const fragment = sha1Fragment(resolved);
	if (!fragment) return { resolved, integrity };
	return {
		resolved: fragment.url,
		integrity: integrity ?? `sha1-${fragment.sha1}`,
	};
};

const addRootSpec = (
	rootSpecs: Map<string, string[]>,
	name: string,
	declared: Descriptor,
) => {
	// Pushed in place: copying the list per entry is quadratic.
	const specs = rootSpecs.get(name);
	if (specs) specs.push(declared);
	else rootSpecs.set(name, [declared]);
};

const readClassicEntry = (lock: YarnLock, entry: YarnEntry) => {
	const { key, value } = entry;
	const first = key.split(",")[0]?.trim() ?? key;
	const name = nameOfSpec(first);
	const declared = first.slice(name.length + 1);
	if (entry.classic) addRootSpec(lock.rootSpecs, name, declared);
	const { resolved, integrity } = classicFetch(value);
	lock.packages.push({
		name,
		version: value.version === undefined ? undefined : String(value.version),
		source: resolved ?? (/^(file|link):/.test(declared) ? declared : undefined),
		integrity,
		line: entry.line,
	});
};

const readEntry = (lock: YarnLock, entry: YarnEntry) => {
	const resolution = berryResolution(entry);
	if (resolution !== undefined) readBerryEntry(lock, entry, resolution);
	// Yarn 1's reading of the entry.
	if (resolution === undefined || entry.value.resolved !== undefined)
		readClassicEntry(lock, entry);
};

const readDoc = (
	lock: YarnLock,
	{ obj, lines }: YarnDocument,
	context: {
		readonly lineOf: ReturnType<typeof lineFinder>;
		readonly classic: boolean;
	},
) => {
	if (isRecord(obj.__metadata)) {
		lock.berry = true;
		lock.problems.push(
			...versionProblem(obj.__metadata.version, [4, 5, 6, 7, 8]),
		);
	}
	for (const [key, value] of Object.entries(obj)) {
		if (key === "__metadata" || !isRecord(value)) continue;
		const line = lines.get(key) ?? context.lineOf(key);
		readEntry(lock, { key, value, line, classic: context.classic });
	}
};

/**
 * yarn.lock, read the way both Yarn 1 (its grammar, then YAML) and Yarn 2+
 * (YAML unless the file has the classic header) read it. Which Yarn installs
 * is not known, so entries from either reading are checked: Berry's
 * `resolution`/`checksum` and Yarn 1's `resolved`/`integrity`.
 */
export const parseYarnLock = (file: SourceFile): Lockfile | undefined => {
	const { docs, classic } = readDocs(file.text);
	if (!docs.length) return undefined;
	const lineOf = lineFinder(file.text);
	const lock: YarnLock = {
		packages: [],
		workspaces: new Map(),
		rootSpecs: new Map(),
		problems: [],
		berry: false,
	};
	for (const doc of docs)
		readDoc(lock, doc, { lineOf, classic: doc.obj === classic?.obj });
	return {
		path: file.path,
		manager: lock.berry ? "yarn-berry" : "yarn",
		packages: lock.packages,
		importers: lock.berry ? lock.workspaces : new Map([["", lock.rootSpecs]]),
		recordsInstallScripts: false,
		problems: uniqueProblems(lock.problems),
	};
};
