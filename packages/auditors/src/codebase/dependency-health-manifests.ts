import { DEP_FIELDS, type Ecosystem, isManifest } from "./dependencies";
import { isFixturePath, isRecord, parseJsonc, type SourceFile } from "./util";

/*
 * Direct (declared) dependencies for code.dependency-health: the names a
 * project's own manifests list, as opposed to transitive ones that only appear
 * in a lockfile.
 */

/** The text of a manifest file. */
type ManifestText = string;
/** One line of a manifest. */
type ManifestLine = string;
/** A TOML table name, such as `project.optional-dependencies`. */
type TomlTable = string;
type PackageName = string;

/** Name as the registry compares it (PEP 503 for PyPI, `-`/`_` for crates). */
const NAME_NORMALIZERS: Partial<
	Record<Ecosystem, (name: PackageName) => PackageName>
> = {
	PyPI: (name) => name.toLowerCase().replace(/[-_.]+/g, "-"),
	"crates.io": (name) => name.toLowerCase().replace(/_/g, "-"),
};

export const directKey = (ecosystem: Ecosystem, name: PackageName) =>
	`${ecosystem}|${NAME_NORMALIZERS[ecosystem]?.(name) ?? name}`;

const REQUIREMENT_NAME = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)/;

/** The first capture group of `re` in `text`, when it matches and is not empty. */
const captured = (re: RegExp, text: string): string[] => {
	const match = re.exec(text)?.[1];
	return match ? [match] : [];
};

/** The package a requirement string such as `requests>=2` names. */
const requirementName = (requirement: ManifestLine) =>
	captured(REQUIREMENT_NAME, requirement);

/** The text of a TOML table header line, e.g. `dependencies` for `[dependencies]`. */
const tomlHeader = (line: ManifestLine) =>
	/^\[([^[\]]+)\]$/.exec(line)?.[1]?.trim();

const packageJsonNames = (text: ManifestText): PackageName[] => {
	const json = parseJsonc(text);
	if (!isRecord(json)) return [];
	return DEP_FIELDS.flatMap((field) => {
		const deps = json[field];
		return isRecord(deps) ? Object.keys(deps) : [];
	});
};

/** The module a go.mod `require` line names, unless it is indirect. */
const goRequirement = (line: ManifestLine): PackageName[] => {
	if (/\/\/\s*indirect\b/.test(line)) return [];
	return captured(/^(?:require\s+)?(\S+)\s+v\S+/, line).filter(
		(name) => !name.startsWith("//"),
	);
};

const goModNames = (text: ManifestText): PackageName[] => {
	const names: string[] = [];
	let inBlock = false;
	for (const raw of text.split("\n")) {
		const line = raw.trim();
		if (/^require\s*\($/.test(line)) inBlock = true;
		else if (inBlock && line === ")") inBlock = false;
		else if (inBlock || /^require\s+/.test(line))
			names.push(...goRequirement(line));
	}
	return names;
};

/**
 * A Cargo.toml table header: `[dependencies.name]` declares one dependency,
 * and `[dependencies]` opens a table of them.
 */
const cargoTable = (header: TomlTable) => {
	const table = /(?:^|\.)(?:dev-|build-)?dependencies\.([\w-]+)$/.exec(
		header,
	)?.[1];
	return {
		names: table ? [table] : [],
		inDeps: !table && /(?:^|\.)(?:dev-|build-)?dependencies$/.test(header),
	};
};

const cargoKey = (line: ManifestLine) => captured(/^([\w-]+)\s*=/, line);

/** `[dependencies]`-like tables of a Cargo.toml, including target and workspace ones. */
const cargoTomlNames = (text: ManifestText): PackageName[] => {
	const names: string[] = [];
	let inDeps = false;
	for (const raw of text.split("\n")) {
		const line = raw.replace(/#.*$/, "").trim();
		const header = tomlHeader(line);
		if (header !== undefined) {
			const table = cargoTable(header);
			names.push(...table.names);
			inDeps = table.inDeps;
		} else if (inDeps) names.push(...cargoKey(line));
	}
	return names;
};

const POETRY_SECTION =
	/^tool\.poetry\.(?:(?:dev-)?dependencies|group\.[\w-]+\.dependencies)$/;

/** Sections whose `name = [...]` entries are dependency arrays (PEP 621 extras, PEP 735 groups). */
const ARRAY_SECTIONS = new Set([
	"project.optional-dependencies",
	"dependency-groups",
]);

/** Requirement names in the quoted strings of an array line, up to its `]`. */
const quotedRequirements = (items: ManifestLine): PackageName[] =>
	[...items.replace(/\].*$/, "").matchAll(/["']([^"']+)["']/g)].flatMap((m) =>
		m[1] ? requirementName(m[1]) : [],
	);

const opensDependencyArray = (
	section: TomlTable,
	line: ManifestLine,
): boolean =>
	section === "project"
		? /^dependencies\s*=\s*\[/.test(line)
		: ARRAY_SECTIONS.has(section) && /^[\w.-]+\s*=\s*\[/.test(line);

/** The rest of a line, after its `[`, when it opens a dependency array. */
const dependencyArrayStart = (
	section: TomlTable,
	line: ManifestLine,
): string | undefined => {
	if (!opensDependencyArray(section, line)) return undefined;
	return line.slice(line.indexOf("[") + 1);
};

const poetryName = (line: ManifestLine) =>
	captured(/^([A-Za-z0-9][\w.-]*)\s*=/, line).filter(
		(key) => key.toLowerCase() !== "python",
	);

/** PEP 621/735 dependency arrays and Poetry dependency tables. */
const pyprojectNames = (text: ManifestText): PackageName[] => {
	const names: string[] = [];
	let section = "";
	let inArray = false;
	for (const raw of text.split("\n")) {
		const line = raw.replace(/\s#.*$/, "").trim();
		const items: string | undefined = inArray
			? line
			: dependencyArrayStart(section, line);
		if (items !== undefined) {
			names.push(...quotedRequirements(items));
			inArray = !items.includes("]");
			continue;
		}
		const header = tomlHeader(line);
		if (header !== undefined) section = header;
		else if (POETRY_SECTION.test(section)) names.push(...poetryName(line));
	}
	return names;
};

const gemfileNames = (text: ManifestText): PackageName[] =>
	[...text.matchAll(/^\s*gem\s+["']([^"']+)["']/gm)].flatMap((m) =>
		m[1] ? [m[1]] : [],
	);

const requirementsNames = (text: ManifestText): PackageName[] =>
	text
		.split("\n")
		.filter((line) => !/^\s*(#|-)/.test(line))
		.flatMap(requirementName);

const DECLARATIONS: ReadonlyArray<
	readonly [RegExp, Ecosystem, (text: ManifestText) => PackageName[]]
> = [
	[/(^|\/)package\.json$/, "npm", packageJsonNames],
	[/(^|\/)go\.mod$/, "Go", goModNames],
	[/(^|\/)Cargo\.toml$/, "crates.io", cargoTomlNames],
	[/(^|\/)pyproject\.toml$/, "PyPI", pyprojectNames],
	[/(^|\/)requirements[\w.-]*\.txt$/, "PyPI", requirementsNames],
	[/(^|\/)Gemfile$/, "RubyGems", gemfileNames],
];

const declaredKeys = (file: SourceFile): string[] =>
	DECLARATIONS.flatMap(([re, ecosystem, names]) =>
		re.test(file.path)
			? names(file.text).map((name) => directKey(ecosystem, name))
			: [],
	);

/**
 * Dependencies the project declares itself (`ecosystem|normalized name`), as
 * opposed to transitive ones that only appear in a lockfile.
 */
export const declaredDependencies = (
	files: ReadonlyArray<SourceFile>,
): Set<string> => new Set(files.flatMap(declaredKeys));

export const isHealthManifest = (path: string) =>
	isManifest(path) ||
	(!isFixturePath(path) &&
		/(^|\/)(Cargo\.toml|pyproject\.toml|Gemfile)$/.test(path));
