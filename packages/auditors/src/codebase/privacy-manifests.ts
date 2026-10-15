import { type Ecosystem, TRACKERS, type Tracker } from "../privacy-data";
import type { FilePath, PackageName, SourceText } from "./privacy-shared";
import { baseName, isRecord } from "./util";

export type Manifest = Ecosystem;

const MANIFEST_BY_NAME = new Map<string, Manifest>([
	["package.json", "npm"],
	["composer.json", "composer"],
	["pyproject.toml", "pypi"],
	["Pipfile", "pypi"],
	["Podfile", "pod"],
	["go.mod", "go"],
	["Gemfile", "gem"],
	["pubspec.yaml", "pub"],
]);

const isRequirementsFile = (path: FilePath) =>
	/^requirements[^/]*\.txt$/.test(baseName(path)) ||
	/(^|\/)requirements\/[^/]+\.txt$/.test(path);

export const manifestOf = (path: FilePath): Manifest | undefined => {
	const base = baseName(path);
	const named = MANIFEST_BY_NAME.get(base);
	if (named) return named;
	if (isRequirementsFile(path))
		return /dev|test|lint|docs/i.test(base) ? undefined : "pypi";
	if (/^build\.gradle(\.kts)?$|^libs\.versions\.toml$/.test(base))
		return "gradle";
	return undefined;
};

export const NPM_LOCKFILE =
	/(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lock)$/;

/* ------------------------------- SDK inventory ------------------------------- */

const PACKAGE_INDEX = new Map<string, Tracker>();
for (const t of TRACKERS)
	for (const [eco, names] of Object.entries(t.packages ?? {}))
		for (const n of names ?? [])
			PACKAGE_INDEX.set(`${eco}:${n.toLowerCase()}`, t);

/** Go modules carry a major-version suffix and sub-packages. */
const goModuleTracker = (key: PackageName): Tracker | undefined => {
	for (const [k, t] of PACKAGE_INDEX)
		if (k.startsWith("go:") && key.startsWith(`${k.slice(3)}/`)) return t;
	return undefined;
};

export const trackerForPackage = (
	eco: Ecosystem,
	name: PackageName,
): Tracker | undefined => {
	const key = name.toLowerCase().replace(/\s+/g, "");
	const exact = PACKAGE_INDEX.get(`${eco}:${key}`);
	if (exact) return exact;
	if (eco === "pypi")
		return PACKAGE_INDEX.get(`${eco}:${key.replace(/_/g, "-")}`);
	if (eco === "go") return goModuleTracker(key);
	return undefined;
};

const strings = (text: SourceText, re: RegExp): PackageName[] =>
	[...text.matchAll(re)].flatMap((m) => (m[1] ? [m[1]] : []));

const HASH_COMMENT = /^\s*#/;
const SLASH_COMMENT = /^\s*\/\//;

const withoutComments = (text: SourceText, marker: RegExp) =>
	text
		.split("\n")
		.filter((l) => !marker.test(l))
		.join("\n");

const PUB_SECTION = /^([a-z_]+):/;
const PUB_DEPENDENCY = /^ {2}([a-z0-9_]+):/g;

/** Only the `dependencies:` block of a pubspec; dev_dependencies are not shipped. */
const pubDependencyNames = (text: SourceText): PackageName[] => {
	const names: PackageName[] = [];
	let section = "";
	for (const line of text.split("\n")) {
		const top = line.match(PUB_SECTION);
		if (top) section = top[1] ?? "";
		else if (section === "dependencies")
			names.push(...strings(line, PUB_DEPENDENCY));
	}
	return names;
};

const jsonDependencyNames = (text: SourceText): PackageName[] => {
	try {
		const json: unknown = JSON.parse(text);
		if (!isRecord(json)) return [];
		return ["dependencies", "optionalDependencies", "require"].flatMap((k) => {
			const section = json[k];
			return isRecord(section) ? Object.keys(section) : [];
		});
	} catch {
		return [];
	}
};

const pythonDependencyNames = (text: SourceText): PackageName[] => {
	const body = withoutComments(text, HASH_COMMENT);
	return [
		...strings(
			body,
			/^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:[<>=!~;@]|$)/gm,
		),
		...strings(
			body,
			/["']([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:[<>=!~;@ ]|["'])/g,
		),
		...strings(body, /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=/gm),
	];
};

/** Names a pattern captures once comment lines are dropped. */
const uncommented =
	(marker: RegExp, re: RegExp) =>
	(text: SourceText): PackageName[] =>
		strings(withoutComments(text, marker), re);

const DEPENDENCY_PARSERS: Record<
	Manifest,
	(text: SourceText) => PackageName[]
> = {
	npm: jsonDependencyNames,
	composer: jsonDependencyNames,
	pypi: pythonDependencyNames,
	pod: uncommented(HASH_COMMENT, /^\s*pod\s+['"]([^'"]+)['"]/gm),
	gem: uncommented(HASH_COMMENT, /^\s*gem\s+['"]([^'"]+)['"]/gm),
	go: uncommented(
		SLASH_COMMENT,
		/^\s*(?:require\s+)?([\w.-]+\.[\w.-]+\/[\w./~-]+)\s+v\d/gm,
	),
	gradle: uncommented(SLASH_COMMENT, /["']([\w.-]+:[\w.-]+)(?::[^"']*)?["']/g),
	pub: pubDependencyNames,
};

/** Package names a manifest depends on directly. */
export const dependenciesOf = (
	eco: Manifest,
	text: SourceText,
): PackageName[] => DEPENDENCY_PARSERS[eco](text);

const LOCKFILE_PATTERNS = new Map<string, RegExp>([
	["yarn.lock", /^"?((?:@[^/@\s"]+\/)?[^@\s"]+)@/gm],
	["pnpm-lock.yaml", /^\s+'?\/?((?:@[^/@\s':]+\/)?[^@\s':]+)@\d/gm],
	["bun.lock", /^\s+"[^"]+":\s*\["((?:@[^/"]+\/)?[^@"]+)@/gm],
]);
const NPM_LOCK_PACKAGE = /"node_modules\/((?:@[^/"]+\/)?[^/"]+)"/g;

/** Names of every package a JS lockfile pins (direct and transitive). */
export const lockfilePackages = (
	path: FilePath,
	text: SourceText,
): PackageName[] =>
	strings(text, LOCKFILE_PATTERNS.get(baseName(path)) ?? NPM_LOCK_PACKAGE);
