import { baseName, isRecord, type SourceFile } from "../util";
import {
	declaredSpecs,
	type Importer,
	jsonKeyLines,
	type LockedPackage,
	type Lockfile,
	malformedEntry,
	parseJson,
	sourceField,
	str,
	versionProblem,
} from "./shared";

const NODE_MODULES = "node_modules/";

/** One `packages` entry of a v2/v3 lockfile, keyed by its install path. */
interface PackagesEntry {
	readonly key: string;
	readonly value: unknown;
	readonly line: number | undefined;
}

/** A `packages` entry outside node_modules: the root, a workspace or a `file:` directory dependency. */
const localPackage = (
	{ key, line }: PackagesEntry,
	value: Record<string, unknown>,
): LockedPackage[] =>
	key
		? [{ name: str(value.name) ?? baseName(key), source: `file:${key}`, line }]
		: [];

const installedPackage = (
	name: string,
	value: Record<string, unknown>,
	line: number | undefined,
): LockedPackage => {
	if (value.link) {
		const resolved = sourceField(value.resolved) ?? "";
		return {
			name,
			source: resolved.startsWith("(") ? resolved : `file:${resolved}`,
			line,
		};
	}
	return {
		name,
		version: str(value.version),
		source: sourceField(value.resolved),
		integrity: str(value.integrity),
		installScript: value.hasInstallScript === true,
		bundled: value.inBundle === true,
		line,
	};
};

/** npm 7+ `packages`, keyed by install path. */
const readPackages = (
	text: string,
	entries: Record<string, unknown>,
	out: { packages: LockedPackage[]; importers: Map<string, Importer> },
) => {
	const lines = jsonKeyLines(text, "packages");
	for (const [key, value] of Object.entries(entries)) {
		const entry = { key, value, line: lines.get(key) };
		const nm = key.lastIndexOf(NODE_MODULES);
		const installed = key.slice(nm + NODE_MODULES.length);
		if (!isRecord(value))
			out.packages.push(
				malformedEntry(nm === -1 ? key : installed, value, entry.line),
			);
		else if (nm === -1) {
			out.importers.set(key, declaredSpecs(value));
			out.packages.push(...localPackage(entry, value));
		} else
			out.packages.push(
				installedPackage(str(value.name) ?? installed, value, entry.line),
			);
	}
};

const dependencyPackage = (
	name: string,
	value: Record<string, unknown>,
	line: number | undefined,
): LockedPackage => {
	const version = str(value.version);
	// v1 records git and file dependencies in `version`.
	const spec = version && !/^\d/.test(version) ? version : undefined;
	return {
		name,
		version: spec ? undefined : version,
		source: sourceField(value.resolved) ?? spec,
		integrity: str(value.integrity),
		bundled: value.bundled === true,
		line,
	};
};

/** npm 6 `dependencies`, nested by install path. */
const readDependencies = (
	text: string,
	dependencies: Record<string, unknown>,
	packages: LockedPackage[],
) => {
	const lines = jsonKeyLines(text, "dependencies");
	// npm 6 nests without a depth limit; an explicit stack has none either.
	const stack: Array<Record<string, unknown>> = [dependencies];
	for (let deps = stack.pop(); deps; deps = stack.pop())
		for (const [name, value] of Object.entries(deps)) {
			if (!isRecord(value)) {
				packages.push(malformedEntry(name, value, lines.get(name)));
				continue;
			}
			packages.push(dependencyPackage(name, value, lines.get(name)));
			if (isRecord(value.dependencies)) stack.push(value.dependencies);
		}
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
	if (isRecord(json.packages))
		readPackages(file.text, json.packages, { packages, importers });
	if (isRecord(json.dependencies))
		readDependencies(file.text, json.dependencies, packages);
	return {
		path: file.path,
		manager: "npm",
		packages,
		importers,
		recordsInstallScripts: isRecord(json.packages),
		problems: versionProblem(json.lockfileVersion, [1, 2, 3]),
	};
};
