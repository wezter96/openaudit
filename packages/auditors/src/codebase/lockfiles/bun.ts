import { isRecord, type SourceFile } from "../util";
import {
	declaredSpecs,
	type Importer,
	jsonKeyLines,
	type LockedPackage,
	type Lockfile,
	malformedEntry,
	sourceField,
	str,
	strings,
	versionProblem,
} from "./shared";

/** `name@spec` from a bun.lock package entry, split at the version `@`. */
const splitIdent = (
	value: unknown,
): { name: string; spec: string } | undefined => {
	if (!Array.isArray(value)) return undefined;
	const ident = str(value[0]);
	const at = ident?.indexOf("@", 1) ?? -1;
	if (!ident || at === -1) return undefined;
	return { name: ident.slice(0, at), spec: ident.slice(at + 1) };
};

const bunPackage = (
	key: string,
	value: unknown,
	line: number | undefined,
): LockedPackage => {
	const ident = splitIdent(value);
	if (!ident || !Array.isArray(value)) return malformedEntry(key, value, line);
	const { name, spec } = ident;
	const registryVersion = /^\d/.test(spec);
	return {
		name,
		...(registryVersion ? { version: spec } : {}),
		// Registry entries carry the tarball URL ("" for registry.npmjs.org).
		source: registryVersion ? sourceField(value[1]) || undefined : spec,
		integrity: str(value[value.length - 1]),
		line,
	};
};

const bunImporters = (workspaces: unknown): Map<string, Importer> => {
	const importers = new Map<string, Importer>();
	if (!isRecord(workspaces)) return importers;
	for (const [dir, ws] of Object.entries(workspaces))
		if (isRecord(ws)) importers.set(dir, declaredSpecs(ws));
	return importers;
};

const parseJsonc = (text: string): unknown => {
	try {
		// Bun's own parser: comments, trailing commas, single quotes and a BOM.
		return Bun.JSONC.parse(text);
	} catch {
		return undefined;
	}
};

/** bun.lock (JSONC): `"key": ["name@spec", registry?, info, integrity?]`. */
export const parseBunLock = (file: SourceFile): Lockfile | undefined => {
	const json = parseJsonc(file.text);
	if (!isRecord(json) || !isRecord(json.packages)) return undefined;
	const lines = jsonKeyLines(file.text, "packages");
	const packages = Object.entries(json.packages).map(([key, value]) =>
		bunPackage(key, value, lines.get(key)),
	);
	return {
		path: file.path,
		manager: "bun",
		packages,
		importers: bunImporters(json.workspaces),
		recordsInstallScripts: false,
		trusted: strings(json.trustedDependencies),
		problems: versionProblem(json.lockfileVersion, [0, 1, 2]),
	};
};
