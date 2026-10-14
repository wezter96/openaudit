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
		const ident = Array.isArray(value) ? str(value[0]) : undefined;
		const at = ident?.indexOf("@", 1) ?? -1;
		if (!Array.isArray(value) || !ident || at === -1) {
			packages.push(malformedEntry(key, value, lines.get(key)));
			continue;
		}
		const name = ident.slice(0, at);
		const spec = ident.slice(at + 1);
		const registryVersion = /^\d/.test(spec);
		packages.push({
			name,
			...(registryVersion ? { version: spec } : {}),
			// Registry entries carry the tarball URL ("" for registry.npmjs.org).
			source: registryVersion ? sourceField(value[1]) || undefined : spec,
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
		problems: versionProblem(json.lockfileVersion, [0, 1, 2]),
	};
};
