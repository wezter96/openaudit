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
			const line = lines.get(key);
			const nm = key.lastIndexOf("node_modules/");
			if (!isRecord(value)) {
				packages.push(
					malformedEntry(
						nm === -1 ? key : key.slice(nm + "node_modules/".length),
						value,
						line,
					),
				);
				continue;
			}
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
				const resolved = sourceField(value.resolved) ?? "";
				packages.push({
					name,
					source: resolved.startsWith("(") ? resolved : `file:${resolved}`,
					line,
				});
				continue;
			}
			packages.push({
				name,
				version: str(value.version),
				source: sourceField(value.resolved),
				integrity: str(value.integrity),
				installScript: value.hasInstallScript === true,
				bundled: value.inBundle === true,
				line,
			});
		}
	}
	if (isRecord(json.dependencies)) {
		const lines = jsonKeyLines(file.text, "dependencies");
		// npm 6 nests without a depth limit; an explicit stack has none either.
		const stack: Array<Record<string, unknown>> = [json.dependencies];
		for (let deps = stack.pop(); deps; deps = stack.pop())
			for (const [name, value] of Object.entries(deps)) {
				if (!isRecord(value)) {
					packages.push(malformedEntry(name, value, lines.get(name)));
					continue;
				}
				const version = str(value.version);
				// v1 records git and file dependencies in `version`.
				const spec = version && !/^\d/.test(version) ? version : undefined;
				packages.push({
					name,
					version: spec ? undefined : version,
					source: sourceField(value.resolved) ?? spec,
					integrity: str(value.integrity),
					bundled: value.bundled === true,
					line: lines.get(name),
				});
				if (isRecord(value.dependencies)) stack.push(value.dependencies);
			}
	}
	return {
		path: file.path,
		manager: "npm",
		packages,
		importers,
		recordsInstallScripts: isRecord(json.packages),
		problems: versionProblem(json.lockfileVersion, [1, 2, 3]),
	};
};
