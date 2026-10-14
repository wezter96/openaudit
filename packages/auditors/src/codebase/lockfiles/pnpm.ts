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

/** `name` from a pnpm package key (v5 `/a/1.0.0`, v6 `/a@1.0.0`, v9 `a@1.0.0`). */
const pnpmName = (key: string): string => {
	const k = key.startsWith("/") ? key.slice(1) : key;
	const at = k.indexOf("@", 1);
	if (at > 0) return k.slice(0, at);
	const parts = k.split("/");
	return k.startsWith("@") ? parts.slice(0, 2).join("/") : (parts[0] ?? k);
};

/** pnpm's `removeSuffix`: `a@1.0.0(peer@2.0.0)` → `a@1.0.0`. */
const withoutPeerSuffix = (depPath: string) => {
	if (!depPath.endsWith(")")) return depPath;
	const i = depPath.indexOf("(", 1);
	return i === -1 ? depPath : depPath.slice(0, i);
};

interface Fetch {
	readonly source?: string;
	readonly integrity?: string;
	readonly runtime?: boolean;
}

/**
 * What a pnpm `resolution` downloads: a registry or tarball URL, a git commit,
 * a directory, or one archive per platform of a `runtime:` dependency.
 * Unknown shapes become an unknown source, which is reported.
 */
const pnpmFetches = (res: unknown, depth = 0): Fetch[] => {
	if (!isRecord(res))
		return [{ source: res === undefined ? undefined : sourceField(res) }];
	const integrity = str(res.integrity);
	switch (res.type) {
		case undefined:
			return [
				{
					source:
						typeof res.directory === "string"
							? `file:${res.directory}`
							: (sourceField(res.directory) ?? sourceField(res.tarball)),
					integrity,
				},
			];
		case "directory":
			return [{ source: `file:${str(res.directory) ?? ""}` }];
		case "git":
			return [
				{ source: `git+${str(res.repo) ?? ""}#${str(res.commit) ?? ""}` },
			];
		case "binary":
			return [
				{ source: sourceField(res.url) ?? "binary:", integrity, runtime: true },
			];
		case "variations":
			if (depth > 2 || !Array.isArray(res.variants))
				return [{ source: "variations:" }];
			return res.variants.flatMap((v) =>
				pnpmFetches(isRecord(v) ? v.resolution : undefined, depth + 1).map(
					(f) => ({ ...f, runtime: true }),
				),
			);
		default:
			return [{ source: `${String(res.type)}:`, integrity }];
	}
};

/** One YAML document of a pnpm lockfile. */
const parsePnpmDocument = (file: SourceFile): Lockfile | undefined => {
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
	const lineOf = lineFinder(file.text);
	// pnpm records an overridden dependency with the override as its specifier.
	const overridden = new Set(
		Object.keys(isRecord(doc.overrides) ? doc.overrides : {})
			.filter((k) => !k.includes(">"))
			.map(pnpmName),
	);
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
	const add = (key: string, value: Record<string, unknown>, line?: number) => {
		const name = str(value.name) ?? pnpmName(key);
		const at = key.lastIndexOf("@");
		const keyVersion = at > 0 ? key.slice(at + 1).split("(")[0] : undefined;
		const version =
			str(value.version) ??
			(keyVersion && /^\d/.test(keyVersion) ? keyVersion : undefined);
		for (const f of pnpmFetches(value.resolution))
			packages.push({
				name,
				version,
				source: f.source,
				integrity: f.integrity,
				...(f.runtime ? { runtime: true } : {}),
				installScript: value.requiresBuild === true,
				line: line ?? lineOf(key),
			});
	};
	const declared = isRecord(doc.packages) ? doc.packages : {};
	const packageLines = yamlKeyLines(file.text, "packages");
	for (const [key, value] of Object.entries(declared))
		if (isRecord(value)) add(key, value, packageLines.get(key));
		else
			packages.push(
				malformedEntry(pnpmName(key), value, packageLines.get(key)),
			);
	// v9 lockfiles install what `snapshots` lists; pnpm fills each snapshot in
	// from `packages`, so a snapshot without a package (or a package without a
	// resolution) brings its own fields.
	if (isRecord(doc.snapshots)) {
		const snapshotLines = yamlKeyLines(file.text, "snapshots");
		for (const [key, snapshot] of Object.entries(doc.snapshots)) {
			if (!isRecord(snapshot)) {
				packages.push(
					malformedEntry(pnpmName(key), snapshot, snapshotLines.get(key)),
				);
				continue;
			}
			const id = withoutPeerSuffix(key);
			const pkg = declared[id];
			if (isRecord(pkg) && pkg.resolution !== undefined) continue;
			add(
				id,
				{ ...snapshot, ...(isRecord(pkg) ? pkg : {}) },
				snapshotLines.get(key),
			);
		}
	}
	return {
		path: file.path,
		manager: "pnpm",
		packages,
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
