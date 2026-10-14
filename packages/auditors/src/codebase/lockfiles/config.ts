import { isRecord, type SourceFile, truncate } from "../util";
import {
	dirOf,
	joinDir,
	type Lockfile,
	lineFinder,
	type Manager,
	parseJson,
	parseYaml,
	str,
	strings,
	stripBom,
} from "./shared";
import { displayUrl } from "./sources";
import { parseYarnClassic } from "./yarn";

/** A setting found in a config file, with where it was found. */
export interface Setting {
	readonly file: string;
	readonly line?: number;
	readonly evidence: string;
}

export interface Registry extends Setting {
	readonly url: string;
	/** `@scope` for a scoped registry. */
	readonly scope?: string;
}

/** What one package-manager config file declares. */
export interface FileConfig {
	readonly file: string;
	readonly registries: Registry[];
	ignoreScripts?: Setting;
	strictSslOff?: Setting;
	/** pnpm `onlyBuiltDependencies` (allow-list). */
	onlyBuilt?: string[];
	/** pnpm `neverBuiltDependencies` (deny-list). */
	neverBuilt?: string[];
	/** pnpm `dangerouslyAllowAllBuilds`, or a wildcard in its allow-list. */
	allowAllBuilds?: Setting;
	/** package.json `trustedDependencies` (Bun's allow-list). */
	trusted?: string[];
}

/**
 * Config files each package manager reads for the project whose lockfile is
 * in a directory: `here` only in that directory, `inherited` also in its
 * parents. Settings in other files do not affect that install.
 */
const MANAGER_CONFIGS: Readonly<
	Record<
		Manager,
		{
			readonly here: ReadonlyArray<string>;
			readonly inherited: ReadonlyArray<string>;
		}
	>
> = {
	npm: { here: [".npmrc", "package.json"], inherited: [] },
	pnpm: {
		here: [".npmrc", "pnpm-workspace.yaml", "package.json"],
		inherited: [],
	},
	bun: { here: ["bunfig.toml", ".npmrc", "package.json"], inherited: [] },
	yarn: { here: [], inherited: [".yarnrc", ".npmrc"] },
	"yarn-berry": { here: [], inherited: [".yarnrc.yml"] },
};

const scopeOf = (key: string) => {
	const scope = key.startsWith("@") ? key : `@${key}`;
	return scope.length > 1 ? scope : undefined;
};

/** A value as the `ini` package (npm's .npmrc parser) unescapes it. */
const iniValue = (raw: string): unknown => {
	let val = raw.trim();
	const quoted =
		val.length > 1 &&
		((val[0] === '"' && val.endsWith('"')) ||
			(val[0] === "'" && val.endsWith("'")));
	if (quoted) {
		if (val[0] === "'") val = val.slice(1, -1);
		try {
			return JSON.parse(val);
		} catch {
			return val;
		}
	}
	let out = "";
	let escaped = false;
	for (const c of val) {
		if (escaped) {
			out += ";#".includes(c) ? c : `\\${c}`;
			escaped = false;
		} else if (c === ";" || c === "#") break;
		else if (c === "\\") escaped = true;
		else out += c;
	}
	if (escaped) out += "\\";
	return out.trim();
};

const INI_LINE = /^\[([^\]]*)\]\s*$|^([^=]+)(=(.*))?$/;

/** Longer values are left as written: a fallback scan per `${` is quadratic. */
const MAX_INTERPOLATED = 4096;

/**
 * npm's env-replace (@npmcli/config) with every variable unset, as
 * openaudit cannot know the install's environment: `${VAR?}` is empty,
 * `${VAR}` stays as written, and a backslash escapes.
 */
const npmEnv = (s: string): string =>
	s.length > MAX_INTERPOLATED
		? s
		: s.replace(
				/(?<!\\)(\\*)\$\{([^${}?]+)(\?)?\}/g,
				(orig: string, esc: string, _name: string, optional?: string) =>
					esc.length % 2
						? orig.slice((esc.length + 1) / 2)
						: esc.slice(esc.length / 2) +
							(optional ? "" : orig.slice(esc.length)),
			);

/**
 * Yarn's replaceEnvVariables with every variable unset: `${VAR:-x}` and
 * `${VAR-x}` are `x`; `${VAR}`, which Yarn needs from the environment, stays.
 */
const yarnEnv = (s: string): string =>
	s.length > MAX_INTERPOLATED
		? s
		: s.replace(
				/\\?\$\{([\w]+)(:)?(?:-([^}]*))?\}/g,
				(match: string, _name: string, _colon?: string, fallback?: string) =>
					match.startsWith("\\") ? match.slice(1) : (fallback ?? match),
			);

/**
 * `.npmrc`, read like npm's `ini` parser: `\r` and `\n` end lines, `;` and `#`
 * start comments (also after a value), keys after a `[section]` header are not
 * npm config, and the last value of a key wins.
 * `${VAR}` references are expanded as npm does (see npmEnv).
 */
const readNpmrc = (file: SourceFile, config: FileConfig): boolean => {
	const values = new Map<
		string,
		{ readonly value: unknown; readonly line: number }
	>();
	let inSection = false;
	stripBom(file.text)
		.split(/\r\n|\r|\n/)
		.forEach((line, i) => {
			if (/^\s*([;#]|$)/.test(line)) return;
			const m = INI_LINE.exec(line);
			if (!m) return;
			if (m[1] !== undefined) {
				inSection = true;
				return;
			}
			if (inSection) return;
			const key = npmEnv(String(iniValue(m[2] ?? "")));
			if (key.length > 2 && key.endsWith("[]")) return;
			const parsed = m[3] ? iniValue(m[4] ?? "") : true;
			const raw = typeof parsed === "string" ? npmEnv(parsed) : parsed;
			const value =
				raw === "true"
					? true
					: raw === "false"
						? false
						: raw === "null"
							? null
							: raw;
			values.set(key, { value, line: i + 1 });
		});
	for (const [key, { value, line }] of values) {
		const at = { file: file.path, line };
		if (
			typeof value === "string" &&
			(key === "registry" || key.endsWith(":registry"))
		) {
			const scope =
				key === "registry"
					? undefined
					: scopeOf(key.slice(0, -":registry".length));
			config.registries.push({
				...at,
				url: value,
				...(scope ? { scope } : {}),
				evidence: `${key}=${displayUrl(value)}`,
			});
		} else if (key === "ignore-scripts" && value === true)
			// The setting, not the raw line: a trailing comment can hold anything.
			config.ignoreScripts = { ...at, evidence: "ignore-scripts=true" };
		else if (key === "strict-ssl" && value === false)
			config.strictSslOff = { ...at, evidence: "strict-ssl=false" };
	}
	return true;
};

/** Classic `.yarnrc`, read with Yarn 1's lockfile grammar like Yarn does. */
const readYarnrc = (file: SourceFile, config: FileConfig): boolean => {
	const parsed = parseYarnClassic(stripBom(file.text));
	if (!parsed) return false;
	for (const [key, value] of Object.entries(parsed.obj)) {
		const at = { file: file.path, line: parsed.lines.get(key) };
		if (
			typeof value === "string" &&
			(key === "registry" || key.endsWith(":registry"))
		) {
			const scope =
				key === "registry"
					? undefined
					: scopeOf(key.slice(0, -":registry".length));
			config.registries.push({
				...at,
				url: value,
				...(scope ? { scope } : {}),
				evidence: `${key} ${displayUrl(value)}`,
			});
		} else if (key === "strict-ssl" && String(value) === "false")
			config.strictSslOff = { ...at, evidence: "strict-ssl false" };
	}
	return true;
};

/** `.yarnrc.yml` (YAML as Yarn reads it): registries and `enableStrictSsl`. */
const readYarnrcYml = (file: SourceFile, config: FileConfig): boolean => {
	let doc: unknown;
	try {
		doc = parseYaml(stripBom(file.text));
	} catch {
		return false;
	}
	if (!isRecord(doc)) return doc === null || doc === undefined;
	const lineOf = lineFinder(file.text);
	const registry = (value: unknown, scope?: string) => {
		if (typeof value !== "string") return;
		const url = yarnEnv(value);
		config.registries.push({
			file: file.path,
			line: lineOf(value),
			url,
			...(scope ? { scope } : {}),
			evidence: `${scope ? `npmScopes.${scope.slice(1)}.` : ""}npmRegistryServer: ${displayUrl(url)}`,
		});
	};
	registry(doc.npmRegistryServer);
	if (isRecord(doc.npmScopes))
		for (const [scope, value] of Object.entries(doc.npmScopes))
			if (isRecord(value)) registry(value.npmRegistryServer, scopeOf(scope));
	if (yarnEnv(String(doc.enableStrictSsl)) === "false")
		config.strictSslOff = {
			file: file.path,
			line: lineOf("enableStrictSsl"),
			evidence: "enableStrictSsl: false",
		};
	return true;
};

/** bunfig.toml, parsed with Bun's TOML parser: `install.registry` and `install.scopes`. */
const readBunfig = (file: SourceFile, config: FileConfig): boolean => {
	let doc: unknown;
	try {
		doc = Bun.TOML.parse(stripBom(file.text));
	} catch {
		return false;
	}
	const install = isRecord(doc) && isRecord(doc.install) ? doc.install : {};
	const lineOf = lineFinder(file.text);
	const registry = (value: unknown, scope?: string) => {
		const url = isRecord(value) ? str(value.url) : str(value);
		if (!url || !/^(https?:)?\/\//i.test(url)) return;
		config.registries.push({
			file: file.path,
			line: lineOf(url),
			url,
			...(scope ? { scope } : {}),
			evidence: `${scope ?? "registry"} = ${displayUrl(url)}`,
		});
	};
	registry(install.registry);
	if (isRecord(install.scopes))
		for (const [scope, value] of Object.entries(install.scopes))
			registry(value, scopeOf(scope));
	return true;
};

/** pnpm build settings, from pnpm-workspace.yaml or package.json `pnpm`. */
const readPnpmBuildSettings = (
	settings: Record<string, unknown>,
	file: SourceFile,
	config: FileConfig,
) => {
	const lineOf = lineFinder(file.text);
	if (Array.isArray(settings.onlyBuiltDependencies)) {
		config.onlyBuilt = strings(settings.onlyBuiltDependencies);
		// Treated as allowing everything, whether or not pnpm expands it.
		if (config.onlyBuilt.some((n) => n.includes("*")))
			config.allowAllBuilds = {
				file: file.path,
				line: lineOf("onlyBuiltDependencies"),
				evidence: `onlyBuiltDependencies: ${truncate(config.onlyBuilt.join(", "), 100)}`,
			};
	}
	if (Array.isArray(settings.neverBuiltDependencies))
		config.neverBuilt = strings(settings.neverBuiltDependencies);
	if (settings.dangerouslyAllowAllBuilds === true)
		config.allowAllBuilds = {
			file: file.path,
			line: lineOf("dangerouslyAllowAllBuilds"),
			evidence: "dangerouslyAllowAllBuilds: true",
		};
};

const readPnpmWorkspace = (file: SourceFile, config: FileConfig): boolean => {
	let doc: unknown;
	try {
		doc = parseYaml(stripBom(file.text));
	} catch {
		return false;
	}
	if (isRecord(doc)) readPnpmBuildSettings(doc, file, config);
	return isRecord(doc) || doc === null || doc === undefined;
};

/** package.json: `pnpm.*` build settings and Bun's `trustedDependencies`. */
const readPackageJson = (file: SourceFile, config: FileConfig): boolean => {
	const json = parseJson(file.text);
	if (!isRecord(json)) return false;
	if (isRecord(json.pnpm)) readPnpmBuildSettings(json.pnpm, file, config);
	if (Array.isArray(json.trustedDependencies))
		config.trusted = strings(json.trustedDependencies);
	return true;
};

/** Reads a config file into `config`; false when the file does not parse. */
export const CONFIG_READERS: Readonly<
	Record<string, (file: SourceFile, config: FileConfig) => boolean>
> = {
	".npmrc": readNpmrc,
	".yarnrc": readYarnrc,
	".yarnrc.yml": readYarnrcYml,
	"bunfig.toml": readBunfig,
	"pnpm-workspace.yaml": readPnpmWorkspace,
	"package.json": readPackageJson,
};

/** Configs the lockfile's package manager reads, nearest first. */
export const configsFor = (
	configs: ReadonlyMap<string, FileConfig>,
	lock: Lockfile,
): FileConfig[] => {
	const { here, inherited } = MANAGER_CONFIGS[lock.manager];
	const out: FileConfig[] = [];
	const lockDir = dirOf(lock.path);
	let d = lockDir;
	for (;;) {
		for (const name of d === lockDir ? [...here, ...inherited] : inherited) {
			const c = configs.get(joinDir(d, name));
			if (c) out.push(c);
		}
		if (!d) return out;
		d = dirOf(d);
	}
};

export const scopeOfPackage = (name: string) =>
	name.startsWith("@") ? name.slice(0, name.indexOf("/")) : undefined;

/** The registry a package manager would fetch `name` from, if configured. */
export const registryFor = (
	configs: ReadonlyArray<FileConfig>,
	name: string,
): Registry | undefined => {
	const scope = scopeOfPackage(name);
	const all = configs.flatMap((c) => c.registries);
	return (
		(scope ? all.find((r) => r.scope === scope) : undefined) ??
		all.find((r) => r.scope === undefined)
	);
};
