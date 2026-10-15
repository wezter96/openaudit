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

const INI_QUOTES = ['"', "'"];

const isQuotedIni = (val: string) =>
	val.length > 1 && INI_QUOTES.some((q) => val[0] === q && val.endsWith(q));

/** A quoted value: JSON-decoded, single quotes stripped first. */
const unquoteIni = (quoted: string): unknown => {
	const val = quoted[0] === "'" ? quoted.slice(1, -1) : quoted;
	try {
		return JSON.parse(val);
	} catch {
		return val;
	}
};

/** An unquoted value: a `;` or `#` ends it unless escaped. */
const unescapeIni = (val: string): string => {
	let out = "";
	let escaped = false;
	for (const c of val) {
		if (escaped) {
			out += ";#".includes(c) ? c : `\\${c}`;
			escaped = false;
		} else if (";#".includes(c)) break;
		else if (c === "\\") escaped = true;
		else out += c;
	}
	if (escaped) out += "\\";
	return out.trim();
};

/** A value as the `ini` package (npm's .npmrc parser) unescapes it. */
const iniValue = (raw: string): unknown => {
	const val = raw.trim();
	return isQuotedIni(val) ? unquoteIni(val) : unescapeIni(val);
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

/** Where a setting was found. */
type SettingSite = Pick<Setting, "file" | "line">;

/** A config key, such as `registry` or `@scope:registry`. */
type ConfigKey = string;

const isRegistryKey = (key: ConfigKey) =>
	key === "registry" || key.endsWith(":registry");

/**
 * The registry a `registry` or `@scope:registry` key sets, if it does.
 * `separator` goes between key and URL in the evidence, as the file writes it.
 */
const registrySetting = (
	at: SettingSite,
	key: ConfigKey,
	value: unknown,
	separator: "=" | " ",
): Registry | undefined => {
	if (typeof value !== "string" || !isRegistryKey(key)) return undefined;
	const scope =
		key === "registry" ? undefined : scopeOf(key.slice(0, -":registry".length));
	return {
		...at,
		url: value,
		...(scope ? { scope } : {}),
		evidence: `${key}${separator}${displayUrl(value)}`,
	};
};

/** `true`, `false` and `null` as npm's config reads them. */
const INI_LITERALS = new Map<unknown, unknown>([
	["true", true],
	["false", false],
	["null", null],
]);

const iniLiteral = (raw: unknown) =>
	INI_LITERALS.has(raw) ? INI_LITERALS.get(raw) : raw;

/** `key[]=value` appends to a list, which no setting read here is. */
const isArrayKey = (key: ConfigKey) => key.length > 2 && key.endsWith("[]");

/** A `key=value` (or bare `key`) line of an .npmrc, or undefined to skip it. */
const npmrcEntry = (
	m: RegExpExecArray,
): { readonly key: ConfigKey; readonly value: unknown } | undefined => {
	const key = npmEnv(String(iniValue(m[2] ?? "")));
	if (isArrayKey(key)) return undefined;
	const parsed = m[3] ? iniValue(m[4] ?? "") : true;
	const raw = typeof parsed === "string" ? npmEnv(parsed) : parsed;
	return { key, value: iniLiteral(raw) };
};

/** The last value and line of each npm config key in an .npmrc. */
const npmrcValues = (text: string) => {
	const values = new Map<
		ConfigKey,
		{ readonly value: unknown; readonly line: number }
	>();
	let inSection = false;
	stripBom(text)
		.split(/\r\n|\r|\n/)
		.forEach((line, i) => {
			if (/^\s*([;#]|$)/.test(line)) return;
			const m = INI_LINE.exec(line);
			if (!m) return;
			if (m[1] !== undefined) inSection = true;
			const entry = inSection ? undefined : npmrcEntry(m);
			if (entry) values.set(entry.key, { value: entry.value, line: i + 1 });
		});
	return values;
};

/** A boolean setting that matters, with the value that turns it on. */
interface FlagRule {
	readonly key: ConfigKey;
	readonly field: "ignoreScripts" | "strictSslOff";
	readonly matches: (value: unknown) => boolean;
	/** The setting, not the raw line: a trailing comment can hold anything. */
	readonly evidence: string;
}

/** How a config format writes its settings. */
interface ConfigSyntax {
	/** Between key and URL in a registry's evidence. */
	readonly separator: "=" | " ";
	readonly flags: ReadonlyArray<FlagRule>;
}

const NPMRC: ConfigSyntax = {
	separator: "=",
	flags: [
		{
			key: "ignore-scripts",
			field: "ignoreScripts",
			matches: (value) => value === true,
			evidence: "ignore-scripts=true",
		},
		{
			key: "strict-ssl",
			field: "strictSslOff",
			matches: (value) => value === false,
			evidence: "strict-ssl=false",
		},
	],
};

const YARNRC: ConfigSyntax = {
	separator: " ",
	flags: [
		{
			key: "strict-ssl",
			field: "strictSslOff",
			matches: (value) => String(value) === "false",
			evidence: "strict-ssl false",
		},
	],
};

/** One `key value` setting of an .npmrc or .yarnrc, applied to `config`. */
const applySetting = (
	config: FileConfig,
	{ at, key, value }: { at: SettingSite; key: ConfigKey; value: unknown },
	syntax: ConfigSyntax,
) => {
	const registry = registrySetting(at, key, value, syntax.separator);
	if (registry) {
		config.registries.push(registry);
		return;
	}
	const flag = syntax.flags.find((f) => f.key === key && f.matches(value));
	if (flag) config[flag.field] = { ...at, evidence: flag.evidence };
};

/**
 * `.npmrc`, read like npm's `ini` parser: `\r` and `\n` end lines, `;` and `#`
 * start comments (also after a value), keys after a `[section]` header are not
 * npm config, and the last value of a key wins.
 * `${VAR}` references are expanded as npm does (see npmEnv).
 */
const readNpmrc = (file: SourceFile, config: FileConfig): boolean => {
	for (const [key, { value, line }] of npmrcValues(file.text))
		applySetting(config, { at: { file: file.path, line }, key, value }, NPMRC);
	return true;
};

/** Classic `.yarnrc`, read with Yarn 1's lockfile grammar like Yarn does. */
const readYarnrc = (file: SourceFile, config: FileConfig): boolean => {
	const parsed = parseYarnClassic(stripBom(file.text));
	if (!parsed) return false;
	for (const [key, value] of Object.entries(parsed.obj)) {
		const at = { file: file.path, line: parsed.lines.get(key) };
		applySetting(config, { at, key, value }, YARNRC);
	}
	return true;
};

/** YAML parses an empty file to null; that is a valid, empty config. */
const isEmptyDoc = (doc: unknown) => doc === null || doc === undefined;

/** The parsed document, or undefined when the parser throws. */
const tryParse = (parse: () => unknown): { doc: unknown } | undefined => {
	try {
		return { doc: parse() };
	} catch {
		return undefined;
	}
};

/** A config file being read into `config`. */
interface ConfigRead {
	readonly file: SourceFile;
	readonly config: FileConfig;
	readonly lineOf: (needle: string) => number | undefined;
}

/** A Yarn `npmRegistryServer`, at the top level or under `npmScopes.<scope>`. */
const yarnRegistry = (
	{ file, config, lineOf }: ConfigRead,
	value: unknown,
	scope?: string,
) => {
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

const yarnScopeRegistries = (read: ConfigRead, scopes: unknown) => {
	if (!isRecord(scopes)) return;
	for (const [scope, value] of Object.entries(scopes))
		if (isRecord(value))
			yarnRegistry(read, value.npmRegistryServer, scopeOf(scope));
};

/** `.yarnrc.yml` (YAML as Yarn reads it): registries and `enableStrictSsl`. */
const readYarnrcYml = (file: SourceFile, config: FileConfig): boolean => {
	const parsed = tryParse(() => parseYaml(stripBom(file.text)));
	if (!parsed) return false;
	const { doc } = parsed;
	if (!isRecord(doc)) return isEmptyDoc(doc);
	const read = { file, config, lineOf: lineFinder(file.text) };
	yarnRegistry(read, doc.npmRegistryServer);
	yarnScopeRegistries(read, doc.npmScopes);
	if (yarnEnv(String(doc.enableStrictSsl)) === "false")
		config.strictSslOff = {
			file: file.path,
			line: read.lineOf("enableStrictSsl"),
			evidence: "enableStrictSsl: false",
		};
	return true;
};

/** A bunfig `install.registry` or `install.scopes.<scope>`: a URL or `{ url }`. */
const bunRegistry = (
	{ file, config, lineOf }: ConfigRead,
	value: unknown,
	scope?: string,
) => {
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

const bunScopeRegistries = (read: ConfigRead, scopes: unknown) => {
	if (!isRecord(scopes)) return;
	for (const [scope, value] of Object.entries(scopes))
		bunRegistry(read, value, scopeOf(scope));
};

const installTable = (doc: unknown): Record<string, unknown> =>
	isRecord(doc) && isRecord(doc.install) ? doc.install : {};

/** bunfig.toml, parsed with Bun's TOML parser: `install.registry` and `install.scopes`. */
const readBunfig = (file: SourceFile, config: FileConfig): boolean => {
	const parsed = tryParse(() => Bun.TOML.parse(stripBom(file.text)));
	if (!parsed) return false;
	const { doc } = parsed;
	const install = installTable(doc);
	const read = { file, config, lineOf: lineFinder(file.text) };
	bunRegistry(read, install.registry);
	bunScopeRegistries(read, install.scopes);
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
	const parsed = tryParse(() => parseYaml(stripBom(file.text)));
	if (!parsed) return false;
	const { doc } = parsed;
	if (isRecord(doc)) readPnpmBuildSettings(doc, file, config);
	return isRecord(doc) || isEmptyDoc(doc);
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

/** `dir` and each directory above it, up to the root (`""`). */
const ancestors = (dir: string): string[] => {
	const out = [dir];
	for (let d = dir; d; ) {
		d = dirOf(d);
		out.push(d);
	}
	return out;
};

/** Configs the lockfile's package manager reads, nearest first. */
export const configsFor = (
	configs: ReadonlyMap<string, FileConfig>,
	lock: Lockfile,
): FileConfig[] => {
	const { here, inherited } = MANAGER_CONFIGS[lock.manager];
	const lockDir = dirOf(lock.path);
	return ancestors(lockDir).flatMap((d) =>
		(d === lockDir ? [...here, ...inherited] : inherited)
			.map((name) => configs.get(joinDir(d, name)))
			.filter((c) => c !== undefined),
	);
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
