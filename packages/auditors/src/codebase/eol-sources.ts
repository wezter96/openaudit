import type { Confidence } from "@openaudit/core";

import {
	type Dependency,
	dependencyLineFinder,
	parseDependencies,
} from "./dependencies";
import { baseName, lineLocator, type SourceFile } from "./util";

/*
 * Where a repository declares its runtime and framework versions, for
 * code.eol. Everything is read as text with regexes; nothing is executed.
 */

export type EolKind = "runtime" | "framework";

/** A runtime or framework version a file declares. */
export interface Declaration {
	/** endoflife.date product id, e.g. `nodejs`. */
	readonly product: string;
	readonly kind: EolKind;
	/** The version string as written, e.g. `>=3.8` or `v18.17.0`. */
	readonly raw: string;
	/** The version judged: the pin, or the lowest version a range allows. */
	readonly version: string;
	/** True when `raw` is a range rather than one version. */
	readonly range: boolean;
	readonly file: string;
	readonly line: number;
	readonly confidence: Confidence;
}

/** A value a source found, before it is turned into a declaration. */
interface Match {
	readonly product: string;
	readonly raw: string;
	readonly index: number;
}

interface Source {
	readonly file: (path: string) => boolean;
	readonly find: (text: string) => Match[];
	/** Ranges are judged by their lowest allowed version. */
	readonly range?: boolean;
	/** For values that are not exact pins (a language level, a minimum). */
	readonly confidence?: Confidence;
}

const named =
	(...names: string[]) =>
	(path: string) =>
		names.includes(baseName(path));

/** Every match of `re` (which needs the `d` and `g` flags) as group 1. */
const matchAll = (text: string, re: RegExp, product: string): Match[] =>
	[...text.matchAll(re)].flatMap((m) => {
		const at = m.indices?.[1];
		return m[1] && at ? [{ product, raw: m[1], index: at[0] }] : [];
	});

/** The first non-blank, non-comment line of a version file. */
const firstLine =
	(product: string) =>
	(text: string): Match[] =>
		matchAll(text, /^[ \t]*([^\s#][^\s#]*)/dgm, product).slice(0, 1);

/** asdf and mise tool names, mapped to endoflife.date products. */
const TOOLS: Record<string, string> = {
	node: "nodejs",
	nodejs: "nodejs",
	python: "python",
	go: "go",
	golang: "go",
	ruby: "ruby",
	java: "eclipse-temurin",
	php: "php",
	dotnet: "dotnet",
	"dotnet-core": "dotnet",
};

/** `tool version` lines (asdf) or `tool = "version"` lines (mise). */
const toolLines =
	(re: RegExp) =>
	(text: string): Match[] =>
		[...text.matchAll(re)].flatMap((m) => {
			const product = TOOLS[m[1] ?? ""];
			const at = m.indices?.[2];
			return product && m[2] && at
				? [{ product, raw: m[2], index: at[0] }]
				: [];
		});

/** Each `netX.Y` / `netcoreappX.Y` of a `<TargetFramework(s)>` element. */
const targetFrameworks = (text: string): Match[] =>
	[...text.matchAll(/<TargetFrameworks?>([^<]+)</dg)].flatMap((m) => {
		const start = m.indices?.[1]?.[0] ?? 0;
		return [...(m[1] ?? "").matchAll(/net(?:coreapp)?(\d+\.\d+)/g)].map(
			(t) => ({
				product: "dotnet",
				raw: t[0],
				index: start + (t.index ?? 0),
			}),
		);
	});

const re = (pattern: string) => new RegExp(pattern, "dgm");

/** A JSON object member `"outer": { ... "inner": "value" }` (flat objects only). */
const jsonMember = (outer: string, inner: string) =>
	re(`"${outer}"\\s*:\\s*\\{[^}]*?"${inner}"\\s*:\\s*"([^"]+)"`);

const SOURCES: ReadonlyArray<Source> = [
	{ file: named(".nvmrc", ".node-version"), find: firstLine("nodejs") },
	{
		file: named("package.json"),
		find: (t) => matchAll(t, jsonMember("engines", "node"), "nodejs"),
		range: true,
	},
	{
		file: named("package.json"),
		find: (t) => matchAll(t, jsonMember("volta", "node"), "nodejs"),
	},
	{
		file: named(".tool-versions"),
		find: toolLines(/^[ \t]*([\w-]+)[ \t]+(\S+)/dgm),
	},
	{
		// shortcut: any `tool = "x"` line counts, not only those under [tools]; parse TOML if that misfires.
		file: named("mise.toml", ".mise.toml"),
		find: toolLines(/^[ \t]*"?([\w-]+)"?[ \t]*=[ \t]*\[?[ \t]*["']([^"']+)/dgm),
	},
	{ file: named(".python-version"), find: firstLine("python") },
	{
		file: named("runtime.txt"),
		find: (t) => matchAll(t, re("^\\s*(python-\\d[\\w.]*)"), "python"),
	},
	{
		file: named("pyproject.toml"),
		find: (t) =>
			matchAll(t, re(`^\\s*requires-python\\s*=\\s*["']([^"']+)`), "python"),
		range: true,
	},
	{
		// The `go` directive is the language version, the minimum toolchain.
		file: named("go.mod"),
		find: (t) => matchAll(t, re("^go\\s+(\\d[\\w.]*)"), "go"),
		confidence: "medium",
	},
	{
		file: named("go.mod"),
		find: (t) => matchAll(t, re("^toolchain\\s+go(\\d[\\w.]*)"), "go"),
	},
	{ file: named(".ruby-version"), find: firstLine("ruby") },
	{
		file: named("Gemfile"),
		find: (t) => matchAll(t, re(`^\\s*ruby\\s+["']([^"']+)`), "ruby"),
		range: true,
	},
	{ file: named(".java-version"), find: firstLine("eclipse-temurin") },
	{
		file: named("pom.xml"),
		find: (t) =>
			matchAll(
				t,
				/<(?:maven\.compiler\.(?:release|source)|java\.version)>\s*([^<\s]+)/dg,
				"eclipse-temurin",
			),
		confidence: "medium",
	},
	{
		file: named("composer.json"),
		find: (t) => matchAll(t, jsonMember("require", "php"), "php"),
		range: true,
	},
	{
		file: named("global.json"),
		find: (t) => matchAll(t, jsonMember("sdk", "version"), "dotnet"),
	},
	{
		file: (p) => /\.(cs|fs|vb)proj$/.test(p),
		find: targetFrameworks,
	},
];

/** Framework sources the lockfile parsers of code.dependencies do not cover. */
const FRAMEWORK_SOURCES: ReadonlyArray<Source> = [
	{
		file: named("pom.xml"),
		find: (t) =>
			matchAll(
				t,
				/<artifactId>spring-boot-starter-parent<\/artifactId>\s*<version>([^<]+)</dg,
				"spring-boot",
			),
	},
	{
		file: named("build.gradle", "build.gradle.kts"),
		find: (t) =>
			matchAll(
				t,
				/id[ \t(]*["']org\.springframework\.boot["'][ \t)]*version[ \t(]*["']([^"']+)/dg,
				"spring-boot",
			),
	},
];

/** Frameworks by `ecosystem|package` in the lockfiles code.dependencies parses. */
const LOCKED_FRAMEWORKS: Record<string, string> = {
	"npm|@angular/core": "angular",
	"npm|next": "nextjs",
	"npm|vue": "vue",
	"PyPI|django": "django",
	"RubyGems|rails": "rails",
	"Packagist|laravel/framework": "laravel",
};

const frameworkOf = (d: Dependency) =>
	LOCKED_FRAMEWORKS[
		`${d.ecosystem}|${d.ecosystem === "PyPI" ? d.name.toLowerCase() : d.name}`
	];

export const isEolSource = (path: string) =>
	[...SOURCES, ...FRAMEWORK_SOURCES].some((s) => s.file(path));

/* -------------------------------------------------------------------------- */
/*                                  Versions                                  */
/* -------------------------------------------------------------------------- */

const NUMBER = /\d+(?:\.\d+){0,2}/;

/** Numeric parts of a dotted version. */
export const versionParts = (v: string): number[] => v.split(".").map(Number);

/** Orders dotted versions numerically: `3.9` before `3.10`. */
export const compareVersions = (a: string, b: string): number => {
	const x = versionParts(a);
	const y = versionParts(b);
	for (let i = 0; i < Math.max(x.length, y.length); i++) {
		const d = (x[i] ?? 0) - (y[i] ?? 0);
		if (d !== 0) return d;
	}
	return 0;
};

/** A bare version such as `18`, `v18.17.0` or `=3.8`. */
const isBare = (raw: string) => /^\s*[v=]?\s*\d+(\.\d+)*\s*$/.test(raw);

/**
 * The version a pin names: `v18.17.0`, `python-3.8.10`, `temurin-17.0.1`.
 * Undefined for aliases such as `lts/*`, `system` or `pypy3.9`.
 */
const pinnedVersion = (raw: string): string | undefined => {
	const m = /^(?:[a-z]+-|v)?(\d+(?:\.\d+){0,2})/i.exec(raw.trim());
	return m?.[1];
};

/**
 * The lowest version a range allows: the smallest bound not introduced by
 * `<` or `!=`. `>=3.8,<4` gives 3.8, `^7.4 || ^8.0` gives 7.4.
 */
export const lowestVersion = (raw: string): string | undefined =>
	[...raw.matchAll(new RegExp(`(<=?|!=)?\\s*v?(${NUMBER.source})`, "g"))]
		.flatMap((m) => (m[1] || !m[2] ? [] : [m[2]]))
		.sort(compareVersions)[0];

/** Java writes 8 as `1.8`; .NET writes 8 as `net8.0`. */
const normalize = (product: string, version: string) =>
	product === "eclipse-temurin" ? version.replace(/^1\.(?=\d)/, "") : version;

/* -------------------------------------------------------------------------- */
/*                                Declarations                                */
/* -------------------------------------------------------------------------- */

const declarationsOf = (
	file: SourceFile,
	source: Source,
	kind: EolKind,
): Declaration[] => {
	const lineOf = lineLocator(file.text);
	return source.find(file.text).flatMap((m) => {
		const raw =
			m.product === "dotnet" ? m.raw.replace(/^net(coreapp)?/, "") : m.raw;
		const range = source.range === true && !isBare(raw);
		const version = range ? lowestVersion(raw) : pinnedVersion(raw);
		if (!version) return [];
		return [
			{
				product: m.product,
				kind,
				raw: m.raw,
				version: normalize(m.product, version),
				range,
				file: file.path,
				line: lineOf(m.index),
				// A bare version in a range field is an exact pin.
				confidence: range
					? "low"
					: source.range
						? "high"
						: (source.confidence ?? "high"),
			},
		];
	});
};

const lockedFrameworks = (files: ReadonlyArray<SourceFile>): Declaration[] => {
	const lineFor = dependencyLineFinder(files);
	return files.flatMap(parseDependencies).flatMap((d) => {
		const product = frameworkOf(d);
		const version = pinnedVersion(d.version);
		return product && version
			? [
					{
						product,
						kind: "framework" as const,
						raw: `${d.name}@${d.version}`,
						version,
						range: false,
						file: d.file,
						line: lineFor(d) ?? 1,
						confidence: "high" as const,
					},
				]
			: [];
	});
};

/** Every runtime and framework version the files declare. */
export const findDeclarations = (
	files: ReadonlyArray<SourceFile>,
): Declaration[] => [
	...files.flatMap((f) =>
		SOURCES.filter((s) => s.file(f.path)).flatMap((s) =>
			declarationsOf(f, s, "runtime"),
		),
	),
	...files.flatMap((f) =>
		FRAMEWORK_SOURCES.filter((s) => s.file(f.path)).flatMap((s) =>
			declarationsOf(f, s, "framework"),
		),
	),
	...lockedFrameworks(files),
];
