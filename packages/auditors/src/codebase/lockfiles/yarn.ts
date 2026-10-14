import { isRecord, type SourceFile } from "../util";
import {
	type Importer,
	type LockedPackage,
	type Lockfile,
	lineFinder,
	type Problem,
	parseYaml,
	scalar,
	sourceField,
	uniqueProblems,
	versionProblem,
	yamlKeyLines,
} from "./shared";
import { classifySource } from "./sources";

const nameOfSpec = (spec: string) => {
	const at = spec.indexOf("@", 1);
	return at === -1 ? spec : spec.slice(0, at);
};

/** Workspace directory from Berry's `::locator=name%40workspace%3Adir`. */
const berryLocatorDir = (params: string): string => {
	for (const pair of params.split("&")) {
		if (!pair.startsWith("locator=")) continue;
		let locator: string;
		try {
			locator = decodeURIComponent(pair.slice("locator=".length));
		} catch {
			return "";
		}
		const i = locator.indexOf("@workspace:");
		return i === -1 ? "" : locator.slice(i + "@workspace:".length);
	}
	return "";
};

/*
 * A port of Yarn 1's lockfile parser (src/lockfile/parse.js), so that what is
 * checked is exactly what Yarn reads: comments run to the next \n, a lone \r
 * is a newline but does not start an indent, only even runs of spaces indent,
 * quoted strings are JSON, and a repeated key overrides the earlier one.
 */

type YarnToken =
	| {
			readonly type:
				| "newline"
				| "colon"
				| "comma"
				| "comment"
				| "eof"
				| "invalid";
			readonly line: number;
	  }
	| { readonly type: "indent"; readonly value: number; readonly line: number }
	| {
			readonly type: "string" | "number" | "boolean";
			readonly value: string | number | boolean;
			readonly line: number;
	  };

class YarnLexer {
	private i = 0;
	private line = 1;
	private lastNewline = false;
	constructor(private readonly s: string) {}

	next(): YarnToken {
		const s = this.s;
		for (;;) {
			const i = this.i;
			if (i >= s.length) return { type: "eof", line: this.line };
			const c = s[i] as string;
			const line = this.line;
			let chop = 1;
			let token: YarnToken | undefined;
			if (c === "\n" || c === "\r") {
				if (c === "\r" && s[i + 1] === "\n") chop = 2;
				this.line++;
				token = { type: "newline", line };
			} else if (c === "#") {
				const nl = s.indexOf("\n", i + 1);
				chop = (nl === -1 ? s.length : nl) - i;
				token = { type: "comment", line };
			} else if (c === " ") {
				if (this.lastNewline) {
					let n = 1;
					while (s[i + n] === " ") n++;
					if (n % 2) throw new Error("Invalid number of spaces");
					chop = n;
					token = { type: "indent", value: n / 2, line };
				}
			} else if (c === '"') {
				let j = i + 1;
				for (; j < s.length; j++)
					if (s[j] === '"' && !(s[j - 1] === "\\" && s[j - 2] !== "\\")) {
						j++;
						break;
					}
				chop = j - i;
				try {
					token = { type: "string", value: JSON.parse(s.slice(i, j)), line };
				} catch {
					token = { type: "invalid", line };
				}
			} else if (c >= "0" && c <= "9") {
				let j = i;
				while (
					s[j] !== undefined &&
					(s[j] as string) >= "0" &&
					(s[j] as string) <= "9"
				)
					j++;
				chop = j - i;
				token = { type: "number", value: Number(s.slice(i, j)), line };
			} else if (s.startsWith("true", i)) {
				chop = 4;
				token = { type: "boolean", value: true, line };
			} else if (s.startsWith("false", i)) {
				chop = 5;
				token = { type: "boolean", value: false, line };
			} else if (c === ":") token = { type: "colon", line };
			else if (c === ",") token = { type: "comma", line };
			else if (/[a-zA-Z/.-]/.test(c)) {
				let j = i;
				for (; j < s.length; j++) {
					const ch = s[j];
					if (
						ch === ":" ||
						ch === " " ||
						ch === "\n" ||
						ch === "\r" ||
						ch === ","
					)
						break;
				}
				chop = j - i;
				token = { type: "string", value: s.slice(i, j), line };
			} else token = { type: "invalid", line };
			this.lastNewline = c === "\n" || (c === "\r" && s[i + 1] === "\n");
			this.i += chop;
			if (token) return token;
		}
	}
}

/** Yarn 1's grammar; throws where Yarn throws. Records top-level key lines. */
const yarnGrammar = (
	text: string,
): {
	readonly obj: Record<string, unknown>;
	readonly lines: Map<string, number>;
} => {
	const lexer = new YarnLexer(text);
	const lines = new Map<string, number>();
	let token = lexer.next();
	const next = () => {
		token = lexer.next();
		return token;
	};
	const parse = (indent: number): Record<string, unknown> => {
		const obj: Record<string, unknown> = Object.create(null);
		for (;;) {
			const t = token;
			if (t.type === "newline") {
				const n = next();
				if (!indent) continue;
				if (n.type !== "indent") break;
				if (n.value === indent) next();
				else break;
			} else if (t.type === "indent") {
				if (t.value === indent) next();
				else break;
			} else if (t.type === "eof") break;
			else if (t.type === "string") {
				if (!t.value) throw new Error("Expected a key");
				const keys = [String(t.value)];
				next();
				while (token.type === "comma") {
					const k = next();
					if (k.type !== "string") throw new Error("Expected string");
					keys.push(String(k.value));
					next();
				}
				const wasColon = token.type === "colon";
				if (wasColon) next();
				const v = token;
				const plain =
					v.type === "string" || v.type === "number" || v.type === "boolean";
				if (!plain && !wasColon) throw new Error("Invalid value type");
				let value: unknown;
				if (plain) {
					value = v.value;
					next();
				} else value = parse(indent + 1);
				for (const k of keys) {
					obj[k] = value;
					if (!indent) lines.set(k, t.line);
				}
				if (!plain && indent && token.type !== "indent") break;
			} else if (t.type === "comment") next();
			else throw new Error("Unknown token");
		}
		return obj;
	};
	return { obj: parse(0), lines };
};

/** Yarn 1 reads lockfiles and .yarnrc with its grammar, falling back to YAML. */
export const parseYarnClassic = (
	text: string,
):
	| {
			readonly obj: Record<string, unknown>;
			readonly lines: Map<string, number>;
	  }
	| undefined => {
	try {
		return yarnGrammar(text);
	} catch {
		// Yarn 1 retries with js-yaml (FAILSAFE schema).
	}
	try {
		const doc: unknown = parseYaml(text);
		if (isRecord(doc))
			return { obj: doc, lines: yamlKeyLines(text, undefined) };
	} catch {
		// Neither parses: Yarn 1 cannot read it either.
	}
	return undefined;
};

/** Yarn 2+ treats files with this header as classic lockfiles. */
const YARN_V1_HEADER = /^(#.*(\r?\n))*?#\s+yarn\s+lockfile\s+v1\r?\n/i;

/**
 * yarn.lock, read the way both Yarn 1 (its grammar, then YAML) and Yarn 2+
 * (YAML unless the file has the classic header) read it. Which Yarn installs
 * is not known, so entries from either reading are checked: Berry's
 * `resolution`/`checksum` and Yarn 1's `resolved`/`integrity`.
 */
export const parseYarnLock = (file: SourceFile): Lockfile | undefined => {
	const text = file.text;
	const docs: Array<{
		readonly obj: Record<string, unknown>;
		readonly lines: Map<string, number>;
	}> = [];
	let classic: ReturnType<typeof parseYarnClassic>;
	try {
		classic = yarnGrammar(text);
		docs.push(classic);
	} catch {
		classic = undefined;
	}
	if (!YARN_V1_HEADER.test(text))
		try {
			const doc: unknown = parseYaml(text);
			if (isRecord(doc))
				docs.push({ obj: doc, lines: yamlKeyLines(text, undefined) });
		} catch {
			// Not YAML: Yarn 2+ cannot read it either.
		}
	if (!docs.length) {
		classic = parseYarnClassic(text);
		if (classic) docs.push(classic);
	}
	if (!docs.length) return undefined;

	const lineOf = lineFinder(text);
	const packages: LockedPackage[] = [];
	const workspaces = new Map<string, Importer>();
	const rootSpecs = new Map<string, string[]>();
	const problems: Problem[] = [];
	let berry = false;
	for (const { obj, lines } of docs) {
		if (isRecord(obj.__metadata)) {
			berry = true;
			problems.push(...versionProblem(obj.__metadata.version, [4, 5, 6, 7, 8]));
		}
		for (const [key, value] of Object.entries(obj)) {
			if (key === "__metadata" || !isRecord(value)) continue;
			const line = lines.get(key) ?? lineOf(key);
			const malformed = sourceField(value.resolution);
			const resolution =
				scalar(value.resolution) ??
				(malformed && `${nameOfSpec(key)}@${malformed}`);
			if (resolution !== undefined) {
				const name = nameOfSpec(resolution);
				const spec = resolution.slice(name.length + 1);
				if (spec.startsWith("workspace:")) {
					const dir = spec.slice("workspace:".length);
					const deps = isRecord(value.dependencies) ? value.dependencies : {};
					workspaces.set(
						dir === "." ? "" : dir,
						new Map(Object.keys(deps).map((n) => [n, undefined])),
					);
				} else {
					const params = spec.indexOf("::");
					const bare = params === -1 ? spec : spec.slice(0, params);
					const isPath = /^(file|link|portal):/.test(bare);
					// npm: packages outside the registry's usual tarball path
					// are downloaded from the URL in their locator.
					const archiveUrl =
						params === -1
							? null
							: new URLSearchParams(spec.slice(params + 2)).get("__archiveUrl");
					const checksum = scalar(value.checksum);
					packages.push({
						name,
						version: scalar(value.version),
						source: archiveUrl ?? (isPath ? bare.split("#")[0] : bare),
						...(isPath && params !== -1
							? { base: berryLocatorDir(spec.slice(params + 2)) }
							: {}),
						// Berry checksums are SHA-512 digests of the package archive.
						integrity: checksum ? `sha512-${checksum}` : undefined,
						line,
					});
				}
			}
			if (resolution !== undefined && value.resolved === undefined) continue;
			// Yarn 1's reading of the entry.
			const first = key.split(",")[0]?.trim() ?? key;
			const name = nameOfSpec(first);
			const declared = first.slice(name.length + 1);
			if (obj === classic?.obj) {
				// Pushed in place: copying the list per entry is quadratic.
				const specs = rootSpecs.get(name);
				if (specs) specs.push(declared);
				else rootSpecs.set(name, [declared]);
			}
			let resolved = scalar(value.resolved) ?? sourceField(value.resolved);
			let integrity = scalar(value.integrity);
			const source = classifySource(resolved);
			const hash = resolved?.indexOf("#") ?? -1;
			const sha1 = resolved && hash !== -1 ? resolved.slice(hash + 1) : "";
			// Classic yarn appends the archive's SHA-1 to registry, tarball and
			// codeload URLs; for those the fragment is a checksum, not a git ref.
			const archive =
				source.kind === "tarball" ||
				(source.kind === "git" && /^https?:/i.test(resolved ?? ""));
			if (resolved && archive && /^[0-9a-f]{40}$/i.test(sha1)) {
				resolved = resolved.slice(0, hash);
				integrity ??= `sha1-${sha1}`;
			}
			packages.push({
				name,
				version:
					value.version === undefined ? undefined : String(value.version),
				source:
					resolved ?? (/^(file|link):/.test(declared) ? declared : undefined),
				integrity,
				line,
			});
		}
	}
	return {
		path: file.path,
		manager: berry ? "yarn-berry" : "yarn",
		packages,
		importers: berry ? workspaces : new Map([["", rootSpecs]]),
		recordsInstallScripts: false,
		problems: uniqueProblems(problems),
	};
};
