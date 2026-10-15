import { isRecord } from "../util";
import { parseYaml, yamlKeyLines } from "./shared";

/*
 * A port of Yarn 1's lockfile parser (src/lockfile/parse.js), so that what is
 * checked is exactly what Yarn reads: comments run to the next \n, a lone \r
 * is a newline but does not start an indent, only even runs of spaces indent,
 * quoted strings are JSON, and a repeated key overrides the earlier one.
 */

type ScalarToken = {
	readonly type: "string" | "number" | "boolean";
	readonly value: string | number | boolean;
	readonly line: number;
};

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
	| ScalarToken;

/** A parsed file and the line of each top-level key. */
export interface YarnDocument {
	readonly obj: Record<string, unknown>;
	readonly lines: Map<string, number>;
}

/** Where the lexer stands, and whether the last token started with a newline. */
interface LexState {
	readonly s: string;
	readonly i: number;
	readonly line: number;
	readonly afterNewline: boolean;
}

/** The characters a token takes up; spaces that do not indent make none. */
interface Scan {
	readonly chop: number;
	readonly token?: YarnToken;
}

const isCrlf = ({ s, i }: LexState) => s[i] === "\r" && s[i + 1] === "\n";

/** A lone \r is a newline but does not start an indent. */
const endsLine = (st: LexState) => st.s[st.i] === "\n" || isCrlf(st);

const scanNewline = (st: LexState): Scan | undefined => {
	const c = st.s[st.i];
	if (c !== "\n" && c !== "\r") return undefined;
	return {
		chop: isCrlf(st) ? 2 : 1,
		token: { type: "newline", line: st.line },
	};
};

const scanComment = (st: LexState): Scan | undefined => {
	if (st.s[st.i] !== "#") return undefined;
	const nl = st.s.indexOf("\n", st.i + 1);
	return {
		chop: (nl === -1 ? st.s.length : nl) - st.i,
		token: { type: "comment", line: st.line },
	};
};

const scanSpaces = (st: LexState): Scan | undefined => {
	if (st.s[st.i] !== " ") return undefined;
	if (!st.afterNewline) return { chop: 1 };
	let n = 1;
	while (st.s[st.i + n] === " ") n++;
	if (n % 2) throw new Error("Invalid number of spaces");
	return { chop: n, token: { type: "indent", value: n / 2, line: st.line } };
};

/** A backslash escapes a quote unless it is escaped itself. */
const isEscaped = (s: string, j: number) =>
	s[j - 1] === "\\" && s[j - 2] !== "\\";

/** The offset just past the closing quote, or the end of the text. */
const quotedEnd = ({ s, i }: LexState) => {
	for (let j = i + 1; j < s.length; j++)
		if (s[j] === '"' && !isEscaped(s, j)) return j + 1;
	return s.length;
};

const scanQuoted = (st: LexState): Scan | undefined => {
	if (st.s[st.i] !== '"') return undefined;
	const end = quotedEnd(st);
	const chop = end - st.i;
	try {
		const value = JSON.parse(st.s.slice(st.i, end));
		return { chop, token: { type: "string", value, line: st.line } };
	} catch {
		return { chop, token: { type: "invalid", line: st.line } };
	}
};

const isDigit = (c: string | undefined) =>
	c !== undefined && c >= "0" && c <= "9";

const scanNumber = (st: LexState): Scan | undefined => {
	if (!isDigit(st.s[st.i])) return undefined;
	let j = st.i;
	while (isDigit(st.s[j])) j++;
	const value = Number(st.s.slice(st.i, j));
	return { chop: j - st.i, token: { type: "number", value, line: st.line } };
};

const BOOLEANS = [
	["true", true],
	["false", false],
] as const;

const scanBoolean = (st: LexState): Scan | undefined => {
	for (const [word, value] of BOOLEANS)
		if (st.s.startsWith(word, st.i))
			return {
				chop: word.length,
				token: { type: "boolean", value, line: st.line },
			};
	return undefined;
};

const PUNCTUATION = new Map<string, "colon" | "comma">([
	[":", "colon"],
	[",", "comma"],
]);

const scanPunctuation = (st: LexState): Scan | undefined => {
	const type = PUNCTUATION.get(st.s[st.i] as string);
	if (!type) return undefined;
	return { chop: 1, token: { type, line: st.line } };
};

const BARE_END = new Set([":", " ", "\n", "\r", ","]);

const scanBare = (st: LexState): Scan | undefined => {
	if (!/[a-zA-Z/.-]/.test(st.s[st.i] as string)) return undefined;
	let j = st.i;
	while (j < st.s.length && !BARE_END.has(st.s[j] as string)) j++;
	const value = st.s.slice(st.i, j);
	return { chop: j - st.i, token: { type: "string", value, line: st.line } };
};

/** Tried in order; the first that applies reads the token. */
const SCANNERS = [
	scanNewline,
	scanComment,
	scanSpaces,
	scanQuoted,
	scanNumber,
	scanBoolean,
	scanPunctuation,
	scanBare,
];

const scan = (st: LexState): Scan => {
	for (const scanner of SCANNERS) {
		const result = scanner(st);
		if (result) return result;
	}
	return { chop: 1, token: { type: "invalid", line: st.line } };
};

class YarnLexer {
	private i = 0;
	private line = 1;
	private lastNewline = false;
	constructor(private readonly s: string) {}

	next(): YarnToken {
		for (;;) {
			if (this.i >= this.s.length) return { type: "eof", line: this.line };
			const st: LexState = {
				s: this.s,
				i: this.i,
				line: this.line,
				afterNewline: this.lastNewline,
			};
			const { chop, token } = scan(st);
			if (token?.type === "newline") this.line++;
			this.lastNewline = endsLine(st);
			this.i += chop;
			if (token) return token;
		}
	}
}

/** How many indents deep a block is; 0 for the top level. */
type Depth = number;

const SCALAR_TYPES = new Set(["string", "number", "boolean"]);

const isScalar = (t: YarnToken): t is ScalarToken => SCALAR_TYPES.has(t.type);

/** Yarn 1's grammar; throws where Yarn throws. Records top-level key lines. */
class YarnParser {
	readonly lines = new Map<string, number>();
	private readonly lexer: YarnLexer;
	private token: YarnToken;

	constructor(text: string) {
		this.lexer = new YarnLexer(text);
		this.token = this.lexer.next();
	}

	private next(): YarnToken {
		this.token = this.lexer.next();
		return this.token;
	}

	parse(indent: Depth): Record<string, unknown> {
		const obj: Record<string, unknown> = Object.create(null);
		let more = true;
		while (more) more = this.step(obj, indent);
		return obj;
	}

	/** Reads the next token of a block; false where the block ends. */
	private step(obj: Record<string, unknown>, indent: Depth): boolean {
		const t = this.token;
		switch (t.type) {
			case "newline":
				this.next();
				return !indent || this.atIndent(indent);
			case "indent":
				return this.atIndent(indent);
			case "eof":
				return false;
			case "string":
				return this.entry(obj, t, indent);
			case "comment":
				this.next();
				return true;
			default:
				throw new Error("Unknown token");
		}
	}

	/** Steps past an indent at this block's depth; any other token ends it. */
	private atIndent(indent: Depth): boolean {
		const t = this.token;
		if (t.type !== "indent" || t.value !== indent) return false;
		this.next();
		return true;
	}

	private entry(
		obj: Record<string, unknown>,
		t: ScalarToken,
		indent: Depth,
	): boolean {
		if (!t.value) throw new Error("Expected a key");
		const keys = this.keys(String(t.value));
		const { value, plain } = this.entryValue(indent);
		for (const k of keys) {
			obj[k] = value;
			if (!indent) this.lines.set(k, t.line);
		}
		if (plain || !indent) return true;
		// A nested block ends its parent unless an indent follows.
		return this.token.type === "indent";
	}

	/** `a, b, c`: the keys an entry is stored under. */
	private keys(first: string): string[] {
		const keys = [first];
		this.next();
		while (this.token.type === "comma") {
			const k = this.next();
			if (k.type !== "string") throw new Error("Expected string");
			keys.push(String(k.value));
			this.next();
		}
		return keys;
	}

	private entryValue(indent: Depth): {
		readonly value: unknown;
		readonly plain: boolean;
	} {
		const wasColon = this.token.type === "colon";
		if (wasColon) this.next();
		const v = this.token;
		if (isScalar(v)) {
			this.next();
			return { value: v.value, plain: true };
		}
		if (!wasColon) throw new Error("Invalid value type");
		return { value: this.parse(indent + 1), plain: false };
	}
}

const yarnGrammar = (text: string): YarnDocument => {
	const parser = new YarnParser(text);
	return { obj: parser.parse(0), lines: parser.lines };
};

/** Yarn 1's reading with its grammar, or `undefined` where Yarn throws. */
export const grammarDocument = (text: string): YarnDocument | undefined => {
	try {
		return yarnGrammar(text);
	} catch {
		return undefined;
	}
};

/** The file read as YAML, or `undefined` where it is not a YAML mapping. */
export const yamlDocument = (text: string): YarnDocument | undefined => {
	try {
		const doc: unknown = parseYaml(text);
		if (isRecord(doc))
			return { obj: doc, lines: yamlKeyLines(text, undefined) };
	} catch {
		// Not YAML.
	}
	return undefined;
};

/** Yarn 1 reads lockfiles and .yarnrc with its grammar, falling back to YAML. */
export const parseYarnClassic = (text: string): YarnDocument | undefined =>
	// Yarn 1 retries with js-yaml (FAILSAFE schema); where neither parses,
	// Yarn 1 cannot read it either.
	grammarDocument(text) ?? yamlDocument(text);
