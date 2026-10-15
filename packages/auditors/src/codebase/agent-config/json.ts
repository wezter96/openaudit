/*
 * A JSONC reader that keeps what a lenient client could see: duplicate keys
 * (JSON.parse keeps only the last, another client may keep the first), with
 * the offset of every key and value. It accepts a BOM, comments and
 * trailing commas (VS Code mcp.json is JSONC), so a config the auditor
 * cannot read is never one a client loads. Strings decode exactly as in
 * JSON, so `"env"` is `env`.
 */

export type JsonNode =
	| {
			readonly kind: "object";
			readonly offset: number;
			readonly entries: ReadonlyArray<JsonEntry>;
	  }
	| {
			readonly kind: "array";
			readonly offset: number;
			readonly items: ReadonlyArray<JsonNode>;
	  }
	| { readonly kind: "string"; readonly offset: number; readonly value: string }
	| {
			readonly kind: "scalar";
			readonly offset: number;
			readonly value: number | boolean | null;
	  };

export interface JsonEntry {
	readonly key: string;
	readonly keyOffset: number;
	readonly value: JsonNode;
}

/** JSONC source text, an offset into it, and a nesting depth. */
type JsonText = string;
type Offset = number;
type Depth = number;

const MAX_DEPTH = 64;
const SCALAR = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null/y;

class Bad extends Error {
	constructor(
		readonly reason: string,
		readonly offset: Offset,
	) {
		super(reason);
	}
}

export type JsonParse =
	| { readonly ok: true; readonly root: JsonNode }
	| { readonly ok: false; readonly reason: string; readonly offset: number };

/** Parses JSONC into a tree, or undefined when it is not JSONC. */
export const parseJsoncTree = (text: JsonText): JsonNode | undefined => {
	const parsed = parseJsoncDetailed(text);
	return parsed.ok ? parsed.root : undefined;
};

const WHITESPACE = new Set([" ", "\t", "\n", "\r"]);

/** A cursor over JSONC text that throws `Bad` where the text stops being JSONC. */
class Reader {
	i: number;
	readonly n: number;

	constructor(readonly text: JsonText) {
		this.i = text.charCodeAt(0) === 0xfeff ? 1 : 0;
		this.n = text.length;
	}

	/** Skips whitespace and comments. */
	skip() {
		while (this.i < this.n) {
			if (WHITESPACE.has(this.text.charAt(this.i))) this.i++;
			else if (!this.comment()) return;
		}
	}

	/** Skips the comment at the cursor, or says there is none. */
	private comment(): boolean {
		if (this.text[this.i] !== "/") return false;
		const next = this.text[this.i + 1];
		if (next === "/") return this.lineComment();
		return next === "*" && this.blockComment();
	}

	private lineComment(): true {
		const e = this.text.indexOf("\n", this.i);
		this.i = e === -1 ? this.n : e + 1;
		return true;
	}

	private blockComment(): true {
		const e = this.text.indexOf("*/", this.i + 2);
		if (e === -1) throw new Bad("unterminated block comment", this.i);
		this.i = e + 2;
		return true;
	}

	/** Moves the cursor past the closing quote of the string opening at `start`. */
	private stringEnd(start: Offset) {
		this.i++;
		while (this.i < this.n && this.text[this.i] !== '"')
			this.i += this.text[this.i] === "\\" ? 2 : 1;
		if (this.i >= this.n) throw new Bad("unterminated string", start);
		this.i++;
	}

	private string(): string {
		const start = this.i;
		this.stringEnd(start);
		try {
			return JSON.parse(this.text.slice(start, this.i)) as string;
		} catch {
			throw new Bad("invalid escape or control character in a string", start);
		}
	}

	value(depth: Depth): JsonNode {
		this.skip();
		if (depth > MAX_DEPTH)
			throw new Bad(`nesting deeper than ${MAX_DEPTH} levels`, this.i);
		const offset = this.i;
		const c = this.text[this.i];
		if (c === "{") return this.object(depth);
		if (c === "[") return this.array(depth);
		if (c === '"') return { kind: "string", offset, value: this.string() };
		return this.scalar();
	}

	/** The members of the container opening at the cursor, and its offset. */
	private members<T>(
		close: "}" | "]",
		member: () => T,
	): { readonly offset: Offset; readonly members: T[] } {
		const offset = this.i++;
		const members: T[] = [];
		for (;;) {
			this.skip();
			if (this.text[this.i] === close) {
				this.i++;
				return { offset, members };
			}
			members.push(member());
			this.separator(close);
		}
	}

	private object(depth: Depth): JsonNode {
		const { offset, members } = this.members("}", () => this.entry(depth));
		return { kind: "object", offset, entries: members };
	}

	private entry(depth: Depth): JsonEntry {
		if (this.text[this.i] !== '"')
			throw new Bad("expected a double-quoted key", this.i);
		const keyOffset = this.i;
		const key = this.string();
		this.skip();
		if (this.text[this.i] !== ":") throw new Bad("expected ':'", this.i);
		this.i++;
		return { key, keyOffset, value: this.value(depth + 1) };
	}

	private array(depth: Depth): JsonNode {
		const { offset, members } = this.members("]", () => this.value(depth + 1));
		return { kind: "array", offset, items: members };
	}

	/** After a member: steps over a comma, or checks the container closes. */
	private separator(close: "}" | "]") {
		this.skip();
		if (this.text[this.i] === ",") this.i++;
		else if (this.text[this.i] !== close)
			throw new Bad(`expected ',' or '${close}'`, this.i);
	}

	private scalar(): JsonNode {
		const offset = this.i;
		SCALAR.lastIndex = this.i;
		const m = SCALAR.exec(this.text);
		if (!m) throw new Bad("unexpected value", this.i);
		this.i += m[0].length;
		return { kind: "scalar", offset, value: JSON.parse(m[0]) };
	}
}

/** The parse of `root`, unless more than comments and whitespace follow it. */
const complete = (reader: Reader, root: JsonNode): JsonParse => {
	reader.skip();
	return reader.i === reader.n
		? { ok: true, root }
		: {
				ok: false,
				reason: "unexpected content after the value",
				offset: reader.i,
			};
};

/** Parses JSONC into a tree, or says why and where it is not JSONC. */
export const parseJsoncDetailed = (text: JsonText): JsonParse => {
	const reader = new Reader(text);
	try {
		return complete(reader, reader.value(0));
	} catch (e) {
		if (e instanceof Bad)
			return { ok: false, reason: e.reason, offset: e.offset };
		throw e;
	}
};

/** Every value stored under `key` in an object node, duplicates included. */
export const fields = (node: JsonNode | undefined, key: string): JsonNode[] =>
	node?.kind === "object"
		? node.entries.filter((e) => e.key === key).map((e) => e.value)
		: [];

/** The string items of every array node. */
export const stringItems = (
	nodes: ReadonlyArray<JsonNode>,
): Array<Extract<JsonNode, { kind: "string" }>> =>
	nodes.flatMap((n) =>
		n.kind === "array"
			? n.items.filter(
					(x): x is Extract<JsonNode, { kind: "string" }> =>
						x.kind === "string",
				)
			: [],
	);

/** Finds where a key or string value sits in the source text. */
type Locate = (needle: string) => number;

const scalarNode = (v: unknown): JsonNode => ({
	kind: "scalar",
	offset: 0,
	value: typeof v === "number" || typeof v === "boolean" ? v : null,
});

/** A string node at its located offset, or a scalar one. */
const leafNode = (v: unknown, locate: Locate): JsonNode =>
	typeof v === "string"
		? { kind: "string", offset: locate(v), value: v }
		: scalarNode(v);

const isObject = (v: unknown): v is object =>
	typeof v === "object" && v !== null;

/** Builds a tree from an already-parsed value (TOML), locating offsets by search. */
export const treeOf = (value: unknown, locate: Locate): JsonNode => {
	const build = (v: unknown, depth: Depth): JsonNode => {
		if (depth > MAX_DEPTH) return scalarNode(null);
		if (Array.isArray(v))
			return {
				kind: "array",
				offset: 0,
				items: v.map((x) => build(x, depth + 1)),
			};
		if (isObject(v))
			return {
				kind: "object",
				offset: 0,
				entries: Object.entries(v).map(([key, x]) => ({
					key,
					keyOffset: locate(key),
					value: build(x, depth + 1),
				})),
			};
		return leafNode(v, locate);
	};
	return build(value, 0);
};
