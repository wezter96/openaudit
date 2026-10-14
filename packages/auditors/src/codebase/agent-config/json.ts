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

const MAX_DEPTH = 64;
const SCALAR = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null/y;

class Bad extends Error {
	constructor(
		readonly reason: string,
		readonly offset: number,
	) {
		super(reason);
	}
}

export type JsonParse =
	| { readonly ok: true; readonly root: JsonNode }
	| { readonly ok: false; readonly reason: string; readonly offset: number };

/** Parses JSONC into a tree, or undefined when it is not JSONC. */
export const parseJsoncTree = (text: string): JsonNode | undefined => {
	const parsed = parseJsoncDetailed(text);
	return parsed.ok ? parsed.root : undefined;
};

/** Parses JSONC into a tree, or says why and where it is not JSONC. */
export const parseJsoncDetailed = (text: string): JsonParse => {
	let i = text.charCodeAt(0) === 0xfeff ? 1 : 0;
	const n = text.length;

	const skip = () => {
		while (i < n) {
			const c = text[i];
			if (c === " " || c === "\t" || c === "\n" || c === "\r") i++;
			else if (c === "/" && text[i + 1] === "/") {
				const e = text.indexOf("\n", i);
				i = e === -1 ? n : e + 1;
			} else if (c === "/" && text[i + 1] === "*") {
				const e = text.indexOf("*/", i + 2);
				if (e === -1) throw new Bad("unterminated block comment", i);
				i = e + 2;
			} else return;
		}
	};

	const string = (): string => {
		const start = i;
		i++;
		while (i < n && text[i] !== '"') i += text[i] === "\\" ? 2 : 1;
		if (i >= n) throw new Bad("unterminated string", start);
		i++;
		try {
			return JSON.parse(text.slice(start, i)) as string;
		} catch {
			throw new Bad("invalid escape or control character in a string", start);
		}
	};

	const value = (depth: number): JsonNode => {
		skip();
		if (depth > MAX_DEPTH)
			throw new Bad(`nesting deeper than ${MAX_DEPTH} levels`, i);
		const offset = i;
		const c = text[i];
		if (c === "{") {
			i++;
			const entries: JsonEntry[] = [];
			for (;;) {
				skip();
				if (text[i] === "}") {
					i++;
					return { kind: "object", offset, entries };
				}
				if (text[i] !== '"') throw new Bad("expected a double-quoted key", i);
				const keyOffset = i;
				const key = string();
				skip();
				if (text[i] !== ":") throw new Bad("expected ':'", i);
				i++;
				entries.push({ key, keyOffset, value: value(depth + 1) });
				skip();
				if (text[i] === ",") i++;
				else if (text[i] !== "}") throw new Bad("expected ',' or '}'", i);
			}
		}
		if (c === "[") {
			i++;
			const items: JsonNode[] = [];
			for (;;) {
				skip();
				if (text[i] === "]") {
					i++;
					return { kind: "array", offset, items };
				}
				items.push(value(depth + 1));
				skip();
				if (text[i] === ",") i++;
				else if (text[i] !== "]") throw new Bad("expected ',' or ']'", i);
			}
		}
		if (c === '"') return { kind: "string", offset, value: string() };
		SCALAR.lastIndex = i;
		const m = SCALAR.exec(text);
		if (!m) throw new Bad("unexpected value", i);
		i += m[0].length;
		return { kind: "scalar", offset, value: JSON.parse(m[0]) };
	};

	try {
		const root = value(0);
		skip();
		return i === n
			? { ok: true, root }
			: { ok: false, reason: "unexpected content after the value", offset: i };
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

/** Builds a tree from an already-parsed value (TOML), locating offsets by search. */
export const treeOf = (
	value: unknown,
	locate: (needle: string) => number,
): JsonNode => {
	const offset = (v: unknown) =>
		typeof v === "string" ? locate(v) : locate(String(v));
	const build = (v: unknown, depth: number): JsonNode => {
		if (depth > MAX_DEPTH) return { kind: "scalar", offset: 0, value: null };
		if (Array.isArray(v))
			return {
				kind: "array",
				offset: 0,
				items: v.map((x) => build(x, depth + 1)),
			};
		if (typeof v === "object" && v !== null)
			return {
				kind: "object",
				offset: 0,
				entries: Object.entries(v).map(([key, x]) => ({
					key,
					keyOffset: locate(key),
					value: build(x, depth + 1),
				})),
			};
		if (typeof v === "string")
			return { kind: "string", offset: offset(v), value: v };
		return {
			kind: "scalar",
			offset: 0,
			value: typeof v === "number" || typeof v === "boolean" ? v : null,
		};
	};
	return build(value, 0);
};
