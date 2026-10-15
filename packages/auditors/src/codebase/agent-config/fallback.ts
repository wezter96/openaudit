import type { JsonEntry, JsonNode } from "./json";
import type { McpServer } from "./mcp";

/*
 * Best-effort structure for a config the strict reader rejects (JSON5,
 * NaN, bad escapes, deep nesting, truncation, broken TOML). Lenient clients
 * may still load such a file, so its strings are still checked: quoted and
 * bare tokens are grouped by the `{…}` object or `[table]` they sit in,
 * keys (a token before `:` or `=`) attach to the values after them, and
 * each group is scanned like a server. Linear time; never throws.
 */

const TOKEN =
	/"(?:[^"\\\n]|\\.)*"?|'(?:[^'\\\n]|\\.)*'?|[{}]|[A-Za-z0-9_$.+-]+/g;
/** A TOML `[table]` or `[[array]]` header line. */
const TOML_HEADER = /^[ \t]*\[\[?[\w."' -]{1,200}\]\]?[ \t]*(?:#.*)?$/gm;

/** A token of the config as written, quotes included. */
type Raw = string;

/** The token without its quotes; `quote` may be missing at the end. */
const unquoted = (token: Raw, quote: string): string =>
	token.slice(1, token.endsWith(quote) && token.length > 1 ? -1 : undefined);

const decodeDouble = (token: Raw): string => {
	try {
		return JSON.parse(
			token.endsWith('"') && token.length > 1 ? token : `${token}"`,
		);
	} catch {
		return token.slice(1, token.endsWith('"') ? -1 : undefined);
	}
};

const decode = (token: Raw): string => {
	if (token.startsWith('"')) return decodeDouble(token);
	if (token.startsWith("'")) return unquoted(token, "'");
	return token;
};

interface Obj {
	readonly name: string;
	readonly nameOffset: number;
	readonly entries: JsonEntry[];
	readonly parent?: Obj;
}

interface Token {
	readonly token: Raw;
	readonly offset: number;
}

interface Key {
	readonly value: string;
	readonly offset: number;
}

/** Where the reader is: the object it fills and the key it collects values for. */
interface Reader {
	readonly text: string;
	readonly toml: boolean;
	readonly root: Obj;
	readonly objects: Obj[];
	readonly stack: Obj[];
	current: Obj;
	key: Key | undefined;
	values: JsonNode[];
	/** End of the last TOML header, whose tokens are already read. */
	headerEnd: number;
}

const SERVER_KEYS = new Set(["command", "args", "url", "httpUrl", "serverUrl"]);
const SERVER_TABLES = new Set(["mcpServers", "servers", "mcp_servers"]);

/** One value as is; several (or any under `args`) as an array. */
const entryValue = (key: Key, values: JsonNode[]): JsonNode =>
	values.length === 1 && key.value !== "args"
		? (values[0] as JsonNode)
		: {
				kind: "array",
				offset: values[0]?.offset ?? key.offset,
				items: values,
			};

/** Attaches the collected values to the current key. */
const flush = (r: Reader) => {
	if (r.key && r.values.length > 0)
		r.current.entries.push({
			key: r.key.value,
			keyOffset: r.key.offset,
			value: entryValue(r.key, r.values),
		});
	r.values = [];
};

const child = (r: Reader, name: Key, parent: Obj | undefined): Obj => {
	const obj: Obj = {
		name: name.value,
		nameOffset: name.offset,
		entries: [],
		parent,
	};
	parent?.entries.push({
		key: name.value,
		keyOffset: name.offset,
		value: { kind: "object", offset: name.offset, entries: obj.entries },
	});
	r.objects.push(obj);
	return obj;
};

const open = (r: Reader, offset: number) => {
	flush(r);
	r.stack.push(r.current);
	r.current = child(
		r,
		{ value: r.key?.value ?? "(object)", offset: r.key?.offset ?? offset },
		r.current,
	);
	r.key = undefined;
};

const close = (r: Reader) => {
	flush(r);
	r.key = undefined;
	r.current = r.stack.pop() ?? r.root;
};

/** A TOML table header starts a top-level table named by its last segment. */
const tomlHeader = (r: Reader, { token, offset }: Token) => {
	flush(r);
	r.headerEnd = offset + token.length;
	const name =
		token
			.trim()
			.replace(/^\[+|\]+.*$/g, "")
			.split(".")
			.at(-1) ?? "";
	r.stack.length = 0;
	r.current = child(
		r,
		{
			value: name.replace(/^["']|["']$/g, ""),
			offset: offset + token.indexOf("["),
		},
		undefined,
	);
	r.key = undefined;
};

const scalar = (token: Raw) =>
	token === "true" ? true : token === "false" ? false : null;

/** A key when `:` or `=` follows it, else a value of the current key. */
const word = (r: Reader, { token, offset }: Token) => {
	const after = r.text.slice(offset + token.length, offset + token.length + 40);
	const value = decode(token);
	if (/^[ \t]*[:=](?!\/\/)/.test(after)) {
		flush(r);
		r.key = { value, offset };
	} else if (/^(?:true|false|null)$/.test(token))
		r.values.push({ kind: "scalar", offset, value: scalar(token) });
	else r.values.push({ kind: "string", offset, value });
};

const read = (r: Reader, t: Token) => {
	if (t.offset < r.headerEnd) return;
	if (t.token === "{") open(r, t.offset);
	else if (t.token === "}") close(r);
	else if (r.toml && /^[ \t]*\[/.test(t.token)) tomlHeader(r, t);
	else word(r, t);
};

const matches = (text: string, re: RegExp): Token[] =>
	[...text.matchAll(re)].map((m) => ({ token: m[0], offset: m.index ?? 0 }));

const tokensOf = (text: string, toml: boolean): Token[] =>
	toml
		? [...matches(text, TOKEN), ...matches(text, TOML_HEADER)].sort(
				(a, b) => a.offset - b.offset,
			)
		: matches(text, TOKEN);

/** Which objects are servers, and which sit inside one. */
class ServerTree {
	private readonly inTables: Set<number>;
	private readonly coveredMemo = new Map<Obj, boolean>();

	constructor(
		private readonly root: Obj,
		objects: ReadonlyArray<Obj>,
	) {
		this.inTables = new Set(
			objects.flatMap((o) =>
				SERVER_TABLES.has(o.name) ? o.entries.map((e) => e.keyOffset) : [],
			),
		);
	}

	/** Objects that launch or reach something, or sit in a server table. */
	isServer(o: Obj): boolean {
		if (o === this.root) return false;
		return (
			this.inTables.has(o.nameOffset) ||
			o.entries.some((e) => SERVER_KEYS.has(e.key))
		);
	}

	/** Inside a server. Memoized and iterative: nesting can be arbitrarily deep. */
	covered(o: Obj): boolean {
		const path: Obj[] = [];
		let p = o.parent;
		let result: boolean | undefined;
		while (p && result === undefined) {
			result = this.isServer(p) ? true : this.coveredMemo.get(p);
			if (result === undefined) path.push(p);
			p = p.parent;
		}
		for (const q of path) this.coveredMemo.set(q, result ?? false);
		return result ?? false;
	}
}

const entry = (o: Obj, entries: JsonEntry[]): McpServer => ({
	name: o.name,
	nameOffset: o.nameOffset,
	node: { kind: "object", offset: o.nameOffset, entries },
});

/**
 * A server outside every other server, or the loose strings of an object
 * outside every server (TOML subtables such as [mcp_servers.a.env], stray
 * values), checked as an extra entry.
 */
const serverOf = (tree: ServerTree, o: Obj): McpServer[] => {
	if (tree.covered(o)) return [];
	if (tree.isServer(o)) return [entry(o, o.entries)];
	const own = o.entries.filter((e) => e.value.kind !== "object");
	return own.length > 0 ? [entry(o, own)] : [];
};

export const fallbackServers = (text: string, toml: boolean): McpServer[] => {
	const root: Obj = { name: "(top level)", nameOffset: 0, entries: [] };
	const r: Reader = {
		text,
		toml,
		root,
		objects: [root],
		stack: [],
		current: root,
		key: undefined,
		values: [],
		headerEnd: -1,
	};
	for (const t of tokensOf(text, toml)) read(r, t);
	flush(r);
	const tree = new ServerTree(root, r.objects);
	return r.objects.flatMap((o) => serverOf(tree, o));
};
