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

const decode = (token: string): string => {
	if (token.startsWith('"')) {
		try {
			return JSON.parse(
				token.endsWith('"') && token.length > 1 ? token : `${token}"`,
			);
		} catch {
			return token.slice(1, token.endsWith('"') ? -1 : undefined);
		}
	}
	if (token.startsWith("'"))
		return token.slice(
			1,
			token.endsWith("'") && token.length > 1 ? -1 : undefined,
		);
	return token;
};

interface Obj {
	readonly name: string;
	readonly nameOffset: number;
	readonly entries: JsonEntry[];
	readonly parent?: Obj;
}

const SERVER_KEYS = new Set(["command", "args", "url", "httpUrl", "serverUrl"]);
const SERVER_TABLES = new Set(["mcpServers", "servers", "mcp_servers"]);

export const fallbackServers = (text: string, toml: boolean): McpServer[] => {
	const root: Obj = { name: "(top level)", nameOffset: 0, entries: [] };
	const objects: Obj[] = [root];
	const stack: Obj[] = [];
	let current = root;
	let key: { value: string; offset: number } | undefined;
	let values: JsonNode[] = [];
	const flush = () => {
		if (key && values.length > 0)
			current.entries.push({
				key: key.value,
				keyOffset: key.offset,
				value:
					values.length === 1 && key.value !== "args"
						? (values[0] as JsonNode)
						: {
								kind: "array",
								offset: values[0]?.offset ?? key.offset,
								items: values,
							},
			});
		values = [];
	};
	const child = (name: string, offset: number, parent: Obj | undefined) => {
		const obj: Obj = { name, nameOffset: offset, entries: [], parent };
		parent?.entries.push({
			key: name,
			keyOffset: offset,
			value: { kind: "object", offset, entries: obj.entries },
		});
		objects.push(obj);
		return obj;
	};

	const tokens = [...text.matchAll(TOKEN)].map((m) => ({
		token: m[0],
		offset: m.index ?? 0,
	}));
	if (toml) {
		tokens.push(
			...[...text.matchAll(TOML_HEADER)].map((m) => ({
				token: m[0],
				offset: m.index ?? 0,
			})),
		);
		tokens.sort((a, b) => a.offset - b.offset);
	}
	let headerEnd = -1;
	for (const { token, offset } of tokens) {
		if (offset < headerEnd) continue;
		if (token === "{") {
			flush();
			stack.push(current);
			current = child(key?.value ?? "(object)", key?.offset ?? offset, current);
			key = undefined;
		} else if (token === "}") {
			flush();
			key = undefined;
			current = stack.pop() ?? root;
		} else if (toml && /^[ \t]*\[/.test(token)) {
			// A TOML table header starts a top-level table named by its last segment.
			flush();
			headerEnd = offset + token.length;
			const name =
				token
					.trim()
					.replace(/^\[+|\]+.*$/g, "")
					.split(".")
					.at(-1) ?? "";
			stack.length = 0;
			current = child(
				name.replace(/^["']|["']$/g, ""),
				offset + token.indexOf("["),
				undefined,
			);
			key = undefined;
		} else {
			const after = text.slice(
				offset + token.length,
				offset + token.length + 40,
			);
			const value = decode(token);
			if (/^[ \t]*[:=](?!\/\/)/.test(after)) {
				flush();
				key = { value, offset };
			} else if (/^(?:true|false|null)$/.test(token))
				values.push({
					kind: "scalar",
					offset,
					value: token === "true" ? true : token === "false" ? false : null,
				});
			else values.push({ kind: "string", offset, value });
		}
	}
	flush();

	// Servers: objects that launch or reach something, or sit in a server
	// table. Strings outside every server (TOML subtables such as
	// [mcp_servers.a.env], stray values) are checked as extra entries.
	const inTables = new Set(
		objects.flatMap((o) =>
			SERVER_TABLES.has(o.name) ? o.entries.map((e) => e.keyOffset) : [],
		),
	);
	const isServer = (o: Obj) =>
		o !== root &&
		(inTables.has(o.nameOffset) ||
			o.entries.some((e) => SERVER_KEYS.has(e.key)));
	// Memoized and iterative: nesting can be arbitrarily deep.
	const coveredMemo = new Map<Obj, boolean>();
	const covered = (o: Obj): boolean => {
		const path: Obj[] = [];
		let p = o.parent;
		let result = false;
		while (p) {
			if (isServer(p)) {
				result = true;
				break;
			}
			const known = coveredMemo.get(p);
			if (known !== undefined) {
				result = known;
				break;
			}
			path.push(p);
			p = p.parent;
		}
		for (const q of path) coveredMemo.set(q, result);
		return result;
	};
	const entry = (o: Obj, entries: JsonEntry[]): McpServer => ({
		name: o.name,
		nameOffset: o.nameOffset,
		node: { kind: "object", offset: o.nameOffset, entries },
	});
	return objects.flatMap((o) => {
		if (isServer(o)) return covered(o) ? [] : [entry(o, o.entries)];
		if (covered(o)) return [];
		const own = o.entries.filter((e) => e.value.kind !== "object");
		return own.length > 0 ? [entry(o, own)] : [];
	});
};
