import type { Severity } from "@openaudit/core";

import { isPlaceholder, SECRET_KEY_NAME, SECRET_RULES } from "../secrets";
import { shannonEntropy } from "../util";
import type { JsonEntry, JsonNode } from "./json";
import type { McpServer } from "./mcp";

/* -------------------------------------------------------------------------- */
/*                                 Credentials                                */
/* -------------------------------------------------------------------------- */

/** A string value from an MCP server entry. */
type ConfigValue = string;
/** How deep a value sits in the server entry, or in another value. */
type Depth = number;

const isReference = (value: ConfigValue) =>
	/\$\{|^\$[A-Za-z_]|^\{?env:/.test(value);

const CREDENTIAL_KEY = new RegExp(
	`${SECRET_KEY_NAME.source}|(?:^|[_-])(?:token|credential)s?(?:$|[_-])|^(?:proxy-)?authorization$|^cookie$|^x-[\\w-]*(?:key|token|auth)[\\w-]*$`,
	"i",
);
/** Short query-parameter names that carry credentials in URLs. */
const QUERY_SECRET =
	/^(?:key|token|sig|signature|auth|code|secret|pass|password|pwd|apikey|api[_-]?key|access[_-]?token|private[_-]?token)$/i;
const NOT_A_SECRET_KEY =
	/(?:_|-|^)(?:url|uri|host|path|file|name|id|type|scopes?|header|length|min|max|ttl|timeout|env|var)$/i;

/** A named value: where it sits, the name it goes by, and the value. */
interface Named {
	readonly where: string;
	readonly key: string;
	readonly value: string;
	readonly offset: number;
}

export interface Candidate extends Named {
	readonly query?: boolean;
}

const decodedPassword = (url: URL): string => {
	try {
		return decodeURIComponent(url.password);
	} catch {
		// Keep the encoded form.
		return url.password;
	}
};

const parsedUrl = (value: ConfigValue): URL | undefined => {
	try {
		return new URL(value.trim());
	} catch {
		return undefined;
	}
};

/** Query, fragment and userinfo credentials, parsed the WHATWG way (as clients do). */
const urlCandidates = ({ where, value, offset }: Named): Candidate[] => {
	const url = value.includes(":") ? parsedUrl(value) : undefined;
	if (!url?.host) return [];
	const params = [
		...url.searchParams,
		...new URLSearchParams(url.hash.slice(1)),
	];
	const out: Candidate[] = params.map(([key, v]) => ({
		where: `${where} ?${key}`,
		key,
		value: v,
		offset,
		query: true,
	}));
	if (url.password)
		out.push({
			where: `${where} password`,
			key: "password",
			value: decodedPassword(url),
			offset,
		});
	return out;
};

const KEY_VALUE = /^(--?[\w-]{1,60}|[A-Za-z_]\w{0,60})=([\s\S]+)$/;
const HEADER = /^([A-Za-z][\w-]{0,60})\s*:\s*([\s\S]+)$/;
const WINDOWS_SWITCH = /^\/([\w-]{1,60}):([\s\S]+)$/;

/** `scheme://…` reads like `Header: //…`, but it is a URL. */
const isUrlNotHeader = (re: RegExp, m: RegExpExecArray) =>
	re === HEADER && (m[2] ?? "").startsWith("//");

const wordsOf = ({ where, value, offset }: Named): Candidate[] =>
	/\s/.test(value.trim())
		? value
				.trim()
				.split(/\s+/)
				.flatMap((word) => expand({ where, key: "", value: word, offset }, 1))
		: [];

/** `--flag=value`, `KEY=value`, `Header: value` and `/name:value`. */
const namedParts = (c: Named, depth: Depth): Candidate[] =>
	[KEY_VALUE, HEADER, WINDOWS_SWITCH].flatMap((re) => {
		const m = re.exec(c.value);
		return m && !isUrlNotHeader(re, m)
			? expand(
					{
						where: c.where,
						key: m[1] ?? "",
						value: m[2] ?? "",
						offset: c.offset,
					},
					depth + 1,
				)
			: [];
	});

/**
 * Every way one string can carry a named value: `--flag=value`, `KEY=value`,
 * `Header: value`, `/name:value`, URL parts, and the same for each
 * whitespace-separated word.
 */
const expand = (c: Named, depth: Depth = 0): Candidate[] => [
	...(depth === 0 ? wordsOf(c) : []),
	c,
	...(depth > 3 ? [] : [...namedParts(c, depth), ...urlCandidates(c)]),
];

/** Where a node sits in a server entry. */
interface Path {
	readonly path: string;
	readonly key: string;
	readonly depth: Depth;
}

const isFlag = (
	node: JsonNode | undefined,
): node is Extract<JsonNode, { kind: "string" }> =>
	node?.kind === "string" && node.value.startsWith("-");

const itemCandidates = (
	items: ReadonlyArray<JsonNode>,
	at: Path,
): Candidate[] =>
	items.flatMap((item, i) => {
		const where = `${at.path}[${i}]`;
		const prev = items[i - 1];
		return [
			...walk(item, { path: where, key: at.key, depth: at.depth + 1 }),
			// `--api-key value`, `-H "Authorization: …"`
			...(isFlag(prev) && item.kind === "string"
				? expand(
						{ where, key: prev.value, value: item.value, offset: item.offset },
						1,
					)
				: []),
		];
	});

const entryCandidates = (e: JsonEntry, at: Path): Candidate[] => [
	{
		where: `${at.path || "server"} key`,
		key: "",
		value: e.key,
		offset: e.keyOffset,
	},
	...walk(e.value, {
		path: at.path ? `${at.path}.${e.key}` : e.key,
		key: e.key,
		depth: at.depth + 1,
	}),
];

const walk = (node: JsonNode, at: Path): Candidate[] => {
	if (at.depth > 32) return [];
	if (node.kind === "string")
		return expand({
			where: at.path,
			key: at.key,
			value: node.value,
			offset: node.offset,
		});
	if (node.kind === "array") return itemCandidates(node.items, at);
	if (node.kind === "object")
		return node.entries.flatMap((e) => entryCandidates(e, at));
	return [];
};

/** Every string in a server entry, keys and its name included. */
export const candidatesOf = (server: McpServer): Candidate[] => [
	{
		where: "server name",
		key: "",
		value: server.name,
		offset: server.nameOffset,
	},
	...walk(server.node, { path: "", key: "", depth: 0 }),
];

export interface LiteralSecret {
	readonly title: string;
	readonly severity: Severity;
	readonly secret: string;
	readonly confidence: "high" | "medium" | "low";
}

type SecretRule = (typeof SECRET_RULES)[number];

/** A placeholder, or too low in entropy for its rule. */
const isLookalike = (rule: SecretRule, secret: ConfigValue): boolean => {
	if (rule.id !== "private-key" && isPlaceholder(secret)) return true;
	return rule.minEntropy ? shannonEntropy(secret) < rule.minEntropy : false;
};

/** Provider token shapes from code.secrets. */
const providerSecret = (value: ConfigValue): LiteralSecret | undefined => {
	for (const rule of SECRET_RULES)
		for (const m of value.matchAll(rule.pattern)) {
			const secret = m.groups?.secret ?? m.groups?.auth ?? m[0];
			if (isLookalike(rule, secret)) continue;
			return {
				title: rule.title,
				severity: rule.severity,
				secret,
				confidence: rule.confidence ?? "high",
			};
		}
	return undefined;
};

const isCredentialKey = ({ key, query }: Candidate): boolean => {
	if (!key || NOT_A_SECRET_KEY.test(key)) return false;
	return query
		? QUERY_SECRET.test(key) || CREDENTIAL_KEY.test(key)
		: CREDENTIAL_KEY.test(key);
};

/** Values too short, spaced, placeholder-like, uniform or wordy to be a credential. */
const NOT_A_SECRET_VALUE: ReadonlyArray<(value: ConfigValue) => boolean> = [
	(v) => v.length < 8,
	(v) => /\s/.test(v),
	isPlaceholder,
	(v) => shannonEntropy(v) < 3,
	(v) => /^https?:\/\/|^[a-z]+(?:[._-][a-z]+)*$/.test(v),
];

/** Credential-named literals. */
const namedCredential = (c: Candidate): LiteralSecret | undefined => {
	if (!isCredentialKey(c)) return undefined;
	const value = c.value.trim().replace(/^(?:bearer|basic|token)\s+/i, "");
	if (NOT_A_SECRET_VALUE.some((test) => test(value))) return undefined;
	return {
		title: "Credential",
		severity: "high",
		secret: value,
		confidence: "medium",
	};
};

/** Provider token shapes from code.secrets, then credential-named literals. */
export const literalSecret = (c: Candidate): LiteralSecret | undefined =>
	isReference(c.value)
		? undefined
		: (providerSecret(c.value) ?? namedCredential(c));
