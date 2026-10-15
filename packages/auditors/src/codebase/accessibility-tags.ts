/* -------------------------------------------------------------------------- */
/*                                 Tag parsing                                */
/* -------------------------------------------------------------------------- */

/** Template, JSX or HTML source text. */
export type Markup = string;
/** Character index into a {@link Markup} string. */
export type Offset = number;
/** Attribute name as written in the source, e.g. `:alt` or `onClick`. */
type RawAttrName = string;

export type AttrValue =
	| { readonly kind: "string"; readonly value: string }
	| { readonly kind: "expr"; readonly value: string }
	| { readonly kind: "bool" };

export interface Tag {
	readonly name: string;
	/** Normalised attribute names: `onClick`, `@click`, `on:click` → `onclick`. */
	readonly attrs: ReadonlyMap<string, AttrValue>;
	/** `{...props}` / `v-bind="obj"`: attributes we cannot see. */
	readonly hasSpread: boolean;
	readonly selfClosing: boolean;
	readonly start: number;
	/** Index just past the closing `>`. */
	readonly end: number;
}

const QUOTES = new Set(['"', "'", "`"]);
/** Longest `{...}` expression and tag we try to parse before giving up. */
const MAX_BRACES = 4000;
const MAX_TAG = 6000;

/** Skips a balanced `{...}` starting at `i`; returns the index after `}`. */
const skipBraces = (text: Markup, i: Offset): Offset => {
	const limit = Math.min(text.length, i + MAX_BRACES);
	let depth = 0;
	for (let j = i; j < limit; j++) {
		const ch = text.charAt(j);
		if (QUOTES.has(ch)) {
			j = text.indexOf(ch, j + 1);
			if (j === -1) return -1;
		} else if (ch === "{") depth++;
		else if (ch === "}" && --depth === 0) return j + 1;
	}
	return -1;
};

/** Framework binding prefixes and what they normalise to, in match order. */
const ATTR_PREFIXES: ReadonlyArray<readonly [string, string]> = [
	["v-bind:", ""],
	[":", ""],
	["v-on:", "on"],
	["@", "on"],
	["on:", "on"],
];

const ATTR_ALIASES: ReadonlyMap<string, string> = new Map([
	["classname", "class"],
	["htmlfor", "for"],
]);

const normaliseAttr = (raw: RawAttrName): string => {
	const prefix = ATTR_PREFIXES.find(([from]) => raw.startsWith(from));
	const name = prefix ? prefix[1] + raw.slice(prefix[0].length) : raw;
	const base = (name.split(".")[0] ?? name).toLowerCase(); // @click.prevent
	return ATTR_ALIASES.get(base) ?? base;
};

/** Mutable cursor over one opening tag while it is being parsed. */
interface TagParser {
	readonly text: Markup;
	pos: Offset;
	readonly attrs: Map<string, AttrValue>;
	hasSpread: boolean;
}

const WHITESPACE = /\s*/y;

const skipWhitespace = (p: TagParser) => {
	WHITESPACE.lastIndex = p.pos;
	p.pos += WHITESPACE.exec(p.text)?.[0].length ?? 0;
};

/** Length of the tag terminator (`>` or `/>`) at the cursor, or 0. */
const terminatorLength = (p: TagParser): number => {
	if (p.text.startsWith("/>", p.pos)) return 2;
	return p.text[p.pos] === ">" ? 1 : 0;
};

/** `{...props}` spread or Svelte's `{alt}` shorthand. */
const parseBraceAttribute = (p: TagParser): boolean => {
	const end = skipBraces(p.text, p.pos);
	if (end === -1) return false;
	const inner = p.text.slice(p.pos + 1, end - 1).trim();
	if (inner.startsWith("...")) p.hasSpread = true;
	else if (/^\w+$/.test(inner))
		p.attrs.set(inner.toLowerCase(), { kind: "expr", value: inner }); // svelte {alt}
	p.pos = end;
	return true;
};

const quotedValue = (
	p: TagParser,
	rawName: RawAttrName,
): AttrValue | undefined => {
	const close = p.text.indexOf(p.text.charAt(p.pos), p.pos + 1);
	if (close === -1) return undefined;
	const bound = /^(?::|v-bind:)/.test(rawName);
	const value: AttrValue = {
		kind: bound ? "expr" : "string",
		value: p.text.slice(p.pos + 1, close),
	};
	p.pos = close + 1;
	return value;
};

const braceValue = (p: TagParser): AttrValue | undefined => {
	const end = skipBraces(p.text, p.pos);
	if (end === -1) return undefined;
	const value: AttrValue = {
		kind: "expr",
		value: p.text.slice(p.pos + 1, end - 1).trim(),
	};
	p.pos = end;
	return value;
};

const bareValue = (p: TagParser): AttrValue => {
	const value = /^[^\s>]+/.exec(p.text.slice(p.pos, p.pos + 256))?.[0] ?? "";
	p.pos += value.length;
	return { kind: "string", value };
};

const VALUE_QUOTES = new Set(['"', "'"]);

/** Parses `=value` after an attribute name; a bare name is a boolean. */
const parseAttrValue = (
	p: TagParser,
	rawName: RawAttrName,
): AttrValue | undefined => {
	if (p.text[p.pos] !== "=") return { kind: "bool" };
	p.pos++;
	skipWhitespace(p);
	const q = p.text.charAt(p.pos);
	if (VALUE_QUOTES.has(q)) return quotedValue(p, rawName);
	if (q === "{") return braceValue(p);
	return bareValue(p);
};

/** Parses one attribute at the cursor; false when the tag is malformed. */
const parseAttribute = (p: TagParser): boolean => {
	if (p.text[p.pos] === "{") return parseBraceAttribute(p);
	const rawName = /^[^\s=>/"'{}<]+/.exec(p.text.slice(p.pos, p.pos + 128))?.[0];
	if (!rawName) return false;
	p.pos += rawName.length;
	skipWhitespace(p);
	const value = parseAttrValue(p, rawName);
	if (!value) return false;
	if (rawName === "v-bind") p.hasSpread = true;
	else p.attrs.set(normaliseAttr(rawName), value);
	return true;
};

/** Parses the tag opening at `start` (`text[start] === "<"`). */
export const parseTag = (text: Markup, start: Offset): Tag | undefined => {
	const name = /^<([a-zA-Z][\w.:-]*)/.exec(text.slice(start, start + 64))?.[1];
	if (!name) return undefined;
	const p: TagParser = {
		text,
		pos: start + 1 + name.length,
		attrs: new Map(),
		hasSpread: false,
	};
	while (p.pos < text.length && p.pos - start <= MAX_TAG) {
		skipWhitespace(p);
		const terminator = terminatorLength(p);
		if (terminator > 0) {
			const { attrs, hasSpread } = p;
			const selfClosing = terminator === 2;
			return {
				name,
				attrs,
				hasSpread,
				selfClosing,
				start,
				end: p.pos + terminator,
			};
		}
		if (!parseAttribute(p)) return undefined;
	}
	return undefined;
};

/** All lowercase (intrinsic HTML) opening tags in `text`. */
export const scanTags = (text: Markup): Tag[] => {
	const tags: Tag[] = [];
	for (const m of text.matchAll(/<[a-z][\w-]*(?=[\s/>])/g)) {
		const tag = parseTag(text, m.index ?? 0);
		if (tag) tags.push(tag);
	}
	return tags;
};
