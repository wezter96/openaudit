import { lineOf } from "@openaudit/core";

/** HCL source text (a whole file or a block body). */
export type HclText = string;
/** Character offset into HCL text. */
export type Offset = number;
/** 1-based line number. */
export type Line = number;
/** Attribute name, or a regex source matching attribute names. */
export type AttrName = string;
/** Block keyword, e.g. `resource`, `ingress`. */
export type Keyword = string;

/** A top-level or nested HCL block located by brace matching. */
export interface HclBlock {
	/** `resource`, `provider`, `ingress`, ... */
	readonly keyword: string;
	/** Quoted labels, e.g. `["aws_s3_bucket", "logs"]`. */
	readonly labels: ReadonlyArray<string>;
	/** Text between the braces. */
	readonly body: string;
	/** 1-based line of the block header within the file. */
	readonly line: number;
	/** Offset of the body start within the file text. */
	readonly offset: number;
}

/** Index of the last character of the token starting at `i`. */
type Skipper = (text: HclText, i: Offset) => Offset;

const skipString: Skipper = (text, i) => {
	let j = i + 1;
	while (j < text.length && text[j] !== '"') {
		if (text[j] === "\\") j++;
		j++;
	}
	return j;
};

const skipLineComment: Skipper = (text, i) => {
	const nl = text.indexOf("\n", i);
	return nl === -1 ? text.length : nl;
};

const skipBlockComment: Skipper = (text, i) => {
	const end = text.indexOf("*/", i + 2);
	return end === -1 ? text.length : end + 1;
};

const skipHeredoc: Skipper = (text, i) => {
	const m = /^<<-?([A-Za-z_]\w*)\s*\n/.exec(text.slice(i));
	if (!m) return i;
	// The heredoc tag matched [A-Za-z_]\w* above.
	// nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
	const end = new RegExp(`^\\s*${m[1]}\\s*$`, "m").exec(
		text.slice(i + m[0].length),
	);
	return end ? i + m[0].length + end.index + end[0].length - 1 : text.length;
};

/** Strings, comments and heredocs, whose braces do not count. */
const SKIPPERS: ReadonlyArray<readonly [ReadonlyArray<string>, Skipper]> = [
	[['"'], skipString],
	[["#", "//"], skipLineComment],
	[["/*"], skipBlockComment],
	[["<<"], skipHeredoc],
];

const skipperAt = (text: HclText, i: Offset): Skipper | undefined =>
	SKIPPERS.find(([starts]) => starts.some((s) => text.startsWith(s, i)))?.[1];

/** How a brace changes the nesting depth; other characters leave it. */
const BRACE_STEP: Readonly<Record<string, number>> = { "{": 1, "}": -1 };

/** The next index to scan after `i`, past a string, comment or heredoc that starts there. */
const nextScanIndex = (text: HclText, i: Offset): Offset => {
	const skipper = skipperAt(text, i);
	return (skipper ? skipper(text, i) : i) + 1;
};

/** Index of the brace closing the one at `open`, skipping strings, comments and heredocs. */
const matchBrace = (text: HclText, open: Offset): Offset => {
	let depth = 0;
	for (let i = open; i < text.length; i = nextScanIndex(text, i)) {
		// Strings, comments and heredocs never start with a brace.
		depth += BRACE_STEP[text[i] ?? ""] ?? 0;
		if (depth === 0 && text[i] === "}") return i;
	}
	return text.length;
};

const BLOCK_SOURCE = /^[ \t]*([A-Za-z_][\w-]*)((?:[ \t]+"[^"\n]*")*)[ \t]*\{/
	.source;

/**
 * Blocks directly inside `text` (no recursion into their bodies).
 * `base` translates offsets back into `fileText`, the enclosing file.
 */
export const parseBlocks = (
	text: HclText,
	base: Offset = 0,
	fileText: HclText = text,
): ReadonlyArray<HclBlock> => {
	const blocks: HclBlock[] = [];
	const re = new RegExp(BLOCK_SOURCE, "gm");
	let m: RegExpExecArray | null = re.exec(text);
	while (m) {
		const open = m.index + m[0].length - 1;
		const close = matchBrace(text, open);
		blocks.push({
			keyword: m[1] ?? "",
			labels: [...(m[2] ?? "").matchAll(/"([^"]*)"/g)].map((l) => l[1] ?? ""),
			body: text.slice(open + 1, close),
			line: lineOf(
				fileText,
				base + m.index + (m[0].length - m[0].trimStart().length),
			),
			offset: base + open + 1,
		});
		re.lastIndex = close + 1;
		m = re.exec(text);
	}
	return blocks;
};

/** Nested blocks of `block` named `keyword`. */
export const subBlocks = (
	block: HclBlock,
	keyword: Keyword,
	fileText: HclText,
) =>
	parseBlocks(block.body, block.offset, fileText).filter(
		(b) => b.keyword === keyword,
	);

/** Text of `body` with nested blocks removed, so attribute lookups stay at this level. */
const ownAttributes = (body: HclText): HclText => {
	let out = "";
	let last = 0;
	for (const b of parseBlocks(body)) {
		out += body.slice(last, b.offset) + " ".repeat(b.body.length);
		last = b.offset + b.body.length;
	}
	return out + body.slice(last);
};

export interface Attr {
	readonly raw: string;
	/** Unquoted string value when the attribute is a string literal. */
	readonly str: string | undefined;
	readonly line: number;
}

export const attr = (
	block: HclBlock,
	name: AttrName,
	fileText: HclText,
): Attr | undefined => {
	const own = ownAttributes(block.body);
	// name is an attribute name literal from this module.
	// nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
	const m = new RegExp(`^[ \\t]*${name}[ \\t]*=[ \\t]*(.+)$`, "m").exec(own);
	if (!m) return undefined;
	const raw = (m[1] ?? "").replace(/\s+(#|\/\/).*$/, "").trim();
	const str = /^"([^"]*)"$/.exec(raw)?.[1];
	return { raw, str, line: lineOf(fileText, block.offset + m.index) };
};

export const isFalse = (
	a: Attr | undefined,
): a is Attr & { readonly raw: "false" } => a?.raw === "false";
export const isTrue = (
	a: Attr | undefined,
): a is Attr & { readonly raw: "true" } => a?.raw === "true";

/** The trimmed source line `line` of `text`, capped for evidence. */
export const lineTextAt = (text: HclText, line: Line) =>
	(text.split("\n")[line - 1] ?? "").trim().slice(0, 160);
