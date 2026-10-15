import { nonCodeMask } from "../util";
import type { Lines } from "./evidence";

type Region = "code" | "comment" | "string";
/** A language id, as the lexer names it. */
type Lang = string;
/** One character of the text. */
type Char = string;
/** The text, or a slice of it. */
type Code = string;
/** An index into the text or its mask. */
type Offset = number;

/*
 * Where a character sits, as far as the lexer can tell. Our lexer will never
 * match every language's tokenizer, so its answer may only lower severity
 * when it is certain: a simple one-line quoted literal, or a comment that
 * starts its line, before anything the lexer does not model. Anything else is
 * judged as code.
 */
export interface Place {
	readonly region: Region;
	readonly certain: boolean;
	/** A regex literal: never certain, but no place for identifiers either. */
	readonly regex?: boolean;
}

const IN_CODE: Place = { region: "code", certain: true };

/** Longest line prefix inspected when judging a literal or comment simple. */
const MAX_PREFIX = 500;

/** Languages whose `'` starts a one-character literal, not a string. */
const CHAR_LITERAL = new Set(["c", "csharp", "go", "java", "rust", "swift"]);

/** Languages whose multi-line literals the lexer models. */
const MODELLED_LITERALS = new Set(["js", "python", "go"]);

/** Heredocs and percent literals, which the lexer does not model. */
const UNMODELLED_OPENER: Readonly<Record<string, RegExp>> = {
	php: /<<</g,
	ruby: /<<[~-]?["'`]?[A-Za-z_]|%[qQwWiIrsx]?[^\w\s=]/g,
};

/** Java decodes `\uXXXX` before lexing, so one can end a string or comment. */
const JAVA_ESCAPE = /\\u+[0-9A-Fa-f]{4}/;

/**
 * Ruby's `?"` and `%q(` literals hide quotes from the lexer. In Java a `\u`
 * escape is an ordinary character: `\u0022` is a quote, `\u000a` a line break.
 */
const PREFIX_TRAP: ReadonlyMap<string, RegExp> = new Map([
	["ruby", /[?%]/],
	["java", JAVA_ESCAPE],
]);

/** Comments start at their delimiter in the mask. */
const COMMENT_START = /^(\/\/|\/\*|#)/;

/** Characters that could fool the lexer in the code before a literal. */
const LEXER_TRAPS = new Set(["/", "`", "#", "*"]);

type Span = Place & { breakAt: number };

/** The lexer's view of a text: its non-code mask and where it may be wrong. */
interface Lexed {
	readonly mask: Uint8Array;
	/** Where each masked span starts, in order. */
	readonly starts: Int32Array;
	/** Past this index nothing is certain. */
	readonly desync: number;
}

interface Source {
	readonly text: string;
	readonly lang: string | undefined;
	readonly lines: Lines;
}

/** A masked span being judged. */
interface Masked {
	readonly s: number;
	readonly end: number;
	/** Code before the span on its line, when short enough to judge. */
	readonly prefix: string | undefined;
	/** Where a Java `\u` escape may end the span early. */
	readonly escapeAt: number;
}

const isQuote = (c: Char | undefined) => c === '"' || c === "'";

/** Whether `'` starts a one-character literal here, not a string. */
const isCharQuote = (c: Char, lang: Lang | undefined) =>
	c === "'" && CHAR_LITERAL.has(lang ?? "");

/** End of the masked span running from `from`. */
const spanEnd = (mask: Uint8Array, from: Offset) => {
	let end = from;
	while (end < mask.length && mask[end]) end++;
	return end;
};

/** The first heredoc or percent literal outside the mask. */
const firstUnmodelled = (text: Code, lang: Lang, mask: Uint8Array) => {
	const openers = UNMODELLED_OPENER[lang];
	if (!openers) return text.length;
	for (const o of text.matchAll(openers))
		if (!mask[o.index ?? 0]) return o.index ?? 0;
	return text.length;
};

/** The first quote before `at` that the mask leaves open at a line end. */
const firstOpenQuote = (
	{ text, lang }: Source,
	mask: Uint8Array,
	at: Offset,
): number => {
	for (let i = 0; i < at; i++) {
		const c = text[i] ?? "";
		if (mask[i] || !isQuote(c)) continue;
		const j = spanEnd(mask, i + 1);
		// One-line character literals cannot leave a string open.
		if (text[j] !== c && !isCharQuote(c, lang)) return i;
		i = text[j] === c ? j : j - 1;
	}
	return at;
};

/**
 * Where the lexer may have lost track of literals: the first quote it left
 * open at a line end (a multi-line string, raw string or text block it reads
 * as one line), or the first heredoc or percent literal. Past it, nothing is
 * certain. One pass over the mask.
 */
const desyncOf = (source: Source, lang: Lang, mask: Uint8Array): number => {
	const at = firstUnmodelled(source.text, lang, mask);
	if (MODELLED_LITERALS.has(lang)) return at;
	return firstOpenQuote(source, mask, at);
};

/** Index of the quote closing a literal whose body starts at `from`, or -1. */
const closingQuote = (s: Code, from: Offset, quote: Char): number => {
	for (let i = from; i < s.length; i++) {
		if (s[i] === "\\") i++;
		else if (s[i] === quote) return i;
	}
	return -1;
};

/** Code before a literal on its line, free of anything that could fool the lexer. */
const isPlainPrefix = (prefix: Code): boolean => {
	if (prefix.includes("<!--") || prefix.includes("-->")) return false;
	for (let i = 0; i < prefix.length; i++) {
		const c = prefix[i] ?? "";
		if (LEXER_TRAPS.has(c)) return false;
		if (!isQuote(c)) continue;
		i = closingQuote(prefix, i + 1, c);
		if (i < 0) return false;
	}
	return true;
};

const isSpanStart = (mask: Uint8Array, i: Offset) =>
	mask[i] === 1 && (i === 0 || mask[i - 1] === 0);

const spanStarts = (mask: Uint8Array): Int32Array => {
	const starts: number[] = [];
	for (let i = 0; i < mask.length; i++)
		if (isSpanStart(mask, i)) starts.push(i);
	return Int32Array.from(starts);
};

const lex = (source: Source): Lexed | undefined => {
	const { text, lang } = source;
	if (!lang) return undefined;
	let mask: Uint8Array;
	try {
		mask = nonCodeMask(text, lang);
	} catch {
		return undefined; // no mask: everything is code, the stricter reading
	}
	return {
		mask,
		starts: spanStarts(mask),
		desync: desyncOf(source, lang, mask),
	};
};

/** Start of the masked span holding `index`. */
const spanStartOf = (starts: Int32Array, index: Offset) => {
	let lo = 0;
	let hi = starts.length - 1;
	while (lo < hi) {
		const mid = (lo + hi + 1) >> 1;
		if ((starts[mid] ?? 0) <= index) lo = mid;
		else hi = mid - 1;
	}
	return starts[lo] ?? 0;
};

/** A prefix holding literals the lexer does not see. */
const hidesLiterals = (prefix: Code, lang: Lang | undefined) =>
	PREFIX_TRAP.get(lang ?? "")?.test(prefix) === true;

const linePrefix = (
	{ text, lang, lines }: Source,
	desync: Offset,
	s: Offset,
): string | undefined => {
	const lineStart = lines.startOf(lines.lineOf(s));
	const prefix =
		s - lineStart <= MAX_PREFIX && s < desync
			? text.slice(lineStart, s)
			: undefined;
	return prefix && hidesLiterals(prefix, lang) ? undefined : prefix;
};

const javaEscapeAt = ({ text, lang }: Source, s: Offset, end: Offset) => {
	const e = lang === "java" ? JAVA_ESCAPE.exec(text.slice(s, end)) : null;
	return e ? s + e.index : end;
};

/**
 * Line comments may also end at CR, NEL (C#), the Unicode line separators
 * (JavaScript, C#) or, in PHP, at `?>`.
 */
const lineCommentBreak = ({ text, lang }: Source, span: Masked): number => {
	const body = text.slice(span.s, span.end);
	const lineBreak = /[\r\u0085\u2028\u2029]/.exec(body);
	const close = lang === "php" ? body.indexOf("?>") : -1;
	let breakAt = span.escapeAt;
	if (lineBreak) breakAt = Math.min(breakAt, span.s + lineBreak.index);
	if (close !== -1) breakAt = Math.min(breakAt, span.s + close);
	return breakAt;
};

const judgeComment = (source: Source, span: Masked): Span => ({
	region: "comment",
	certain: span.prefix !== undefined && /^\s*$/.test(span.prefix),
	breakAt:
		source.text[span.s + 1] === "*"
			? span.escapeAt
			: lineCommentBreak(source, span),
});

/** A `'` literal longer than one character where `'` delimits characters. */
const isLongCharLiteral = ({ text, lang }: Source, span: Masked) =>
	isCharQuote(text[span.s - 1] ?? "", lang) &&
	(span.end - span.s > 2 ||
		Array.from(text.slice(span.s, span.end)).length > 1);

const closesOnItsLine = (source: Source, span: Masked, quote: Char) =>
	isQuote(quote) &&
	source.text[span.end] === quote &&
	!isLongCharLiteral(source, span);

/** Not prefixed (f"", r#"", $"", @""), interpolating or multi-line. */
const isPlainLiteral = (text: Code, { s, end }: Masked) =>
	!/[\w#$@"'`]/.test(text[s - 2] ?? "") && !/[{$\r\n]/.test(text.slice(s, end));

const hasPlainPrefix = ({ prefix }: Masked) =>
	prefix !== undefined && isPlainPrefix(prefix.slice(0, -1));

/**
 * Strings start after their quote. Prefixed (f"", r#"", $"", @""),
 * interpolating, multi-line or unclosed literals are never certain, nor is a
 * `'` literal longer than one character where `'` delimits characters (it is
 * a Rust lifetime or a C++ digit separator).
 */
const judgeString = (source: Source, span: Masked): Span => {
	const { text } = source;
	const quote = text[span.s - 1] ?? "";
	return {
		region: "string",
		certain:
			closesOnItsLine(source, span, quote) &&
			isPlainLiteral(text, span) &&
			hasPlainPrefix(span),
		regex: text[span.s] === "/" && quote !== "/",
		breakAt: span.escapeAt,
	};
};

/** Judged once per masked span, so the work stays linear. */
const judge = (source: Source, lexed: Lexed, s: Offset): Span => {
	const end = spanEnd(lexed.mask, s);
	const span: Masked = {
		s,
		end,
		prefix: linePrefix(source, lexed.desync, s),
		escapeAt: javaEscapeAt(source, s, end),
	};
	return COMMENT_START.test(source.text.slice(s, s + 2))
		? judgeComment(source, span)
		: judgeString(source, span);
};

const cached = <K, V>(cache: Map<K, V>, key: K, make: () => V): V => {
	let value = cache.get(key);
	if (value === undefined) {
		value = make();
		cache.set(key, value);
	}
	return value;
};

export const placeFinder = (
	text: Code,
	lang: Lang | undefined,
	lines: Lines,
): ((index: Offset) => Place) => {
	const source: Source = { text, lang, lines };
	const spans = new Map<number, Span>();
	let built = false;
	let lexed: Lexed | undefined;
	return (index) => {
		if (!built) {
			built = true;
			lexed = lex(source);
		}
		const current = lexed;
		if (!current?.mask[index]) return IN_CODE;
		const s = spanStartOf(current.starts, index);
		const span = cached(spans, s, () => judge(source, current, s));
		// Past a CR or line separator, a line comment may already have ended.
		return index <= span.breakAt
			? span
			: { region: span.region, certain: false };
	};
};
