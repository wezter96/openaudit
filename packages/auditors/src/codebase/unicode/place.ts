import { nonCodeMask } from "../util";
import type { Lines } from "./evidence";

type Region = "code" | "comment" | "string";

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
 * Where the lexer may have lost track of literals: the first quote it left
 * open at a line end (a multi-line string, raw string or text block it reads
 * as one line), or the first heredoc or percent literal. Past it, nothing is
 * certain. One pass over the mask.
 */
const desyncOf = (text: string, lang: string, m: Uint8Array): number => {
	let at = text.length;
	const openers = UNMODELLED_OPENER[lang];
	if (openers)
		for (const o of text.matchAll(openers))
			if (!m[o.index ?? 0]) {
				at = o.index ?? 0;
				break;
			}
	if (MODELLED_LITERALS.has(lang)) return at;
	for (let i = 0; i < at; i++) {
		const c = text[i];
		if (m[i] || (c !== '"' && c !== "'")) continue;
		let j = i + 1;
		while (j < m.length && m[j]) j++;
		// One-line character literals cannot leave a string open.
		if (text[j] !== c && !(c === "'" && CHAR_LITERAL.has(lang))) return i;
		i = text[j] === c ? j : j - 1;
	}
	return at;
};

/** Code before a literal on its line, free of anything that could fool the lexer. */
const isPlainPrefix = (prefix: string): boolean => {
	if (prefix.includes("<!--") || prefix.includes("-->")) return false;
	let quote = "";
	for (let i = 0; i < prefix.length; i++) {
		const c = prefix[i];
		if (quote) {
			if (c === "\\") i++;
			else if (c === quote) quote = "";
		} else if (c === '"' || c === "'") quote = c;
		else if (c === "/" || c === "`" || c === "#" || c === "*") return false;
	}
	return quote === "";
};

export const placeFinder = (
	text: string,
	lang: string | undefined,
	lines: Lines,
): ((index: number) => Place) => {
	let built = false;
	let mask: Uint8Array | undefined;
	let starts = new Int32Array(0);
	let desync = text.length;
	const spans = new Map<number, Place & { breakAt: number }>();

	const build = () => {
		built = true;
		if (!lang) return;
		try {
			mask = nonCodeMask(text, lang);
		} catch {
			return; // no mask: everything is code, the stricter reading
		}
		const m = mask;
		desync = desyncOf(text, lang, m);
		const isStart = (i: number) => m[i] === 1 && (i === 0 || m[i - 1] === 0);
		let count = 0;
		for (let i = 0; i < m.length; i++) if (isStart(i)) count++;
		starts = new Int32Array(count);
		let k = 0;
		for (let i = 0; i < m.length; i++) if (isStart(i)) starts[k++] = i;
	};

	// Judged once per masked span, so the work stays linear.
	const judge = (s: number, m: Uint8Array): Place & { breakAt: number } => {
		let end = s;
		while (end < m.length && m[end]) end++;
		const lineStart = lines.startOf(lines.lineOf(s));
		let prefix =
			s - lineStart <= MAX_PREFIX && s < desync
				? text.slice(lineStart, s)
				: undefined;
		// Ruby's `?"` and `%q(` literals hide quotes from the lexer.
		if (lang === "ruby" && prefix && /[?%]/.test(prefix)) prefix = undefined;
		// In Java a `\u` escape is an ordinary character: `\u0022` is a quote,
		// `\u000a` a line break.
		let escapeAt = end;
		if (lang === "java") {
			if (prefix && JAVA_ESCAPE.test(prefix)) prefix = undefined;
			const e = JAVA_ESCAPE.exec(text.slice(s, end));
			if (e) escapeAt = s + e.index;
		}
		if (/^(\/\/|\/\*|#)/.test(text.slice(s, s + 2))) {
			// The mask starts comments at their delimiter. Line comments may also
			// end at CR, NEL (C#), the Unicode line separators (JavaScript, C#)
			// or, in PHP, at `?>`.
			let breakAt = escapeAt;
			if (text[s + 1] !== "*") {
				const body = text.slice(s, end);
				const lineBreak = /[\r\u0085\u2028\u2029]/.exec(body);
				if (lineBreak) breakAt = Math.min(breakAt, s + lineBreak.index);
				const close = lang === "php" ? body.indexOf("?>") : -1;
				if (close !== -1) breakAt = Math.min(breakAt, s + close);
			}
			return {
				region: "comment",
				certain: prefix !== undefined && /^\s*$/.test(prefix),
				breakAt,
			};
		}
		// Strings start after their quote. Prefixed (f"", r#"", $"", @""),
		// interpolating, multi-line or unclosed literals are never certain,
		// nor is a `'` literal longer than one character where `'` delimits
		// characters (it is a Rust lifetime or a C++ digit separator).
		const quote = text[s - 1] ?? "";
		const certain =
			(quote === '"' || quote === "'") &&
			text[end] === quote &&
			!(
				quote === "'" &&
				lang !== undefined &&
				CHAR_LITERAL.has(lang) &&
				(end - s > 2 || [...text.slice(s, end)].length > 1)
			) &&
			!/[\w#$@"'`]/.test(text[s - 2] ?? "") &&
			!/[{$\r\n]/.test(text.slice(s, end)) &&
			prefix !== undefined &&
			isPlainPrefix(prefix.slice(0, -1));
		return {
			region: "string",
			certain,
			regex: text[s] === "/" && quote !== "/",
			breakAt: escapeAt,
		};
	};

	return (index) => {
		if (!built) build();
		const m = mask;
		if (!m?.[index]) return IN_CODE;
		let lo = 0;
		let hi = starts.length - 1;
		while (lo < hi) {
			const mid = (lo + hi + 1) >> 1;
			if ((starts[mid] ?? 0) <= index) lo = mid;
			else hi = mid - 1;
		}
		const s = starts[lo] ?? 0;
		let span = spans.get(s);
		if (!span) {
			span = judge(s, m);
			spans.set(s, span);
		}
		// Past a CR or line separator, a line comment may already have ended.
		return index <= span.breakAt
			? span
			: { region: span.region, certain: false };
	};
};
