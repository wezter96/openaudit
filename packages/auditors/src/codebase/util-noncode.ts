import type { Language, Offset, SourceText } from "./util-types";

/** Past this `${...}` nesting in JS templates the rest of the file is code. */
const MAX_TEMPLATE_DEPTH = 64;

/** `if (...) /re/`: a regex, not a division, follows these conditions. */
const CONTROL_KEYWORD = /(?:^|[^\w$])(?:if|while|for|with)$/;

const REGEX_PRECEDER =
	/[(,=:[!&|?{};+\-*%<>~^]$|(?:^|[^\w$])(?:return|typeof|case|do|else|in|of|void|yield|await|delete|throw|new)$/;

const NO_SLASH_COMMENTS = new Set(["python", "ruby"]);
const HASH_COMMENTS = new Set(["python", "ruby", "php"]);
const TEMPLATE_LANGUAGES = new Set(["js", "go"]);

/** A `#` followed by these is code: Ruby interpolation, a PHP 8 attribute. */
const HASH_NOT_COMMENT = new Map([
	["ruby", "{"],
	["php", "["],
]);

/** One character of source text. */
type Char = string;

/** Lexer state of one stretch of code (the file, or one `${...}`). */
interface CodeState {
	i: Offset;
	depth: number;
	/** The last few non-space characters, spaces collapsed. */
	prev: string;
	/** Per open `(`: whether it follows a control keyword. */
	readonly parens: boolean[];
	closedControl: boolean;
	/** Stop at the `}` that closes a `${`. */
	readonly untilBrace: boolean;
}

const mayFollowRegex = (state: CodeState): boolean => {
	const prev = state.prev.trimEnd();
	return (
		REGEX_PRECEDER.test(prev) || (state.closedControl && prev.endsWith(")"))
	);
};

/** Tracks parentheses and the recent characters a regex decision looks at. */
const trackToken = (state: CodeState, ch: Char) => {
	if (ch === "(") state.parens.push(CONTROL_KEYWORD.test(state.prev.trimEnd()));
	else if (ch === ")") state.closedControl = state.parens.pop() ?? false;
	if (!/\s/.test(ch)) state.prev = (state.prev + ch).slice(-8);
	else if (state.prev && !state.prev.endsWith(" "))
		state.prev = `${state.prev} `.slice(-8);
};

class NonCodeLexer {
	private readonly mask: Uint8Array;
	private readonly n: number;
	private readonly slashComments: boolean;
	private readonly hashComments: boolean;
	private readonly templates: boolean;
	private readonly triple: boolean;
	// Bounds that keep hostile input linear: template nesting depth, and the
	// end of a line on which a regex literal already failed to close.
	private nesting = 0;
	private noRegexUntil = -1;
	/** Where lexing gave up; everything from here on stays code. */
	private abandonedAt = -1;

	constructor(
		private readonly text: SourceText,
		private readonly lang: Language,
	) {
		this.n = text.length;
		this.mask = new Uint8Array(this.n);
		this.slashComments = !NO_SLASH_COMMENTS.has(lang);
		this.hashComments = HASH_COMMENTS.has(lang);
		this.templates = TEMPLATE_LANGUAGES.has(lang);
		this.triple = lang === "python";
	}

	run(): Uint8Array {
		this.scanCode(0, false);
		if (this.abandonedAt >= 0) this.mask.fill(0, this.abandonedAt);
		return this.mask;
	}

	private fill(from: Offset, to: Offset) {
		this.mask.fill(1, from, Math.min(to, this.n));
	}

	private lineEnd(i: Offset): Offset {
		const e = this.text.indexOf("\n", i);
		return e === -1 ? this.n : e;
	}

	private scanCode(start: Offset, untilBrace: boolean): Offset {
		const state: CodeState = {
			i: start,
			depth: 0,
			prev: "",
			parens: [],
			closedControl: false,
			untilBrace,
		};
		while (state.i < this.n) if (this.step(state)) return state.i + 1;
		return this.n;
	}

	/** Lexes one token; true when it is the `}` that ends the code. */
	private step(state: CodeState): boolean {
		const i = state.i;
		const comment = this.commentEnd(i);
		if (comment !== undefined) {
			this.fill(i, comment);
			state.i = comment;
			return false;
		}
		const literal = this.literalEnd(i) ?? this.regexEnd(state);
		if (literal !== undefined) {
			state.i = literal;
			state.prev = "x";
			return false;
		}
		if (this.closesBrace(state)) return true;
		trackToken(state, this.text[i] ?? "");
		state.i++;
		return false;
	}

	/** End of the comment that starts at `i`, if one does. */
	private commentEnd(i: Offset): Offset | undefined {
		const ch = this.text[i];
		const next = this.text[i + 1];
		if (this.slashComments && ch === "/") {
			if (next === "/") return this.lineEnd(i);
			if (next === "*") {
				const e = this.text.indexOf("*/", i + 2);
				return e === -1 ? this.n : e + 2;
			}
		}
		if (this.startsHashComment(i)) return this.lineEnd(i);
		return undefined;
	}

	private startsHashComment(i: Offset): boolean {
		if (!this.hashComments || this.text[i] !== "#") return false;
		const notComment = HASH_NOT_COMMENT.get(this.lang);
		return notComment === undefined || this.text[i + 1] !== notComment;
	}

	/** End of the string or template literal that starts at `i`, if one does. */
	private literalEnd(i: Offset): Offset | undefined {
		const ch = this.text[i] ?? "";
		if (this.triple && this.startsTripleQuote(i)) return this.scanTriple(i);
		if (ch === '"' || ch === "'") return this.scanQuoted(i, ch);
		if (this.templates && ch === "`") return this.scanTemplate(i);
		return undefined;
	}

	private startsTripleQuote(i: Offset): boolean {
		return this.text.startsWith('"""', i) || this.text.startsWith("'''", i);
	}

	private scanTriple(i: Offset): Offset {
		const q = this.text.slice(i, i + 3);
		const e = this.text.indexOf(q, i + 3);
		const end = e === -1 ? this.n : e;
		this.fill(i + 3, end);
		return end + 3;
	}

	private scanQuoted(i: Offset, quote: Char): Offset {
		let j = i + 1;
		while (!this.quotedEnds(j, quote)) j += this.text[j] === "\\" ? 2 : 1;
		this.fill(i + 1, j);
		return j + 1;
	}

	private quotedEnds(j: Offset, quote: Char): boolean {
		if (j >= this.n) return true;
		const ch = this.text[j];
		return ch === quote || ch === "\n";
	}

	private scanTemplate(i: Offset): Offset {
		let j = i + 1;
		let segment = j;
		while (j < this.n && this.text[j] !== "`") {
			if (this.opensInterpolation(j)) {
				this.fill(segment, j);
				j = this.scanInterpolation(j);
				segment = j;
			} else j += this.text[j] === "\\" ? 2 : 1;
		}
		this.fill(segment, j);
		return j + 1;
	}

	private opensInterpolation(j: Offset): boolean {
		return this.lang === "js" && this.text.startsWith("${", j);
	}

	/** Lexes the `${...}` at `j` as code; returns where the template resumes. */
	private scanInterpolation(j: Offset): Offset {
		if (this.nesting >= MAX_TEMPLATE_DEPTH) {
			this.abandonedAt = j;
			return this.n;
		}
		this.nesting++;
		const end = this.scanCode(j + 2, true);
		this.nesting--;
		return end;
	}

	/** End of the JS regex literal at the current `/`, if there is one. */
	private regexEnd(state: CodeState): Offset | undefined {
		if (!this.mayStartRegex(state)) return undefined;
		const after = this.scanRegex(state.i);
		if (after > state.i + 1) return after;
		this.noRegexUntil = this.lineEnd(state.i);
		return undefined;
	}

	private mayStartRegex(state: CodeState): boolean {
		if (this.lang !== "js" || this.text[state.i] !== "/") return false;
		return state.i > this.noRegexUntil && mayFollowRegex(state);
	}

	private scanRegex(i: Offset): Offset {
		const close = this.regexClose(i);
		if (close === undefined) return i + 1; // not a regex after all
		this.fill(i, close + 1);
		return close + 1;
	}

	/** The `/` that closes a regex opened at `i`, if it closes on this line. */
	private regexClose(i: Offset): Offset | undefined {
		let inClass = false;
		for (let j = i + 1; j < this.n; j++) {
			const ch = this.text[j];
			if (ch === "\n") return undefined;
			if (ch === "\\") j++;
			else if (ch === "/" && !inClass) return j;
			else if (ch === "[" || ch === "]") inClass = ch === "[";
		}
		return undefined;
	}

	/** Counts braces inside `${...}`; true at the `}` that closes it. */
	private closesBrace(state: CodeState): boolean {
		if (!state.untilBrace) return false;
		const ch = this.text[state.i];
		if (ch === "{") state.depth++;
		else if (ch === "}") {
			if (state.depth === 0) return true;
			state.depth--;
		}
		return false;
	}
}

/**
 * Marks characters inside string literals, comments and (JS) regex literals
 * with 1, so pattern matches in prose can be ignored. Opening delimiters stay
 * 0, so rules may still match on a quote. `${...}` inside JS templates is code.
 * Best-effort lexer: it never throws and degrades to "code" on odd input,
 * including input nested deeper than it tracks.
 */
export const nonCodeMask = (text: SourceText, lang: Language): Uint8Array =>
	new NonCodeLexer(text, lang).run();
