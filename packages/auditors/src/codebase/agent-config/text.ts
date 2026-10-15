/*
 * Text as an agent understands it, for the instruction heuristics. Attackers
 * dodge phrase matching with entities, full-width letters, look-alike
 * letters, invisible characters, Markdown emphasis and odd whitespace; models
 * read straight through all of those. Everything here is linear-time.
 */

const ENTITIES: Readonly<Record<string, string>> = {
	amp: "&",
	lt: "<",
	gt: ">",
	quot: '"',
	apos: "'",
	nbsp: " ",
	sol: "/",
	bsol: "\\",
	verbar: "|",
	vert: "|",
	period: ".",
	colon: ":",
	semi: ";",
	comma: ",",
	tilde: "~",
	hyphen: "-",
	dash: "-",
	ndash: "-",
	mdash: "-",
	lowbar: "_",
	ast: "*",
	grave: "`",
	excl: "!",
	num: "#",
	dollar: "$",
	percnt: "%",
	lpar: "(",
	rpar: ")",
	equals: "=",
	plus: "+",
	quest: "?",
	commat: "@",
	lsqb: "[",
	rsqb: "]",
	lbrack: "[",
	rbrack: "]",
	lcub: "{",
	rcub: "}",
};
const ENTITY = /&(?:#(\d{1,7})|#[xX]([0-9A-Fa-f]{1,6})|([A-Za-z]{2,8}));/y;

const decodeEntity = (m: RegExpExecArray): string | undefined => {
	const [, dec, hex, name] = m;
	if (name) return ENTITIES[name.toLowerCase()];
	const cp = dec ? Number.parseInt(dec, 10) : Number.parseInt(hex ?? "", 16);
	return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : undefined;
};

/** Cyrillic, Greek and Armenian letters that render like Latin, and dashes. */
const CONFUSABLES = new Map<number, string>(
	Object.entries({
		a: [0x0430, 0x03b1, 0x0251],
		c: [0x0441, 0x03f2],
		d: [0x0501],
		e: [0x0435, 0x03b5],
		g: [0x0261],
		h: [0x04bb],
		i: [0x0456, 0x03b9, 0x0131],
		j: [0x0458],
		k: [0x03ba],
		l: [0x04cf],
		n: [0x0578],
		o: [0x043e, 0x03bf, 0x0585],
		p: [0x0440, 0x03c1],
		q: [0x051b],
		s: [0x0455],
		t: [0x03c4],
		u: [0x03c5, 0x057d],
		v: [0x03bd],
		w: [0x0461, 0x051d],
		x: [0x0445, 0x03c7],
		y: [0x0443, 0x03b3],
		A: [0x0410, 0x0391],
		B: [0x0412, 0x0392],
		C: [0x0421],
		E: [0x0415, 0x0395],
		H: [0x041d, 0x0397],
		I: [0x0406, 0x0399],
		J: [0x0408],
		K: [0x041a, 0x039a],
		M: [0x041c, 0x039c],
		N: [0x039d],
		O: [0x041e, 0x039f],
		P: [0x0420, 0x03a1],
		S: [0x0405],
		T: [0x0422, 0x03a4],
		X: [0x0425, 0x03a7],
		Y: [0x04ae, 0x03a5],
		Z: [0x0396],
		"-": [0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015, 0x2212],
	}).flatMap(([latin, cps]) => cps.map((cp) => [cp, latin] as const)),
);

const FORMAT = /^\p{Cf}$/u;
const FILLERS = new Set([
	0x034f, 0x115f, 0x1160, 0x17b4, 0x17b5, 0x3164, 0xffa0,
]);
const VARIATION_SELECTORS: ReadonlyArray<readonly [number, number]> = [
	[0xfe00, 0xfe0f],
	[0xe0100, 0xe01ef],
];

const isVariationSelector = (cp: number) =>
	VARIATION_SELECTORS.some(([lo, hi]) => cp >= lo && cp <= hi);

/** Format characters, variation selectors and fillers that render as nothing. */
const isInvisible = (cp: number, c: string) =>
	FORMAT.test(c) || isVariationSelector(cp) || FILLERS.has(cp);

const isAlnum = (c: string | undefined) =>
	c !== undefined && /[A-Za-z0-9]/.test(c);
const isSpace = (c: string | undefined) => c !== undefined && /\s/.test(c);

export interface Normalized {
	readonly text: string;
	/** Offset in the raw input of each UTF-16 unit of `text`. */
	readonly source: ReadonlyArray<number>;
}

/** Folded characters before emphasis and whitespace handling, with their raw offsets. */
interface Folded {
	readonly chars: string[];
	readonly from: number[];
}

/** A decoded piece of raw input and how many raw UTF-16 units it took. */
interface Token {
	readonly text: string;
	readonly length: number;
}

const EMPHASIS = new Set(["*", "~", "`"]);

const foldChar = (out: Folded, c: string, at: number) => {
	const cp = c.codePointAt(0) ?? 0;
	if (isInvisible(cp, c)) return;
	for (const folded of CONFUSABLES.get(cp) ?? c.normalize("NFKC")) {
		if (EMPHASIS.has(folded)) continue;
		out.chars.push(folded);
		out.from.push(at);
	}
};

const entityAt = (raw: string, i: number): Token | undefined => {
	if (raw[i] !== "&") return undefined;
	ENTITY.lastIndex = i;
	const m = ENTITY.exec(raw);
	const decoded = m ? decodeEntity(m) : undefined;
	return m && decoded !== undefined
		? { text: decoded, length: m[0].length }
		: undefined;
};

const codePointAt = (raw: string, i: number): Token => {
	const c = String.fromCodePoint(raw.codePointAt(i) ?? 0);
	return { text: c, length: c.length };
};

const fold = (raw: string): Folded => {
	const out: Folded = { chars: [], from: [] };
	let i = 0;
	while (i < raw.length) {
		const token = entityAt(raw, i) ?? codePointAt(raw, i);
		for (const c of token.text) foldChar(out, c, i);
		i += token.length;
	}
	return out;
};

/** `_word_` emphasis, but keep snake_case such as id_rsa. */
const isEmphasisUnderscore = (chars: ReadonlyArray<string>, k: number) =>
	chars[k] === "_" && !(isAlnum(chars[k - 1]) && isAlnum(chars[k + 1]));

/** What the k-th folded character adds to `text` once whitespace collapses. */
const appended = (text: string, chars: ReadonlyArray<string>, k: number) => {
	const c = chars[k] ?? "";
	if (isEmphasisUnderscore(chars, k)) return "";
	if (!isSpace(c)) return c;
	return text.length === 0 || text.endsWith(" ") ? "" : " ";
};

const collapse = ({ chars, from }: Folded): Normalized => {
	let text = "";
	const source: number[] = [];
	for (let k = 0; k < chars.length; k++) {
		text += appended(text, chars, k);
		while (source.length < text.length) source.push(from[k] ?? 0);
	}
	return { text, source };
};

/**
 * Decodes HTML entities, applies NFKC (full-width and compatibility forms),
 * drops invisible characters, folds look-alike letters and dashes to ASCII,
 * removes Markdown emphasis (`*`, `~`, backticks, and `_` at word edges) and
 * collapses whitespace to single spaces.
 */
export const normalize = (raw: string): Normalized => collapse(fold(raw));

const BLOCK_START = /^ {0,3}(?:[-*+>]\s|\d{1,9}[.)]\s|#|\||<)/;
const FENCE = /^ {0,3}(?:`{3,}|~{3,})/;
const SENTENCE_END = new Set([".", ";", "!", "?"]);

type Span = [number, number];

/** Sentence splitting state: the open paragraph and whether a fence is open. */
interface Splitter {
	readonly text: string;
	readonly out: Span[];
	para: Span | undefined;
	inFence: boolean;
}

const endsSentence = (text: string, k: number) =>
	SENTENCE_END.has(text.charAt(k)) && isSpace(text[k + 1]);

const split = (text: string, [start, end]: Span, out: Span[]) => {
	let from = start;
	for (let k = start; k < end - 1; k++) {
		if (!endsSentence(text, k)) continue;
		out.push([from, k + 1]);
		from = k + 1;
	}
	if (from < end) out.push([from, end]);
};

const flush = (s: Splitter) => {
	if (s.para) split(s.text, s.para, s.out);
	s.para = undefined;
};

const paragraphLine = (s: Splitter, line: string, [start, end]: Span) => {
	if (BLOCK_START.test(line)) flush(s);
	s.para = s.para ? [s.para[0], end] : [start, end];
};

const addLine = (s: Splitter, line: string, start: number) => {
	const span: Span = [start, start + line.length];
	if (FENCE.test(line)) {
		flush(s);
		s.inFence = !s.inFence;
		s.out.push(span);
	} else if (s.inFence) s.out.push(span);
	else if (line.trim() === "") flush(s);
	else paragraphLine(s, line, span);
};

/**
 * Sentences as raw [start, end) offsets. Soft-wrapped lines of a paragraph
 * join; blank lines, list items, headings, tables, HTML and every line of a
 * fenced code block start a new one. Sentences end at `.;!?` before
 * whitespace.
 */
export const sentences = (text: string): Array<[number, number]> => {
	const s: Splitter = { text, out: [], para: undefined, inFence: false };
	let pos = 0;
	for (const line of text.split("\n")) {
		addLine(s, line, pos);
		pos += line.length + 1;
	}
	flush(s);
	return s.out;
};
