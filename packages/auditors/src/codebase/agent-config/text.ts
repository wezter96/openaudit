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

/** Format characters, variation selectors and fillers that render as nothing. */
const isInvisible = (cp: number, c: string) =>
	FORMAT.test(c) ||
	(cp >= 0xfe00 && cp <= 0xfe0f) ||
	(cp >= 0xe0100 && cp <= 0xe01ef) ||
	cp === 0x034f ||
	cp === 0x115f ||
	cp === 0x1160 ||
	cp === 0x17b4 ||
	cp === 0x17b5 ||
	cp === 0x3164 ||
	cp === 0xffa0;

const isAlnum = (c: string | undefined) =>
	c !== undefined && /[A-Za-z0-9]/.test(c);
const isSpace = (c: string | undefined) => c !== undefined && /\s/.test(c);

export interface Normalized {
	readonly text: string;
	/** Offset in the raw input of each UTF-16 unit of `text`. */
	readonly source: ReadonlyArray<number>;
}

/**
 * Decodes HTML entities, applies NFKC (full-width and compatibility forms),
 * drops invisible characters, folds look-alike letters and dashes to ASCII,
 * removes Markdown emphasis (`*`, `~`, backticks, and `_` at word edges) and
 * collapses whitespace to single spaces.
 */
export const normalize = (raw: string): Normalized => {
	const chars: string[] = [];
	const from: number[] = [];
	const emit = (s: string, at: number) => {
		for (const c of s) {
			const cp = c.codePointAt(0) ?? 0;
			if (isInvisible(cp, c)) continue;
			for (const out of CONFUSABLES.get(cp) ?? c.normalize("NFKC")) {
				if (out === "*" || out === "~" || out === "`") continue;
				chars.push(out);
				from.push(at);
			}
		}
	};
	let i = 0;
	while (i < raw.length) {
		if (raw[i] === "&") {
			ENTITY.lastIndex = i;
			const m = ENTITY.exec(raw);
			const decoded = m ? decodeEntity(m) : undefined;
			if (m && decoded !== undefined) {
				emit(decoded, i);
				i += m[0].length;
				continue;
			}
		}
		const c = String.fromCodePoint(raw.codePointAt(i) ?? 0);
		emit(c, i);
		i += c.length;
	}

	let text = "";
	const source: number[] = [];
	for (let k = 0; k < chars.length; k++) {
		const c = chars[k] ?? "";
		// `_word_` emphasis, but keep snake_case such as id_rsa.
		if (c === "_" && !(isAlnum(chars[k - 1]) && isAlnum(chars[k + 1])))
			continue;
		if (isSpace(c)) {
			if (text.length === 0 || text.endsWith(" ")) continue;
			text += " ";
		} else text += c;
		while (source.length < text.length) source.push(from[k] ?? 0);
	}
	return { text, source };
};

const BLOCK_START = /^ {0,3}(?:[-*+>]\s|\d{1,9}[.)]\s|#|\||<)/;
const FENCE = /^ {0,3}(?:`{3,}|~{3,})/;

/**
 * Sentences as raw [start, end) offsets. Soft-wrapped lines of a paragraph
 * join; blank lines, list items, headings, tables, HTML and every line of a
 * fenced code block start a new one. Sentences end at `.;!?` before
 * whitespace.
 */
export const sentences = (text: string): Array<[number, number]> => {
	const out: Array<[number, number]> = [];
	const split = (start: number, end: number) => {
		let from = start;
		for (let k = start; k < end - 1; k++) {
			const c = text[k];
			if (
				(c === "." || c === ";" || c === "!" || c === "?") &&
				isSpace(text[k + 1])
			) {
				out.push([from, k + 1]);
				from = k + 1;
			}
		}
		if (from < end) out.push([from, end]);
	};
	let para: [number, number] | undefined;
	const flush = () => {
		if (para) split(para[0], para[1]);
		para = undefined;
	};
	let inFence = false;
	let pos = 0;
	for (const line of text.split("\n")) {
		const start = pos;
		const end = pos + line.length;
		pos = end + 1;
		if (FENCE.test(line)) {
			flush();
			inFence = !inFence;
			out.push([start, end]);
		} else if (inFence) out.push([start, end]);
		else if (line.trim() === "") flush();
		else {
			if (BLOCK_START.test(line)) flush();
			para = para ? [para[0], end] : [start, end];
		}
	}
	flush();
	return out;
};
