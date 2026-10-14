/*
 * The characters this auditor reports, when they are legitimate, and how
 * they are escaped and decoded for messages and evidence.
 */

const NAMES: ReadonlyMap<number, string> = new Map([
	[0x00ad, "SOFT HYPHEN"],
	[0x034f, "COMBINING GRAPHEME JOINER"],
	[0x061c, "ARABIC LETTER MARK"],
	[0x115f, "HANGUL CHOSEONG FILLER"],
	[0x1160, "HANGUL JUNGSEONG FILLER"],
	[0x17b4, "KHMER VOWEL INHERENT AQ"],
	[0x17b5, "KHMER VOWEL INHERENT AA"],
	[0x180b, "MONGOLIAN FREE VARIATION SELECTOR ONE"],
	[0x180c, "MONGOLIAN FREE VARIATION SELECTOR TWO"],
	[0x180d, "MONGOLIAN FREE VARIATION SELECTOR THREE"],
	[0x180e, "MONGOLIAN VOWEL SEPARATOR"],
	[0x180f, "MONGOLIAN FREE VARIATION SELECTOR FOUR"],
	[0x200b, "ZERO WIDTH SPACE"],
	[0x200c, "ZERO WIDTH NON-JOINER"],
	[0x200d, "ZERO WIDTH JOINER"],
	[0x200e, "LEFT-TO-RIGHT MARK"],
	[0x200f, "RIGHT-TO-LEFT MARK"],
	[0x2028, "LINE SEPARATOR"],
	[0x2029, "PARAGRAPH SEPARATOR"],
	[0x202a, "LEFT-TO-RIGHT EMBEDDING"],
	[0x202b, "RIGHT-TO-LEFT EMBEDDING"],
	[0x202c, "POP DIRECTIONAL FORMATTING"],
	[0x202d, "LEFT-TO-RIGHT OVERRIDE"],
	[0x202e, "RIGHT-TO-LEFT OVERRIDE"],
	[0x2060, "WORD JOINER"],
	[0x2061, "FUNCTION APPLICATION"],
	[0x2062, "INVISIBLE TIMES"],
	[0x2063, "INVISIBLE SEPARATOR"],
	[0x2064, "INVISIBLE PLUS"],
	[0x2066, "LEFT-TO-RIGHT ISOLATE"],
	[0x2067, "RIGHT-TO-LEFT ISOLATE"],
	[0x2068, "FIRST STRONG ISOLATE"],
	[0x2069, "POP DIRECTIONAL ISOLATE"],
	[0x206a, "INHIBIT SYMMETRIC SWAPPING"],
	[0x206b, "ACTIVATE SYMMETRIC SWAPPING"],
	[0x206c, "INHIBIT ARABIC FORM SHAPING"],
	[0x206d, "ACTIVATE ARABIC FORM SHAPING"],
	[0x206e, "NATIONAL DIGIT SHAPES"],
	[0x206f, "NOMINAL DIGIT SHAPES"],
	[0x3164, "HANGUL FILLER"],
	[0xfeff, "ZERO WIDTH NO-BREAK SPACE"],
	[0xffa0, "HALFWIDTH HANGUL FILLER"],
	[0xfff9, "INTERLINEAR ANNOTATION ANCHOR"],
	[0xfffa, "INTERLINEAR ANNOTATION SEPARATOR"],
	[0xfffb, "INTERLINEAR ANNOTATION TERMINATOR"],
]);

/**
 * Every character this auditor reports, as runs: all of Unicode's
 * Default_Ignorable_Code_Point (which renderers draw as nothing, including
 * the deprecated format controls and unassigned reserved ranges), the
 * interlinear annotation controls, and the line and paragraph separators.
 */
export const HIDDEN =
	/[\p{Default_Ignorable_Code_Point}\u2028\u2029\uFFF9-\uFFFB]+/gu;

export type Group = "bidi" | "mark" | "tag" | "selector" | "invisible";

export const groupOf = (cp: number): Group => {
	if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069))
		return "bidi";
	if (cp === 0x200e || cp === 0x200f || cp === 0x061c) return "mark";
	if (cp >= 0xe0000 && cp <= 0xe007f) return "tag";
	if ((cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef))
		return "selector";
	return "invisible";
};

/** Characters that only make sense in code as escapes. */
export const CODE_ONLY = new Set([
	0x00ad, 0x115f, 0x1160, 0x2028, 0x2029, 0x2061, 0x2062, 0x2063, 0x2064,
	0x3164, 0xffa0,
]);

const isEmojiPart = (ch: string) =>
	// biome-ignore lint/suspicious/noMisleadingCharacterClass: tests one character at a time
	/[\p{Extended_Pictographic}\p{Emoji_Modifier}\p{Regional_Indicator}\uFE0F\u20E3]/u.test(
		ch,
	);

/** Letters and marks of scripts that use joiners and zero-width breaks. */
const isComplexScript = (ch: string) =>
	/[\p{L}\p{M}]/u.test(ch) &&
	!/[\p{Script=Latin}\p{Script=Common}\p{Script=Inherited}]/u.test(ch);

/**
 * True when an invisible character is plausibly part of the text around it.
 * Emoji are never identifier characters, so a joiner between them is safe
 * anywhere. In prose a neighbouring Persian, Indic or Thai letter is enough.
 * In code the character must sit between two such letters, where joiners
 * visibly change the shaping, so it cannot silently end an identifier; this
 * holds whatever the lexer thinks, so it never depends on its guesses.
 */
export const legitimateInvisible = (
	cp: number,
	prev: string,
	next: string,
	context: "prose" | "code" | "comment",
) => {
	if (cp === 0x200d && (isEmojiPart(prev) || isEmojiPart(next))) return true;
	// `**\u200B/` keeps a glob from closing a block comment.
	if (cp === 0x200b && context === "comment" && prev === "*" && next === "/")
		return true;
	const near = (test: (ch: string) => boolean) =>
		context === "prose" ? test(prev) || test(next) : test(prev) && test(next);
	switch (cp) {
		case 0x200b:
		case 0x200c:
		case 0x200d:
		case 0x2060:
		case 0x034f: // grapheme joiner
		case 0x17b4: // Khmer inherent vowels
		case 0x17b5:
			return near(isComplexScript);
		case 0x180b:
		case 0x180c:
		case 0x180d:
		case 0x180e:
		case 0x180f:
			return near((ch) => /\p{Script=Mongolian}/u.test(ch));
		default:
			return false;
	}
};

/** Escapes characters that render invisibly or reorder text. */
export const escapeHidden = (s: string): string =>
	s.replace(HIDDEN, (run) => {
		const chars = [...run];
		// Long tag or selector payloads are decoded in the message instead.
		if (chars.length <= 6) return chars.map(escapeChar).join("");
		return `${chars.slice(0, 3).map(escapeChar).join("")}...(+${chars.length - 3} hidden)`;
	});

export const escapeChar = (ch: string): string => {
	const cp = ch.codePointAt(0) ?? 0;
	const hex = cp.toString(16).toUpperCase();
	return cp > 0xffff ? `\\u{${hex}}` : `\\u${hex.padStart(4, "0")}`;
};

const label = (cp: number) =>
	`${NAMES.get(cp) ?? "CHARACTER"} (U+${cp.toString(16).toUpperCase().padStart(4, "0")})`;

/** Hidden payloads are decoded only this far, so huge runs stay cheap. */
export const MAX_DECODE = 200;

/** ASCII hidden in tag characters (U+E0020-U+E007E). */
export const decodeTags = (cps: ReadonlyArray<number>): string =>
	cps
		.map((cp) => cp - 0xe0000)
		.filter((c) => c >= 0x20 && c <= 0x7e)
		.map((c) => String.fromCharCode(c))
		.join("");

/** Tag letters of the recommended subdivision flags: England, Scotland, Wales. */
const FLAG_TAGS = new Set(["gbeng", "gbsct", "gbwls"]);

/** A recommended subdivision flag: U+1F3F4, its tag letters, CANCEL TAG. */
export const isFlagSequence = (
	cps: ReadonlyArray<number>,
	before: string,
): boolean =>
	before === "\u{1F3F4}" &&
	cps.length === 6 &&
	cps.at(-1) === 0xe007f &&
	FLAG_TAGS.has(decodeTags(cps.slice(0, -1)));

/**
 * Bytes hidden in variation selectors, one selector per byte (U+FE00-FE0F for
 * 0-15, U+E0100-E01EF for 16-255). Returns printable text or undefined.
 */
export const decodeSelectors = (
	cps: ReadonlyArray<number>,
): string | undefined => {
	const bytes = cps.map((cp) =>
		cp <= 0xfe0f ? cp - 0xfe00 : cp - 0xe0100 + 16,
	);
	const text = new TextDecoder().decode(new Uint8Array(bytes));
	const printable = [...text].filter((c) => /[\x20-\x7E]/.test(c)).length;
	return printable / Math.max(1, [...text].length) >= 0.7 ? text : undefined;
};

export const charList = (cps: Iterable<number>) =>
	[...new Set(cps)].map(label).join(", ");

export const charBefore = (text: string, i: number): string => {
	const low = text.charCodeAt(i - 1);
	return i >= 2 && low >= 0xdc00 && low <= 0xdfff
		? text.slice(i - 2, i)
		: (text[i - 1] ?? "");
};

export const charAt = (text: string, i: number): string =>
	i < text.length ? String.fromCodePoint(text.codePointAt(i) ?? 0) : "";
