import { truncate } from "../util";

/** Cyrillic and Greek letters that render like a Latin letter. */
const LATIN_LOOKALIKE: Readonly<Record<string, string>> = {
	"\u0430": "a",
	"\u0435": "e",
	"\u043E": "o",
	"\u0440": "p",
	"\u0441": "c",
	"\u0443": "y",
	"\u0445": "x",
	"\u0455": "s",
	"\u0456": "i",
	"\u0458": "j",
	"\u0501": "d",
	"\u04BB": "h",
	"\u051B": "q",
	"\u051D": "w",
	"\u04CF": "l",
	"\u04AF": "y",
	"\u0410": "A",
	"\u0412": "B",
	"\u0415": "E",
	"\u041A": "K",
	"\u041C": "M",
	"\u041D": "H",
	"\u041E": "O",
	"\u0420": "P",
	"\u0421": "C",
	"\u0422": "T",
	"\u0425": "X",
	"\u0406": "I",
	"\u0408": "J",
	"\u0405": "S",
	"\u04AE": "Y",
	"\u051A": "Q",
	"\u051C": "W",
	"\u0391": "A",
	"\u0392": "B",
	"\u0395": "E",
	"\u0396": "Z",
	"\u0397": "H",
	"\u0399": "I",
	"\u039A": "K",
	"\u039C": "M",
	"\u039D": "N",
	"\u039F": "O",
	"\u03A1": "P",
	"\u03A4": "T",
	"\u03A5": "Y",
	"\u03A7": "X",
	"\u03BF": "o",
	"\u03BD": "v",
	"\u03C1": "p",
};

const GREEK_OR_CYRILLIC = /[\u0370-\u03FF\u0400-\u052F]/g;
const isGreekOrCyrillic = (ch: string | undefined) =>
	ch !== undefined && /[\u0370-\u03FF\u0400-\u052F]/.test(ch);
const ID_PART = /[\p{ID_Continue}$\u200C\u200D]/u;
const isLatinLetter = (ch: string | undefined) =>
	ch !== undefined && /\p{Script=Latin}/u.test(ch) && /\p{L}/u.test(ch);

interface Homoglyph {
	readonly start: number;
	readonly end: number;
	readonly lookalike: string;
	readonly mixed: boolean;
}

/** The identifier around `at`, reaching back no further than `from`. */
const identifierAround = (text: string, at: number, from: number) => {
	let start = at;
	while (start > from && ID_PART.test(text[start - 1] ?? "")) start--;
	let end = at + 1;
	while (end < text.length && ID_PART.test(text[end] ?? "")) end++;
	return { start, end };
};

/** End of the run of Cyrillic/Greek letters starting at `i`. */
const runEnd = (chars: ReadonlyArray<string>, i: number) => {
	let j = i;
	while (j < chars.length && isGreekOrCyrillic(chars[j])) j++;
	return j;
};

const isLookalikeRun = (run: ReadonlyArray<string>) =>
	run.every((c) => LATIN_LOOKALIKE[c] !== undefined);

const touchesLatin = (chars: ReadonlyArray<string>, i: number, j: number) =>
	isLatinLetter(chars[i - 1]) || isLatinLetter(chars[j]);

/** A run of look-alikes glued to Latin letters (`sayHello` with a Cyrillic H). */
const hasGluedLookalikes = (chars: ReadonlyArray<string>): boolean => {
	for (let i = 0; i < chars.length; i++) {
		if (!isGreekOrCyrillic(chars[i])) continue;
		const j = runEnd(chars, i);
		if (isLookalikeRun(chars.slice(i, j)) && touchesLatin(chars, i, j))
			return true;
		i = j;
	}
	return false;
};

/** Passes for a Latin identifier of at least two letters. */
const passesForLatin = (chars: ReadonlyArray<string>, lookalike: string) =>
	/^[\w$]+$/.test(lookalike) &&
	chars.filter((c) => /\p{L}/u.test(c)).length >= 2;

/** Whether a word appears as an ASCII identifier, indexing the text once. */
const asciiIdentifiersOf = (text: string) => {
	let identifiers: Set<string> | undefined;
	return (word: string) => {
		identifiers ??= new Set(text.match(/[A-Za-z_$][\w$]*/g) ?? []);
		return identifiers.has(word);
	};
};

const homoglyphOf = (
	identifier: string,
	hasTwin: (word: string) => boolean,
): Pick<Homoglyph, "lookalike" | "mixed"> | undefined => {
	const chars = Array.from(identifier);
	const hasLatin = chars.some(isLatinLetter);
	const mixed = hasLatin && hasGluedLookalikes(chars);
	const lookalike = chars.map((c) => LATIN_LOOKALIKE[c] ?? c).join("");
	if (mixed) return { lookalike: truncate(lookalike, 80), mixed };
	// An identifier made only of look-alikes whose Latin twin is in the file.
	if (hasLatin || !passesForLatin(chars, lookalike)) return undefined;
	if (!hasTwin(lookalike)) return undefined;
	return { lookalike: truncate(lookalike, 80), mixed };
};

/**
 * Identifiers that pass for Latin: a run of Cyrillic/Greek look-alikes glued
 * to Latin letters (`sayHello` with a Cyrillic H), or an identifier made only
 * of look-alikes whose Latin twin appears in the same file (a Cyrillic `cop`
 * next to the Latin one). A cheap stand-in for UTS #39 confusable detection.
 * Each identifier is visited once and the twins come from one pass over the
 * file, so the work is linear in the text.
 */
export const findHomoglyphs = (
	text: string,
	isCode: (index: number) => boolean,
): Homoglyph[] => {
	const out: Homoglyph[] = [];
	const hasTwin = asciiIdentifiersOf(text);
	let lastEnd = 0;
	for (const m of text.matchAll(GREEK_OR_CYRILLIC)) {
		const at = m.index ?? 0;
		if (at < lastEnd) continue; // inside an identifier already checked
		const { start, end } = identifierAround(text, at, lastEnd);
		lastEnd = end;
		if (!isCode(start)) continue;
		const found = homoglyphOf(text.slice(start, end), hasTwin);
		if (found) out.push({ start, end, ...found });
	}
	return out;
};
