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
	let asciiIdentifiers: Set<string> | undefined;
	let lastEnd = 0;
	for (const m of text.matchAll(GREEK_OR_CYRILLIC)) {
		const at = m.index ?? 0;
		if (at < lastEnd) continue; // inside an identifier already checked
		let start = at;
		while (start > lastEnd && ID_PART.test(text[start - 1] ?? "")) start--;
		let end = at + 1;
		while (end < text.length && ID_PART.test(text[end] ?? "")) end++;
		lastEnd = end;
		if (!isCode(start)) continue;
		const chars = Array.from(text.slice(start, end));
		const hasLatin = chars.some(isLatinLetter);
		let mixed = false;
		for (let i = 0; i < chars.length && hasLatin && !mixed; i++) {
			if (!isGreekOrCyrillic(chars[i])) continue;
			let j = i;
			while (j < chars.length && isGreekOrCyrillic(chars[j])) j++;
			let lookalikes = true;
			for (let k = i; k < j && lookalikes; k++)
				lookalikes = LATIN_LOOKALIKE[chars[k] ?? ""] !== undefined;
			mixed =
				lookalikes && (isLatinLetter(chars[i - 1]) || isLatinLetter(chars[j]));
			i = j;
		}
		const lookalike = chars.map((c) => LATIN_LOOKALIKE[c] ?? c).join("");
		let wholeScript = false;
		if (
			!mixed &&
			!hasLatin &&
			/^[\w$]+$/.test(lookalike) &&
			chars.filter((c) => /\p{L}/u.test(c)).length >= 2
		) {
			asciiIdentifiers ??= new Set(text.match(/[A-Za-z_$][\w$]*/g) ?? []);
			wholeScript = asciiIdentifiers.has(lookalike);
		}
		if (mixed || wholeScript)
			out.push({ start, end, lookalike: truncate(lookalike, 80), mixed });
	}
	return out;
};
