import type { FindingInput } from "@openaudit/core";

import {
	extOf,
	fullLineAt,
	isCommentLine,
	languageOf,
	lineLocator,
	type SourceFile,
	scrubLine,
	truncate,
} from "./util";

/** A workspace-relative file path. */
export type FilePath = string;
/** The full text of a source file. */
export type SourceText = string;
/** One line of source text. */
export type SourceLine = string;
/** A character offset into a source text. */
export type Offset = number;
/** A 1-based line number. */
export type LineNumber = number;
/** A package name as a manifest or lockfile spells it. */
export type PackageName = string;

/* ------------------------------ file classes ------------------------------ */

const HTML_EXTS = new Set([
	"html",
	"htm",
	"xhtml",
	"ejs",
	"hbs",
	"handlebars",
	"njk",
	"twig",
	"liquid",
	"erb",
	"jinja",
	"jinja2",
	"j2",
	"cshtml",
	"razor",
	"mustache",
	"pug",
	"php",
]);
const STYLE_EXTS = new Set(["css", "scss", "sass", "less", "styl"]);
const CODE_LANGS = new Set(["js", "python", "go", "ruby", "java"]);

export const isHtmlLike = (path: FilePath) => HTML_EXTS.has(extOf(path));
const isStyle = (path: FilePath) => STYLE_EXTS.has(extOf(path));
export const isJs = (path: FilePath) => languageOf(path) === "js";
export const isCode = (path: FilePath) =>
	CODE_LANGS.has(languageOf(path) ?? "");
export const isUiSource = (path: FilePath) =>
	isHtmlLike(path) || isStyle(path) || isJs(path);

/* ------------------------------ PII in evidence ----------------------------- */

const luhn = (digits: SourceText): boolean => {
	let sum = 0;
	for (let i = 0; i < digits.length; i++) {
		let d = Number(digits[digits.length - 1 - i]);
		if (i % 2 === 1) d = d * 2 > 9 ? d * 2 - 9 : d * 2;
		sum += d;
	}
	return sum % 10 === 0;
};

/** Personal-data literals, in the order they are masked. */
const PERSONAL_DATA: ReadonlyArray<{
	re: RegExp;
	label: string;
	keep?: (m: SourceText) => boolean;
}> = [
	{
		re: /[\w.%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g,
		label: "email",
	},
	{
		re: /(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\w.])/g,
		label: "ip",
	},
	{
		re: /(?<![\w:])(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}(?![\w:])|(?<![\w:])(?:[0-9a-f]{1,4}:){1,6}(?::[0-9a-f]{1,4}){1,6}(?![\w:])/gi,
		label: "ip",
		keep: (m) => !/\d/.test(m),
	},
	{
		re: /(?<![\w.-])(?:\d{13,19}|\d{4}(?:[ -]\d{4}){2}[ -]\d{1,7}|\d{4}[ -]\d{6}[ -]\d{5})(?![\w.-])/g,
		label: "card",
		keep: (m) => !luhn(m.replace(/\D/g, "")),
	},
	{ re: /(?<![\w-])\d{3}-\d{2}-\d{4}(?![\w-])/g, label: "ssn" },
	{
		re: /(?<![\w.+])(?:\+\d{1,3}[ .-]?)?(?:\(\d{1,4}\)[ .-]?)?\d{2,4}(?:[ .-]\d{2,4}){1,3}(?![\w.])|\+\d{8,15}\b/g,
		label: "phone",
		keep: (m) =>
			m.replace(/\D/g, "").length < 9 || /^\d{4}-\d{2}-\d{2}\b/.test(m),
	},
];

/**
 * Replaces personal-data literals (emails, IP addresses, card-like numbers,
 * SSNs, phone numbers) in quoted source with a placeholder naming the kind,
 * so shared reports point at code without repeating anyone's data.
 */
export const maskPersonalData = (line: SourceLine): string =>
	PERSONAL_DATA.reduce(
		(out, { re, label, keep }) =>
			out.replace(re, (m) => (keep?.(m) ? m : `[${label}]`)),
		line,
	);

/** A source line as evidence: credentials and personal data masked. */
export const evidenceOf = (line: SourceLine) =>
	truncate(maskPersonalData(scrubLine(line)));

/* -------------------------------- scanning -------------------------------- */

export const finding = (
	f: Omit<FindingInput, "category"> & { category?: FindingInput["category"] },
): FindingInput => ({ category: "privacy", ...f });

/** A file being scanned, with its line lookup. */
export interface FileScan {
	readonly path: FilePath;
	readonly text: SourceText;
	readonly lineOf: (index: Offset) => LineNumber;
}

export const fileScan = (file: SourceFile): FileScan => ({
	path: file.path,
	text: file.text,
	lineOf: lineLocator(file.text),
});

/** A regex match on a line that is not a comment. */
export interface CodeSite {
	readonly match: RegExpExecArray;
	readonly index: Offset;
	readonly line: SourceLine;
}

export const codeSites = (text: SourceText, re: RegExp): CodeSite[] =>
	[...text.matchAll(re)].flatMap((match) => {
		const index = match.index ?? 0;
		const line = fullLineAt(text, index);
		return isCommentLine(line) ? [] : [{ match, index, line }];
	});

/** Whether an optional context pattern is absent or found in `text`. */
export const contextMatches = (
	needs: RegExp | undefined,
	text: SourceText,
): boolean => needs === undefined || needs.test(text);
