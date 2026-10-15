/** Small helpers for drawing badges and cards as text. */
import type { Grade } from "./api";
import type { UnixSeconds } from "./view";

/** Text that goes into SVG or HTML markup. */
export type Text = string;

const ENTITIES: Record<string, string> = {
	"&": "&amp;",
	"<": "&lt;",
	">": "&gt;",
	'"': "&quot;",
	"'": "&#39;",
};

/**
 * C0 and C1 controls (but tab and newline), bidi embeddings, overrides and
 * isolates, and other invisible format characters, as code point ranges.
 * They're not valid XML, or they let text reorder what's around it.
 */
const UNSAFE: ReadonlyArray<readonly [number, number]> = [
	[0x00, 0x08],
	[0x0b, 0x0c],
	[0x0e, 0x1f],
	[0x7f, 0x9f],
	[0x200b, 0x200f],
	[0x2028, 0x202e],
	[0x2060, 0x206f],
	[0xfeff, 0xfeff],
	[0xfff9, 0xfffb],
];

const isUnsafe = (c: string) => {
	const code = c.codePointAt(0) ?? 0;
	return UNSAFE.some(([low, high]) => code >= low && code <= high);
};

const neutralise = (text: Text) =>
	[...text].map((c) => (isUnsafe(c) ? "\ufffd" : c)).join("");

/**
 * Escapes text for an XML or HTML element or a quoted attribute, and
 * replaces unsafe invisible characters with U+FFFD.
 */
export const escapeXml = (text: Text): Text =>
	neutralise(String(text)).replace(/[&<>"']/g, (c) => ENTITIES[c] ?? c);

const NARROW = /[ .,:;|!'ilIjft1()[\]]/;
const WIDE = /[mwMW@%]/;
const UPPER = /[A-Z0-9]/;

const charWidth = (c: string) => {
	if (NARROW.test(c)) return 3.9;
	if (WIDE.test(c)) return 10.5;
	return UPPER.test(c) ? 7.5 : 6.6;
};

/** Approximate width in px of Verdana 11px text, as shields-style badges use. */
export const textWidth = (text: Text): number =>
	Math.ceil([...text].reduce((sum, c) => sum + charWidth(c), 0));

const MONTHS = [
	"Jan",
	"Feb",
	"Mar",
	"Apr",
	"May",
	"Jun",
	"Jul",
	"Aug",
	"Sep",
	"Oct",
	"Nov",
	"Dec",
];

/** `15 Oct 2026`, in UTC. */
export const formatDate = (at: UnixSeconds): Text => {
	const d = new Date(at * 1000);
	return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
};

export const GREY = "#9f9f9f";
export const LABEL = "#555";
export const FAILED = "#e05d44";

const GRADE_COLOURS: Record<Grade, string> = {
	A: "#4c1",
	B: "#97ca00",
	C: "#dfb317",
	D: "#fe7d37",
	F: "#e05d44",
};

export const gradeColour = (grade: Grade) => GRADE_COLOURS[grade] ?? GREY;

/** Cuts text to `max` characters, with an ellipsis when cut. */
export const truncate = (text: Text, max: number): Text =>
	text.length > max ? `${text.slice(0, max - 1)}…` : text;
