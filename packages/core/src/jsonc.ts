/**
 * Turns JSON with comments and trailing commas (tsconfig, bun.lock,
 * openaudit.config.json) into plain JSON. Newlines inside comments are kept,
 * so positions in a later parse error still point at the right line.
 * Throws a SyntaxError for an unterminated block comment.
 */
export const stripJsonc = (text: string): string => {
	const s: Strip = { text, out: "", comma: false, i: 0 };
	while (s.i < text.length) step(s);
	return s.comma ? `${s.out},` : s.out;
};

/** Scanner state: output so far, a held-back comma, and the read position. */
interface Strip {
	readonly text: string;
	out: string;
	comma: boolean;
	i: number;
}

const CLOSERS = new Set(["}", "]"]);

const step = (s: Strip): void => {
	const ch = s.text[s.i] ?? "";
	const pair = ch + (s.text[s.i + 1] ?? "");
	if (pair === "//") s.i = lineEnd(s.text, s.i);
	else if (pair === "/*") blockComment(s);
	else if (/\s/.test(ch)) {
		s.out += ch;
		s.i++;
	} else if (ch === ",") holdComma(s);
	else token(s, ch);
};

const lineEnd = (text: string, from: number): number => {
	const end = text.indexOf("\n", from);
	return end === -1 ? text.length : end;
};

const blockComment = (s: Strip): void => {
	const end = s.text.indexOf("*/", s.i + 2);
	if (end === -1) throw new SyntaxError("Unterminated block comment");
	s.out += s.text.slice(s.i, end).replace(/[^\n]/g, "");
	s.i = end + 2;
};

// Held back until the next token shows whether it is trailing.
const holdComma = (s: Strip): void => {
	if (s.comma) s.out += ",";
	s.comma = true;
	s.i++;
};

const token = (s: Strip, ch: string): void => {
	if (s.comma && !CLOSERS.has(ch)) s.out += ",";
	s.comma = false;
	const end = ch === '"' ? stringEnd(s.text, s.i) : s.i + 1;
	s.out += s.text.slice(s.i, end);
	s.i = end;
};

/** Index just past the closing quote of the string starting at `start`. */
const stringEnd = (text: string, start: number): number => {
	let j = start + 1;
	while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
	return j + 1;
};

/**
 * Parses JSON with comments and trailing commas. Returns undefined when the
 * text is not valid JSONC.
 */
export const parseJsonc = (text: string): unknown => {
	try {
		return JSON.parse(stripJsonc(text));
	} catch {
		return undefined;
	}
};
