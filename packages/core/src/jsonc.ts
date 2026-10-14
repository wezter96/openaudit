/**
 * Turns JSON with comments and trailing commas (tsconfig, bun.lock,
 * openaudit.config.json) into plain JSON. Newlines inside comments are kept,
 * so positions in a later parse error still point at the right line.
 * Throws a SyntaxError for an unterminated block comment.
 */
export const stripJsonc = (text: string): string => {
	let out = "";
	let comma = false;
	let i = 0;
	const n = text.length;
	while (i < n) {
		const ch = text[i] ?? "";
		const next = text[i + 1];
		if (ch === "/" && next === "/") {
			while (i < n && text[i] !== "\n") i++;
		} else if (ch === "/" && next === "*") {
			const end = text.indexOf("*/", i + 2);
			if (end === -1) throw new SyntaxError("Unterminated block comment");
			out += text.slice(i, end).replace(/[^\n]/g, "");
			i = end + 2;
		} else if (/\s/.test(ch)) {
			out += ch;
			i++;
		} else if (ch === ",") {
			// Held back until the next token shows whether it is trailing.
			if (comma) out += ",";
			comma = true;
			i++;
		} else {
			if (comma && ch !== "}" && ch !== "]") out += ",";
			comma = false;
			if (ch === '"') {
				let j = i + 1;
				while (j < n && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
				out += text.slice(i, j + 1);
				i = j + 1;
			} else {
				out += ch;
				i++;
			}
		}
	}
	return comma ? `${out},` : out;
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
