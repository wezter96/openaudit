/** Text helpers shared by the Code Health analyzers. */

const isCommentOnly = (line: string) =>
	line.startsWith("//") || /^\/\*.*\*\/$/.test(line);

/**
 * 1 for each (1-based) line that holds code, 0 for blank and comment-only
 * lines. Like a reader skimming the file, it judges a line by how it starts.
 */
export const codeLineMask = (text: string): Uint8Array => {
	const lines = text.split("\n");
	const mask = new Uint8Array(lines.length + 2);
	let inComment = false;
	lines.forEach((raw, i) => {
		let line = raw.trim();
		if (inComment) {
			const end = line.indexOf("*/");
			if (end === -1) return;
			inComment = false;
			line = line.slice(end + 2).trim();
		}
		if (line.startsWith("/*") && !line.includes("*/")) {
			inComment = true;
			return;
		}
		if (line && !isCommentOnly(line)) mask[i + 1] = 1;
	});
	return mask;
};

const COMMENT_LINE = /^(\/\/|\/\*|\*)|\*\/$/;
const DIRECTIVE = /@codescene\(([^)]*)\)/g;
const DISABLED = /disable:\s*"([^"]+)"/g;

/**
 * Smells switched off for the function starting at `start` by a CodeScene
 * directive in the comment right above it: `// @codescene(disable:"Complex
 * Method")`, or `@codescene(disable-all)` for every function smell (`*`).
 */
export const directivesBefore = (
	text: string,
	start: number,
): ReadonlyArray<string> => {
	const lines = text.slice(0, start).split("\n");
	lines.pop();
	const comment: string[] = [];
	for (let i = lines.length - 1; i >= 0; i--) {
		const line = (lines[i] ?? "").trim();
		if (!COMMENT_LINE.test(line)) break;
		comment.push(line);
	}
	const out: string[] = [];
	for (const m of comment.join("\n").matchAll(DIRECTIVE)) {
		const args = m[1] ?? "";
		if (/\bdisable-all\b/.test(args)) out.push("*");
		for (const d of args.matchAll(DISABLED)) out.push(d[1] ?? "");
	}
	return out;
};
