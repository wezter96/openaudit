import type {
	Indent,
	LineNumber,
	Offset,
	SourceLine,
	SourceText,
} from "./quality-types";

const CONTROL_KEYWORD =
	/\b(?:if|else|for|foreach|while|switch|try|catch|finally|do|case|select|match|unless|until)\b/;

const PYTHON_CONTROL =
	/^\s*(?:if|elif|else|for|async\s+for|while|with|async\s+with|try|except|finally|match|case)\b.*:\s*(?:#.*)?$/;
const PYTHON_DEFINITION = /^\s*(?:def|async\s+def|class)\b.*:\s*(?:#.*)?$/;

const stripCode = (line: SourceLine) =>
	line
		.replace(/\\./g, "")
		.replace(/"[^"]*"|'[^']*'|`[^`]*`/g, '""')
		.replace(/\/\/.*$/, "");

export interface Nesting {
	readonly depth: number;
	readonly line: number;
}

/** Whether the `{` at `index` opens a control-flow block (keyword before it, or on the previous line). */
const isControlBrace = (
	code: SourceLine,
	index: Offset,
	prevCode: SourceLine,
) => {
	const before = code.slice(0, index);
	return (
		CONTROL_KEYWORD.test(before) ||
		(before.trim() === "" && CONTROL_KEYWORD.test(prevCode))
	);
};

interface BraceScan {
	/** One entry per open brace: whether it opened a control-flow block. */
	readonly stack: boolean[];
	controls: number;
	max: Nesting;
	inComment: boolean;
	prevCode: SourceLine;
}

/** Code of one line without comments, or undefined while inside a block comment. */
const stripComments = (
	line: SourceLine,
	scan: BraceScan,
): SourceLine | undefined => {
	let code = stripCode(line);
	if (scan.inComment) {
		const end = code.indexOf("*/");
		if (end === -1) return undefined;
		code = code.slice(end + 2);
		scan.inComment = false;
	}
	code = code.replace(/\/\*.*?\*\//g, "");
	const open = code.indexOf("/*");
	if (open !== -1) {
		code = code.slice(0, open);
		scan.inComment = true;
	}
	return code;
};

const closeBrace = (scan: BraceScan) => {
	if (scan.stack.pop()) scan.controls--;
};

const openBrace = (
	scan: BraceScan,
	code: SourceLine,
	index: Offset,
	line: LineNumber,
) => {
	const isControl = isControlBrace(code, index, scan.prevCode);
	scan.stack.push(isControl);
	if (!isControl) return;
	scan.controls++;
	if (scan.controls > scan.max.depth) scan.max = { depth: scan.controls, line };
};

/** Updates the brace stack for the character at `index`. */
const trackBrace = (
	scan: BraceScan,
	code: SourceLine,
	index: Offset,
	line: LineNumber,
) => {
	const ch = code[index];
	if (ch === "}") closeBrace(scan);
	else if (ch === "{") openBrace(scan, code, index, line);
};

const scanBraceLine = (scan: BraceScan, raw: SourceLine, line: LineNumber) => {
	const code = stripComments(raw, scan);
	if (code === undefined) return;
	for (let i = 0; i < code.length; i++) trackBrace(scan, code, i, line);
	if (code.trim()) scan.prevCode = code;
};

/** Deepest control-flow nesting in a brace language (best-effort). */
export const braceNesting = (text: SourceText): Nesting => {
	const scan: BraceScan = {
		stack: [],
		controls: 0,
		max: { depth: 0, line: 0 },
		inComment: false,
		prevCode: "",
	};
	const lines = text.split("\n");
	for (let n = 0; n < lines.length; n++)
		scanBraceLine(scan, lines[n] ?? "", n + 1);
	return scan.max;
};

interface PythonBlock {
	readonly indent: Indent;
	readonly control: boolean;
}

const isPythonCodeLine = (raw: SourceLine) =>
	Boolean(raw.trim()) && !raw.trimStart().startsWith("#");

/** Pops the blocks that a line at `indent` has left. */
const popDedented = (stack: PythonBlock[], indent: Indent) => {
	while (stack.length && (stack[stack.length - 1]?.indent ?? 0) >= indent)
		stack.pop();
};

/** Deepest control-flow nesting in Python (indentation-based). */
export const pythonNesting = (text: SourceText): Nesting => {
	const stack: PythonBlock[] = [];
	let max: Nesting = { depth: 0, line: 0 };
	const lines = text.split("\n");
	for (let n = 0; n < lines.length; n++) {
		const raw = (lines[n] ?? "").replace(/\t/g, "    ");
		if (!isPythonCodeLine(raw)) continue;
		const indent = raw.length - raw.trimStart().length;
		popDedented(stack, indent);
		const control = PYTHON_CONTROL.test(raw);
		if (!control && !PYTHON_DEFINITION.test(raw)) continue;
		stack.push({ indent, control });
		const depth = stack.filter((s) => s.control).length;
		if (depth > max.depth) max = { depth, line: n + 1 };
	}
	return max;
};
