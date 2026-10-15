/*
 * Which parts of a Markdown file a reviewer does not see in the rendered
 * view (CommonMark/GFM rendered to HTML, then shown by a browser), while an
 * agent reads every byte. Where rendering is ambiguous (unclosed or
 * unbalanced markup) the region counts as hidden, so it is checked rather
 * than skipped. Every scan is linear in the input.
 */

/** Markdown source, an offset into it, and the text of one of its lines. */
type Markdown = string;
type Offset = number;
type LineText = string;

export interface Region {
	readonly start: number;
	readonly end: number;
	readonly kind: string;
}

/** Whether `index` falls in one of `regions`, which are sorted and disjoint. */
export const within = (regions: ReadonlyArray<Region>, index: Offset) =>
	containing(regions, index) !== undefined;

const containing = (
	regions: ReadonlyArray<Region>,
	index: Offset,
): Region | undefined => {
	let lo = 0;
	let hi = regions.length - 1;
	while (lo <= hi) {
		const mid = (lo + hi) >> 1;
		const r = regions[mid] as Region;
		if (index < r.start) hi = mid - 1;
		else if (index >= r.end) lo = mid + 1;
		else return r;
	}
	return undefined;
};

/** First element of the sorted `values` greater than `x`, or undefined. */
const firstAfter = (values: ReadonlyArray<number>, x: Offset) => {
	let lo = 0;
	let hi = values.length;
	while (lo < hi) {
		const mid = (lo + hi) >> 1;
		if ((values[mid] ?? 0) <= x) lo = mid + 1;
		else hi = mid;
	}
	return values[lo];
};

interface Line {
	readonly start: number;
	readonly end: number;
	readonly text: string;
}

const linesOf = (text: Markdown): Line[] => {
	const out: Line[] = [];
	let start = 0;
	for (const line of text.split("\n")) {
		out.push({ start, end: start + line.length, text: line });
		start += line.length + 1;
	}
	return out;
};

const indentOf = (line: LineText) => {
	let width = 0;
	for (const c of line) {
		if (c === " ") width++;
		else if (c === "\t") width += 4 - (width % 4);
		else break;
	}
	return width;
};

const isBlank = (line: LineText) => line.trim() === "";

const LIST_ITEM = /^ {0,3}(?:[-*+]|\d{1,9}[.)])(?:[ \t]|$)/;
const FENCE = /^ {0,3}(`{3,}|~{3,})/;

interface Fence {
	readonly start: number;
	readonly marker: string;
}

/** Code block state while walking the lines. */
interface CodeScan {
	readonly blocks: Region[];
	fence?: Fence;
	prevBlank: boolean;
	inList: boolean;
	indented?: { start: number; end: number };
}

const closeIndented = (scan: CodeScan) => {
	if (scan.indented) scan.blocks.push({ ...scan.indented, kind: "code" });
	scan.indented = undefined;
};

/** A fence closes on a marker of the same character that is at least as long. */
const closesFence = (fence: Fence, marker: string) =>
	marker[0] === fence.marker[0] && marker.length >= fence.marker.length;

const fencedLine = (scan: CodeScan, fence: Fence, line: Line) => {
	const marker = FENCE.exec(line.text)?.[1];
	if (marker && closesFence(fence, marker)) {
		scan.blocks.push({ start: fence.start, end: line.end, kind: "code" });
		scan.fence = undefined;
	}
};

/** Indented code needs a blank line or more indented code before it, outside lists. */
const continuesIndented = (scan: CodeScan) =>
	!scan.inList && (scan.prevBlank || scan.indented !== undefined);

const trackList = (scan: CodeScan, line: Line, indent: number) => {
	if (LIST_ITEM.test(line.text)) scan.inList = true;
	else if (indent === 0) scan.inList = false;
};

const proseLine = (scan: CodeScan, line: Line) => {
	const indent = indentOf(line.text);
	if (indent >= 4 && continuesIndented(scan)) {
		scan.indented = {
			start: scan.indented?.start ?? line.start,
			end: line.end,
		};
	} else {
		closeIndented(scan);
		trackList(scan, line, indent);
	}
	scan.prevBlank = false;
};

const codeLine = (scan: CodeScan, line: Line) => {
	if (scan.fence) return fencedLine(scan, scan.fence, line);
	const m = FENCE.exec(line.text);
	if (m) {
		closeIndented(scan);
		scan.fence = { start: line.start, marker: m[1] ?? "" };
		scan.prevBlank = false;
	} else if (isBlank(line.text)) scan.prevBlank = true;
	else proseLine(scan, line);
};

/**
 * Code blocks, whose content renders as visible text: fenced blocks, and
 * indented blocks after a blank line outside lists (four-space list
 * content is not code, so it is left to the hidden-region checks).
 */
const codeBlocks = (lines: ReadonlyArray<Line>, end: Offset): Region[] => {
	const scan: CodeScan = { blocks: [], prevBlank: true, inList: false };
	for (const line of lines) codeLine(scan, line);
	closeIndented(scan);
	if (scan.fence)
		scan.blocks.push({ start: scan.fence.start, end, kind: "code" });
	return scan.blocks;
};

interface Run {
	readonly start: number;
	readonly length: number;
}

/** Inline scan state: backtick runs, and what was found so far. */
interface InlineScan {
	readonly text: Markdown;
	readonly blocks: ReadonlyArray<Region>;
	readonly breaks: ReadonlyArray<number>;
	readonly runs: ReadonlyArray<Run>;
	/** Next run of exactly the same length, for O(1) closer lookup. */
	readonly next: ReadonlyArray<number | undefined>;
	readonly comments: Region[];
	readonly spans: Region[];
	/** Index of the first run that does not start before the scan position. */
	run: number;
}

const nextOfSameLength = (runs: ReadonlyArray<Run>) => {
	const next: Array<number | undefined> = [];
	const lastOfLength = new Map<number, number>();
	for (let k = runs.length - 1; k >= 0; k--) {
		const len = runs[k]?.length ?? 0;
		next[k] = lastOfLength.get(len);
		lastOfLength.set(len, k);
	}
	return next;
};

const COMMENT_CLOSE = /--!?>/g;

/** Where the content of the HTML comment opening at `at` ends, and where the comment ends. */
const commentEnds = (text: Markdown, at: Offset): [number, number] => {
	if (text.startsWith("<!-->", at)) return [at + 4, at + 5];
	if (text.startsWith("<!--->", at)) return [at + 4, at + 6];
	COMMENT_CLOSE.lastIndex = at + 4;
	const c = COMMENT_CLOSE.exec(text);
	return c ? [c.index, c.index + c[0].length] : [text.length, text.length];
};

const comment = (scan: InlineScan, at: Offset) => {
	const [contentEnd, after] = commentEnds(scan.text, at);
	scan.comments.push({
		start: at + 4,
		end: contentEnd,
		kind: "an HTML comment",
	});
	return after;
};

/** The backtick run starting at `at`, if `at` starts one. */
const runAt = (scan: InlineScan, at: Offset) => {
	while (scan.run < scan.runs.length && (scan.runs[scan.run]?.start ?? 0) < at)
		scan.run++;
	const open = scan.runs[scan.run];
	return open?.start === at ? open : undefined;
};

/** The next run as long as the current one that starts at or after `pos`. */
const closingRun = (scan: InlineScan, pos: Offset) => {
	let j = scan.next[scan.run];
	while (j !== undefined && (scan.runs[j]?.start ?? 0) < pos) j = scan.next[j];
	return j === undefined ? undefined : scan.runs[j];
};

/** Takes a code span opening at `at` and says where scanning resumes. */
const codeSpan = (scan: InlineScan, at: Offset, pos: Offset) => {
	const open = runAt(scan, at);
	if (!open) return at + 1;
	const limit = firstAfter(scan.breaks, at) ?? scan.text.length;
	const close = closingRun(scan, pos);
	if (close && close.start < limit) {
		scan.spans.push({
			start: at,
			end: close.start + close.length,
			kind: "code",
		});
		return close.start + close.length;
	}
	return at + open.length;
};

const inlineStep = (scan: InlineScan, m: RegExpExecArray, pos: Offset) => {
	const block = containing(scan.blocks, m.index);
	if (block) return block.end;
	if (m[0] === "<!--") return comment(scan, m.index);
	return codeSpan(scan, m.index, pos);
};

/**
 * Left-to-right inline scan outside code blocks, as CommonMark does it: an
 * HTML comment or a code span, whichever starts first, takes the text up
 * to its end. Comments end at `-->`, or `--!>` as browsers end them;
 * `<!-->` and `<!--->` are empty. An unclosed comment hides the rest.
 */
const inlineScan = (
	text: Markdown,
	blocks: ReadonlyArray<Region>,
	breaks: ReadonlyArray<number>,
) => {
	const runs = [...text.matchAll(/`+/g)].map((m) => ({
		start: m.index ?? 0,
		length: m[0].length,
	}));
	const scan: InlineScan = {
		text,
		blocks,
		breaks,
		runs,
		next: nextOfSameLength(runs),
		comments: [],
		spans: [],
		run: 0,
	};
	const opener = /<!--|`/g;
	let pos = 0;
	for (;;) {
		opener.lastIndex = pos;
		const m = opener.exec(text);
		if (!m) break;
		pos = inlineStep(scan, m, pos);
	}
	return { comments: scan.comments, spans: scan.spans };
};

const DETAILS = "a collapsed <details> block";
const HIDING_ELEMENTS = new Set(["template", "noscript", "script", "style"]);
const HIDING_ATTRIBUTES = [
	/\shidden(?=[\s=/]|$)/i,
	/display\s*:\s*none|visibility\s*:\s*hidden/i,
];
const OPEN_ATTRIBUTE = /\sopen(?=[\s=/]|$)/i;

/** The text and its lines, with the code (blocks and spans) that renders visibly. */
interface Doc {
	readonly text: Markdown;
	readonly lines: ReadonlyArray<Line>;
	readonly code: ReadonlyArray<Region>;
}

/** Code spans cannot cross a blank line or a code block. */
const breaksOf = (lines: ReadonlyArray<Line>, blocks: ReadonlyArray<Region>) =>
	[
		...lines.filter((l) => isBlank(l.text)).map((l) => l.start),
		...blocks.map((b) => b.start),
	].sort((a, b) => a - b);

/** The body of a collapsed <details> after its <summary>, up to its close. */
const detailsBody = (
	text: Markdown,
	bodyStart: Offset,
	closes: ReadonlyArray<number>,
): Region => {
	// Offsets are integers, so the first close after bodyStart - 1 is the
	// first one at or after bodyStart.
	const end = firstAfter(closes, bodyStart - 1) ?? text.length;
	const body = text.slice(bodyStart, end);
	const summaryEnd = body.search(/<\/summary\s*>/i);
	const skipSummary = summaryEnd === -1 ? 0 : body.indexOf(">", summaryEnd) + 1;
	return { start: bodyStart + skipSummary, end, kind: DETAILS };
};

/** <details> without `open` is collapsed; an unclosed one runs to the end. */
const collapsedDetails = ({ text, code }: Doc): Region[] => {
	const closes = [...text.matchAll(/<\/details\s*>/gi)].map((m) => m.index);
	const regions: Region[] = [];
	let covered = 0;
	for (const m of text.matchAll(/<details\b([^>]{0,1000})>/gi)) {
		const open = m.index;
		if (open < covered || within(code, open)) continue;
		if (OPEN_ATTRIBUTE.test(m[1] ?? "")) continue;
		const region = detailsBody(text, open + m[0].length, closes);
		covered = region.end;
		regions.push(region);
	}
	return regions;
};

const isSkippedElement = (name: string, attrs: string) =>
	name === "details" || attrs.endsWith("/");

const hides = (name: string, attrs: string) =>
	HIDING_ELEMENTS.has(name) || HIDING_ATTRIBUTES.some((r) => r.test(attrs));

/** The body of a hidden element up to its closing tag, or the end. */
const elementBody = (
	text: Markdown,
	name: string,
	bodyStart: Offset,
): Region => {
	// name matched [a-z][\w-]{0,30} above, so it is literal in a pattern.
	// nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
	const closing = new RegExp(`</${name}\\s*>`, "gi");
	closing.lastIndex = bodyStart;
	const end = closing.exec(text)?.index ?? text.length;
	return { start: bodyStart, end, kind: `a hidden <${name}> element` };
};

/**
 * Elements a renderer hides: the hidden attribute, display:none or
 * visibility:hidden, and template/noscript/script/style. An unclosed one
 * hides the rest of the document.
 */
const hiddenElements = ({ text, code }: Doc): Region[] => {
	const regions: Region[] = [];
	let hiddenUntil = 0;
	for (const m of text.matchAll(/<([a-z][\w-]{0,30})\b([^>]{0,1000})>/gi)) {
		const name = (m[1] ?? "").toLowerCase();
		const attrs = m[2] ?? "";
		const open = m.index;
		if (open < hiddenUntil || isSkippedElement(name, attrs)) continue;
		if (!hides(name, attrs) || within(code, open)) continue;
		const region = elementBody(text, name, open + m[0].length);
		hiddenUntil = region.end;
		regions.push(region);
	}
	return regions;
};

const FOOTNOTE_REF = /\[\^([^\]\s]{1,100})\](?!:)/g;
const FOOTNOTE_DEF = /^ {0,3}\[\^([^\]\s]{1,100})\]:/;
const LINK_DEF = /^ {0,3}\[((?:[^\]\\\n]|\\.){1,999})\]:[ \t]*(\S*)[ \t]*(.*)$/;
const TITLE_CLOSERS = new Map([
	['"', '"'],
	["'", "'"],
	["(", ")"],
]);

/** Whether the line after `last` continues a footnote: indented, or blank before an indented line. */
const continuesFootnote = (lines: ReadonlyArray<Line>, last: number) => {
	const next = lines[last + 1]?.text;
	if (next === undefined) return false;
	if (!isBlank(next)) return indentOf(next) >= 4;
	const after = lines[last + 2]?.text ?? "";
	return indentOf(after) >= 4 && !isBlank(after);
};

/** The last line of the footnote definition on line `k`. */
const footnoteEnd = (lines: ReadonlyArray<Line>, k: number) => {
	let last = k;
	while (continuesFootnote(lines, last)) last++;
	return last;
};

/** Whether `s` starts a link title that it does not close. */
const opensTitle = (s: string) => {
	const t = s.trim();
	const close = TITLE_CLOSERS.get(t[0] ?? "");
	return close !== undefined && !t.slice(1).includes(close);
};

/** Where a link title may still run, while walking the lines after a definition. */
interface TitleScan {
	readonly lines: ReadonlyArray<Line>;
	last: number;
	unclosed: boolean;
}

const titleOnNextLine = (scan: TitleScan) => {
	if (!/^\s*["'(]/.test(scan.lines[scan.last + 1]?.text ?? "")) return;
	scan.last++;
	scan.unclosed = opensTitle(scan.lines[scan.last]?.text ?? "");
};

const hasNextText = ({ lines, last }: TitleScan) =>
	Boolean(lines[last + 1]?.text.trim());

/** An unclosed title continues until it closes or a blank line. */
const continueTitle = (scan: TitleScan) => {
	while (scan.unclosed && hasNextText(scan)) {
		scan.last++;
		if (/["')]/.test(scan.lines[scan.last]?.text ?? "")) scan.unclosed = false;
	}
};

/**
 * The last line of the link reference definition on line `k`: the
 * destination may be on the next line, then a title on the same or next
 * line.
 */
const linkDefEnd = (
	lines: ReadonlyArray<Line>,
	k: number,
	def: RegExpExecArray,
) => {
	const last = !def[2] && k + 1 < lines.length ? k + 1 : k;
	const rest =
		last === k
			? (def[3] ?? "")
			: (lines[last]?.text ?? "").trim().split(/\s+/).slice(1).join(" ");
	const scan: TitleScan = { lines, last, unclosed: opensTitle(rest) };
	if (!rest.trim()) titleOnNextLine(scan);
	continueTitle(scan);
	return scan.last;
};

interface Definition {
	readonly last: number;
	readonly kind: string;
}

/** The never-rendered definition starting on line `k`, if any. */
const definitionAt = (
	lines: ReadonlyArray<Line>,
	k: number,
	referenced: ReadonlySet<string | undefined>,
): Definition | undefined => {
	const text = (lines[k] as Line).text;
	const footnote = FOOTNOTE_DEF.exec(text);
	if (footnote)
		return referenced.has(footnote[1])
			? undefined
			: {
					last: footnoteEnd(lines, k),
					kind: "an unreferenced footnote definition",
				};
	const def = LINK_DEF.exec(text);
	return def
		? {
				last: linkDefEnd(lines, k, def),
				kind: "a Markdown link reference definition",
			}
		: undefined;
};

/**
 * Link reference definitions never render, nor do footnote definitions
 * nothing refers to. A title may continue on following lines until it
 * closes or a blank line; a footnote continues on indented lines.
 */
const definitions = ({ text, lines, code }: Doc): Region[] => {
	const referenced = new Set([...text.matchAll(FOOTNOTE_REF)].map((m) => m[1]));
	const regions: Region[] = [];
	for (let k = 0; k < lines.length; k++) {
		const line = lines[k] as Line;
		if (within(code, line.start)) continue;
		const def = definitionAt(lines, k, referenced);
		if (!def) continue;
		regions.push({
			start: line.start + line.text.indexOf("["),
			end: lines[def.last]?.end ?? line.end,
			kind: def.kind,
		});
		k = def.last;
	}
	return regions;
};

/** Parts of a Markdown file that the rendered view hides from a reviewer. */
export const hiddenRegions = (text: Markdown): Region[] => {
	const lines = linesOf(text);
	const blocks = codeBlocks(lines, text.length);
	const { comments, spans } = inlineScan(text, blocks, breaksOf(lines, blocks));
	const doc: Doc = {
		text,
		lines,
		code: [...blocks, ...spans].sort((a, b) => a.start - b.start),
	};
	const regions = [
		...comments,
		...collapsedDetails(doc),
		...hiddenElements(doc),
		...definitions(doc),
	];
	return regions.filter((r) => !within(doc.code, r.start));
};

export { DETAILS };
