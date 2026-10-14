/*
 * Which parts of a Markdown file a reviewer does not see in the rendered
 * view (CommonMark/GFM rendered to HTML, then shown by a browser), while an
 * agent reads every byte. Where rendering is ambiguous (unclosed or
 * unbalanced markup) the region counts as hidden, so it is checked rather
 * than skipped. Every scan is linear in the input.
 */

export interface Region {
	readonly start: number;
	readonly end: number;
	readonly kind: string;
}

/** Whether `index` falls in one of `regions`, which are sorted and disjoint. */
export const within = (regions: ReadonlyArray<Region>, index: number) =>
	containing(regions, index) !== undefined;

const containing = (
	regions: ReadonlyArray<Region>,
	index: number,
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
const firstAfter = (values: ReadonlyArray<number>, x: number) => {
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

const linesOf = (text: string): Line[] => {
	const out: Line[] = [];
	let start = 0;
	for (const line of text.split("\n")) {
		out.push({ start, end: start + line.length, text: line });
		start += line.length + 1;
	}
	return out;
};

const indentOf = (line: string) => {
	let width = 0;
	for (const c of line) {
		if (c === " ") width++;
		else if (c === "\t") width += 4 - (width % 4);
		else break;
	}
	return width;
};

const LIST_ITEM = /^ {0,3}(?:[-*+]|\d{1,9}[.)])(?:[ \t]|$)/;

/**
 * Code blocks, whose content renders as visible text: fenced blocks, and
 * indented blocks after a blank line outside lists (four-space list
 * content is not code, so it is left to the hidden-region checks).
 */
const codeBlocks = (lines: ReadonlyArray<Line>, end: number): Region[] => {
	const blocks: Region[] = [];
	let fence: { start: number; marker: string } | undefined;
	let prevBlank = true;
	let inList = false;
	let indented: { start: number; end: number } | undefined;
	const closeIndented = () => {
		if (indented) blocks.push({ ...indented, kind: "code" });
		indented = undefined;
	};
	for (const line of lines) {
		const m = /^ {0,3}(`{3,}|~{3,})/.exec(line.text);
		if (fence) {
			const marker = m?.[1];
			if (
				marker &&
				marker[0] === fence.marker[0] &&
				marker.length >= fence.marker.length
			) {
				blocks.push({ start: fence.start, end: line.end, kind: "code" });
				fence = undefined;
			}
			continue;
		}
		if (m) {
			closeIndented();
			fence = { start: line.start, marker: m[1] ?? "" };
			prevBlank = false;
			continue;
		}
		if (line.text.trim() === "") {
			prevBlank = true;
			continue;
		}
		const indent = indentOf(line.text);
		if (indent >= 4 && !inList && (prevBlank || indented)) {
			indented = { start: indented?.start ?? line.start, end: line.end };
		} else {
			closeIndented();
			if (LIST_ITEM.test(line.text)) inList = true;
			else if (indent === 0) inList = false;
		}
		prevBlank = false;
	}
	closeIndented();
	if (fence) blocks.push({ start: fence.start, end, kind: "code" });
	return blocks;
};

/**
 * Left-to-right inline scan outside code blocks, as CommonMark does it: an
 * HTML comment or a code span, whichever starts first, takes the text up
 * to its end. Comments end at `-->`, or `--!>` as browsers end them;
 * `<!-->` and `<!--->` are empty. An unclosed comment hides the rest.
 */
const inlineScan = (
	text: string,
	blocks: ReadonlyArray<Region>,
	breaks: ReadonlyArray<number>,
) => {
	const comments: Region[] = [];
	const spans: Region[] = [];
	const runs = [...text.matchAll(/`+/g)].map((m) => ({
		start: m.index ?? 0,
		length: m[0].length,
	}));
	// Next run of exactly the same length, for O(1) closer lookup.
	const next: Array<number | undefined> = [];
	const lastOfLength = new Map<number, number>();
	for (let k = runs.length - 1; k >= 0; k--) {
		const len = runs[k]?.length ?? 0;
		next[k] = lastOfLength.get(len);
		lastOfLength.set(len, k);
	}
	const closer = /--!?>/g;
	let pos = 0;
	let run = 0;
	const opener = /<!--|`/g;
	for (;;) {
		opener.lastIndex = pos;
		const m = opener.exec(text);
		if (!m) break;
		const at = m.index;
		const block = containing(blocks, at);
		if (block) {
			pos = block.end;
			continue;
		}
		if (m[0] === "<!--") {
			let contentEnd: number;
			let after: number;
			if (text.startsWith("<!-->", at)) [contentEnd, after] = [at + 4, at + 5];
			else if (text.startsWith("<!--->", at))
				[contentEnd, after] = [at + 4, at + 6];
			else {
				closer.lastIndex = at + 4;
				const c = closer.exec(text);
				contentEnd = c ? c.index : text.length;
				after = c ? c.index + c[0].length : text.length;
			}
			comments.push({
				start: at + 4,
				end: contentEnd,
				kind: "an HTML comment",
			});
			pos = after;
			continue;
		}
		while (run < runs.length && (runs[run]?.start ?? 0) < at) run++;
		const open = runs[run];
		if (!open || open.start !== at) {
			pos = at + 1;
			continue;
		}
		const limit = firstAfter(breaks, at) ?? text.length;
		let j = next[run];
		while (j !== undefined && (runs[j]?.start ?? 0) < pos) j = next[j];
		const close = j === undefined ? undefined : runs[j];
		if (close && close.start < limit) {
			spans.push({ start: at, end: close.start + close.length, kind: "code" });
			pos = close.start + close.length;
		} else pos = at + open.length;
	}
	return { comments, spans };
};

const DETAILS = "a collapsed <details> block";
const HIDING_ELEMENTS = new Set(["template", "noscript", "script", "style"]);

/** Parts of a Markdown file that the rendered view hides from a reviewer. */
export const hiddenRegions = (text: string): Region[] => {
	const lines = linesOf(text);
	const blocks = codeBlocks(lines, text.length);
	// Code spans cannot cross a blank line or a code block.
	const breaks = [
		...lines.filter((l) => l.text.trim() === "").map((l) => l.start),
		...blocks.map((b) => b.start),
	].sort((a, b) => a - b);
	const { comments, spans } = inlineScan(text, blocks, breaks);
	const code = [...blocks, ...spans].sort((a, b) => a.start - b.start);
	const visibleCode = (index: number) => within(code, index);
	const regions: Region[] = [...comments];

	// <details> without `open` is collapsed; an unclosed one runs to the end.
	const closes = [...text.matchAll(/<\/details\s*>/gi)];
	let nextClose = 0;
	let covered = 0;
	for (const m of text.matchAll(/<details\b([^>]{0,1000})>/gi)) {
		const open = m.index ?? 0;
		if (open < covered || visibleCode(open)) continue;
		if (/\sopen(?=[\s=/]|$)/i.test(m[1] ?? "")) continue;
		const bodyStart = open + m[0].length;
		while (
			nextClose < closes.length &&
			(closes[nextClose]?.index ?? 0) < bodyStart
		)
			nextClose++;
		const end = closes[nextClose]?.index ?? text.length;
		const body = text.slice(bodyStart, end);
		const summaryEnd = body.search(/<\/summary\s*>/i);
		const skipSummary =
			summaryEnd === -1 ? 0 : body.indexOf(">", summaryEnd) + 1;
		covered = end;
		regions.push({ start: bodyStart + skipSummary, end, kind: DETAILS });
	}

	// Elements a renderer hides: the hidden attribute, display:none or
	// visibility:hidden, and template/noscript/script/style. An unclosed one
	// hides the rest of the document.
	let hiddenUntil = 0;
	for (const m of text.matchAll(/<([a-z][\w-]{0,30})\b([^>]{0,1000})>/gi)) {
		const name = (m[1] ?? "").toLowerCase();
		const attrs = m[2] ?? "";
		const open = m.index ?? 0;
		if (name === "details" || attrs.endsWith("/") || open < hiddenUntil)
			continue;
		const hides =
			HIDING_ELEMENTS.has(name) ||
			/\shidden(?=[\s=/]|$)/i.test(attrs) ||
			/display\s*:\s*none|visibility\s*:\s*hidden/i.test(attrs);
		if (!hides || visibleCode(open)) continue;
		const bodyStart = open + m[0].length;
		// name matched [a-z][\w-]{0,30} above, so it is literal in a pattern.
		// nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
		const closing = new RegExp(`</${name}\\s*>`, "gi");
		closing.lastIndex = bodyStart;
		const end = closing.exec(text)?.index ?? text.length;
		hiddenUntil = end;
		regions.push({ start: bodyStart, end, kind: `a hidden <${name}> element` });
	}

	// Link reference definitions never render, nor do footnote definitions
	// nothing refers to. A title may continue on following lines until it
	// closes or a blank line; a footnote continues on indented lines.
	const referenced = new Set(
		[...text.matchAll(/\[\^([^\]\s]{1,100})\](?!:)/g)].map((m) => m[1]),
	);
	for (let k = 0; k < lines.length; k++) {
		const line = lines[k] as Line;
		if (visibleCode(line.start)) continue;
		const footnote = /^ {0,3}\[\^([^\]\s]{1,100})\]:/.exec(line.text);
		if (footnote) {
			if (referenced.has(footnote[1])) continue;
			let last = k;
			while (
				last + 1 < lines.length &&
				(lines[last + 1]?.text.trim() === ""
					? indentOf(lines[last + 2]?.text ?? "") >= 4 &&
						lines[last + 2]?.text.trim() !== ""
					: indentOf(lines[last + 1]?.text ?? "") >= 4)
			)
				last++;
			regions.push({
				start: line.start + line.text.indexOf("["),
				end: lines[last]?.end ?? line.end,
				kind: "an unreferenced footnote definition",
			});
			k = last;
			continue;
		}
		const def =
			/^ {0,3}\[((?:[^\]\\\n]|\\.){1,999})\]:[ \t]*(\S*)[ \t]*(.*)$/.exec(
				line.text,
			);
		if (!def) continue;
		let last = k;
		// Destination on the next line, then a title on the same or next line.
		if (!def[2] && k + 1 < lines.length) last = k + 1;
		const titleLine = lines[last]?.text ?? "";
		const opensTitle = (s: string) => {
			const t = s.trim();
			const open = t[0];
			if (open !== '"' && open !== "'" && open !== "(") return false;
			const close = open === "(" ? ")" : open;
			return !t.slice(1).includes(close);
		};
		const rest =
			last === k
				? (def[3] ?? "")
				: titleLine.trim().split(/\s+/).slice(1).join(" ");
		let unclosed = opensTitle(rest);
		if (!rest.trim() && /^\s*["'(]/.test(lines[last + 1]?.text ?? "")) {
			last++;
			unclosed = opensTitle(lines[last]?.text ?? "");
		}
		while (
			unclosed &&
			last + 1 < lines.length &&
			lines[last + 1]?.text.trim()
		) {
			last++;
			if (/["')]/.test(lines[last]?.text ?? "")) unclosed = false;
		}
		regions.push({
			start: line.start + line.text.indexOf("["),
			end: lines[last]?.end ?? line.end,
			kind: "a Markdown link reference definition",
		});
		k = last;
	}
	return regions.filter((r) => !visibleCode(r.start));
};

export { DETAILS };
