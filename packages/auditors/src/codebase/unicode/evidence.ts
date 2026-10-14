import { scrubLine, truncate } from "../util";
import { escapeChar, escapeHidden } from "./chars";

/** Line starts of a text, for line numbers and bounded evidence windows. */
export interface Lines {
	readonly lineOf: (index: number) => number;
	readonly startOf: (line: number) => number;
	readonly endOf: (line: number) => number;
}

export const indexLines = (text: string): Lines => {
	let count = 1;
	for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1))
		count++;
	const starts = new Int32Array(count);
	let k = 1;
	for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1))
		starts[k++] = i + 1;
	return {
		lineOf: (index) => {
			let lo = 0;
			let hi = count - 1;
			while (lo < hi) {
				const mid = (lo + hi + 1) >> 1;
				if ((starts[mid] ?? 0) <= index) lo = mid;
				else hi = mid - 1;
			}
			return lo + 1;
		},
		startOf: (line) => starts[line - 1] ?? 0,
		endOf: (line) => (line < count ? (starts[line] ?? 1) - 1 : text.length),
	};
};

/** Lines up to this long are quoted whole, as fingerprints were before. */
const EVIDENCE_LINE = 2000;
/** On longer lines, raw characters kept before a hit (each may grow to 9 escaped). */
const EVIDENCE_BEFORE = 24;
const EVIDENCE_AFTER = 200;

/**
 * The escaped text around `index` on its line, scrubbed of secrets. Long
 * lines are cut to a window before escaping, so evidence stays cheap on
 * megabyte-long lines. Non-ASCII characters inside `reveal` are escaped too
 * (homoglyphs).
 */
export const evidenceAt = (
	text: string,
	lines: Lines,
	index: number,
	reveal?: readonly [number, number],
): string => {
	const line = lines.lineOf(index);
	const lineStart = lines.startOf(line);
	const lineEnd = lines.endOf(line);
	const part = (a: number, b: number) =>
		a < b ? escapeHidden(text.slice(a, b)) : "";
	const escaped = (from: number, to: number) => {
		if (!reveal) return part(from, to);
		const a = Math.min(Math.max(reveal[0], from), to);
		const b = Math.min(Math.max(reveal[1], from), to);
		const revealed = Array.from(text.slice(a, b), (c) =>
			/[\x20-\x7E]/.test(c) ? c : escapeChar(c),
		).join("");
		return part(from, a) + revealed + part(b, to);
	};
	if (lineEnd - lineStart <= EVIDENCE_LINE) {
		const whole = escaped(lineStart, lineEnd);
		const col = part(lineStart, index).length;
		const from = whole.length > 160 ? Math.max(0, col - 60) : 0;
		return truncate(
			scrubLine((from > 0 ? "…" : "") + whole.slice(from, from + 160)),
		);
	}
	let from = Math.max(lineStart, index - EVIDENCE_BEFORE);
	if (/[\uDC00-\uDFFF]/.test(text[from] ?? "")) from--;
	let to = Math.min(lineEnd, index + EVIDENCE_AFTER);
	if (/[\uD800-\uDBFF]/.test(text[to - 1] ?? "")) to++;
	return truncate(
		scrubLine(
			(from > lineStart ? "…" : "") +
				escaped(from, to) +
				(to < lineEnd ? "…" : ""),
		),
	);
};
