import {
	defineAuditor,
	type FindingInput,
	requireWorkspace,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import { isBinaryPath, MAX_SCAN_BYTES } from "../util";
import { decodeTexts } from "./decode";
import { type Kind, kindOf } from "./kinds";
import { AUDITOR } from "./rules";
import { scanUnicode } from "./scan";

export { decodeTexts } from "./decode";
export { type ScanOptions, scanUnicode } from "./scan";

/*
 * Invisible and deceptive Unicode: Trojan Source bidi controls
 * (CVE-2021-42574), zero-width and filler characters, tag characters that
 * smuggle hidden prompts, variation-selector payloads, and Latin look-alike
 * identifiers (CVE-2021-42694). Legitimate text is left alone: RTL letters and
 * directional marks in prose, ZWJ in emoji and Indic text, ZWNJ in Persian,
 * subdivision-flag tag sequences, single variation selectors and a leading BOM.
 *
 * Known limitations:
 * - Strings and comments are found by an approximate, per-language lexer. Its
 *   answer can only lower severity (high to medium) when it is certain, and
 *   it gives up certainty past anything it does not model (multi-line, raw
 *   and heredoc literals, Java `\u` escapes, Ruby percent literals), so a
 *   miss costs severity, never the finding. Languages without a lexer here
 *   are judged entirely as code.
 * - Files are decoded as UTF-8, and as UTF-16 or UTF-32 when they carry a BOM
 *   or (UTF-16 only) look like it from the NUL bytes in their first 4 KB.
 *   BOM-less UTF-16 that opens with non-ASCII text, BOM-less UTF-32 and other
 *   encodings (Shift-JIS, UTF-7, EBCDIC, ...) are read only as UTF-8.
 * - Files over 16 MB, and files past the 512 MB per-audit read budget, are
 *   not scanned; they are listed in one `scan-incomplete` finding.
 * - Homoglyphs: only Cyrillic and Greek look-alikes of Latin letters are
 *   checked, in files with a lexer, not full UTS #39 confusables (Armenian,
 *   Cherokee, mathematical alphanumerics, fullwidth forms and so on).
 * - Visible tricks with no hidden character are out of scope, such as a Java
 *   `\u000a` escape that ends a comment early.
 */

/** Largest file scanned (quick mode above MAX_SCAN_BYTES). */
const MAX_FILE_BYTES = 16 * 1024 * 1024;
/**
 * Total bytes read per audit. Files are read smallest first within each kind,
 * so padding a repository with large files cannot push small ones out.
 */
const MAX_TOTAL_BYTES = 512 * 1024 * 1024;

/** Agent files first, so the byte budget never pushes them out. */
const PRIORITY: Readonly<Record<Kind, number>> = { agent: 0, code: 1, text: 2 };

interface Sized {
	readonly path: string;
	/** -1 when the size could not be read. */
	readonly size: number;
	readonly kind: Kind | undefined;
}

/** The read budget, and the files left out of the scan. */
interface Tally {
	budget: number;
	unread: number;
	readonly tooLarge: string[];
}

const sizeOf = (ws: Workspace, path: string) =>
	ws.size(path).pipe(
		Effect.map((size): Sized => ({ path, size, kind: kindOf(path) })),
		Effect.orElseSucceed(
			(): Sized => ({
				path,
				size: -1,
				kind: kindOf(path),
			}),
		),
	);

const rank = (f: Sized) =>
	f.kind ? PRIORITY[f.kind] : isBinaryPath(f.path) ? 4 : 3;

/** Whether a file is read, counting it when it is left out. */
const admit = ({ path, size, kind }: Sized, tally: Tally): boolean => {
	if (size === 0) return false;
	if (size < 0) {
		tally.unread++;
		return false;
	}
	// Binary formats are only sniffed when small enough to be text.
	if (isBinaryPath(path) && size > MAX_SCAN_BYTES) return false;
	if (size > MAX_FILE_BYTES) {
		if (kind) tally.tooLarge.push(path);
		return false;
	}
	if (size > tally.budget) {
		tally.unread++;
		return false;
	}
	tally.budget -= size;
	return true;
};

const scanBytes = ({ path, kind }: Sized, bytes: Uint8Array) => {
	const texts = decodeTexts(bytes, !kind);
	const quick = isBinaryPath(path) || texts.length > 1;
	return texts.flatMap((text) =>
		scanUnicode(
			{ path, text },
			{
				kind: kindOf(path, text) ?? "code",
				mode: quick ? "quick" : undefined,
			},
		),
	);
};

const scanFile = (ws: Workspace, file: Sized, tally: Tally) =>
	Effect.gen(function* () {
		if (!admit(file, tally)) return [];
		return scanBytes(file, yield* ws.readBytes(file.path));
	}).pipe(
		Effect.orElseSucceed(() => {
			tally.unread++;
			return [];
		}),
	);

export const unicode = defineAuditor({
	id: AUDITOR,
	title: "Hidden Unicode",
	description:
		"Finds Trojan Source bidi controls, invisible and zero-width characters, hidden text in Unicode tag characters, variation-selector payloads and homoglyph identifiers in code, docs and agent instruction files. Known limits: string and comment detection is approximate per language and only ever lowers severity when certain; only UTF-8, UTF-16 and UTF-32 are decoded; files over 16 MB are reported as not scanned; homoglyphs are checked for Cyrillic and Greek look-alikes only.",
	categories: ["security"],
	targets: ["codebase"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			// Every listed file is a candidate: skip heuristics such as
			// minified, generated or fixture paths only quieten the noisier rules,
			// since attackers control file names. Ignored directories and the
			// user's disclosed ignore paths still apply.
			const sized = yield* Effect.forEach(
				yield* ws.files,
				(path) => sizeOf(ws, path),
				{ concurrency: 32 },
			);
			const candidates = sized.sort(
				(a, b) => rank(a) - rank(b) || a.size - b.size,
			);
			const tally: Tally = { budget: MAX_TOTAL_BYTES, unread: 0, tooLarge: [] };
			const results = yield* Effect.forEach(
				candidates,
				(file) => scanFile(ws, file, tally),
				{ concurrency: 16 },
			);
			const findings = results.flat();
			if (tally.tooLarge.length || tally.unread)
				findings.push(incomplete(tally.tooLarge.sort(), tally.unread));
			return findings;
		}),
});

const incomplete = (
	tooLarge: ReadonlyArray<string>,
	unread: number,
): FindingInput => {
	const parts: string[] = [];
	if (tooLarge.length)
		parts.push(
			`${tooLarge.length} larger than 16 MB (${tooLarge.slice(0, 5).join(", ")}${tooLarge.length > 5 ? ", ..." : ""})`,
		);
	if (unread)
		parts.push(`${unread} beyond the 512 MB read budget or unreadable`);
	return {
		ruleId: `${AUDITOR}/scan-incomplete`,
		title: "Some files were not scanned for hidden Unicode",
		severity: "info",
		category: "security",
		message: `Files not scanned: ${parts.join("; ")}. Hidden characters in them would go unreported.`,
		remediation:
			"Audit the skipped paths separately (e.g. point openaudit at their directory), or remove oversized generated files from the repository.",
		...(tooLarge.length === 1 ? { location: { file: tooLarge[0] } } : {}),
		confidence: "high",
		tags: ["hidden-unicode"],
	};
};
