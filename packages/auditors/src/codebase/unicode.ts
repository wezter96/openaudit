import {
	type Confidence,
	defineAuditor,
	type FindingInput,
	requireWorkspace,
	type Severity,
	severityRank,
} from "@openaudit/core";
import { Effect } from "effect";

import {
	baseName,
	cweUrl,
	extOf,
	isBinaryPath,
	isFixturePath,
	isGeneratedPath,
	isLockfile,
	isMinifiedPath,
	languageOf,
	looksMinified,
	MAX_SCAN_BYTES,
	nonCodeMask,
	type SourceFile,
	scrubLine,
	truncate,
} from "./util";

/*
 * Invisible and deceptive Unicode: Trojan Source bidi controls
 * (CVE-2021-42574), zero-width and filler characters, tag characters that
 * smuggle hidden prompts, variation-selector payloads, and Latin look-alike
 * identifiers (CVE-2021-42694). Legitimate text is left alone: RTL letters and
 * directional marks in prose, ZWJ in emoji and Indic text, ZWNJ in Persian,
 * subdivision-flag tag sequences, single variation selectors and a leading BOM.
 */

const AUDITOR = "code.unicode";

/** `agent` files are instructions read by coding agents. */
type Kind = "code" | "agent" | "text";

const CODE_EXT = new Set([
	"sh",
	"bash",
	"zsh",
	"fish",
	"ksh",
	"ps1",
	"psm1",
	"bat",
	"cmd",
	"lua",
	"pl",
	"pm",
	"r",
	"sql",
	"ex",
	"exs",
	"erl",
	"hrl",
	"hs",
	"ml",
	"mli",
	"fs",
	"fsx",
	"clj",
	"cljs",
	"zig",
	"nim",
	"groovy",
	"gradle",
	"kts",
	"m",
	"mm",
	"sol",
	"tf",
	"hcl",
	"vb",
	"jl",
	"cr",
	"elm",
	"dockerfile",
	"html",
	"htm",
	"xhtml",
	"svg",
]);

const CODE_NAME =
	/^(Dockerfile|Containerfile|Makefile|GNUmakefile|Justfile|Jenkinsfile|Rakefile|Gemfile|Vagrantfile|Podfile|Fastfile)(\.|$)|^\.gitlab-ci\.ya?ml$/;

const TEXT_EXT = new Set([
	"md",
	"mdx",
	"markdown",
	"txt",
	"text",
	"rst",
	"adoc",
	"asciidoc",
	"org",
	"tex",
	"json",
	"jsonc",
	"json5",
	"yaml",
	"yml",
	"toml",
	"ini",
	"cfg",
	"conf",
	"properties",
	"env",
	"po",
	"pot",
	"ftl",
	"arb",
	"strings",
	"stringsdict",
	"xliff",
	"xlf",
	"resx",
	"xml",
	"plist",
	"csv",
	"tsv",
	"map",
]);

/** Instruction and rule files that coding agents load into their prompt. */
const AGENT_FILE =
	/(^|\/)(AGENTS?|CLAUDE|CLAUDE\.local|GEMINI|SKILL)\.md$|(^|\/)\.(cursorrules|windsurfrules|clinerules)$|\.mdc$|(^|\/)\.github\/(copilot-instructions\.md|(instructions|prompts|chatmodes|agents)\/[^/]+\.md)$|(^|\/)\.(cursor\/rules|clinerules|windsurf\/rules|kiro\/steering|roo\/rules[^/]*|continue\/rules|amazonq\/rules|claude\/(commands|agents|skills))\//i;

/** Sources that interleave prose with code (JSX, component templates). */
const MARKUP_EXT = new Set([
	"jsx",
	"tsx",
	"vue",
	"svelte",
	"astro",
	"html",
	"htm",
	"xhtml",
	"svg",
]);

/** Config files whose values run as commands. */
const EXECUTABLE_CONFIG =
	/(^|\/)(package\.json|composer\.json|deno\.jsonc?|Taskfile\.ya?ml|\.pre-commit-config\.ya?ml|azure-pipelines\.ya?ml|bitbucket-pipelines\.ya?ml|\.travis\.ya?ml|cloudbuild\.ya?ml|buildspec\.ya?ml|\.envrc|\.circleci\/config\.ya?ml|\.husky\/[^/]+)$/;

/** Extensionless prose; other unknown files are judged as code. */
const PROSE_NAME =
	/^(README|LICEN[CS]E|COPYING|NOTICE|AUTHORS|CONTRIBUTORS|CHANGELOG|CHANGES|HISTORY|CODEOWNERS)$/i;

/** Undefined for unknown files, which are scanned as code. */
const kindOf = (path: string): Kind | undefined => {
	if (AGENT_FILE.test(path)) return "agent";
	const ext = extOf(path);
	if (
		languageOf(path) ||
		CODE_EXT.has(ext) ||
		CODE_NAME.test(baseName(path)) ||
		EXECUTABLE_CONFIG.test(path) ||
		/(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/.test(path)
	)
		return "code";
	if (
		TEXT_EXT.has(ext) ||
		/^\.env(\.|$)/.test(baseName(path)) ||
		PROSE_NAME.test(baseName(path))
	)
		return "text";
	return undefined;
};

/* ------------------------------- characters ------------------------------- */

const NAMES: ReadonlyMap<number, string> = new Map([
	[0x00ad, "SOFT HYPHEN"],
	[0x061c, "ARABIC LETTER MARK"],
	[0x115f, "HANGUL CHOSEONG FILLER"],
	[0x1160, "HANGUL JUNGSEONG FILLER"],
	[0x180e, "MONGOLIAN VOWEL SEPARATOR"],
	[0x200b, "ZERO WIDTH SPACE"],
	[0x200c, "ZERO WIDTH NON-JOINER"],
	[0x200d, "ZERO WIDTH JOINER"],
	[0x200e, "LEFT-TO-RIGHT MARK"],
	[0x200f, "RIGHT-TO-LEFT MARK"],
	[0x2028, "LINE SEPARATOR"],
	[0x2029, "PARAGRAPH SEPARATOR"],
	[0x202a, "LEFT-TO-RIGHT EMBEDDING"],
	[0x202b, "RIGHT-TO-LEFT EMBEDDING"],
	[0x202c, "POP DIRECTIONAL FORMATTING"],
	[0x202d, "LEFT-TO-RIGHT OVERRIDE"],
	[0x202e, "RIGHT-TO-LEFT OVERRIDE"],
	[0x2060, "WORD JOINER"],
	[0x2061, "FUNCTION APPLICATION"],
	[0x2062, "INVISIBLE TIMES"],
	[0x2063, "INVISIBLE SEPARATOR"],
	[0x2064, "INVISIBLE PLUS"],
	[0x2066, "LEFT-TO-RIGHT ISOLATE"],
	[0x2067, "RIGHT-TO-LEFT ISOLATE"],
	[0x2068, "FIRST STRONG ISOLATE"],
	[0x2069, "POP DIRECTIONAL ISOLATE"],
	[0x3164, "HANGUL FILLER"],
	[0xfeff, "ZERO WIDTH NO-BREAK SPACE"],
	[0xffa0, "HALFWIDTH HANGUL FILLER"],
]);

/** Every character this auditor reports, as runs. */
const HIDDEN =
	// biome-ignore lint/suspicious/noMisleadingCharacterClass: matches variation selectors on their own
	/[\u00AD\u061C\u115F\u1160\u180E\u200B-\u200F\u2028\u2029\u202A-\u202E\u2060-\u2064\u2066-\u2069\u3164\uFE00-\uFE0F\uFEFF\uFFA0\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]+/gu;

type Group = "bidi" | "mark" | "tag" | "selector" | "invisible";

const groupOf = (cp: number): Group => {
	if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069))
		return "bidi";
	if (cp === 0x200e || cp === 0x200f || cp === 0x061c) return "mark";
	if (cp >= 0xe0000 && cp <= 0xe007f) return "tag";
	if ((cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef))
		return "selector";
	return "invisible";
};

/** Characters that only make sense in code as escapes. */
const CODE_ONLY = new Set([
	0x00ad, 0x115f, 0x1160, 0x2028, 0x2029, 0x2061, 0x2062, 0x2063, 0x2064,
	0x3164, 0xffa0,
]);

const isEmojiPart = (ch: string) =>
	// biome-ignore lint/suspicious/noMisleadingCharacterClass: tests one character at a time
	/[\p{Extended_Pictographic}\p{Emoji_Modifier}\p{Regional_Indicator}\uFE0F\u20E3]/u.test(
		ch,
	);

/** Letters and marks of scripts that use joiners and zero-width breaks. */
const isComplexScript = (ch: string) =>
	/[\p{L}\p{M}]/u.test(ch) &&
	!/[\p{Script=Latin}\p{Script=Common}\p{Script=Inherited}]/u.test(ch);

/**
 * True when an invisible character is plausibly part of the text around it.
 * Emoji are never identifier characters, so a joiner between them is safe
 * anywhere. In prose a neighbouring Persian, Indic or Thai letter is enough.
 * In code the character must sit between two such letters, where joiners
 * visibly change the shaping, so it cannot silently end an identifier; this
 * holds whatever the lexer thinks, so it never depends on its guesses.
 */
const legitimateInvisible = (
	cp: number,
	prev: string,
	next: string,
	context: "prose" | "code" | "comment",
) => {
	if (cp === 0x200d && (isEmojiPart(prev) || isEmojiPart(next))) return true;
	// `**\u200B/` keeps a glob from closing a block comment.
	if (cp === 0x200b && context === "comment" && prev === "*" && next === "/")
		return true;
	const near = (test: (ch: string) => boolean) =>
		context === "prose" ? test(prev) || test(next) : test(prev) && test(next);
	switch (cp) {
		case 0x200b:
		case 0x200c:
		case 0x200d:
		case 0x2060:
			return near(isComplexScript);
		case 0x180e:
			return near((ch) => /\p{Script=Mongolian}/u.test(ch));
		default:
			return false;
	}
};

/** Escapes characters that render invisibly or reorder text. */
const escapeHidden = (s: string): string =>
	s.replace(HIDDEN, (run) => {
		const chars = [...run];
		// Long tag or selector payloads are decoded in the message instead.
		if (chars.length <= 6) return chars.map(escapeChar).join("");
		return `${chars.slice(0, 3).map(escapeChar).join("")}...(+${chars.length - 3} hidden)`;
	});

const escapeChar = (ch: string): string => {
	const cp = ch.codePointAt(0) ?? 0;
	const hex = cp.toString(16).toUpperCase();
	return cp > 0xffff ? `\\u{${hex}}` : `\\u${hex.padStart(4, "0")}`;
};

const label = (cp: number) =>
	`${NAMES.get(cp) ?? "CHARACTER"} (U+${cp.toString(16).toUpperCase().padStart(4, "0")})`;

/** Hidden payloads are decoded only this far, so huge runs stay cheap. */
const MAX_DECODE = 200;

/** ASCII hidden in tag characters (U+E0020-U+E007E). */
const decodeTags = (cps: ReadonlyArray<number>): string =>
	cps
		.map((cp) => cp - 0xe0000)
		.filter((c) => c >= 0x20 && c <= 0x7e)
		.map((c) => String.fromCharCode(c))
		.join("");

/** Tag letters of the recommended subdivision flags: England, Scotland, Wales. */
const FLAG_TAGS = new Set(["gbeng", "gbsct", "gbwls"]);

/** A recommended subdivision flag: U+1F3F4, its tag letters, CANCEL TAG. */
const isFlagSequence = (cps: ReadonlyArray<number>, before: string): boolean =>
	before === "\u{1F3F4}" &&
	cps.length === 6 &&
	cps.at(-1) === 0xe007f &&
	FLAG_TAGS.has(decodeTags(cps.slice(0, -1)));

/**
 * Bytes hidden in variation selectors, one selector per byte (U+FE00-FE0F for
 * 0-15, U+E0100-E01EF for 16-255). Returns printable text or undefined.
 */
const decodeSelectors = (cps: ReadonlyArray<number>): string | undefined => {
	const bytes = cps.map((cp) =>
		cp <= 0xfe0f ? cp - 0xfe00 : cp - 0xe0100 + 16,
	);
	const text = new TextDecoder().decode(new Uint8Array(bytes));
	const printable = [...text].filter((c) => /[\x20-\x7E]/.test(c)).length;
	return printable / Math.max(1, [...text].length) >= 0.7 ? text : undefined;
};

/** Line starts of a text, for line numbers and bounded evidence windows. */
interface Lines {
	readonly lineOf: (index: number) => number;
	readonly startOf: (line: number) => number;
	readonly endOf: (line: number) => number;
}

const indexLines = (text: string): Lines => {
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
const evidenceAt = (
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
		const revealed = [...text.slice(a, b)]
			.map((c) => (/[\x20-\x7E]/.test(c) ? c : escapeChar(c)))
			.join("");
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

const charList = (cps: Iterable<number>) =>
	[...new Set(cps)].map(label).join(", ");

/* ------------------------------- homoglyphs ------------------------------- */

/** Cyrillic and Greek letters that render like a Latin letter. */
const LATIN_LOOKALIKE: Readonly<Record<string, string>> = {
	"\u0430": "a",
	"\u0435": "e",
	"\u043E": "o",
	"\u0440": "p",
	"\u0441": "c",
	"\u0443": "y",
	"\u0445": "x",
	"\u0455": "s",
	"\u0456": "i",
	"\u0458": "j",
	"\u0501": "d",
	"\u04BB": "h",
	"\u051B": "q",
	"\u051D": "w",
	"\u04CF": "l",
	"\u04AF": "y",
	"\u0410": "A",
	"\u0412": "B",
	"\u0415": "E",
	"\u041A": "K",
	"\u041C": "M",
	"\u041D": "H",
	"\u041E": "O",
	"\u0420": "P",
	"\u0421": "C",
	"\u0422": "T",
	"\u0425": "X",
	"\u0406": "I",
	"\u0408": "J",
	"\u0405": "S",
	"\u04AE": "Y",
	"\u051A": "Q",
	"\u051C": "W",
	"\u0391": "A",
	"\u0392": "B",
	"\u0395": "E",
	"\u0396": "Z",
	"\u0397": "H",
	"\u0399": "I",
	"\u039A": "K",
	"\u039C": "M",
	"\u039D": "N",
	"\u039F": "O",
	"\u03A1": "P",
	"\u03A4": "T",
	"\u03A5": "Y",
	"\u03A7": "X",
	"\u03BF": "o",
	"\u03BD": "v",
	"\u03C1": "p",
};

const GREEK_OR_CYRILLIC = /[\u0370-\u03FF\u0400-\u052F]/g;
const isGreekOrCyrillic = (ch: string | undefined) =>
	ch !== undefined && /[\u0370-\u03FF\u0400-\u052F]/.test(ch);
const ID_PART = /[\p{ID_Continue}$\u200C\u200D]/u;
const isLatinLetter = (ch: string | undefined) =>
	ch !== undefined && /\p{Script=Latin}/u.test(ch) && /\p{L}/u.test(ch);

interface Homoglyph {
	readonly start: number;
	readonly end: number;
	readonly lookalike: string;
	readonly mixed: boolean;
}

/**
 * Identifiers that pass for Latin: a run of Cyrillic/Greek look-alikes glued
 * to Latin letters (`sayHello` with a Cyrillic H), or an identifier made only
 * of look-alikes whose Latin twin appears in the same file (a Cyrillic `cop`
 * next to the Latin one). A cheap stand-in for UTS #39 confusable detection.
 * Each identifier is visited once and the twins come from one pass over the
 * file, so the work is linear in the text.
 */
const findHomoglyphs = (
	text: string,
	isCode: (index: number) => boolean,
): Homoglyph[] => {
	const out: Homoglyph[] = [];
	let asciiIdentifiers: Set<string> | undefined;
	let lastEnd = 0;
	for (const m of text.matchAll(GREEK_OR_CYRILLIC)) {
		const at = m.index ?? 0;
		if (at < lastEnd) continue; // inside an identifier already checked
		let start = at;
		while (start > lastEnd && ID_PART.test(text[start - 1] ?? "")) start--;
		let end = at + 1;
		while (end < text.length && ID_PART.test(text[end] ?? "")) end++;
		lastEnd = end;
		if (!isCode(start)) continue;
		const chars = [...text.slice(start, end)];
		const hasLatin = chars.some(isLatinLetter);
		let mixed = false;
		for (let i = 0; i < chars.length && hasLatin && !mixed; i++) {
			if (!isGreekOrCyrillic(chars[i])) continue;
			let j = i;
			while (j < chars.length && isGreekOrCyrillic(chars[j])) j++;
			let lookalikes = true;
			for (let k = i; k < j && lookalikes; k++)
				lookalikes = LATIN_LOOKALIKE[chars[k] ?? ""] !== undefined;
			mixed =
				lookalikes && (isLatinLetter(chars[i - 1]) || isLatinLetter(chars[j]));
			i = j;
		}
		const lookalike = chars.map((c) => LATIN_LOOKALIKE[c] ?? c).join("");
		let wholeScript = false;
		if (
			!mixed &&
			!hasLatin &&
			/^[\w$]+$/.test(lookalike) &&
			chars.filter((c) => /\p{L}/u.test(c)).length >= 2
		) {
			asciiIdentifiers ??= new Set(text.match(/[A-Za-z_$][\w$]*/g) ?? []);
			wholeScript = asciiIdentifiers.has(lookalike);
		}
		if (mixed || wholeScript)
			out.push({ start, end, lookalike: truncate(lookalike, 80), mixed });
	}
	return out;
};

/* --------------------------------- rules ---------------------------------- */

const REFS = {
	trojanSource: "https://trojansource.codes/",
	bidiCve: "https://nvd.nist.gov/vuln/detail/CVE-2021-42574",
	homoglyphCve: "https://nvd.nist.gov/vuln/detail/CVE-2021-42694",
	tr36: "https://www.unicode.org/reports/tr36/",
	uts39: "https://www.unicode.org/reports/tr39/",
	tags: "https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/",
	selectors:
		"https://paulbutler.org/2025/smuggling-arbitrary-data-through-an-emoji/",
} as const;

type RuleId =
	| "bidi-control"
	| "invisible-character"
	| "tag-characters"
	| "variation-selector-run"
	| "mixed-script-identifier";

interface Rule {
	readonly title: string;
	readonly remediation: string;
	readonly references: ReadonlyArray<string>;
	readonly tags: ReadonlyArray<string>;
}

const RULES: Readonly<Record<RuleId, Rule>> = {
	"bidi-control": {
		title: "Bidirectional control characters (Trojan Source)",
		remediation:
			"Remove the bidirectional control characters, or write them as escapes (e.g. \\u202E) where they are genuinely needed. Review the surrounding code in a viewer that reveals them; reject such changes in review and CI.",
		references: [REFS.trojanSource, REFS.bidiCve, REFS.tr36, cweUrl(451)],
		tags: ["cwe-451", "hidden-unicode", "trojan-source"],
	},
	"invisible-character": {
		title: "Invisible character",
		remediation:
			"Delete the invisible character, or write it as an escape (e.g. \\u200B) if it is intentional. Configure the editor to render invisible characters.",
		references: [REFS.tr36, REFS.trojanSource, cweUrl(451)],
		tags: ["cwe-451", "hidden-unicode"],
	},
	"tag-characters": {
		title: "Hidden text in Unicode tag characters",
		remediation:
			"Delete the tag characters. They render as nothing but language models read them, so treat the file as compromised and check where the text came from.",
		references: [REFS.tags, REFS.tr36, cweUrl(451)],
		tags: ["cwe-451", "hidden-unicode", "prompt-injection"],
	},
	"variation-selector-run": {
		title: "Data hidden in variation selectors",
		remediation:
			"Delete the run of variation selectors and check whether code decodes and executes it. A visible character never needs more than one selector.",
		references: [REFS.selectors, REFS.tr36, cweUrl(451)],
		tags: ["cwe-451", "hidden-unicode"],
	},
	"mixed-script-identifier": {
		title: "Identifier uses look-alike letters (homoglyph)",
		remediation:
			"Rename the identifier using a single script. If it imitates another identifier, find out who introduced it and why.",
		references: [
			REFS.homoglyphCve,
			REFS.uts39,
			REFS.trojanSource,
			cweUrl(1007),
		],
		tags: ["cwe-1007", "hidden-unicode", "trojan-source"],
	},
};

const charBefore = (text: string, i: number): string => {
	const low = text.charCodeAt(i - 1);
	return i >= 2 && low >= 0xdc00 && low <= 0xdfff
		? text.slice(i - 2, i)
		: (text[i - 1] ?? "");
};

const charAt = (text: string, i: number): string =>
	i < text.length ? String.fromCodePoint(text.codePointAt(i) ?? 0) : "";

type Region = "code" | "comment" | "string";

/*
 * Where a character sits, as far as the lexer can tell. Our lexer will never
 * match every language's tokenizer, so its answer may only lower severity
 * when it is certain: a simple one-line quoted literal, or a comment that
 * starts its line. Anything else is judged as code.
 */
interface Place {
	readonly region: Region;
	readonly certain: boolean;
	/** A regex literal: never certain, but no place for identifiers either. */
	readonly regex?: boolean;
}

const IN_CODE: Place = { region: "code", certain: true };

/** Longest line prefix inspected when judging a literal or comment simple. */
const MAX_PREFIX = 500;

/** Code before a literal on its line, free of anything that could fool the lexer. */
const isPlainPrefix = (prefix: string): boolean => {
	if (prefix.includes("<!--") || prefix.includes("-->")) return false;
	let quote = "";
	for (let i = 0; i < prefix.length; i++) {
		const c = prefix[i];
		if (quote) {
			if (c === "\\") i++;
			else if (c === quote) quote = "";
		} else if (c === '"' || c === "'") quote = c;
		else if (c === "/" || c === "`" || c === "#" || c === "*") return false;
	}
	return quote === "";
};

const placeFinder = (
	text: string,
	lang: string | undefined,
	lines: Lines,
): ((index: number) => Place) => {
	let built = false;
	let mask: Uint8Array | undefined;
	let starts = new Int32Array(0);
	const spans = new Map<number, Place & { breakAt: number }>();

	const build = () => {
		built = true;
		if (!lang) return;
		try {
			mask = nonCodeMask(text, lang);
		} catch {
			return; // no mask: everything is code, the stricter reading
		}
		const m = mask;
		const isStart = (i: number) => m[i] === 1 && (i === 0 || m[i - 1] === 0);
		let count = 0;
		for (let i = 0; i < m.length; i++) if (isStart(i)) count++;
		starts = new Int32Array(count);
		let k = 0;
		for (let i = 0; i < m.length; i++) if (isStart(i)) starts[k++] = i;
	};

	// Judged once per masked span, so the work stays linear.
	const judge = (s: number, m: Uint8Array): Place & { breakAt: number } => {
		let end = s;
		while (end < m.length && m[end]) end++;
		const lineStart = lines.startOf(lines.lineOf(s));
		const prefix =
			s - lineStart <= MAX_PREFIX ? text.slice(lineStart, s) : undefined;
		if (/^(\/\/|\/\*|#)/.test(text.slice(s, s + 2))) {
			// The mask starts comments at their delimiter. JavaScript also ends
			// line comments at CR and the Unicode line separators.
			let breakAt = end;
			if (text[s + 1] !== "*")
				for (let i = s; i < end; i++)
					if (/[\r\u2028\u2029]/.test(text[i] ?? "")) {
						breakAt = i;
						break;
					}
			return {
				region: "comment",
				certain: prefix !== undefined && /^\s*$/.test(prefix),
				breakAt,
			};
		}
		// Strings start after their quote. Prefixed (f"", r#"", $"", @""),
		// interpolating, multi-line or unclosed literals are never certain.
		const quote = text[s - 1] ?? "";
		const certain =
			(quote === '"' || quote === "'") &&
			text[end] === quote &&
			!/[\w#$@"'`]/.test(text[s - 2] ?? "") &&
			!/[{$\r\n]/.test(text.slice(s, end)) &&
			prefix !== undefined &&
			isPlainPrefix(prefix.slice(0, -1));
		return {
			region: "string",
			certain,
			regex: text[s] === "/" && quote !== "/",
			breakAt: end,
		};
	};

	return (index) => {
		if (!built) build();
		const m = mask;
		if (!m?.[index]) return IN_CODE;
		let lo = 0;
		let hi = starts.length - 1;
		while (lo < hi) {
			const mid = (lo + hi + 1) >> 1;
			if ((starts[mid] ?? 0) <= index) lo = mid;
			else hi = mid - 1;
		}
		const s = starts[lo] ?? 0;
		let span = spans.get(s);
		if (!span) {
			span = judge(s, m);
			spans.set(s, span);
		}
		// Past a CR or line separator, a line comment may already have ended.
		return index <= span.breakAt
			? span
			: { region: span.region, certain: false };
	};
};

/** Line and paragraph separators end `//` comments in JS but are valid in strings. */
const isSeparator = (cp: number) => cp === 0x2028 || cp === 0x2029;

const isDeliberateInString = (cp: number) => isSeparator(cp) || cp === 0xfeff;

interface Context {
	readonly kind: Kind;
	readonly path: string;
	readonly prev: string;
	readonly next: string;
	readonly placeAt: (index: number) => Place;
}

const classify = (seg: Segment, ctx: Context): Hit | undefined => {
	const { kind } = ctx;
	const { cps, start: index } = seg;
	switch (seg.group) {
		case "bidi":
			return {
				rule: "bidi-control",
				index,
				severity: kind === "text" ? "medium" : "high",
				confidence:
					kind === "code" ? "high" : kind === "agent" ? "medium" : "low",
				chars: cps,
				message: (list) =>
					kind === "code"
						? `Contains ${list}. Bidirectional controls make code display in a different order than the compiler reads it, hiding logic in comments and strings (Trojan Source, CVE-2021-42574).`
						: `Contains ${list}. Bidirectional controls make text display in a different order than tools and language models read it.`,
			};
		case "mark":
			// Directional marks are normal in RTL prose; in code they still reorder.
			if (kind !== "code") return undefined;
			return {
				rule: "bidi-control",
				index,
				severity: "medium",
				confidence: "low",
				chars: cps,
				message: (list) =>
					`Contains ${list}. Directional marks are invisible and can change how neighbouring code is displayed (Trojan Source, CVE-2021-42574).`,
			};
		case "tag": {
			if (isFlagSequence(seg.head, ctx.prev)) return undefined;
			const hidden = decodeTags(seg.head);
			return {
				rule: "tag-characters",
				index,
				severity: "high",
				confidence: "high",
				chars: cps,
				message: () =>
					hidden
						? `Invisible Unicode tag characters spell out hidden text: "${truncate(scrubLine(hidden), 120)}". Humans cannot see it but language models and tools read it, a known prompt-injection technique.`
						: "Contains invisible Unicode tag characters, which can carry text that humans cannot see but language models read.",
			};
		}
		case "selector": {
			const presentation = cps.every((c) => c === 0xfe0e || c === 0xfe0f);
			// One selector per character is how variants work, except after ASCII
			// letters, which have none.
			const orphan = seg.count === 1 && /[A-Za-z]/.test(ctx.prev);
			// Repeating one presentation selector is a copy-paste slip; mixing
			// U+FE0E and U+FE0F can carry bits.
			if (
				!orphan &&
				(seg.count < 2 ||
					(presentation && (seg.count <= 2 || cps.length === 1)))
			)
				return undefined;
			const decoded = orphan ? undefined : decodeSelectors(seg.head);
			return {
				rule: "variation-selector-run",
				index,
				severity: kind === "text" ? "medium" : "high",
				confidence: "medium",
				chars: cps,
				message: () =>
					orphan
						? "Variation selectors follow characters that have no variants. One per character is a known way to hide bytes in plain-looking text."
						: `A run of ${seg.count} variation selectors follows one character. Each selector can encode a byte, so this is a known way to hide payloads in code and prompts${decoded ? `; it decodes to "${truncate(scrubLine(decoded), 120)}"` : ""}.`,
			};
		}
		case "invisible": {
			if (index === 0 && cps[0] === 0xfeff && seg.count === 1) return undefined;
			if (kind !== "code") {
				const reported = cps.filter(
					(cp) =>
						!CODE_ONLY.has(cp) &&
						!legitimateInvisible(cp, ctx.prev, ctx.next, "prose"),
				);
				if (!reported.length) return undefined;
				return {
					rule: "invisible-character",
					index,
					severity: kind === "agent" ? "medium" : "low",
					confidence: kind === "agent" ? "medium" : "low",
					chars: reported,
					message: (list) =>
						`Contains ${list}, which renders as nothing and makes text differ from what it looks like.`,
				};
			}
			const place = ctx.placeAt(index);
			const trusted = place.certain && place.region !== "code";
			const markup = MARKUP_EXT.has(extOf(ctx.path));
			// Soft hyphens are hyphenation hints in markup prose, and identifiers
			// cannot contain them.
			const reported = cps.filter(
				(cp) =>
					!(markup && cp === 0x00ad) &&
					!legitimateInvisible(
						cp,
						ctx.prev,
						ctx.next,
						trusted && place.region === "comment" ? "comment" : "code",
					),
			);
			if (!reported.length) return undefined;
			// Soft hyphens cannot form identifiers in most languages, so outside
			// plain code they stay medium.
			const hyphens =
				place.region !== "code" && reported.every((cp) => cp === 0x00ad);
			if (!trusted)
				return {
					rule: "invisible-character",
					index,
					severity: markup || hyphens ? "medium" : "high",
					confidence: "medium",
					chars: reported,
					message: (list) =>
						place.region === "code"
							? `Contains ${list} outside strings and comments. Invisible characters in code can make two identifiers look identical or hide parameters (the "invisible backdoor").`
							: `Contains ${list} where the scanner cannot be sure it is inside a ${place.region}, so it is judged as code. Invisible characters in code can make two identifiers look identical or hide parameters (the "invisible backdoor").`,
				};
			// Soft hyphens are ordinary hyphenation hints in strings and comments.
			if (reported.every((cp) => cp === 0x00ad)) return undefined;
			// A raw BOM (CSV for Excel) or separator in a string is deliberate data,
			// just invisible; zero-width characters inside words are the risk.
			if (place.region === "string" && reported.every(isDeliberateInString))
				return {
					rule: "invisible-character",
					index,
					severity: "low",
					confidence: "medium",
					chars: reported,
					message: (list) =>
						`Contains a raw ${list} in a string. It is valid but invisible, so reviewers cannot tell it is there; write it as an escape.`,
				};
			const separator =
				place.region === "comment" && reported.some(isSeparator);
			return {
				rule: "invisible-character",
				index,
				severity: separator ? "high" : "medium",
				confidence: "medium",
				chars: reported,
				message: (list) =>
					separator
						? `Contains ${list} in a comment. JavaScript and C# treat it as a line break, so code after it runs although it looks commented out.`
						: place.region === "string"
							? `Contains ${list} in a string. Strings that look identical can then compare unequal, and reviewers cannot see the difference.`
							: `Contains ${list} in a comment. It hides what reviewers see and often marks pasted text.`,
			};
		}
	}
};

/** Findings per rule per file; the last one counts the rest. */
const MAX_PER_RULE = 20;

interface Hit {
	readonly rule: RuleId;
	readonly index: number;
	readonly severity: Severity;
	readonly confidence: Confidence;
	/** Reported code points; merged per line before `message` renders them. */
	readonly chars: ReadonlyArray<number>;
	readonly message: (chars: string) => string;
	/** Characters to reveal in evidence (homoglyph identifiers). */
	readonly reveal?: readonly [number, number];
}

interface Kept extends Hit {
	readonly line: number;
	readonly allChars: Set<number>;
}

/**
 * Groups hits into one finding per rule and line, keeping at most
 * MAX_PER_RULE lines per rule and counting the rest, so memory stays bounded
 * however many hits a hostile file produces. Hits arrive in text order.
 */
const collector = (lines: Lines) => {
	const rules = new Map<
		RuleId,
		{ kept: Map<number, Kept>; more: number; lastMore: number }
	>();
	return {
		add: (hit: Hit) => {
			const line = lines.lineOf(hit.index);
			let rule = rules.get(hit.rule);
			if (!rule) {
				rule = { kept: new Map(), more: 0, lastMore: 0 };
				rules.set(hit.rule, rule);
			}
			const prior = rule.kept.get(line);
			if (prior) {
				for (const cp of hit.chars) prior.allChars.add(cp);
				if (severityRank(hit.severity) < severityRank(prior.severity))
					rule.kept.set(line, {
						...hit,
						index: prior.index,
						reveal: prior.reveal,
						line,
						allChars: prior.allChars,
					});
			} else if (rule.kept.size < MAX_PER_RULE)
				rule.kept.set(line, { ...hit, line, allChars: new Set(hit.chars) });
			else if (line !== rule.lastMore) {
				rule.more++;
				rule.lastMore = line;
			}
		},
		results: () => rules,
	};
};

type Mode = "thorough" | "quick";

export interface ScanOptions {
	/**
	 * `quick` runs only the rules attackers rely on (bidi controls, tag
	 * characters, variation-selector payloads). The default picks `quick` for
	 * files whose noisier rules would mostly report third-party text:
	 * minified, generated, fixture and lock files, and files over 1 MB.
	 */
	readonly mode?: Mode;
	/** Overrides the kind derived from the path (e.g. shebang scripts). */
	readonly kind?: Kind;
}

/** Paths whose content is usually generated or third-party text. */
const isNoisyPath = (path: string) =>
	isMinifiedPath(path) ||
	isFixturePath(path) ||
	isGeneratedPath(path) ||
	isLockfile(path);

const modeOf = (file: SourceFile): Mode =>
	isNoisyPath(file.path) ||
	file.text.length > MAX_SCAN_BYTES ||
	looksMinified(file.text)
		? "quick"
		: "thorough";

interface Segment {
	readonly group: Group;
	readonly start: number;
	readonly end: number;
	readonly count: number;
	/** Distinct code points in the segment. */
	readonly cps: ReadonlyArray<number>;
	/** The first MAX_DECODE code points, for decoding payloads. */
	readonly head: ReadonlyArray<number>;
}

/** Scans one file. Linear in the text; exported for unit tests. */
export const scanUnicode = (
	file: SourceFile,
	options: ScanOptions = {},
): FindingInput[] => {
	const { path, text } = file;
	const kind = options.kind ?? kindOf(path) ?? "code";
	if (!/[^\p{ASCII}]/u.test(text)) return [];
	const mode = options.mode ?? modeOf(file);
	const lang = kind === "code" ? languageOf(path) : undefined;
	const lines = indexLines(text);
	const placeAt = placeFinder(text, lang, lines);
	const found = collector(lines);

	for (const m of text.matchAll(HIDDEN)) {
		const runEnd = (m.index ?? 0) + m[0].length;
		// Split the run into segments of one group each.
		for (let i = m.index ?? 0; i < runEnd; ) {
			const start = i;
			const group = groupOf(text.codePointAt(i) ?? 0);
			const cps = new Set<number>();
			const head: number[] = [];
			let count = 0;
			while (i < runEnd) {
				const cp = text.codePointAt(i) ?? 0;
				if (groupOf(cp) !== group) break;
				cps.add(cp);
				if (head.length < MAX_DECODE) head.push(cp);
				count++;
				i += cp > 0xffff ? 2 : 1;
			}
			if (mode === "quick" && group === "mark") continue;
			const hit = classify(
				{ group, start, end: i, count, cps: [...cps], head },
				{
					kind,
					path,
					prev: charBefore(text, start),
					next: charAt(text, i),
					placeAt,
				},
			);
			// Quick mode keeps everything that could change what code does.
			if (hit && !(mode === "quick" && hit.severity === "low")) found.add(hit);
		}
	}

	if (mode === "thorough" && lang && /[\u0370-\u052F]/.test(text))
		for (const h of findHomoglyphs(text, (i) => {
			const place = placeAt(i);
			return place.region === "code" || !(place.certain || place.regex);
		}))
			found.add({
				rule: "mixed-script-identifier",
				index: h.start,
				severity: "medium",
				confidence: "low",
				chars: [],
				reveal: [h.start, h.end],
				message: () =>
					h.mixed
						? `Identifier mixes Latin letters with Cyrillic or Greek look-alikes and renders like "${h.lookalike}". Homoglyph identifiers can shadow or impersonate real ones (CVE-2021-42694).`
						: `Identifier is spelled entirely with Cyrillic or Greek look-alikes of "${h.lookalike}", which also appears in this file. Homoglyph identifiers can shadow or impersonate real ones (CVE-2021-42694).`,
			});

	const findings: Array<FindingInput & { index: number }> = [];
	for (const [ruleId, { kept, more }] of found.results()) {
		const rule = RULES[ruleId];
		const list = [...kept.values()];
		list.forEach((hit, i) => {
			const message = hit.message(charList(hit.allChars));
			findings.push({
				index: hit.index,
				ruleId: `${AUDITOR}/${ruleId}`,
				title: rule.title,
				severity: hit.severity,
				category: "security",
				message:
					more > 0 && i === list.length - 1
						? `${message} (and ${more} more lines in this file)`
						: message,
				location: {
					file: path,
					line: hit.line,
					column: hit.index - lines.startOf(hit.line) + 1,
				},
				evidence: evidenceAt(text, lines, hit.index, hit.reveal),
				remediation: rule.remediation,
				references: [...rule.references],
				confidence: hit.confidence,
				tags: [...rule.tags],
			});
		});
	}
	return findings
		.sort((a, b) => a.index - b.index)
		.map(({ index: _, ...f }) => f);
};

/* ---------------------------------- run ----------------------------------- */

/** Largest file scanned (quick mode above MAX_SCAN_BYTES). */
const MAX_FILE_BYTES = 16 * 1024 * 1024;
/**
 * Total bytes read per audit. Files are read smallest first within each kind,
 * so padding a repository with large files cannot push small ones out.
 */
const MAX_TOTAL_BYTES = 512 * 1024 * 1024;

const utf32 = (bytes: Uint8Array, littleEndian: boolean): string => {
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	let out = "";
	for (let i = 4; i + 4 <= bytes.length; i += 4) {
		const cp = view.getUint32(i, littleEndian);
		out += String.fromCodePoint(cp <= 0x10ffff ? cp : 0xfffd);
	}
	return out;
};

/**
 * Every plausible reading of a file's bytes. UTF-32 and UTF-16 (with a BOM, or
 * detected from the NUL pattern of mostly-ASCII text) are decoded as such,
 * because compilers such as tsc and csc honour them, and the UTF-8 reading is
 * scanned as well, because others ignore the BOM. Binary content yields
 * nothing when `sniff` is set; for known kinds and shebang scripts a NUL never
 * hides the file.
 */
export const decodeTexts = (bytes: Uint8Array, sniff: boolean): string[] => {
	const utf8 = () => new TextDecoder().decode(bytes);
	const [b0, b1, b2, b3] = bytes;
	if (b0 === 0xff && b1 === 0xfe && b2 === 0 && b3 === 0)
		return [utf32(bytes, true), utf8()];
	if (b0 === 0 && b1 === 0 && b2 === 0xfe && b3 === 0xff)
		return [utf32(bytes, false), utf8()];
	if (b0 === 0xff && b1 === 0xfe)
		return [new TextDecoder("utf-16le").decode(bytes), utf8()];
	if (b0 === 0xfe && b1 === 0xff)
		return [new TextDecoder("utf-16be").decode(bytes), utf8()];
	const head = bytes.subarray(0, 4096);
	let even = 0;
	let odd = 0;
	for (let i = 0; i < head.length; i++)
		if (head[i] === 0) {
			if (i % 2) odd++;
			else even++;
		}
	if (even + odd > 0) {
		const half = head.length / 2;
		if (odd > half * 0.6 && even < half * 0.1)
			return [new TextDecoder("utf-16le").decode(bytes), utf8()];
		if (even > half * 0.6 && odd < half * 0.1)
			return [new TextDecoder("utf-16be").decode(bytes), utf8()];
		const shebang = b0 === 0x23 && b1 === 0x21;
		if (sniff && !shebang) return [];
	}
	return [utf8()];
};

/** Agent files first, so the byte budget never pushes them out. */
const PRIORITY: Readonly<Record<Kind, number>> = { agent: 0, code: 1, text: 2 };

export const unicode = defineAuditor({
	id: AUDITOR,
	title: "Hidden Unicode",
	description:
		"Finds Trojan Source bidi controls, invisible and zero-width characters, hidden text in Unicode tag characters, variation-selector payloads and homoglyph identifiers in code, docs and agent instruction files.",
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
				(path) =>
					ws.size(path).pipe(
						Effect.map((size) => ({ path, size, kind: kindOf(path) })),
						Effect.orElseSucceed(() => ({
							path,
							size: -1,
							kind: kindOf(path),
						})),
					),
				{ concurrency: 32 },
			);
			const rank = (f: { path: string; kind?: Kind }) =>
				f.kind ? PRIORITY[f.kind] : isBinaryPath(f.path) ? 4 : 3;
			const candidates = sized.sort(
				(a, b) => rank(a) - rank(b) || a.size - b.size,
			);
			const tooLarge: string[] = [];
			let unread = 0;
			let budget = MAX_TOTAL_BYTES;
			const results = yield* Effect.forEach(
				candidates,
				({ path, size, kind }) =>
					Effect.gen(function* () {
						const binary = isBinaryPath(path);
						if (size === 0) return [];
						if (size < 0) {
							unread++;
							return [];
						}
						// Binary formats are only sniffed when small enough to be text.
						if (binary && size > MAX_SCAN_BYTES) return [];
						if (size > MAX_FILE_BYTES) {
							if (kind) tooLarge.push(path);
							return [];
						}
						if (size > budget) {
							unread++;
							return [];
						}
						budget -= size;
						const texts = decodeTexts(yield* ws.readBytes(path), !kind);
						return texts.flatMap((text) =>
							scanUnicode(
								{ path, text },
								{
									kind: kind ?? "code",
									mode: binary || texts.length > 1 ? "quick" : undefined,
								},
							),
						);
					}).pipe(
						Effect.orElseSucceed(() => {
							unread++;
							return [];
						}),
					),
				{ concurrency: 16 },
			);
			const findings = results.flat();
			if (tooLarge.length || unread)
				findings.push(incomplete(tooLarge.sort(), unread));
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
