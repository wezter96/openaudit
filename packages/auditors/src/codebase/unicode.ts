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
	"svg",
	"html",
	"htm",
	"xhtml",
]);

/** Instruction and rule files that coding agents load into their prompt. */
const AGENT_FILE =
	/(^|\/)(AGENTS?|CLAUDE|CLAUDE\.local|GEMINI|SKILL)\.md$|(^|\/)\.(cursorrules|windsurfrules|clinerules)$|\.mdc$|(^|\/)\.github\/(copilot-instructions\.md|(instructions|prompts|chatmodes|agents)\/[^/]+\.md)$|(^|\/)\.(cursor\/rules|clinerules|windsurf\/rules|kiro\/steering|roo\/rules[^/]*|continue\/rules|amazonq\/rules|claude\/(commands|agents|skills))\//i;

/** Sources that interleave prose with code (JSX, component templates). */
const MARKUP_EXT = new Set(["jsx", "tsx", "vue", "svelte", "astro"]);

const kindOf = (path: string): Kind | undefined => {
	if (AGENT_FILE.test(path)) return "agent";
	const ext = extOf(path);
	if (
		languageOf(path) ||
		CODE_EXT.has(ext) ||
		CODE_NAME.test(baseName(path)) ||
		/(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/.test(path)
	)
		return "code";
	if (TEXT_EXT.has(ext) || /^\.env(\.|$)/.test(baseName(path))) return "text";
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

/** True when an invisible character is plausibly part of the text around it. */
const legitimateInvisible = (cp: number, prev: string, next: string) => {
	switch (cp) {
		case 0x200d:
			return (
				isEmojiPart(prev) ||
				isEmojiPart(next) ||
				isComplexScript(prev) ||
				isComplexScript(next)
			);
		case 0x200b:
			// `**\u200B/` keeps a glob from closing a block comment.
			if (prev === "*" && next === "/") return true;
			return isComplexScript(prev) || isComplexScript(next);
		case 0x200c:
		case 0x2060:
			return isComplexScript(prev) || isComplexScript(next);
		case 0x180e:
			return /\p{Script=Mongolian}/u.test(prev + next);
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

/** Subdivision flags such as England: U+1F3F4, tag letters, CANCEL TAG. */
const isFlagSequence = (cps: ReadonlyArray<number>, before: string): boolean =>
	before === "\u{1F3F4}" &&
	cps.length >= 3 &&
	cps.length <= 7 &&
	cps.at(-1) === 0xe007f &&
	cps
		.slice(0, -1)
		.every(
			(cp) =>
				(cp >= 0xe0030 && cp <= 0xe0039) || (cp >= 0xe0061 && cp <= 0xe007a),
		);

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

/** Line and paragraph separators end `//` comments in JS but are valid in strings. */
const isSeparator = (cp: number) => cp === 0x2028 || cp === 0x2029;

const isDeliberateInString = (cp: number) => isSeparator(cp) || cp === 0xfeff;

interface Context {
	readonly kind: Kind;
	readonly path: string;
	readonly prev: string;
	readonly next: string;
	readonly regionAt: (index: number) => Region;
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
			if (seg.count < 2 || cps.every((c) => c === 0xfe0e || c === 0xfe0f))
				return undefined;
			const decoded = decodeSelectors(seg.head);
			return {
				rule: "variation-selector-run",
				index,
				severity: kind === "text" ? "medium" : "high",
				confidence: "medium",
				chars: cps,
				message: () =>
					`A run of ${seg.count} variation selectors follows one character. Each selector can encode a byte, so this is a known way to hide payloads in code and prompts${decoded ? `; it decodes to "${truncate(scrubLine(decoded), 120)}"` : ""}.`,
			};
		}
		case "invisible": {
			if (index === 0 && cps[0] === 0xfeff && seg.count === 1) return undefined;
			const reported = cps.filter(
				(cp) =>
					!legitimateInvisible(cp, ctx.prev, ctx.next) &&
					(kind === "code" || !CODE_ONLY.has(cp)),
			);
			if (!reported.length) return undefined;
			if (kind !== "code")
				return {
					rule: "invisible-character",
					index,
					severity: kind === "agent" ? "medium" : "low",
					confidence: kind === "agent" ? "medium" : "low",
					chars: reported,
					message: (list) =>
						`Contains ${list}, which renders as nothing and makes text differ from what it looks like.`,
				};
			const region = ctx.regionAt(index);
			// Soft hyphens are ordinary hyphenation hints inside strings and comments.
			if (region !== "code" && reported.every((cp) => cp === 0x00ad))
				return undefined;
			// A raw BOM (CSV for Excel) or separator in a string is deliberate data,
			// just invisible; zero-width characters inside words are the risk.
			if (region === "string" && reported.every(isDeliberateInString))
				return {
					rule: "invisible-character",
					index,
					severity: "low",
					confidence: "medium",
					chars: reported,
					message: (list) =>
						`Contains a raw ${list} in a string. It is valid but invisible, so reviewers cannot tell it is there; write it as an escape.`,
				};
			const [severity, why]: [Severity, string] =
				region === "code"
					? [
							MARKUP_EXT.has(extOf(ctx.path)) ? "medium" : "high",
							'outside strings and comments. Invisible characters in code can make two identifiers look identical or hide parameters (the "invisible backdoor").',
						]
					: region === "string"
						? [
								"medium",
								"in a string. Strings that look identical can then compare unequal, and reviewers cannot see the difference.",
							]
						: reported.some(isSeparator)
							? [
									"high",
									"in a comment. JavaScript and C# treat it as a line break, so code after it runs although it looks commented out.",
								]
							: [
									"low",
									"in a comment. It does not change behaviour there, but it hides what reviewers see and often marks pasted text.",
								];
			return {
				rule: "invisible-character",
				index,
				severity,
				confidence: "medium",
				chars: reported,
				message: (list) => `Contains ${list} ${why}`,
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
	const kind = options.kind ?? kindOf(path) ?? "text";
	if (!/[^\p{ASCII}]/u.test(text)) return [];
	const mode = options.mode ?? modeOf(file);
	const lang = kind === "code" ? languageOf(path) : undefined;
	let regions: Uint8Array | undefined;
	let regionsDone = false;
	// 0 code, 1 string, 2 comment. The mask fills comments from their opening
	// delimiter but strings from after the quote, so one pass tells them apart.
	const regionAt = (index: number): Region => {
		if (!regionsDone) {
			regionsDone = true;
			regions = lang ? regionMap(text, lang) : undefined;
		}
		const r = regions?.[index] ?? 0;
		return r === 0 ? "code" : r === 1 ? "string" : "comment";
	};
	const lines = indexLines(text);
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
			if (mode === "quick" && (group === "mark" || group === "invisible"))
				continue;
			const hit = classify(
				{ group, start, end: i, count, cps: [...cps], head },
				{
					kind,
					path,
					prev: charBefore(text, start),
					next: charAt(text, i),
					regionAt,
				},
			);
			if (hit) found.add(hit);
		}
	}

	if (mode === "thorough" && lang && /[\u0370-\u052F]/.test(text))
		for (const h of findHomoglyphs(text, (i) => regionAt(i) === "code"))
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

/** Code/string/comment map from the lexer; undefined if it cannot lex. */
const regionMap = (text: string, lang: string): Uint8Array | undefined => {
	let mask: Uint8Array;
	try {
		mask = nonCodeMask(text, lang);
	} catch {
		return undefined; // treat everything as code: the stricter reading
	}
	const regions = new Uint8Array(text.length);
	for (let i = 0; i < text.length; i++) {
		if (!mask[i]) continue;
		regions[i] =
			i > 0 && mask[i - 1]
				? (regions[i - 1] ?? 1)
				: /^(\/\/|\/\*|#)/.test(text.slice(i, i + 2))
					? 2
					: 1;
	}
	return regions;
};

/* ---------------------------------- run ----------------------------------- */

/** Files read per audit; beyond this the scan reports itself incomplete. */
const MAX_FILES = 20_000;
/** Largest file scanned (quick mode above MAX_SCAN_BYTES). */
const MAX_FILE_BYTES = 16 * 1024 * 1024;
/** Total bytes read per audit. */
const MAX_TOTAL_BYTES = 512 * 1024 * 1024;

/**
 * Decodes file bytes. UTF-16 (with a BOM, or detected from the NUL pattern of
 * mostly-ASCII text) is decoded as such, because compilers such as tsc and
 * csc read it. Returns undefined for binary content when `sniff` is set; for
 * known text kinds a NUL never hides the file.
 */
export const decodeText = (
	bytes: Uint8Array,
	sniff: boolean,
): string | undefined => {
	if (bytes[0] === 0xff && bytes[1] === 0xfe)
		return new TextDecoder("utf-16le").decode(bytes);
	if (bytes[0] === 0xfe && bytes[1] === 0xff)
		return new TextDecoder("utf-16be").decode(bytes);
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
			return new TextDecoder("utf-16le").decode(bytes);
		if (even > half * 0.6 && odd < half * 0.1)
			return new TextDecoder("utf-16be").decode(bytes);
		if (sniff) return undefined;
	}
	return new TextDecoder().decode(bytes);
};

/** Agent files first, so caps never push them out of the scan. */
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
			const candidates = (yield* ws.files)
				.map((path) => ({ path, kind: kindOf(path) }))
				.sort(
					(a, b) =>
						(a.kind ? PRIORITY[a.kind] : 3) - (b.kind ? PRIORITY[b.kind] : 3),
				);
			const tooLarge: string[] = [];
			let unread = Math.max(0, candidates.length - MAX_FILES);
			let budget = MAX_TOTAL_BYTES;
			const results = yield* Effect.forEach(
				candidates.slice(0, MAX_FILES),
				({ path, kind }) =>
					Effect.gen(function* () {
						const binary = isBinaryPath(path);
						const size = yield* ws.size(path);
						if (size === 0) return [];
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
						const text = decodeText(yield* ws.readBytes(path), !kind);
						if (text === undefined) return [];
						return scanUnicode(
							{ path, text },
							{
								kind: kind ?? (text.startsWith("#!") ? "code" : "text"),
								mode: binary ? "quick" : undefined,
							},
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
		parts.push(
			`${unread} beyond the ${MAX_FILES}-file / 512 MB budget or unreadable`,
		);
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
