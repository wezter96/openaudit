import type { Confidence, Severity } from "@openaudit/core";

import { cweUrl, extOf, scrubLine, truncate } from "../util";
import {
	CODE_ONLY,
	decodeSelectors,
	decodeTags,
	type Group,
	isFlagSequence,
	legitimateInvisible,
} from "./chars";
import { type Kind, MARKUP_EXT } from "./kinds";
import type { Place } from "./place";

/* The rules: how each run of hidden characters is judged and described. */

export const AUDITOR = "code.unicode";

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

export type RuleId =
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

export const RULES: Readonly<Record<RuleId, Rule>> = {
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

type Classifier = (seg: Segment, ctx: Context) => Hit | undefined;

const BIDI_CONFIDENCE: Readonly<Record<Kind, Confidence>> = {
	code: "high",
	agent: "medium",
	text: "low",
};

const bidiHit: Classifier = ({ cps, start: index }, { kind }) => ({
	rule: "bidi-control",
	index,
	severity: kind === "text" ? "medium" : "high",
	confidence: BIDI_CONFIDENCE[kind],
	chars: cps,
	message: (list) =>
		kind === "code"
			? `Contains ${list}. Bidirectional controls make code display in a different order than the compiler reads it, hiding logic in comments and strings (Trojan Source, CVE-2021-42574).`
			: `Contains ${list}. Bidirectional controls make text display in a different order than tools and language models read it.`,
});

const markHit: Classifier = ({ cps, start: index }, { kind }) => {
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
};

const tagHit: Classifier = (seg, ctx) => {
	if (isFlagSequence(seg.head, ctx.prev)) return undefined;
	const hidden = decodeTags(seg.head);
	return {
		rule: "tag-characters",
		index: seg.start,
		severity: "high",
		confidence: "high",
		chars: seg.cps,
		message: () =>
			hidden
				? `Invisible Unicode tag characters spell out hidden text: "${truncate(scrubLine(hidden), 120)}". Humans cannot see it but language models and tools read it, a known prompt-injection technique.`
				: "Contains invisible Unicode tag characters, which can carry text that humans cannot see but language models read.",
	};
};

const isPresentationOnly = (cps: ReadonlyArray<number>) =>
	cps.every((c) => c === 0xfe0e || c === 0xfe0f);

/**
 * One selector per character is how variants work. Repeating one
 * presentation selector is a copy-paste slip; mixing U+FE0E and U+FE0F can
 * carry bits.
 */
const isOrdinarySelectorUse = ({ count, cps }: Segment) =>
	count < 2 || (isPresentationOnly(cps) && (count <= 2 || cps.length === 1));

/** A selector after an ASCII letter, which has no variants. */
const isOrphan = ({ count }: Segment, prev: string) =>
	count === 1 && /[A-Za-z]/.test(prev);

const selectorHit: Classifier = (seg, ctx) => {
	const orphan = isOrphan(seg, ctx.prev);
	if (!orphan && isOrdinarySelectorUse(seg)) return undefined;
	const decoded = orphan ? undefined : decodeSelectors(seg.head);
	return {
		rule: "variation-selector-run",
		index: seg.start,
		severity: ctx.kind === "text" ? "medium" : "high",
		confidence: "medium",
		chars: seg.cps,
		message: () =>
			orphan
				? "Variation selectors follow characters that have no variants. One per character is a known way to hide bytes in plain-looking text."
				: `A run of ${seg.count} variation selectors follows one character. Each selector can encode a byte, so this is a known way to hide payloads in code and prompts${decoded ? `; it decodes to "${truncate(scrubLine(decoded), 120)}"` : ""}.`,
	};
};

const isSoftHyphen = (cp: number) => cp === 0x00ad;

const isLeadingBom = ({ start, cps, count }: Segment) =>
	start === 0 && cps[0] === 0xfeff && count === 1;

const proseInvisibleHit: Classifier = ({ cps, start: index }, ctx) => {
	const reported = cps.filter(
		(cp) =>
			!CODE_ONLY.has(cp) &&
			!legitimateInvisible(cp, ctx.prev, ctx.next, "prose"),
	);
	if (!reported.length) return undefined;
	const level = ctx.kind === "agent" ? "medium" : "low";
	return {
		rule: "invisible-character",
		index,
		severity: level,
		confidence: level,
		chars: reported,
		message: (list) =>
			`Contains ${list}, which renders as nothing and makes text differ from what it looks like.`,
	};
};

/** Invisible characters in code, where the lexer places them. */
interface Placed {
	readonly index: number;
	readonly place: Place;
	readonly chars: ReadonlyArray<number>;
}

const untrustedHit = (
	{ index, place, chars }: Placed,
	markup: boolean,
): Hit => {
	// Soft hyphens cannot form identifiers in most languages, so outside
	// plain code they stay medium.
	const hyphens = place.region !== "code" && chars.every(isSoftHyphen);
	return {
		rule: "invisible-character",
		index,
		severity: markup || hyphens ? "medium" : "high",
		confidence: "medium",
		chars,
		message: (list) =>
			place.region === "code"
				? `Contains ${list} outside strings and comments. Invisible characters in code can make two identifiers look identical or hide parameters (the "invisible backdoor").`
				: `Contains ${list} where the scanner cannot be sure it is inside a ${place.region}, so it is judged as code. Invisible characters in code can make two identifiers look identical or hide parameters (the "invisible backdoor").`,
	};
};

const literalMessage =
	(region: Place["region"], separator: boolean) => (list: string) =>
		separator
			? `Contains ${list} in a comment. JavaScript and C# treat it as a line break, so code after it runs although it looks commented out.`
			: region === "string"
				? `Contains ${list} in a string. Strings that look identical can then compare unequal, and reviewers cannot see the difference.`
				: `Contains ${list} in a comment. It hides what reviewers see and often marks pasted text.`;

/** Invisible characters certainly inside a string or comment. */
const literalHit = ({ index, place, chars }: Placed): Hit | undefined => {
	// Soft hyphens are ordinary hyphenation hints in strings and comments.
	if (chars.every(isSoftHyphen)) return undefined;
	// A raw BOM (CSV for Excel) or separator in a string is deliberate data,
	// just invisible; zero-width characters inside words are the risk.
	if (place.region === "string" && chars.every(isDeliberateInString))
		return {
			rule: "invisible-character",
			index,
			severity: "low",
			confidence: "medium",
			chars,
			message: (list) =>
				`Contains a raw ${list} in a string. It is valid but invisible, so reviewers cannot tell it is there; write it as an escape.`,
		};
	const separator = place.region === "comment" && chars.some(isSeparator);
	return {
		rule: "invisible-character",
		index,
		severity: separator ? "high" : "medium",
		confidence: "medium",
		chars,
		message: literalMessage(place.region, separator),
	};
};

/** Certainly inside a string or comment. */
const isTrusted = (place: Place) => place.certain && place.region !== "code";

const lexicalContext = (place: Place) =>
	isTrusted(place) && place.region === "comment" ? "comment" : "code";

/**
 * Soft hyphens are hyphenation hints in markup prose, and identifiers
 * cannot contain them.
 */
const isMarkupHyphen = (cp: number, markup: boolean) =>
	markup && isSoftHyphen(cp);

const codeInvisibleHit: Classifier = ({ cps, start: index }, ctx) => {
	const place = ctx.placeAt(index);
	const trusted = isTrusted(place);
	const markup = MARKUP_EXT.has(extOf(ctx.path));
	const context = lexicalContext(place);
	const chars = cps.filter(
		(cp) =>
			!isMarkupHyphen(cp, markup) &&
			!legitimateInvisible(cp, ctx.prev, ctx.next, context),
	);
	if (!chars.length) return undefined;
	const placed = { index, place, chars };
	return trusted ? literalHit(placed) : untrustedHit(placed, markup);
};

const invisibleHit: Classifier = (seg, ctx) => {
	if (isLeadingBom(seg)) return undefined;
	return ctx.kind === "code"
		? codeInvisibleHit(seg, ctx)
		: proseInvisibleHit(seg, ctx);
};

const CLASSIFIERS: Readonly<Record<Group, Classifier>> = {
	bidi: bidiHit,
	mark: markHit,
	tag: tagHit,
	selector: selectorHit,
	invisible: invisibleHit,
};

export const classify = (seg: Segment, ctx: Context): Hit | undefined =>
	CLASSIFIERS[seg.group](seg, ctx);

export interface Hit {
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

export interface Segment {
	readonly group: Group;
	readonly start: number;
	readonly end: number;
	readonly count: number;
	/** Distinct code points in the segment. */
	readonly cps: ReadonlyArray<number>;
	/** The first MAX_DECODE code points, for decoding payloads. */
	readonly head: ReadonlyArray<number>;
}
