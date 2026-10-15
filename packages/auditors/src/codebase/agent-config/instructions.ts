import type { FindingInput } from "@openaudit/core";

import {
	cweUrl,
	fullLineAt,
	lineLocator,
	owaspLlmUrl,
	type SourceFile,
	scrubLine,
	truncate,
} from "../util";
import { DETAILS, hiddenRegions, type Region } from "./markdown";
import {
	CLAUDE_PERMISSIONS,
	finding,
	MCP_SECURITY,
	PROMPT_INJECTION_TAGS,
} from "./shared";
import { normalize, sentences } from "./text";

/* -------------------------------------------------------------------------- */
/*                           Hidden Unicode characters                        */
/* -------------------------------------------------------------------------- */

const isTag = (cp: number) => cp >= 0xe0000 && cp <= 0xe007f;
const isBidi = (cp: number) =>
	(cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069);
const isVariationSelector = (cp: number) =>
	(cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);
/** Zero-width characters with no legitimate use inside instruction prose. */
const isZeroWidth = (cp: number) =>
	cp === 0x200b ||
	cp === 0x180e ||
	cp === 0xfeff ||
	(cp >= 0x2060 && cp <= 0x2064);
/** ZWNJ/ZWJ, which emoji sequences and several scripts rely on. */
const isJoiner = (cp: number) => cp === 0x200c || cp === 0x200d;

type UnicodeKind = "invisible-text" | "bidi" | "zero-width";

interface UnicodeHit {
	readonly kind: UnicodeKind;
	readonly index: number;
	readonly count: number;
	/** ASCII or UTF-8 text the characters encode (invisible-text only). */
	readonly decoded?: string;
}

/** Text hidden as Unicode tags (U+E0020–U+E007E mirror printable ASCII). */
const decodeTags = (cps: ReadonlyArray<number>): string =>
	String.fromCharCode(
		...cps
			.filter((cp) => cp >= 0xe0020 && cp <= 0xe007e)
			.map((cp) => cp - 0xe0000),
	);

/** Bytes smuggled as variation selectors (VS1–16 = 0–15, VS17–256 = 16–255). */
const decodeSelectors = (cps: ReadonlyArray<number>): string =>
	new TextDecoder().decode(
		new Uint8Array(
			cps.map((cp) => (cp < 0xe0100 ? cp - 0xfe00 : cp - 0xe0100 + 16)),
		),
	);

/** Subdivision flags such as 🏴 + tags `gbsct` + CANCEL TAG. */
const isFlagSequence = (prev: number | undefined, run: ReadonlyArray<number>) =>
	prev === 0x1f3f4 &&
	run.at(-1) === 0xe007f &&
	run
		.slice(0, -1)
		.every(
			(cp) =>
				(cp >= 0xe0030 && cp <= 0xe0039) || (cp >= 0xe0061 && cp <= 0xe007a),
		);

const isZeroWidthOrJoiner = (cp: number) => isZeroWidth(cp) || isJoiner(cp);
const never = () => false;

/** A run of hidden characters and the code points around it. */
interface Run {
	readonly cps: ReadonlyArray<number>;
	readonly prev: number | undefined;
	readonly next: number | undefined;
	readonly index: number;
}

/** One kind of hidden character: what starts a run, what extends it, and when it is a hit. */
interface HiddenKind {
	readonly starts: (cp: number) => boolean;
	readonly extends: (cp: number) => boolean;
	readonly hit: (run: Run) => UnicodeHit | undefined;
}

const isAlnum = (c: number | undefined) =>
	c !== undefined && /[A-Za-z0-9]/.test(String.fromCharCode(c));
const insideWord = (run: Run) => isAlnum(run.prev) && isAlnum(run.next);
/** Several selectors, at least one of them a supplementary one (VS17–256). */
const encodesBytes = (run: Run) =>
	run.cps.length >= 2 && run.cps.some((c) => c >= 0xe0100);

const HIDDEN_KINDS: ReadonlyArray<HiddenKind> = [
	{
		starts: isTag,
		extends: isTag,
		hit: (run) =>
			isFlagSequence(run.prev, run.cps)
				? undefined
				: {
						kind: "invisible-text",
						index: run.index,
						count: run.cps.length,
						decoded: decodeTags(run.cps),
					},
	},
	{
		starts: isVariationSelector,
		extends: isVariationSelector,
		// One selector after an emoji or ideograph is normal; runs encode bytes.
		hit: (run) =>
			encodesBytes(run)
				? {
						kind: "invisible-text",
						index: run.index,
						count: run.cps.length,
						decoded: decodeSelectors(run.cps),
					}
				: undefined,
	},
	{
		starts: isBidi,
		extends: never,
		hit: (run) => ({ kind: "bidi", index: run.index, count: 1 }),
	},
	{
		starts: isZeroWidthOrJoiner,
		extends: isZeroWidthOrJoiner,
		// A lone one at a word or line edge (a leading BOM, an emoji ZWJ
		// sequence, Persian ZWNJ, a docs formatting trick) is ordinary text;
		// inside an ASCII word or as a run it splits keywords or encodes data.
		hit: (run) =>
			run.cps.length >= 2 || insideWord(run)
				? { kind: "zero-width", index: run.index, count: run.cps.length }
				: undefined,
	},
];

/** Code points of `text` with the UTF-16 offset of each. */
const codePoints = (text: string) => {
	const cps: number[] = [];
	const offsets: number[] = [];
	let offset = 0;
	for (const ch of text) {
		cps.push(ch.codePointAt(0) ?? 0);
		offsets.push(offset);
		offset += ch.length;
	}
	return { cps, offsets };
};

/** End (exclusive) of the run from `k` whose code points satisfy `test`. */
const runEnd = (
	cps: ReadonlyArray<number>,
	k: number,
	test: (cp: number) => boolean,
) => {
	let j = k;
	while (j < cps.length && test(cps[j] ?? 0)) j++;
	return j;
};

export const hiddenUnicode = (text: string): UnicodeHit[] => {
	const { cps, offsets } = codePoints(text);
	const hits: UnicodeHit[] = [];
	let k = 0;
	while (k < cps.length) {
		const cp = cps[k] ?? 0;
		const kind = HIDDEN_KINDS.find((h) => h.starts(cp));
		if (!kind) {
			k++;
			continue;
		}
		const end = runEnd(cps, k + 1, kind.extends);
		const hit = kind.hit({
			cps: cps.slice(k, end),
			prev: cps[k - 1],
			next: cps[end],
			index: offsets[k] ?? 0,
		});
		if (hit) hits.push(hit);
		k = end;
	}
	return hits;
};

const isInvisible = (cp: number) =>
	isTag(cp) ||
	isBidi(cp) ||
	isVariationSelector(cp) ||
	isZeroWidth(cp) ||
	isJoiner(cp) ||
	cp === 0x200e ||
	cp === 0x200f;

/** The line with invisible characters spelled out as `<U+XXXX>`. */
const visibleLine = (text: string, index: number): string =>
	truncate(
		scrubLine(
			[...fullLineAt(text, index)]
				.map((c) => {
					const cp = c.codePointAt(0) ?? 0;
					return isInvisible(cp)
						? `<U+${cp.toString(16).toUpperCase().padStart(4, "0")}>`
						: c;
				})
				.join(""),
		),
	);

/** Matches code.unicode's tags, so correlation merges the two at one line. */
const UNICODE_TAGS = ["cwe-451", "hidden-unicode", "owasp-llm01"];
const UNICODE_REFERENCES = [
	owaspLlmUrl("llm01"),
	cweUrl(451),
	"https://www.unicode.org/reports/tr36/#Invisible_Characters",
];

const scanUnicode = (file: SourceFile): FindingInput[] => {
	const { path, text } = file;
	const lineOf = lineLocator(text);
	const byLine = new Map<string, UnicodeHit[]>();
	for (const hit of hiddenUnicode(text)) {
		const key = `${hit.kind}:${lineOf(hit.index)}`;
		byLine.set(key, [...(byLine.get(key) ?? []), hit]);
	}
	const findings: FindingInput[] = [];
	for (const hits of byLine.values()) {
		const first = hits[0] as UnicodeHit;
		const line = lineOf(first.index);
		const count = hits.reduce((n, h) => n + h.count, 0);
		if (first.kind === "invisible-text") {
			const decoded = hits
				.map((h) => h.decoded ?? "")
				.join(" ")
				.trim();
			findings.push(
				finding("hidden-unicode-invisible-text", path, line, {
					title: "Invisible text in an agent instruction file",
					severity: "high",
					category: "security",
					message: `${path} line ${line} contains ${count} invisible Unicode tag or variation-selector characters that encode text. Models read it; editors, diffs and code review do not show it, which is how instructions are smuggled past reviewers.`,
					evidence: truncate(`hidden text: "${scrubLine(decoded)}"`),
					remediation:
						"Delete the invisible characters (re-type the line) and review who added them. Block U+E0000–U+E007F and variation-selector runs in instruction files with a pre-commit or CI check.",
					references: UNICODE_REFERENCES,
					confidence: "high",
					tags: UNICODE_TAGS,
				}),
			);
		} else if (first.kind === "bidi") {
			findings.push(
				finding("hidden-unicode-bidi", path, line, {
					title: "Bidirectional control character in an agent instruction file",
					severity: "high",
					category: "security",
					message: `${path} line ${line} contains ${count} bidirectional override/isolate character(s), which make the displayed text differ from what the agent reads (Trojan Source).`,
					evidence: visibleLine(text, first.index),
					remediation:
						"Remove the bidi control characters. Instruction files have no need for U+202A–U+202E or U+2066–U+2069.",
					references: [...UNICODE_REFERENCES, "https://trojansource.codes/"],
					confidence: "medium",
					tags: UNICODE_TAGS,
				}),
			);
		} else {
			findings.push(
				finding("hidden-unicode-zero-width", path, line, {
					title: "Zero-width characters in an agent instruction file",
					severity: "medium",
					category: "security",
					message: `${path} line ${line} contains ${count} zero-width character(s). They are invisible in review and can split keywords or encode hidden data for the agent.`,
					evidence: visibleLine(text, first.index),
					remediation:
						"Remove the zero-width characters. If they came from copy-pasting, retype the line.",
					references: UNICODE_REFERENCES,
					confidence: "medium",
					tags: UNICODE_TAGS,
				}),
			);
		}
	}
	return findings;
};

/* -------------------------------------------------------------------------- */
/*                         Hidden and unsafe instructions                     */
/* -------------------------------------------------------------------------- */

/** Local credential stores an injected instruction would point the agent at. */
const CREDENTIAL_PATH =
	/~\/\.ssh\b|\.ssh\/id_|\bid_(?:rsa|ecdsa|ed25519)\b|~\/\.aws\b|\.aws\/credentials|~\/\.(?:npmrc|netrc|pypirc|git-credentials|docker\/config\.json|kube\/config)|(?:^|[\s"'`(])\.env\b|\bprintenv\b/i;
/** Sending something to a remote destination. */
const SEND_SOMEWHERE =
	/\b(?:send|post|upload|transmit|forward|exfiltrat\w*|leak)\b[^\n]{0,80}\b(?:to|into)\b[^\n]{0,40}(?:https?:\/\/|\b[\w-]+\.(?:com|net|org|io|dev|xyz|sh|ru|cn|app|site)\b|webhook|pastebin|gist)|\b(?:curl|wget)\b[^\n]{0,120}(?:\s-d\b|--data|\s-F\b|--form|\s-T\b|--upload-file|\s@)/i;

interface InstructionPattern {
	readonly label: string;
	readonly test: (text: string) => number | undefined;
	/** Also suspicious in a collapsed <details> block, which readers can open. */
	readonly inDetails: boolean;
}

const at = (re: RegExp) => (text: string) => re.exec(text)?.index;

/** Agent-directed imperatives that have no business being hidden. */
const HIDDEN_INSTRUCTIONS: ReadonlyArray<InstructionPattern> = [
	{
		label: "tells the agent to ignore its other instructions",
		inDetails: true,
		test: at(
			/\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?(?:(?:the|your)\s+)?(?:previous|prior|above|earlier|preceding|other|system|original)\s+(?:instructions?|prompts?|rules|directions|guidelines)\b/i,
		),
	},
	{
		label: "tells the agent to hide what it does from the user",
		inDetails: true,
		test: at(
			/\b(?:do\s+not|don't|never)\s+(?:tell|inform|mention\s+(?:this\s+|it\s+)?to|reveal\s+(?:this\s+|it\s+)?to|notify|alert|warn)\s+(?:the\s+)?(?:user|human|developer|reviewer|operator|maintainer)s?\b|\bwithout\s+(?:telling|informing|notifying|alerting)\s+(?:the\s+)?(?:user|human|developer|reviewer)s?\b|\b(?:hide|conceal|keep)\s+(?:this|it)\s+(?:secret\s+|hidden\s+)?from\s+(?:the\s+)?(?:user|human|developer|reviewer)s?\b/i,
		),
	},
	{
		label: "asks the agent to exfiltrate data",
		inDetails: true,
		test: at(/\bexfiltrate\b/i),
	},
	{
		// Collapsed install sections legitimately hold `curl … | sh`.
		label: "pipes a download into a shell",
		inDetails: false,
		test: at(
			/\b(?:curl|wget)\b[^|\n]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|\n]{0,200}\|\s*(?:iex|invoke-expression)\b/i,
		),
	},
	{
		label: "sends local credentials somewhere",
		inDetails: true,
		test: (text) =>
			SEND_SOMEWHERE.test(text) ? CREDENTIAL_PATH.exec(text)?.index : undefined,
	},
	{
		label: "decodes and runs an encoded payload",
		inDetails: true,
		test: at(
			/\bbase64\s+(?:-d|--decode|-D)\b[^\n]{0,60}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\b(?:eval|exec)\s*\(\s*(?:atob|base64|Buffer\.from)\b/i,
		),
	},
];

/** Flags and settings that switch off an agent's approval prompts or sandbox. */
const SAFETY_FLAGS: ReadonlyArray<RegExp> = [
	// One or two dashes (an em dash folds to one), any case, singular too.
	/(?<![\w-])--?dangerously-skip-permissions?\b/i,
	/(?<![\w-])--?dangerously-bypass-approvals?-and-sandbox\b/i,
	/(?:(?<![\w-])--?permission-mode[ =:]\s*|defaultMode"?\s*[:=]\s*"?)bypassPermissions\b/i,
	/(?<![\w-])--?approval-mode[ =:]\s*yolo\b|(?<![\w-])--?yolo\b/i,
	/(?:(?<![\w-])--?sandbox[ =:]\s*|sandbox_mode\s*=\s*"?)danger-full-access\b/i,
	/(?<![\w-])--?allow-all-tools\b/i,
	/(?<![\w-])--?trust-all-tools\b/i,
];
/** The same thing in words, only as an imperative that opens a sentence. */
const SAFETY_IMPERATIVE =
	/^(?:[-*+>]\s+|\d+[.)]\s+)?(?:please\s+|always\s+|you\s+(?:should|must|can|may)\s+)?(?:disable|turn\s+off|bypass)\s+(?:the\s+|your\s+|all\s+)?(?:sandbox(?:ing)?|permission\s+(?:prompts?|checks?)|approval\s+prompts?)(?=\s*(?:$|[.,;:!)]|\s(?:and|so|for|when|entirely|completely)\b))|^(?:[-*+>]\s+|\d+[.)]\s+)?(?:please\s+|always\s+)?auto-?approve\s+(?:all|every|any)\b/i;

const NEGATION =
	/\b(?:never|not|no|avoid|without|unless|forbid\w*|prohibit\w*|disallow\w*|instead\s+of|rather\s+than)\b|n't\b/i;
/** "Don't forget to", "never hesitate to": negation words that negate nothing. */
const NOT_NEGATION =
	/\b(?:do\s+not|don't|dont|never|not)\s+(?:forget|hesitate|fail|neglect|omit)\b|\bnot\s+only\b|\bno\s+matter\b/gi;

const VERB =
	"(?:use|run|start|launch|enable|set|invoke|execute|pass|add|append|include|call|switch\\s+to)(?![\\w-])";
const LIST_MARK = "(?:[-+>]\\s+|\\d+[.)]\\s+|#+\\s+)?";
/**
 * Something that tells the reader to do it: an imperative opening the
 * sentence after lead-ins ("Then, run …", "Claude, run …"), a modal ("you
 * must pass …"), "it's required to …", "make sure to …", a label ("Flags:
 * --yolo"), or "always" anywhere. Descriptions ("Live runs launch …") are not.
 */
const IMPERATIVE_CUE = new RegExp(
	[
		`^${LIST_MARK}(?:(?:then|first|next|now|also|finally|just|simply|please|always|instead|so|and)\\b,?\\s+|[\\w-]{1,30},\\s+){0,3}${VERB}`,
		`\\b(?:you|agents?|claude|codex|gemini|copilot|cursor|the\\s+agent)\\s+(?:should|must|need\\s+to|have\\s+to|are\\s+(?:required|expected)\\s+to)\\s+(?:always\\s+)?${VERB}`,
		`\\b(?:it's|it\\s+is|this\\s+is)\\s+(?:required|mandatory|necessary|important)\\s+to\\s+${VERB}`,
		"\\b(?:make\\s+sure|be\\s+sure|remember|don't\\s+forget|do\\s+not\\s+forget|never\\s+forget)\\s+(?:to|you)\\b",
		`^${LIST_MARK}(?:flags?|options?|args?|arguments?|command|cmd|usage|invocation|launch|run|start)\\s*:`,
		"(?<![\\w-])always(?![\\w-])",
	].join("|"),
	"i",
);
/**
 * A stated, un-negated scope: "only in …", "inside a disposable VM", "in CI".
 * "we're not in a container" does not count.
 */
const ISOLATED_CONTEXT =
	/(?<!(?:\b(?:not|never|no)|n't|\boutside(?:\s+of)?)\s{1,3})\b(?:only\s+(?:in|inside|within|when|if|for|on)\b|(?:in|inside|within|on)\s+(?:an?\s+|the\s+|your\s+|our\s+|its\s+)?(?:[\w-]+\s+){0,2}?(?:sandbox(?:ed)?|containers?|devcontainers?|vms?|virtual\s+machines?|codespaces?|ci)\b)/i;

/** Offset within `sentence` of an un-negated safety bypass, if any. */
const safetyBypass = (
	sentence: string,
	imperative: boolean,
): number | undefined => {
	const words = SAFETY_IMPERATIVE.exec(sentence.trim());
	if (words) return sentence.length - sentence.trimStart().length;
	for (const re of SAFETY_FLAGS) {
		const m = re.exec(sentence);
		if (!m) continue;
		const before = sentence.slice(0, m.index);
		const rest = before + sentence.slice(m.index + m[0].length);
		if (
			NEGATION.test(before.replace(NOT_NEGATION, " ")) ||
			ISOLATED_CONTEXT.test(rest)
		)
			continue;
		if (imperative || IMPERATIVE_CUE.test(before.trimStart())) return m.index;
	}
	return undefined;
};

/** Raw offset of the first un-negated safety bypass in `raw`, if any. */
const bypassIn = (
	raw: string,
	offset: number,
	imperative: boolean,
): number | undefined => {
	for (const [start, end] of sentences(raw)) {
		const norm = normalize(raw.slice(start, end));
		const i = safetyBypass(norm.text, imperative);
		if (i !== undefined) return offset + start + (norm.source[i] ?? 0);
	}
	return undefined;
};

/** A file being scanned and how to turn offsets into lines. */
interface Scan {
	readonly file: SourceFile;
	readonly lineOf: (offset: number) => number;
}

interface Match {
	readonly label: string;
	readonly index: number;
}

/** What a hidden region tells the agent to do, at raw offsets. */
const regionMatches = (text: string, region: Region): Match[] => {
	const raw = text.slice(region.start, region.end);
	const body = normalize(raw);
	const details = region.kind === DETAILS;
	const matches = HIDDEN_INSTRUCTIONS.flatMap((p) => {
		if (details && !p.inDetails) return [];
		const i = p.test(body.text);
		return i === undefined
			? []
			: [{ label: p.label, index: region.start + (body.source[i] ?? 0) }];
	});
	const bypass = bypassIn(raw, region.start, true);
	if (bypass !== undefined)
		matches.push({
			label: "disables the agent's approval prompts or sandbox",
			index: bypass,
		});
	return matches;
};

const hiddenInstructions = (
	{ file, lineOf }: Scan,
	hidden: ReadonlyArray<Region>,
): FindingInput[] => {
	const { path, text } = file;
	const reportedLines = new Set<number>();
	return hidden.flatMap((region) => {
		const matches = regionMatches(text, region);
		if (matches.length === 0) return [];
		const index = Math.min(...matches.map((m) => m.index));
		// Overlapping regions (a comment inside a hidden element) report once.
		if (reportedLines.has(lineOf(index))) return [];
		reportedLines.add(lineOf(index));
		return [
			finding("hidden-instruction", path, lineOf(index), {
				title: "Hidden instruction in an agent instruction file",
				severity: "high",
				category: "security",
				message: `${path} has ${region.kind} that is hidden in the rendered view but read verbatim by the agent, and it ${matches.map((m) => m.label).join("; ")}. This is the shape of an indirect prompt injection.`,
				evidence: visibleLine(text, index),
				remediation:
					"Read the raw file. If you did not write this, remove it and find out how it got in. Keep instructions for agents visible so reviewers see exactly what the agent is told.",
				references: [owaspLlmUrl("llm01"), cweUrl(1427), MCP_SECURITY],
				confidence: "low",
				tags: PROMPT_INJECTION_TAGS,
			}),
		];
	});
};

/** `text` with hidden regions blanked (keeping line breaks), so only visible text is read. */
const visibleText = (text: string, hidden: ReadonlyArray<Region>): string => {
	const parts: string[] = [];
	let last = 0;
	for (const r of [...hidden].sort((a, b) => a.start - b.start)) {
		const start = Math.max(r.start, last);
		if (r.end <= start) continue;
		parts.push(
			text.slice(last, start),
			text.slice(start, r.end).replace(/[^\n]/g, " "),
		);
		last = r.end;
	}
	parts.push(text.slice(last));
	return parts.join("");
};

const safetyBypasses = (
	{ file, lineOf }: Scan,
	visible: string,
): FindingInput[] => {
	const { path, text } = file;
	const flagged = new Set<number>();
	return sentences(visible).flatMap(([start, end]) => {
		const index = bypassIn(visible.slice(start, end), start, false);
		if (index === undefined || flagged.has(lineOf(index))) return [];
		flagged.add(lineOf(index));
		return [
			finding("instruction-disables-safety", path, lineOf(index), {
				title: "Agent told to bypass its safety controls",
				severity: "medium",
				category: "security",
				message: `${path} instructs the agent (or whoever starts it) to skip approval prompts or the sandbox, so every command and edit the agent decides on runs unreviewed, including ones planted by a prompt injection.`,
				evidence: visibleLine(text, index),
				remediation:
					"Remove the instruction. Grant narrow allow rules for the commands the agent needs instead, and run fully unattended agents only inside a disposable container or VM.",
				references: [owaspLlmUrl("llm06"), CLAUDE_PERMISSIONS],
				confidence: "low",
				tags: ["owasp-llm06"],
			}),
		];
	});
};

const scanInstructions = (file: SourceFile): FindingInput[] => {
	const scan: Scan = { file, lineOf: lineLocator(file.text) };
	const hidden = hiddenRegions(file.text);
	return [
		...hiddenInstructions(scan, hidden),
		...safetyBypasses(scan, visibleText(file.text, hidden)),
	];
};

/** Hidden Unicode plus hidden or safety-disabling instructions. Exported for tests. */
export const scanInstructionFile = (file: SourceFile): FindingInput[] => [
	...scanUnicode(file),
	...scanInstructions(file),
];
