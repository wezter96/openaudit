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
import {
	CLAUDE_PERMISSIONS,
	finding,
	MCP_SECURITY,
	PROMPT_INJECTION_TAGS,
} from "./shared";

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

export const hiddenUnicode = (text: string): UnicodeHit[] => {
	const cps: number[] = [];
	const offsets: number[] = [];
	let offset = 0;
	for (const ch of text) {
		cps.push(ch.codePointAt(0) ?? 0);
		offsets.push(offset);
		offset += ch.length;
	}
	const hits: UnicodeHit[] = [];
	/** End (exclusive) of the run starting at `k` whose code points satisfy `test`. */
	const runEnd = (k: number, test: (cp: number) => boolean) => {
		let j = k;
		while (j < cps.length && test(cps[j] ?? 0)) j++;
		return j;
	};
	let k = 0;
	while (k < cps.length) {
		const cp = cps[k] ?? 0;
		const index = offsets[k] ?? 0;
		if (isTag(cp)) {
			const end = runEnd(k, isTag);
			const run = cps.slice(k, end);
			if (!isFlagSequence(cps[k - 1], run))
				hits.push({
					kind: "invisible-text",
					index,
					count: run.length,
					decoded: decodeTags(run),
				});
			k = end;
		} else if (isVariationSelector(cp)) {
			const end = runEnd(k, isVariationSelector);
			const run = cps.slice(k, end);
			// One selector after an emoji or ideograph is normal; runs encode bytes.
			if (run.length >= 2 && run.some((c) => c >= 0xe0100))
				hits.push({
					kind: "invisible-text",
					index,
					count: run.length,
					decoded: decodeSelectors(run),
				});
			k = end;
		} else if (isBidi(cp)) {
			hits.push({ kind: "bidi", index, count: 1 });
			k++;
		} else if (isZeroWidth(cp) || isJoiner(cp)) {
			const end = runEnd(k, (c) => isZeroWidth(c) || isJoiner(c));
			const run = cps.slice(k, end);
			// A lone one at a word or line edge (a leading BOM, an emoji ZWJ
			// sequence, Persian ZWNJ, a docs formatting trick) is ordinary text;
			// inside an ASCII word or as a run it splits keywords or encodes data.
			const isAlnum = (c: number | undefined) =>
				c !== undefined && /[A-Za-z0-9]/.test(String.fromCharCode(c));
			if (run.length >= 2 || (isAlnum(cps[k - 1]) && isAlnum(cps[end])))
				hits.push({ kind: "zero-width", index, count: run.length });
			k = end;
		} else k++;
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

interface Region {
	readonly start: number;
	readonly end: number;
	readonly kind: string;
}

/** Fenced code blocks (``` or ~~~), as [start, end) offsets. */
const fencedBlocks = (text: string): Region[] => {
	const blocks: Region[] = [];
	const re = /^ {0,3}(`{3,}|~{3,})[^\n]*$/gm;
	let open: { start: number; fence: string } | undefined;
	for (const m of text.matchAll(re)) {
		const fence = m[1] ?? "";
		const index = m.index ?? 0;
		if (!open) open = { start: index, fence };
		else if (fence[0] === open.fence[0] && fence.length >= open.fence.length) {
			blocks.push({
				start: open.start,
				end: index + m[0].length,
				kind: "code",
			});
			open = undefined;
		}
	}
	if (open) blocks.push({ start: open.start, end: text.length, kind: "code" });
	return blocks;
};

const within = (regions: ReadonlyArray<Region>, index: number) =>
	regions.some((r) => index >= r.start && index < r.end);

const DETAILS = "a collapsed <details> block";

/** Parts of a Markdown file that the rendered view hides from a reviewer. */
export const hiddenRegions = (text: string): Region[] => {
	const fences = fencedBlocks(text);
	const regions: Region[] = [];
	for (const m of text.matchAll(/<!--([\s\S]*?)(?:-->|$)/g)) {
		const start = (m.index ?? 0) + 4;
		regions.push({
			start,
			end: start + (m[1] ?? "").length,
			kind: "an HTML comment",
		});
	}
	for (const m of text.matchAll(
		/<details\b(?![^>]*\bopen\b)[^>]*>([\s\S]*?)<\/details>/gi,
	)) {
		const body = m[1] ?? "";
		const summaryEnd = body.search(/<\/summary>/i);
		const skipSummary =
			summaryEnd === -1 ? 0 : summaryEnd + "</summary>".length;
		const start = (m.index ?? 0) + m[0].indexOf(body) + skipSummary;
		regions.push({
			start,
			end: start + body.length - skipSummary,
			kind: DETAILS,
		});
	}
	for (const m of text.matchAll(
		/^\[(?:\/\/|comment|_)\]:\s*(?:#|<>)\s*(.*)$/gm,
	)) {
		const body = m[1] ?? "";
		const start = (m.index ?? 0) + m[0].length - body.length;
		regions.push({
			start,
			end: start + body.length,
			kind: "a Markdown link-reference comment",
		});
	}
	return regions.filter((r) => !within(fences, r.start));
};

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
	/--dangerously-skip-permissions\b/,
	/--dangerously-bypass-approvals-and-sandbox\b/,
	/(?:--permission-mode[ =]|defaultMode"?\s*[:=]\s*"?)bypassPermissions\b/,
	/--approval-mode[ =]yolo\b|(?<![\w-])--yolo\b/,
	/(?:--sandbox[ =]|sandbox_mode\s*=\s*"?)danger-full-access\b/,
	/--allow-all-tools\b/,
	/--trust-all-tools\b/,
];
/** The same thing in words, only as an imperative that opens a sentence. */
const SAFETY_IMPERATIVE =
	/^(?:[-*+>]\s+|\d+[.)]\s+)?(?:please\s+|always\s+|you\s+(?:should|must|can|may)\s+)?(?:disable|turn\s+off|bypass)\s+(?:the\s+|your\s+|all\s+)?(?:sandbox(?:ing)?|permission\s+(?:prompts?|checks?)|approval\s+prompts?)(?=\s*(?:$|[.,;:!)]|\s(?:and|so|for|when|entirely|completely)\b))|^(?:[-*+>]\s+|\d+[.)]\s+)?(?:please\s+|always\s+)?auto-?approve\s+(?:all|every|any)\b/i;

const NEGATION =
	/\b(?:never|not|no|avoid|without|unless|forbid\w*|prohibit\w*|disallow\w*|instead\s+of|rather\s+than)\b|n't\b/i;
const IMPERATIVE_CUE =
	/(?<![\w-])(?:always|use|run|start|launch|enable|set|invoke|execute|pass|add|switch\s+to)(?![\w-])/i;
/** "only in a container", "inside the devcontainer": a scoped, deliberate choice. */
const ISOLATED_CONTEXT =
	/\bonly\s+(?:in|inside|within|when|if|for)\b|\b(?:sandbox(?:ed)?|container|devcontainer|vm|virtual\s+machine|isolated|disposable|ephemeral)\b/i;

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
		if (NEGATION.test(before) || ISOLATED_CONTEXT.test(rest)) continue;
		if (imperative || IMPERATIVE_CUE.test(before)) return m.index;
	}
	return undefined;
};

const scanInstructions = (file: SourceFile): FindingInput[] => {
	const { path, text } = file;
	const lineOf = lineLocator(text);
	const findings: FindingInput[] = [];
	const hidden = hiddenRegions(text);

	for (const region of hidden) {
		const body = text.slice(region.start, region.end);
		const details = region.kind === DETAILS;
		const matches = HIDDEN_INSTRUCTIONS.flatMap((p) => {
			if (details && !p.inDetails) return [];
			const i = p.test(body);
			return i === undefined ? [] : [{ label: p.label, index: i }];
		});
		const bypass = body
			.split(/(?<=[.;!?])\s+|\n/)
			.map((s) => ({ s, i: safetyBypass(s, true) }))
			.find((x) => x.i !== undefined);
		if (bypass)
			matches.push({
				label: "disables the agent's approval prompts or sandbox",
				index: body.indexOf(bypass.s) + (bypass.i ?? 0),
			});
		if (matches.length === 0) continue;
		const first = matches.reduce((a, b) => (b.index < a.index ? b : a));
		const index = region.start + first.index;
		findings.push(
			finding("hidden-instruction", path, lineOf(index), {
				title: "Hidden instruction in an agent instruction file",
				severity: "high",
				category: "security",
				message: `${path} has ${region.kind} that is hidden in the rendered view but read verbatim by the agent, and it ${matches.map((m) => m.label).join("; ")}. This is the shape of an indirect prompt injection.`,
				evidence: truncate(scrubLine(fullLineAt(text, index))),
				remediation:
					"Read the raw file. If you did not write this, remove it and find out how it got in. Keep instructions for agents visible so reviewers see exactly what the agent is told.",
				references: [owaspLlmUrl("llm01"), cweUrl(1427), MCP_SECURITY],
				confidence: "low",
				tags: PROMPT_INJECTION_TAGS,
			}),
		);
	}

	let lineStart = 0;
	for (const line of text.split("\n")) {
		const start = lineStart;
		lineStart += line.length + 1;
		if (within(hidden, start)) continue;
		for (const sentence of line.split(/(?<=[.;!?])\s+/)) {
			const i = safetyBypass(sentence, false);
			if (i === undefined) continue;
			findings.push(
				finding("instruction-disables-safety", path, lineOf(start), {
					title: "Agent told to bypass its safety controls",
					severity: "medium",
					category: "security",
					message: `${path} instructs the agent (or whoever starts it) to skip approval prompts or the sandbox, so every command and edit the agent decides on runs unreviewed, including ones planted by a prompt injection.`,
					evidence: truncate(scrubLine(line)),
					remediation:
						"Remove the instruction. Grant narrow allow rules for the commands the agent needs instead, and run fully unattended agents only inside a disposable container or VM.",
					references: [owaspLlmUrl("llm06"), CLAUDE_PERMISSIONS],
					confidence: "low",
					tags: ["owasp-llm06"],
				}),
			);
			break;
		}
	}
	return findings;
};

/** Hidden Unicode plus hidden or safety-disabling instructions. Exported for tests. */
export const scanInstructionFile = (file: SourceFile): FindingInput[] => [
	...scanUnicode(file),
	...scanInstructions(file),
];
