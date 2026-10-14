import { type FindingInput, severityRank } from "@openaudit/core";

import {
	isFixturePath,
	isGeneratedPath,
	isLockfile,
	isMinifiedPath,
	languageOf,
	looksMinified,
	MAX_SCAN_BYTES,
	type SourceFile,
} from "../util";
import {
	charAt,
	charBefore,
	charList,
	groupOf,
	HIDDEN,
	MAX_DECODE,
} from "./chars";
import { evidenceAt, indexLines, type Lines } from "./evidence";
import { findHomoglyphs } from "./homoglyphs";
import { type Kind, kindOf } from "./kinds";
import { placeFinder } from "./place";
import { AUDITOR, classify, type Hit, RULES, type RuleId } from "./rules";

/** Findings per rule per file; the last one counts the rest. */
const MAX_PER_RULE = 20;

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
	/** Overrides the kind derived from the path and shebang. */
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

/** Scans one file. Linear in the text; exported for unit tests. */
export const scanUnicode = (
	file: SourceFile,
	options: ScanOptions = {},
): FindingInput[] => {
	const { path, text } = file;
	const kind = options.kind ?? kindOf(path, text) ?? "code";
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
