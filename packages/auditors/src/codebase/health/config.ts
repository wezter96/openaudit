import { isRecord } from "../util";
import {
	DEFAULT_THRESHOLDS,
	type RuleName,
	type RuleSet,
	type Thresholds,
} from "./rules";

/**
 * Reads `.codescene/code-health-rules.json`, so a project that tunes its
 * Code Health rules for CodeScene gets the same rules here: per glob, rule
 * weights (0 switches a rule off) and threshold overrides. The first rule
 * set whose `matching_content_path` matches a file applies to it.
 */
export const RULES_FILE = ".codescene/code-health-rules.json";

export interface MatchedRuleSet extends RuleSet {
	readonly glob: string;
}

const numberEntries = (list: unknown, key: "value" | "weight") =>
	(Array.isArray(list) ? list : []).flatMap((item) => {
		if (!isRecord(item)) return [];
		const name = item.name;
		const value = item[key];
		if (typeof name !== "string") return [];
		return typeof value === "number" ? [[name, value] as const] : [];
	});

const thresholdsOf = (list: unknown): Thresholds => {
	const out: Record<string, number> = { ...DEFAULT_THRESHOLDS };
	for (const [name, value] of numberEntries(list, "value"))
		if (name in DEFAULT_THRESHOLDS) out[name] = value;
	return out as unknown as Thresholds;
};

const ruleSetOf = (raw: unknown): MatchedRuleSet | undefined => {
	if (!isRecord(raw)) return undefined;
	const glob = raw.matching_content_path;
	if (typeof glob !== "string") return undefined;
	const weights: Partial<Record<RuleName, number>> = {};
	for (const [name, weight] of numberEntries(raw.rules, "weight"))
		weights[name as RuleName] = Math.max(0, weight);
	return { glob, weights, thresholds: thresholdsOf(raw.thresholds) };
};

/** The rule sets in a rules file, in order. Malformed parts are ignored. */
export const parseRulesFile = (json: unknown): MatchedRuleSet[] => {
	if (!isRecord(json) || !Array.isArray(json.rule_sets)) return [];
	return json.rule_sets.flatMap((raw) => ruleSetOf(raw) ?? []);
};

export const DEFAULT_RULES: RuleSet = {
	thresholds: DEFAULT_THRESHOLDS,
	weights: {},
};

/** The rules for one file: the first matching set, else the defaults. */
export const rulesFor = (
	path: string,
	sets: ReadonlyArray<MatchedRuleSet>,
): RuleSet =>
	sets.find((s) => new Bun.Glob(s.glob).match(path)) ?? DEFAULT_RULES;
