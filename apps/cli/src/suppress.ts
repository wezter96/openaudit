import {
	type Finding,
	filterFindings,
	matchesPattern,
	type Report,
	type SuppressionEntry,
	type SuppressionSummary,
} from "@openaudit/core";

/** One place findings can be suppressed from: a config file or a baseline. */
export interface SuppressionSource {
	/** Shown to users, e.g. `/repo/openaudit.config.json` or `--baseline old.json`. */
	readonly source: string;
	/** Entries that apply. */
	readonly entries: ReadonlyArray<SuppressionEntry>;
	/** Entries past their `until` date: disclosed, never applied. */
	readonly expired?: ReadonlyArray<SuppressionEntry>;
}

const COUNTER = {
	rule: "rules",
	path: "paths",
	fingerprint: "fingerprints",
} as const;

/** Index of the entry that suppresses `f`: fingerprints, then rules, then paths. */
const matcher = (entries: ReadonlyArray<SuppressionEntry>) => {
	const fingerprints = new Map<string, number>();
	const rules: [number, string][] = [];
	const globs: [number, Bun.Glob][] = [];
	for (const [i, e] of entries.entries()) {
		if (e.kind === "fingerprint") {
			if (!fingerprints.has(e.value)) fingerprints.set(e.value, i);
		} else if (e.kind === "rule") rules.push([i, e.value]);
		else globs.push([i, new Bun.Glob(e.value)]);
	}
	return (f: Finding): number | undefined => {
		const byFingerprint = fingerprints.get(f.fingerprint);
		if (byFingerprint !== undefined) return byFingerprint;
		const rule = rules.find(([, p]) => matchesPattern(f.ruleId, p));
		if (rule) return rule[0];
		const file = f.location?.file;
		return file ? globs.find(([, g]) => g.match(file))?.[0] : undefined;
	};
};

/**
 * Removes suppressed findings and counts them per source, so that a config
 * shipped inside an audited repo cannot silently hide issues. The first
 * matching source gets the credit. Entries with a reason or expiry are listed
 * with their counts, and expired entries are disclosed. Statuses and the
 * summary are recomputed.
 */
export const applySuppressions = (
	report: Report,
	sources: ReadonlyArray<SuppressionSource>,
): { report: Report; suppressed: SuppressionSummary[] } => {
	const active = sources.filter((s) => s.entries.length || s.expired?.length);
	if (!active.length) return { report, suppressed: [] };
	const matchers = active.map((s) => matcher(s.entries));
	const hits = active.map((s) => s.entries.map(() => 0));

	const { results, summary } = filterFindings(report.results, (f) => {
		for (const [i, match] of matchers.entries()) {
			const hit = match(f);
			const counts = hits[i];
			if (hit !== undefined && counts) {
				counts[hit] = (counts[hit] ?? 0) + 1;
				return false;
			}
		}
		return true;
	});
	const suppressed = active.map((s, i): SuppressionSummary => {
		const counts = { rules: 0, paths: 0, fingerprints: 0 };
		const entries: (SuppressionEntry & { count: number })[] = [];
		for (const [j, e] of s.entries.entries()) {
			const count = hits[i]?.[j] ?? 0;
			counts[COUNTER[e.kind]] += count;
			if (count && (e.reason !== undefined || e.until !== undefined))
				entries.push({ ...e, count });
		}
		return {
			source: s.source,
			...counts,
			...(entries.length ? { entries } : {}),
			...(s.expired?.length ? { expired: [...s.expired] } : {}),
		};
	});
	return { report: { ...report, results, summary }, suppressed };
};
