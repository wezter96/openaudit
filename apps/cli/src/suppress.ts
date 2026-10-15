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

interface EntryIndex {
	readonly fingerprints: ReadonlyMap<string, number>;
	readonly rules: ReadonlyArray<readonly [number, string]>;
	readonly globs: ReadonlyArray<readonly [number, Bun.Glob]>;
}

/** `[index, make(value)]` for every entry of one kind, in entry order. */
const ofKind = <T>(
	entries: ReadonlyArray<SuppressionEntry>,
	kind: SuppressionEntry["kind"],
	make: (value: string) => T,
): Array<readonly [number, T]> =>
	entries.flatMap((e, i) =>
		e.kind === kind ? [[i, make(e.value)] as const] : [],
	);

const indexEntries = (entries: ReadonlyArray<SuppressionEntry>): EntryIndex => {
	const fingerprints = new Map<string, number>();
	for (const [i, e] of entries.entries())
		if (e.kind === "fingerprint" && !fingerprints.has(e.value))
			fingerprints.set(e.value, i);
	return {
		fingerprints,
		rules: ofKind(entries, "rule", (value) => value),
		globs: ofKind(entries, "path", (value) => new Bun.Glob(value)),
	};
};

/** Index of the entry that suppresses `f`: fingerprints, then rules, then paths. */
const matchEntry = (index: EntryIndex, f: Finding): number | undefined => {
	const byFingerprint = index.fingerprints.get(f.fingerprint);
	if (byFingerprint !== undefined) return byFingerprint;
	const rule = index.rules.find(([, p]) => matchesPattern(f.ruleId, p));
	if (rule) return rule[0];
	const file = f.location?.file;
	return file ? index.globs.find(([, g]) => g.match(file))?.[0] : undefined;
};

const matcher = (entries: ReadonlyArray<SuppressionEntry>) => {
	const index = indexEntries(entries);
	return (f: Finding): number | undefined => matchEntry(index, f);
};

const isActive = (s: SuppressionSource) =>
	s.entries.length || s.expired?.length;

/** Entries with a reason or expiry are listed with their counts. */
const isAnnotated = (e: SuppressionEntry) =>
	e.reason !== undefined || e.until !== undefined;

/** Keeps a finding unless a source suppresses it; the first match is counted. */
const keepUnsuppressed =
	(
		matchers: ReadonlyArray<(f: Finding) => number | undefined>,
		hits: ReadonlyArray<number[]>,
	) =>
	(f: Finding): boolean => {
		for (const [i, match] of matchers.entries()) {
			const hit = match(f);
			const counts = hits[i];
			if (hit !== undefined && counts) {
				counts[hit] = (counts[hit] ?? 0) + 1;
				return false;
			}
		}
		return true;
	};

const summarize = (
	s: SuppressionSource,
	hits: ReadonlyArray<number> | undefined,
): SuppressionSummary => {
	const counts = { rules: 0, paths: 0, fingerprints: 0 };
	const entries: (SuppressionEntry & { count: number })[] = [];
	for (const [j, e] of s.entries.entries()) {
		const count = hits?.[j] ?? 0;
		counts[COUNTER[e.kind]] += count;
		if (count && isAnnotated(e)) entries.push({ ...e, count });
	}
	return {
		source: s.source,
		...counts,
		...(entries.length ? { entries } : {}),
		...(s.expired?.length ? { expired: [...s.expired] } : {}),
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
	const active = sources.filter(isActive);
	if (!active.length) return { report, suppressed: [] };
	const matchers = active.map((s) => matcher(s.entries));
	const hits = active.map((s) => s.entries.map(() => 0));

	const { results, summary } = filterFindings(
		report.results,
		keepUnsuppressed(matchers, hits),
	);
	const suppressed = active.map((s, i) => summarize(s, hits[i]));
	return { report: { ...report, results, summary }, suppressed };
};
