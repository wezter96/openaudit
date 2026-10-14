import {
	type Finding,
	filterFindings,
	matchesPattern,
	type Report,
	type SuppressionSummary,
} from "@openaudit/core";

/** One place findings can be suppressed from: a config file or a baseline. */
export interface SuppressionSource {
	/** Shown to users, e.g. `/repo/openaudit.config.json` or `--baseline old.json`. */
	readonly source: string;
	readonly rules?: ReadonlyArray<string>;
	readonly paths?: ReadonlyArray<string>;
	readonly fingerprints?: ReadonlyArray<string>;
}

type Reason = "rules" | "paths" | "fingerprints";

const reasonFor = (
	f: Finding,
	s: SuppressionSource,
	globs: ReadonlyArray<Bun.Glob>,
): Reason | undefined => {
	if (s.fingerprints?.includes(f.fingerprint)) return "fingerprints";
	if (s.rules?.some((p) => matchesPattern(f.ruleId, p))) return "rules";
	const file = f.location?.file;
	if (file && globs.some((g) => g.match(file))) return "paths";
	return undefined;
};

/**
 * Removes suppressed findings and counts them per source, so that a config
 * shipped inside an audited repo cannot silently hide issues. The first
 * matching source gets the credit. Statuses and the summary are recomputed.
 */
export const applySuppressions = (
	report: Report,
	sources: ReadonlyArray<SuppressionSource>,
): { report: Report; suppressed: SuppressionSummary[] } => {
	const active = sources.filter(
		(s) => s.rules?.length || s.paths?.length || s.fingerprints?.length,
	);
	if (!active.length) return { report, suppressed: [] };
	const counts = active.map((s) => ({
		source: s.source,
		rules: 0,
		paths: 0,
		fingerprints: 0,
	}));
	const globs = active.map((s) => (s.paths ?? []).map((p) => new Bun.Glob(p)));

	const { results, summary } = filterFindings(report.results, (f) => {
		for (const [i, s] of active.entries()) {
			const reason = reasonFor(f, s, globs[i] ?? []);
			const count = counts[i];
			if (reason && count) {
				count[reason]++;
				return false;
			}
		}
		return true;
	});
	return { report: { ...report, results, summary }, suppressed: counts };
};
