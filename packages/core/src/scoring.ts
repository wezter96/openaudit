import {
	type AuditorResult,
	CATEGORIES,
	type Category,
	type CategorySummary,
	type Finding,
	type Grade,
	type Severity,
	type SeverityCounts,
	type Summary,
} from "./model";

/** Penalty per finding. Info findings never lower a score. */
const WEIGHTS: Record<Severity, number> = {
	critical: 40,
	high: 15,
	medium: 5,
	low: 1,
	info: 0,
};

/**
 * Score in [0, 100] that decays with accumulated penalty: one critical → 50,
 * one high → 73, one medium → 89, ten lows → 80.
 */
export const scoreFor = (findings: ReadonlyArray<Finding>): number => {
	const penalty = findings.reduce((sum, f) => sum + WEIGHTS[f.severity], 0);
	return Math.round((100 * 40) / (40 + penalty));
};

export const gradeFor = (score: number): Grade =>
	score >= 90
		? "A"
		: score >= 80
			? "B"
			: score >= 70
				? "C"
				: score >= 50
					? "D"
					: "F";

export const countSeverities = (
	findings: ReadonlyArray<Finding>,
): SeverityCounts => {
	const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
	for (const f of findings) counts[f.severity]++;
	return counts;
};

export const summarize = (results: ReadonlyArray<AuditorResult>): Summary => {
	// Duplicates confirm a finding another auditor already reported.
	const findings = results
		.flatMap((r) => r.findings)
		.filter((f) => f.duplicateOf === undefined);

	// Only score categories that some auditor actually examined.
	const examined = new Set<Category>();
	for (const r of results) {
		if (r.status === "passed" || r.status === "failed") {
			for (const c of r.categories) examined.add(c);
		}
	}
	for (const f of findings) examined.add(f.category);

	const categories: CategorySummary[] = CATEGORIES.filter((c) =>
		examined.has(c),
	).map((category) => {
		const inCategory = findings.filter((f) => f.category === category);
		const score = scoreFor(inCategory);
		return {
			category,
			score,
			grade: gradeFor(score),
			counts: countSeverities(inCategory),
		};
	});

	const score = categories.length
		? Math.round(
				categories.reduce((sum, c) => sum + c.score, 0) / categories.length,
			)
		: 100;

	const auditors = { passed: 0, failed: 0, skipped: 0, error: 0 };
	for (const r of results) auditors[r.status]++;

	return {
		score,
		grade: gradeFor(score),
		counts: countSeverities(findings),
		categories,
		auditors,
	};
};
