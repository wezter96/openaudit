import type { Finding, Report } from "@openaudit/core";

/** Returns `value`, failing the test with a clear message when it is missing. */
export const must = <T>(value: T | null | undefined, what: string): T => {
	if (value === undefined || value === null)
		throw new Error(`expected ${what}, got ${value}`);
	return value;
};

/** The first (usually only) auditor result of a report. */
export const firstResult = (report: Report) =>
	must(report.results[0], "an auditor result");

/** The findings of the first auditor result, or none. */
export const findingsOf = (report: Report): ReadonlyArray<Finding> =>
	report.results[0]?.findings ?? [];

/** The first finding with `ruleId`, failing the test when there is none. */
export const findingWith = <F extends { readonly ruleId: string }>(
	findings: ReadonlyArray<F>,
	ruleId: string,
): F =>
	must(
		findings.find((f) => f.ruleId === ruleId),
		`a finding ${ruleId}`,
	);
