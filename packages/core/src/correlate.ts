import type { AuditorResult, Finding } from "./model";
import { severityRank } from "./model";

/*
 * Several wrapped tools often report the same issue: one leaked key found by
 * code.secrets, gitleaks and trufflehog, or one advisory found by osv-scanner,
 * npm audit and trivy. Correlation keeps the most severe report of each issue
 * and marks the others as duplicates of it, so the issue is scored once and
 * the kept finding lists every tool that confirmed it.
 *
 * Findings correlate when they come from different auditors and share a key:
 * - the same advisory (CVE/GHSA/…) in the same directory;
 * - a secret at the same file and line;
 * - the same CWE at the same file and line, or the same URL and selector;
 * - the same WCAG criterion at the same URL and selector;
 * - the same lint rule (`eslint:<ESLint rule id>`, which linters that port
 *   ESLint rules map their own ids to) at the same file and line.
 * Findings from one auditor never merge with each other.
 */

const ADVISORY =
	/^(cve-\d{4}-\d+|ghsa(-[a-z0-9]{4}){3}|pysec-\d{4}-\d+|go-\d{4}-\d+|rustsec-\d{4}-\d+)$/;

const dirOf = (file: string): string => {
	const i = file.lastIndexOf("/");
	return i === -1 ? "." : file.slice(0, i);
};

/** Where a finding points, or undefined when it is too vague to correlate. */
const placeOf = (f: Finding): string | undefined => {
	const loc = f.location;
	if (loc?.file && loc.line !== undefined) return `f:${loc.file}:${loc.line}`;
	if (loc?.url) return `u:${loc.url}|${loc.selector ?? ""}`;
	return undefined;
};

export const correlationKeys = (f: Finding): string[] => {
	const tags = (f.tags ?? []).map((t) => t.toLowerCase());
	const advisories = tags.filter((t) => ADVISORY.test(t));
	// Two packages can share a CVE, so advisories never fall back to CWE.
	if (advisories.length) return advisoryKeys(f, advisories);
	const place = placeOf(f);
	return place ? placeKeys(f, tags, place) : [];
};

const advisoryKeys = (f: Finding, advisories: string[]): string[] => {
	const dir = f.location?.file ? dirOf(f.location.file) : "*";
	return advisories.map((id) => `adv:${dir}:${id}`);
};

const PLACED_TAG = /^(cwe-\d+|wcag-\d+\.\d+\.\d+)$/;

/** CWE and WCAG tags correlate at any place, lint rules only at a file. */
const correlatesAt = (tag: string, inFile: boolean): boolean => {
	if (PLACED_TAG.test(tag)) return true;
	return inFile && tag.startsWith("eslint:");
};

const placeKeys = (f: Finding, tags: string[], place: string): string[] => {
	const inFile = Boolean(f.location?.file);
	const keys = tags.includes("secrets") && inFile ? [`secret:${place}`] : [];
	for (const t of tags) if (correlatesAt(t, inFile)) keys.push(`${t}:${place}`);
	return keys;
};

const CONFIDENCE_RANK = { high: 0, medium: 1, low: 2 } as const;

/** Lower is preferred as the finding to keep. */
const preference = (f: Finding): number[] => [
	severityRank(f.severity),
	CONFIDENCE_RANK[f.confidence ?? "medium"],
	f.remediation ? 0 : 1,
];

const prefer = (a: Finding, b: Finding): number => {
	const pa = preference(a);
	const pb = preference(b);
	for (let i = 0; i < pa.length; i++) {
		const d = (pa[i] ?? 0) - (pb[i] ?? 0);
		if (d !== 0) return d;
	}
	return a.auditor.localeCompare(b.auditor);
};

const strip = (f: Finding): Finding => {
	if (f.duplicateOf === undefined && f.alsoReportedBy === undefined) return f;
	const { duplicateOf: _d, alsoReportedBy: _a, ...rest } = f;
	return rest;
};

/**
 * Marks findings that repeat another auditor's finding. Idempotent: earlier
 * marks are recomputed, so call it again after findings are removed (e.g. by
 * suppressions) or added (e.g. by an agent).
 */
export const correlate = (
	results: ReadonlyArray<AuditorResult>,
): AuditorResult[] => {
	const updated = results.flatMap((r) => r.findings.map(strip));
	for (const members of groupsOf(updated)) markDuplicates(updated, members);
	let k = 0;
	return results.map((r) => ({
		...r,
		findings: r.findings.map(() => updated[k++] as Finding),
	}));
};

/** Union-find root of `start`, halving the path on the way. */
const rootOf = (parent: number[], start: number): number => {
	let i = start;
	while (parent[i] !== i) {
		parent[i] = parent[parent[i] as number] as number;
		i = parent[i] as number;
	}
	return i;
};

/** Indexes of findings that share any key, grouped, in order of first index. */
const groupsOf = (findings: ReadonlyArray<Finding>): number[][] => {
	const parent = findings.map((_, i) => i);
	const owner = new Map<string, number>();
	findings.forEach((f, i) => {
		for (const key of correlationKeys(f)) {
			const j = owner.get(key);
			if (j === undefined) owner.set(key, i);
			else parent[rootOf(parent, i)] = rootOf(parent, j);
		}
	});
	const groups = new Map<number, number[]>();
	findings.forEach((_, i) => {
		const root = rootOf(parent, i);
		groups.set(root, [...(groups.get(root) ?? []), i]);
	});
	return [...groups.values()];
};

/** Keeps the preferred finding of a group and marks the others' duplicates. */
const markDuplicates = (updated: Finding[], members: number[]): void => {
	const auditors = new Set(members.map((i) => updated[i]?.auditor));
	if (auditors.size < 2) return;
	const sorted = [...members].sort((a, b) =>
		prefer(updated[a] as Finding, updated[b] as Finding),
	);
	const first = sorted[0] as number;
	const keep = updated[first] as Finding;
	const others = new Set<string>();
	for (const i of sorted.slice(1)) {
		const f = updated[i] as Finding;
		// A second report from the kept auditor is a separate issue.
		if (f.auditor === keep.auditor) continue;
		updated[i] = { ...f, duplicateOf: keep.fingerprint };
		others.add(f.auditor);
	}
	updated[first] = { ...keep, alsoReportedBy: [...others].sort() };
};

/** Findings that count: duplicates of another auditor's finding removed. */
export const isPrimary = (f: Finding): boolean => f.duplicateOf === undefined;
