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
	const keys: string[] = [];
	const advisories = tags.filter((t) => ADVISORY.test(t));
	if (advisories.length) {
		const dir = f.location?.file ? dirOf(f.location.file) : "*";
		for (const id of advisories) keys.push(`adv:${dir}:${id}`);
		// Two packages can share a CVE, so advisories never fall back to CWE.
		return keys;
	}
	const place = placeOf(f);
	if (!place) return keys;
	if (tags.includes("secrets") && f.location?.file)
		keys.push(`secret:${place}`);
	for (const t of tags) {
		if (/^cwe-\d+$/.test(t)) keys.push(`${t}:${place}`);
		else if (/^wcag-\d+\.\d+\.\d+$/.test(t)) keys.push(`${t}:${place}`);
		else if (t.startsWith("eslint:") && f.location?.file)
			keys.push(`${t}:${place}`);
	}
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
	const findings = results.flatMap((r, ri) =>
		r.findings.map((f, fi) => ({ f: strip(f), ri, fi })),
	);

	// Union-find over findings that share any key.
	const parent = findings.map((_, i) => i);
	const find = (start: number): number => {
		let i = start;
		while (parent[i] !== i) {
			parent[i] = parent[parent[i] as number] as number;
			i = parent[i] as number;
		}
		return i;
	};
	const owner = new Map<string, number>();
	findings.forEach(({ f }, i) => {
		for (const key of correlationKeys(f)) {
			const j = owner.get(key);
			if (j === undefined) owner.set(key, i);
			else parent[find(i)] = find(j);
		}
	});

	const groups = new Map<number, number[]>();
	findings.forEach((_, i) => {
		const root = find(i);
		groups.set(root, [...(groups.get(root) ?? []), i]);
	});

	const updated = findings.map(({ f }) => f);
	for (const members of groups.values()) {
		const auditors = new Set(members.map((i) => findings[i]?.f.auditor));
		if (auditors.size < 2) continue;
		const sorted = [...members].sort((a, b) =>
			prefer(findings[a]?.f as Finding, findings[b]?.f as Finding),
		);
		const keep = updated[sorted[0] as number] as Finding;
		const others = new Set<string>();
		for (const i of sorted.slice(1)) {
			const f = updated[i] as Finding;
			// A second report from the kept auditor is a separate issue.
			if (f.auditor === keep.auditor) continue;
			updated[i] = { ...f, duplicateOf: keep.fingerprint };
			others.add(f.auditor);
		}
		updated[sorted[0] as number] = {
			...keep,
			alsoReportedBy: [...others].sort(),
		};
	}

	let k = 0;
	return results.map((r) => ({
		...r,
		findings: r.findings.map(() => updated[k++] as Finding),
	}));
};

/** Findings that count: duplicates of another auditor's finding removed. */
export const isPrimary = (f: Finding): boolean => f.duplicateOf === undefined;
