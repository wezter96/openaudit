import type { Finding } from "./model";

/*
 * Mapping data for the compliance views of the reports. Findings carry
 * `owasp-a01`…`owasp-a10` and `cwe-<n>` tags; this module groups them by
 * OWASP Top 10 (2021) category and by CWE Top 25 (2024) membership.
 *
 * Being grouped under a control only means an auditor reported something
 * related to it. A control with no findings is not evidence of compliance.
 */

export type OwaspId =
	| "A01"
	| "A02"
	| "A03"
	| "A04"
	| "A05"
	| "A06"
	| "A07"
	| "A08"
	| "A09"
	| "A10";

export interface OwaspCategory {
	readonly id: OwaspId;
	readonly title: string;
	/** The CWE category that represents it in MITRE's CWE-1344 view. */
	readonly cweCategory: number;
}

/** OWASP Top 10:2021. */
export const OWASP_TOP10_2021: ReadonlyArray<OwaspCategory> = [
	{ id: "A01", title: "Broken Access Control", cweCategory: 1345 },
	{ id: "A02", title: "Cryptographic Failures", cweCategory: 1346 },
	{ id: "A03", title: "Injection", cweCategory: 1347 },
	{ id: "A04", title: "Insecure Design", cweCategory: 1348 },
	{ id: "A05", title: "Security Misconfiguration", cweCategory: 1349 },
	{ id: "A06", title: "Vulnerable and Outdated Components", cweCategory: 1352 },
	{
		id: "A07",
		title: "Identification and Authentication Failures",
		cweCategory: 1353,
	},
	{
		id: "A08",
		title: "Software and Data Integrity Failures",
		cweCategory: 1354,
	},
	{
		id: "A09",
		title: "Security Logging and Monitoring Failures",
		cweCategory: 1355,
	},
	{ id: "A10", title: "Server-Side Request Forgery (SSRF)", cweCategory: 1356 },
];

export interface CweEntry {
	readonly rank: number;
	readonly cwe: number;
	readonly name: string;
}

/** The 2024 CWE Top 25 Most Dangerous Software Weaknesses, in rank order. */
export const CWE_TOP25_2024: ReadonlyArray<CweEntry> = [
	{ rank: 1, cwe: 79, name: "Cross-site Scripting" },
	{ rank: 2, cwe: 787, name: "Out-of-bounds Write" },
	{ rank: 3, cwe: 89, name: "SQL Injection" },
	{ rank: 4, cwe: 352, name: "Cross-Site Request Forgery (CSRF)" },
	{ rank: 5, cwe: 22, name: "Path Traversal" },
	{ rank: 6, cwe: 125, name: "Out-of-bounds Read" },
	{ rank: 7, cwe: 78, name: "OS Command Injection" },
	{ rank: 8, cwe: 416, name: "Use After Free" },
	{ rank: 9, cwe: 862, name: "Missing Authorization" },
	{
		rank: 10,
		cwe: 434,
		name: "Unrestricted Upload of File with Dangerous Type",
	},
	{ rank: 11, cwe: 94, name: "Code Injection" },
	{ rank: 12, cwe: 20, name: "Improper Input Validation" },
	{ rank: 13, cwe: 77, name: "Command Injection" },
	{ rank: 14, cwe: 287, name: "Improper Authentication" },
	{ rank: 15, cwe: 269, name: "Improper Privilege Management" },
	{ rank: 16, cwe: 502, name: "Deserialization of Untrusted Data" },
	{
		rank: 17,
		cwe: 200,
		name: "Exposure of Sensitive Information to an Unauthorized Actor",
	},
	{ rank: 18, cwe: 863, name: "Incorrect Authorization" },
	{ rank: 19, cwe: 918, name: "Server-Side Request Forgery (SSRF)" },
	{
		rank: 20,
		cwe: 119,
		name: "Improper Restriction of Operations within the Bounds of a Memory Buffer",
	},
	{ rank: 21, cwe: 476, name: "NULL Pointer Dereference" },
	{ rank: 22, cwe: 798, name: "Use of Hard-coded Credentials" },
	{ rank: 23, cwe: 190, name: "Integer Overflow or Wraparound" },
	{ rank: 24, cwe: 400, name: "Uncontrolled Resource Consumption" },
	{ rank: 25, cwe: 306, name: "Missing Authentication for Critical Function" },
];

/**
 * Weakness members of each OWASP Top 10:2021 category in MITRE's CWE-1344
 * view. CWE categories and deprecated entries are left out, as are CWEs the
 * view lists under more than one OWASP category.
 */
const OWASP_MEMBERS: Record<OwaspId, ReadonlyArray<number>> = {
	A01: [
		22, 23, 35, 59, 200, 201, 219, 276, 284, 285, 352, 359, 377, 402, 425, 441,
		497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922,
		1275,
	],
	A02: [
		261, 296, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335,
		336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916,
	],
	A03: [
		20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98,
		99, 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917,
	],
	A04: [
		73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419,
		430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650,
		653, 656, 657, 799, 807, 841, 927, 1021, 1173,
	],
	A05: [
		11, 13, 15, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942,
		1004, 1174,
	],
	A06: [1104],
	A07: [
		287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613,
		620, 640, 798, 940, 1216,
	],
	A08: [345, 353, 426, 494, 502, 565, 784, 829, 830, 915],
	A09: [117, 223, 532, 778],
	A10: [918],
};

/** CWE id → OWASP Top 10:2021 category, for findings without an OWASP tag. */
export const CWE_TO_OWASP_2021: ReadonlyMap<number, OwaspId> = new Map(
	(
		Object.entries(OWASP_MEMBERS) as Array<[OwaspId, ReadonlyArray<number>]>
	).flatMap(([id, cwes]) => cwes.map((cwe) => [cwe, id] as const)),
);

const OWASP_IDS = new Set<string>(OWASP_TOP10_2021.map((c) => c.id));
const TOP25 = new Set(CWE_TOP25_2024.map((c) => c.cwe));

/** CWE numbers from a finding's `cwe-<n>` tags, without repeats. */
export const cweIdsOf = (finding: Finding): number[] => {
	const ids = new Set<number>();
	for (const tag of finding.tags ?? []) {
		const m = /^cwe-(\d+)$/i.exec(tag);
		if (m?.[1]) ids.add(Number(m[1]));
	}
	return [...ids];
};

/** How a finding came to be grouped under a control. */
export interface ComplianceMatch {
	readonly finding: Finding;
	/** Set when the OWASP category was derived from this CWE, not a tag. */
	readonly viaCwe?: number;
}

/**
 * OWASP Top 10:2021 categories of a finding: its `owasp-aNN` tags, or, when
 * it has none, the categories its CWEs map to.
 */
export const owaspMatchesOf = (
	finding: Finding,
): Array<{ readonly id: OwaspId; readonly viaCwe?: number }> => {
	const tagged = new Set<OwaspId>();
	for (const tag of finding.tags ?? []) {
		const m = /^owasp-(a\d{2})$/i.exec(tag);
		const id = m?.[1]?.toUpperCase();
		if (id && OWASP_IDS.has(id)) tagged.add(id as OwaspId);
	}
	if (tagged.size) return [...tagged].map((id) => ({ id }));
	const derived = new Map<OwaspId, number>();
	for (const cwe of cweIdsOf(finding)) {
		const id = CWE_TO_OWASP_2021.get(cwe);
		if (id && !derived.has(id)) derived.set(id, cwe);
	}
	return [...derived].map(([id, viaCwe]) => ({ id, viaCwe }));
};

const counted = (findings: ReadonlyArray<Finding>) =>
	findings.filter((f) => f.duplicateOf === undefined);

/** Every OWASP Top 10:2021 category, in order, with its non-duplicate findings. */
export const groupByOwasp = (
	findings: ReadonlyArray<Finding>,
): Array<{
	readonly category: OwaspCategory;
	readonly matches: ComplianceMatch[];
}> => {
	const byId = new Map<OwaspId, ComplianceMatch[]>(
		OWASP_TOP10_2021.map((c) => [c.id, []]),
	);
	for (const finding of counted(findings)) {
		for (const { id, viaCwe } of owaspMatchesOf(finding)) {
			byId
				.get(id)
				?.push(viaCwe === undefined ? { finding } : { finding, viaCwe });
		}
	}
	return OWASP_TOP10_2021.map((category) => ({
		category,
		matches: byId.get(category.id) ?? [],
	}));
};

/** Every CWE Top 25 (2024) entry, in rank order, with its non-duplicate findings. */
export const groupByCweTop25 = (
	findings: ReadonlyArray<Finding>,
): Array<{ readonly entry: CweEntry; readonly matches: ComplianceMatch[] }> => {
	const byCwe = new Map<number, ComplianceMatch[]>(
		CWE_TOP25_2024.map((c) => [c.cwe, []]),
	);
	for (const finding of counted(findings)) {
		for (const cwe of cweIdsOf(finding)) {
			if (TOP25.has(cwe)) byCwe.get(cwe)?.push({ finding });
		}
	}
	return CWE_TOP25_2024.map((entry) => ({
		entry,
		matches: byCwe.get(entry.cwe) ?? [],
	}));
};

/** True when a finding has an OWASP or CWE tag, or a CWE that maps to OWASP. */
export const hasComplianceMapping = (finding: Finding): boolean =>
	cweIdsOf(finding).length > 0 || owaspMatchesOf(finding).length > 0;
