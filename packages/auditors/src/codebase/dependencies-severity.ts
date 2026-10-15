import type { Severity } from "@openaudit/core";

/* -------------------------------------------------------------------------- */
/*                          OSV advisories and CVSS                           */
/* -------------------------------------------------------------------------- */

/** A CVSS vector such as `CVSS:3.1/AV:N/AC:L/...`. */
type CvssVector = string;
type CvssScore = number;

export interface OsvVuln {
	readonly id: string;
	readonly summary?: string;
	readonly details?: string;
	readonly aliases?: ReadonlyArray<string>;
	readonly severity?: ReadonlyArray<OsvSeverityEntry>;
	readonly affected?: ReadonlyArray<OsvAffected>;
	readonly references?: ReadonlyArray<{
		readonly type?: string;
		readonly url: string;
	}>;
	readonly database_specific?: Record<string, unknown>;
}

interface OsvSeverityEntry {
	readonly type: string;
	readonly score: string;
}

export interface OsvAffected {
	readonly package?: { readonly name?: string; readonly ecosystem?: string };
	readonly ranges?: ReadonlyArray<{
		readonly events?: ReadonlyArray<Record<string, string>>;
	}>;
	readonly database_specific?: Record<string, unknown>;
	readonly ecosystem_specific?: Record<string, unknown>;
}

type WeightTable = Record<string, Record<string, number>>;
type BaseWeights = readonly [number, number, number, number, number, number];

const CVSS3_WEIGHTS: WeightTable = {
	AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
	AC: { L: 0.77, H: 0.44 },
	UI: { N: 0.85, R: 0.62 },
	C: { H: 0.56, L: 0.22, N: 0 },
	I: { H: 0.56, L: 0.22, N: 0 },
	A: { H: 0.56, L: 0.22, N: 0 },
};

type Cvss3Scope = "U" | "C";

/** Privileges Required weights per scope (unchanged / changed). */
const CVSS3_PRIVILEGES: Record<string, Record<Cvss3Scope, number>> = {
	N: { U: 0.85, C: 0.85 },
	L: { U: 0.62, C: 0.68 },
	H: { U: 0.27, C: 0.5 },
};

const roundUp = (x: CvssScore) => {
	const i = Math.round(x * 100_000);
	return i % 10_000 === 0 ? i / 100_000 : (Math.floor(i / 10_000) + 1) / 10;
};

/** `K:V` metrics of a CVSS vector, keyed by metric. */
const vectorMetrics = (vector: CvssVector): Record<string, string> => {
	const m: Record<string, string> = {};
	for (const part of vector.split("/")) {
		const [k, v] = part.split(":");
		if (k && v) m[k] = v;
	}
	return m;
};

/** Weights for six metrics, or undefined when any is missing or unknown. */
const baseWeights = (
	m: Record<string, string>,
	table: WeightTable,
	keys: ReadonlyArray<string>,
): BaseWeights | undefined => {
	const weights = keys.map((k) => (m[k] ? table[k]?.[m[k]] : undefined));
	return weights.some((w) => w === undefined)
		? undefined
		: (weights as unknown as BaseWeights);
};

const isCvss3Scope = (scope: string | undefined): scope is Cvss3Scope =>
	scope === "U" || scope === "C";

const cvss3Score = (
	scope: Cvss3Scope,
	[av, ac, ui, c, i, a]: BaseWeights,
	pr: number,
): CvssScore => {
	const iss = 1 - (1 - c) * (1 - i) * (1 - a);
	const impact =
		scope === "U"
			? 6.42 * iss
			: 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
	const exploitability = 8.22 * av * ac * pr * ui;
	if (impact <= 0) return 0;
	return scope === "U"
		? roundUp(Math.min(impact + exploitability, 10))
		: roundUp(Math.min(1.08 * (impact + exploitability), 10));
};

/** CVSS v3.x base score from a vector like `CVSS:3.1/AV:N/AC:L/...`. */
export const cvss3BaseScore = (vector: CvssVector): CvssScore | undefined => {
	const m = vectorMetrics(vector);
	const scope = m.S;
	if (!isCvss3Scope(scope)) return undefined;
	const weights = baseWeights(m, CVSS3_WEIGHTS, [
		"AV",
		"AC",
		"UI",
		"C",
		"I",
		"A",
	]);
	const pr = CVSS3_PRIVILEGES[m.PR ?? ""]?.[scope];
	if (!weights || pr === undefined) return undefined;
	return cvss3Score(scope, weights, pr);
};

export const severityFromScore = (score: CvssScore): Severity =>
	score >= 9
		? "critical"
		: score >= 7
			? "high"
			: score >= 4
				? "medium"
				: score > 0
					? "low"
					: "info";

const LABELS: Record<string, Severity> = {
	CRITICAL: "critical",
	HIGH: "high",
	MODERATE: "medium",
	MEDIUM: "medium",
	LOW: "low",
};

const CVSS2_WEIGHTS: WeightTable = {
	AV: { L: 0.395, A: 0.646, N: 1 },
	AC: { H: 0.35, M: 0.61, L: 0.71 },
	Au: { M: 0.45, S: 0.56, N: 0.704 },
	C: { N: 0, P: 0.275, C: 0.66 },
	I: { N: 0, P: 0.275, C: 0.66 },
	A: { N: 0, P: 0.275, C: 0.66 },
};

/** CVSS v2 base score from a vector like `AV:N/AC:L/Au:N/C:P/I:P/A:P`. */
export const cvss2BaseScore = (vector: CvssVector): CvssScore | undefined => {
	const weights = baseWeights(
		vectorMetrics(vector.replace(/[()]/g, "")),
		CVSS2_WEIGHTS,
		["AV", "AC", "Au", "C", "I", "A"],
	);
	if (!weights) return undefined;
	const [av, ac, au, c, i, a] = weights;
	const impact = 10.41 * (1 - (1 - c) * (1 - i) * (1 - a));
	const exploitability = 20 * av * ac * au;
	const f = impact === 0 ? 0 : 1.176;
	return Math.round((0.6 * impact + 0.4 * exploitability - 1.5) * f * 10) / 10;
};

/** Severity of one entry: a scorable CVSS v3 vector, else a numeric score. */
const entrySeverity = (s: OsvSeverityEntry): Severity | undefined => {
	const cvss3 = s.type.startsWith("CVSS_V3")
		? cvss3BaseScore(s.score)
		: undefined;
	if (cvss3 !== undefined) return severityFromScore(cvss3);
	const n = Number(s.score);
	return Number.isFinite(n) && n > 0 ? severityFromScore(n) : undefined;
};

const scoredSeverity = (vuln: OsvVuln): Severity | undefined => {
	for (const s of vuln.severity ?? []) {
		const sev = entrySeverity(s);
		if (sev) return sev;
	}
	return undefined;
};

const labelSeverity = (vuln: OsvVuln): Severity | undefined => {
	const labels = [
		vuln.database_specific?.severity,
		...(vuln.affected ?? []).flatMap((a) => [
			a.database_specific?.severity,
			a.ecosystem_specific?.severity,
		]),
	];
	return labels
		.map((label) =>
			typeof label === "string" ? LABELS[label.toUpperCase()] : undefined,
		)
		.find((sev): sev is Severity => Boolean(sev));
};

const cvss2Severity = (vuln: OsvVuln): Severity | undefined => {
	for (const s of vuln.severity ?? []) {
		if (s.type !== "CVSS_V2") continue;
		const score = cvss2BaseScore(s.score);
		if (score !== undefined) return severityFromScore(score);
	}
	return undefined;
};

/**
 * Severity from a CVSS v3 vector, a numeric score, the database's own label
 * (GitHub's label already reflects CVSS v4), then a CVSS v2 vector. CVSS v4
 * vectors are not scored here: their score needs MacroVector lookup tables.
 */
export const osvSeverity = (vuln: OsvVuln): Severity =>
	scoredSeverity(vuln) ??
	labelSeverity(vuln) ??
	cvss2Severity(vuln) ??
	"medium";
