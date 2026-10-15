import type { Confidence, FindingInput, Severity } from "@openaudit/core";

import { cweUrl, isRecord, scrubLine, truncate } from "./util";

/** Workspace-relative path of a scanned file. */
export type FilePath = string;
/** Full text of a scanned file. */
export type SourceText = string;
/** Key path into a parsed spec document. */
export type Path = ReadonlyArray<string | number>;

const API_TOP10 = "https://owasp.org/API-Security/editions/2023/en/";
const API_SLUGS: Readonly<Record<string, string>> = {
	api1: "0xa1-broken-object-level-authorization",
	api2: "0xa2-broken-authentication",
	api3: "0xa3-broken-object-property-level-authorization",
	api4: "0xa4-unrestricted-resource-consumption",
	api5: "0xa5-broken-function-level-authorization",
	api6: "0xa6-unrestricted-access-to-sensitive-business-flows",
	api7: "0xa7-server-side-request-forgery",
	api8: "0xa8-security-misconfiguration",
	api9: "0xa9-improper-inventory-management",
	api10: "0xaa-unsafe-consumption-of-apis",
};

/** An OWASP API Security Top 10 id such as `api2`. */
export type OwaspApiId = keyof typeof API_SLUGS;

/** OWASP API Security Top 10 (2023) page for an id such as `api2`. */
export const owaspApiUrl = (id: OwaspApiId) =>
	`${API_TOP10}${API_SLUGS[id] ?? ""}/`;

export interface RuleSpec {
	readonly id: string;
	readonly title: string;
	readonly severity: Severity;
	readonly confidence?: Confidence;
	readonly owasp: OwaspApiId;
	readonly cwe: number;
	readonly remediation: string;
	readonly category?: "security" | "best-practices";
}

/** The per-occurrence part of a finding. */
export interface FindingDraft {
	readonly file: FilePath;
	readonly line: number | undefined;
	readonly message: string;
	readonly evidence: string;
	readonly severity?: Severity;
	readonly title?: string;
}

export const finding = (rule: RuleSpec, draft: FindingDraft): FindingInput => ({
	ruleId: `code.api/${rule.id}`,
	title: truncate(draft.title ?? rule.title, 120),
	severity: draft.severity ?? rule.severity,
	category: rule.category ?? "security",
	message: draft.message,
	location: { file: draft.file, line: draft.line },
	evidence: truncate(scrubLine(draft.evidence), 200),
	remediation: rule.remediation,
	references: [owaspApiUrl(rule.owasp), cweUrl(rule.cwe)],
	confidence: rule.confidence ?? "high",
	tags: [`owasp-${rule.owasp}`, `cwe-${rule.cwe}`],
});

/** The parsed object of a JSON document, or undefined when it is not one. */
export const parseJsonRecord = (
	text: SourceText,
): Record<string, unknown> | undefined => {
	try {
		const parsed: unknown = JSON.parse(text);
		return isRecord(parsed) ? parsed : undefined;
	} catch {
		return undefined;
	}
};

/** Dependency names declared in the given package.json sections, in order. */
export const dependencyNames = (
	pkg: Record<string, unknown>,
	sections: ReadonlyArray<string>,
): string[] =>
	sections.flatMap((key) => {
		const section = pkg[key];
		return isRecord(section) ? Object.keys(section) : [];
	});
