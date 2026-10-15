import type { FindingInput } from "@openaudit/core";

import { arr } from "../../tool";

/* -------------------------------------------------------------------------- */
/*                  Domain types and helpers for report parsers               */
/* -------------------------------------------------------------------------- */

/** A parsed JSON object. */
export type Json = Record<string, unknown>;
/** Workspace-relative path of a scanned file. */
export type FilePath = string;
/** Absolute path of the scanned workspace. */
export type RootPath = string;
/** An advisory id (`GHSA-…`, `CVE-…`, `GO-…`, `RUSTSEC-…`). */
export type AdvisoryId = string;
/** A package name as its registry spells it. */
export type PackageName = string;
/** Raw text of a scanned file or of a tool's output. */
export type FileText = string;
/** An advisory or registry page. */
export type Url = string;
/** Path of an external tool's binary. */
export type ToolBin = string;

/** A finding and the key that its duplicates share. */
export interface Keyed {
	readonly key: string;
	readonly finding: FindingInput;
}

/** The first finding per key, in order. */
export const firstPerKey = (entries: Iterable<Keyed>): FindingInput[] => {
	const seen = new Set<string>();
	const findings: FindingInput[] = [];
	for (const { key, finding } of entries) {
		if (seen.has(key)) continue;
		seen.add(key);
		findings.push(finding);
	}
	return findings;
};

/** The string items of a JSON array. */
export const strings = (value: unknown): string[] =>
	arr(value).filter((v): v is string => typeof v === "string");
