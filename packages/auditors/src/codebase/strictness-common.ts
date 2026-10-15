import type { FindingInput, Severity, Workspace } from "@openaudit/core";
import { Effect } from "effect";

import { isRecord } from "./util";

/** Shared helpers for the code.strictness auditor's per-language checks. */

/** A workspace-relative file path. */
export type FilePath = string;
/** The text of a file read from the target. */
export type SourceText = string;
/** The rule part of a `code.strictness/<rule>` id. */
export type RuleName = string;

/** A file and 1-based line where something was first seen. */
export interface SourceLocation {
	readonly file: FilePath;
	readonly line: number;
}

export const SOURCE_LIMIT = 2000;

const depth = (path: FilePath) => path.split("/").length;
export const byDepth = (a: FilePath, b: FilePath) =>
	depth(a) - depth(b) || a.localeCompare(b);

export interface StrictnessFinding {
	title: string;
	severity: Severity;
	message: string;
	remediation: string;
	file?: FilePath;
	line?: number;
	evidence?: string;
	confidence?: "high" | "medium" | "low";
	tags?: ReadonlyArray<string>;
	references?: ReadonlyArray<string>;
}

export const finding = (
	rule: RuleName,
	f: StrictnessFinding,
): FindingInput => ({
	ruleId: `code.strictness/${rule}`,
	title: f.title,
	severity: f.severity,
	category: "maintainability",
	message: f.message,
	location: f.file ? { file: f.file, line: f.line } : undefined,
	evidence: f.evidence,
	remediation: f.remediation,
	references: f.references ?? [],
	confidence: f.confidence ?? "high",
	tags: ["strictness", ...(f.tags ?? [])],
});

export const readOrEmpty = (ws: Workspace, path: FilePath) =>
	ws.readText(path).pipe(Effect.orElseSucceed(() => ""));

export const parseToml = (text: SourceText): Record<string, unknown> => {
	try {
		const doc: unknown = Bun.TOML.parse(text);
		return isRecord(doc) ? doc : {};
	} catch {
		return {};
	}
};

export const asRecord = (v: unknown): Record<string, unknown> =>
	isRecord(v) ? v : {};

export const lineOfIndex = (text: SourceText, index: number) => {
	let line = 1;
	for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) line++;
	return line;
};
