import {
	CATEGORIES,
	type Category,
	isReportFormat,
	type ReportFormat,
	SEVERITIES,
	type Severity,
} from "@openaudit/core";

import type { Config, LoadedConfig } from "./config";

export interface AuditFlags {
	readonly target: string;
	readonly format: ReadonlyArray<string>;
	readonly out?: string;
	readonly only: ReadonlyArray<string>;
	readonly exclude: ReadonlyArray<string>;
	readonly category: ReadonlyArray<string>;
	readonly failOn?: string;
	readonly offline: boolean;
	readonly browser: boolean;
	readonly maxPages?: number;
	readonly header: ReadonlyArray<string>;
	readonly agentic: boolean;
	readonly ai: boolean;
	readonly model?: string;
	readonly baseline?: string;
	/** Keep only findings in files changed since this git ref. */
	readonly diff?: string;
	readonly concurrency?: number;
	readonly json: boolean;
	readonly quiet: boolean;
	readonly verbose: boolean;
	readonly config?: string;
	/** Ignore `openaudit.config.json` in the target. */
	readonly noConfig?: boolean;
	readonly allowErrors?: boolean;
	/** Clock for `until` dates in suppressions; tests set it. */
	readonly now?: Date;
}

export class UsageError extends Error {}

/** Splits repeatable, comma-separated flag values: `-f json,sarif -f html`. */
export const splitList = (values: ReadonlyArray<string>): string[] =>
	values
		.flatMap((v) => v.split(","))
		.map((v) => v.trim())
		.filter(Boolean);

/** A non-empty header name without whitespace. */
const isHeaderName = (name: string): boolean => name !== "" && !/\s/.test(name);

export const parseHeaders = (
	values: ReadonlyArray<string>,
): Record<string, string> => {
	const headers: Record<string, string> = {};
	for (const raw of values) {
		const i = raw.indexOf(":");
		const name = i > 0 ? raw.slice(0, i).trim() : "";
		if (!isHeaderName(name))
			throw new UsageError(
				`Invalid --header "${raw}". Use "Name: value", e.g. --header "Cookie: session=abc".`,
			);
		headers[name] = raw.slice(i + 1).trim();
	}
	return headers;
};

const parseSeverity = (value: string | undefined): Severity | undefined => {
	if (value === undefined || value === "none") return undefined;
	if ((SEVERITIES as ReadonlyArray<string>).includes(value))
		return value as Severity;
	throw new UsageError(
		`Invalid --fail-on "${value}". Use one of: ${SEVERITIES.join(", ")}, none.`,
	);
};

const parseCategories = (values: ReadonlyArray<string>): Category[] => {
	for (const c of values) {
		if (!(CATEGORIES as ReadonlyArray<string>).includes(c))
			throw new UsageError(
				`Unknown category "${c}". Use: ${CATEGORIES.join(", ")}.`,
			);
	}
	return values as Category[];
};

/** Fingerprints of every finding in an earlier JSON report. */
export const readBaseline = async (path: string): Promise<string[]> => {
	const file = Bun.file(path);
	if (!(await file.exists()))
		throw new UsageError(`Baseline not found: ${path}`);
	let report: {
		results?: Array<{ findings?: Array<{ fingerprint?: unknown }> }>;
	};
	try {
		report = JSON.parse(await file.text());
	} catch {
		throw new UsageError(`Baseline is not valid JSON: ${path}`);
	}
	if (!Array.isArray(report?.results))
		throw new UsageError(
			`Baseline is not an openaudit JSON report: ${path} (create one with --format json)`,
		);
	return report.results.flatMap((r) =>
		(r.findings ?? [])
			.map((f) => f.fingerprint)
			.filter((fp): fp is string => typeof fp === "string"),
	);
};

/** The report formats asked for; stdout takes one, so several need `--out`. */
const parseFormats = (flags: AuditFlags): ReportFormat[] => {
	const formats = flags.json ? ["json"] : splitList(flags.format);
	if (!formats.length) formats.push("terminal");
	const unknown = formats.find((f) => !isReportFormat(f));
	if (unknown !== undefined)
		throw new UsageError(
			`Unknown format "${unknown}". Use: terminal, json, sarif, markdown, html, csv.`,
		);
	const unique = [...new Set(formats)] as ReportFormat[];
	if (unique.length > 1 && !flags.out)
		throw new UsageError(
			"Several formats need --out <dir>; stdout takes a single format.",
		);
	return unique;
};

/**
 * Which auditors run. A config inside the target may only narrow the default
 * set; `--only` and `--config <path>` can also enable opt-in auditors.
 */
const selectionOf = (flags: AuditFlags, { config, trusted }: LoadedConfig) => {
	const configOnly = [...(config.only ?? [])];
	return {
		only: flags.only.length ? splitList(flags.only) : trusted ? configOnly : [],
		narrow: trusted ? [] : configOnly,
		exclude: [...(config.exclude ?? []), ...splitList(flags.exclude)],
		categories: flags.category.length
			? parseCategories(splitList(flags.category))
			: [...(config.categories ?? [])],
	};
};

const isPositiveInteger = (n: number): boolean => Number.isInteger(n) && n >= 1;

/** Rejects a count that is set but not a positive integer. */
const checkCount = (
	value: number | undefined,
	flag: "--max-pages" | "--concurrency",
): void => {
	if (value !== undefined && !isPositiveInteger(value))
		throw new UsageError(`${flag} must be a positive integer.`);
};

/** Flags merged with the config and checked; flags win. */
export interface AuditSettings {
	readonly formats: ReadonlyArray<ReportFormat>;
	readonly selection: ReturnType<typeof selectionOf>;
	readonly failOn?: Severity;
	readonly maxPages?: number;
	readonly concurrency?: number;
}

export const auditSettings = (
	flags: AuditFlags,
	loaded: LoadedConfig,
): AuditSettings => {
	const config: Config = loaded.config;
	const opts = config.options ?? {};
	const formats = parseFormats(flags);
	const selection = selectionOf(flags, loaded);
	const failOn = parseSeverity(flags.failOn ?? config.failOn);
	const maxPages = flags.maxPages ?? opts.maxPages;
	const concurrency = flags.concurrency ?? opts.concurrency;
	checkCount(maxPages, "--max-pages");
	checkCount(concurrency, "--concurrency");
	return { formats, selection, failOn, maxPages, concurrency };
};
