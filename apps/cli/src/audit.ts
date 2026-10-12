import { mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import * as Agent from "@openaudit/agent";
import { builtinAuditors } from "@openaudit/auditors";
import {
	type Auditor,
	CATEGORIES,
	type Category,
	CoreLive,
	colorEnabled,
	FORMAT_EXTENSIONS,
	isAtLeast,
	isReportFormat,
	type Report,
	type ReportFormat,
	renderReport,
	runAudit,
	SEVERITIES,
	type Severity,
} from "@openaudit/core";
import { Effect } from "effect";

import { ConfigError, loadConfig } from "./config";
import { createProgress } from "./progress";

/** Built-in plus agentic auditors; agentic ones only run with `--agentic`. */
export const allAuditors = (): ReadonlyArray<Auditor> => [
	...builtinAuditors,
	...Agent.agenticAuditors,
];

export const EXIT = { ok: 0, findings: 1, usage: 2 } as const;

export class UsageError extends Error {}

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
	readonly concurrency?: number;
	readonly json: boolean;
	readonly quiet: boolean;
	readonly verbose: boolean;
	readonly config?: string;
}

export interface Io {
	readonly stdout: (text: string) => void;
	readonly stderr: (text: string) => void;
	readonly stderrIsTTY: boolean;
	readonly cwd: string;
}

export const processIo = (): Io => ({
	stdout: (t) => process.stdout.write(t),
	stderr: (t) => process.stderr.write(t),
	stderrIsTTY: process.stderr.isTTY === true,
	cwd: process.cwd(),
});

/** Splits repeatable, comma-separated flag values: `-f json,sarif -f html`. */
export const splitList = (values: ReadonlyArray<string>): string[] =>
	values
		.flatMap((v) => v.split(","))
		.map((v) => v.trim())
		.filter(Boolean);

export const parseHeaders = (
	values: ReadonlyArray<string>,
): Record<string, string> => {
	const headers: Record<string, string> = {};
	for (const raw of values) {
		const i = raw.indexOf(":");
		const name = i > 0 ? raw.slice(0, i).trim() : "";
		if (!name || /\s/.test(name))
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

/** Runs `openaudit audit` and returns the process exit code. */
export const auditCommand = async (
	flags: AuditFlags,
	io: Io = processIo(),
	auditors: ReadonlyArray<Auditor> = allAuditors(),
): Promise<number> => {
	try {
		return await audit(flags, io, auditors);
	} catch (error) {
		if (error instanceof UsageError || error instanceof ConfigError) {
			io.stderr(`openaudit: ${error.message}\n`);
			return EXIT.usage;
		}
		throw error;
	}
};

const audit = async (
	flags: AuditFlags,
	io: Io,
	auditors: ReadonlyArray<Auditor>,
): Promise<number> => {
	const { config, path: configPath } = await loadConfig({
		explicit: flags.config,
		target: flags.target,
		cwd: io.cwd,
	});
	const opts = config.options ?? {};

	const formats = flags.json ? ["json"] : splitList(flags.format);
	if (!formats.length) formats.push("terminal");
	for (const f of formats) {
		if (!isReportFormat(f))
			throw new UsageError(
				`Unknown format "${f}". Use: terminal, json, sarif, markdown, html.`,
			);
	}
	const uniqueFormats = [...new Set(formats)] as ReportFormat[];
	if (uniqueFormats.length > 1 && !flags.out)
		throw new UsageError(
			"Several formats need --out <dir>; stdout takes a single format.",
		);

	const only = flags.only.length
		? splitList(flags.only)
		: [...(config.only ?? [])];
	const exclude = [...(config.exclude ?? []), ...splitList(flags.exclude)];
	const categories = flags.category.length
		? parseCategories(splitList(flags.category))
		: [...(config.categories ?? [])];
	const failOn = parseSeverity(flags.failOn ?? config.failOn);
	const maxPages = flags.maxPages ?? opts.maxPages;
	const concurrency = flags.concurrency ?? opts.concurrency;
	if (maxPages !== undefined && (!Number.isInteger(maxPages) || maxPages < 1))
		throw new UsageError("--max-pages must be a positive integer.");
	if (
		concurrency !== undefined &&
		(!Number.isInteger(concurrency) || concurrency < 1)
	)
		throw new UsageError("--concurrency must be a positive integer.");

	const baseline = flags.baseline
		? await readBaseline(resolve(io.cwd, flags.baseline))
		: [];

	const machine = flags.json;
	const showProgress = io.stderrIsTTY && !machine && !flags.quiet;
	const color = colorEnabled() && io.stderrIsTTY;
	const progress = showProgress
		? createProgress({ color, write: io.stderr })
		: undefined;
	if (configPath && showProgress)
		io.stderr(`\x1b[2mUsing ${configPath}\x1b[0m\n`);

	const target = /^https?:\/\/|^image:/i.test(flags.target)
		? flags.target
		: resolve(io.cwd, flags.target);

	const result = await Effect.runPromise(
		Effect.result(
			runAudit({
				target,
				auditors,
				options: {
					offline: flags.offline || opts.offline,
					browser: flags.browser || opts.browser,
					maxPages,
					agentic: flags.agentic || opts.agentic,
					model: flags.model ?? opts.model,
					headers: parseHeaders(flags.header),
					settings: opts.settings,
				},
				selection: { only, exclude, categories },
				suppress: {
					rules: config.ignore?.rules,
					paths: config.ignore?.paths,
					fingerprints: [...(config.ignore?.fingerprints ?? []), ...baseline],
				},
				concurrency,
				onEvent: progress?.onEvent,
			}).pipe(Effect.provide(CoreLive)),
		),
	).finally(() => progress?.stop());

	if (result._tag === "Failure") {
		io.stderr(`openaudit: ${result.failure.message}\n`);
		return EXIT.usage;
	}
	let report = result.success;

	if (flags.ai)
		report = await attachInsights(
			report,
			flags.model ?? opts.model,
			io,
			flags.quiet,
		);

	if (flags.out) {
		const dir = resolve(io.cwd, flags.out);
		await mkdir(dir, { recursive: true });
		for (const format of uniqueFormats) {
			const file = join(dir, `openaudit-report.${FORMAT_EXTENSIONS[format]}`);
			await Bun.write(
				file,
				renderReport(report, format, { color: false, verbose: true }),
			);
			if (!flags.quiet && !machine) io.stderr(`Wrote ${file}\n`);
		}
		if (machine) io.stdout(renderReport(report, "json"));
		else if (!flags.quiet)
			io.stdout(
				renderReport(report, "terminal", {
					color: colorEnabled() && process.stdout.isTTY === true,
					verbose: flags.verbose,
				}),
			);
	} else {
		const format = uniqueFormats[0] ?? "terminal";
		io.stdout(
			renderReport(report, format, {
				color: colorEnabled() && process.stdout.isTTY === true,
				verbose: flags.verbose,
			}),
		);
	}

	if (failOn) {
		const breached = report.results
			.flatMap((r) => r.findings)
			.filter((f) => isAtLeast(f.severity, failOn));
		if (breached.length) {
			if (!machine && !flags.quiet)
				io.stderr(
					`openaudit: ${breached.length} finding(s) at or above "${failOn}" (exit 1)\n`,
				);
			return EXIT.findings;
		}
	}
	return EXIT.ok;
};

/** Adds Claude's prioritised summary; failures only warn. */
const attachInsights = async (
	report: Report,
	model: string | undefined,
	io: Io,
	quiet: boolean,
): Promise<Report> => {
	const insights = (Agent as { aiInsights?: typeof Agent.aiInsights })
		.aiInsights;
	if (typeof insights !== "function") {
		if (!quiet) io.stderr("openaudit: --ai is not available in this build\n");
		return report;
	}
	const res = await Effect.runPromise(
		Effect.result(insights(report, model ? { model } : undefined)),
	).catch((cause: unknown) => ({
		_tag: "Failure" as const,
		failure: {
			message: cause instanceof Error ? cause.message : String(cause),
		},
	}));
	if (res._tag === "Failure") {
		if (!quiet)
			io.stderr(
				`openaudit: AI insights failed, continuing without them: ${res.failure.message}\n`,
			);
		return report;
	}
	return { ...report, ai: res.success };
};
