import { basename, isAbsolute, relative, resolve } from "node:path";
import * as Agent from "@openaudit/agent";
import { builtinAuditors } from "@openaudit/auditors";
import {
	type AuditOptions,
	type Auditor,
	CoreLive,
	changedFilesSince,
	colorEnabled,
	GitError,
	hasSuppressionNotice,
	limitToChangedFiles,
	type Report,
	runAudit,
	sanitizeText,
} from "@openaudit/core";
import { Effect } from "effect";

import {
	type AuditFlags,
	type AuditSettings,
	auditSettings,
	parseHeaders,
	readBaseline,
	UsageError,
} from "./audit-flags";
import {
	type AuditOutput,
	discloseSuppressions,
	EXIT,
	exitCode,
	type Finished,
	type Io,
	writeOutput,
} from "./audit-output";
import {
	CONFIG_FILE,
	type Config,
	ConfigError,
	type IgnoreEntry,
	isoDay,
	type LoadedConfig,
	loadConfig,
	resolveIgnores,
} from "./config";
import { createProgress } from "./progress";
import { applySuppressions } from "./suppress";

export {
	type AuditFlags,
	parseHeaders,
	readBaseline,
	splitList,
	UsageError,
} from "./audit-flags";
export { EXIT, type Io } from "./audit-output";

/** Built-in plus agentic auditors; agentic ones only run with `--agentic`. */
export const allAuditors = (): ReadonlyArray<Auditor> => [
	...builtinAuditors,
	...Agent.agenticAuditors,
];

export const processIo = (): Io => ({
	stdout: (t) => process.stdout.write(t),
	stderr: (t) => process.stderr.write(t),
	stderrIsTTY: process.stderr.isTTY === true,
	cwd: process.cwd(),
});

/** Targets that are not paths on disk. */
const REMOTE_TARGET = /^https?:\/\/|^image:|^cloud:/i;

/** One audit's inputs, resolved from flags and config before it runs. */
interface Run {
	readonly flags: AuditFlags;
	readonly io: Io;
	readonly loaded: LoadedConfig;
	readonly settings: AuditSettings;
	readonly ignores: ReturnType<typeof resolveIgnores>;
	/** Fingerprints from `--baseline`. */
	readonly baseline: ReadonlyArray<string>;
}

const NARROWING_KEYS = ["only", "exclude", "categories"] as const;

/** How the config narrows the auditor selection, e.g. `only: code.secrets`. */
const narrowingOf = (config: Config): string[] =>
	NARROWING_KEYS.flatMap((key) => {
		const values = config[key];
		return values?.length ? [`${key}: ${values.join(", ")}`] : [];
	});

/** Notices about what the config changed, for stderr. */
const configNotices = (
	{ config, path, ignored }: LoadedConfig,
	expired: ReadonlyArray<IgnoreEntry>,
): string[] => {
	const narrowing = narrowingOf(config);
	return [
		...(narrowing.length && path
			? [
					`openaudit: ${sanitizeText(`${path} narrows the audit (${narrowing.join("; ")})`)}\n`,
				]
			: []),
		...(ignored.length
			? [
					`openaudit: ignoring ${ignored.join(", ")} in ${path}: a config inside the audited target cannot enable settings that send data, cost money or add credentials. Use flags or --config <path> instead.\n`,
				]
			: []),
		...(expired.length
			? [
					`openaudit: ${sanitizeText(`${path}: ${expired.length} suppression(s) expired and no longer apply: ${expired.map((e) => `${e.kind} ${e.value} (until ${e.until})`).join(", ")}. Fix the findings, or remove the entries or move their "until" dates.`)}\n`,
				]
			: []),
	];
};

const isInside = (rel: string): boolean =>
	rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);

/**
 * A path as shown in reports: relative to where openaudit was run, or just the
 * file name when it lies elsewhere, so reports don't reveal local directories.
 */
const shownPath = (cwd: string, path: string): string => {
	const rel = relative(cwd, path);
	return isInside(rel) ? rel : basename(path);
};

/** Files changed since `base`; diff mode only makes sense for a git checkout. */
const diffFiles = async (target: string, base: string): Promise<string[]> => {
	if (REMOTE_TARGET.test(target))
		throw new UsageError(
			"--diff needs a directory target inside a git repository.",
		);
	try {
		return await changedFilesSince(target, base);
	} catch (error) {
		if (error instanceof GitError) throw new UsageError(error.message);
		throw error;
	}
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

/** Live progress on stderr, only for a person at a terminal. */
const startProgress = ({ flags, io, loaded }: Run) => {
	const showProgress = io.stderrIsTTY && !flags.json && !flags.quiet;
	const color = colorEnabled() && io.stderrIsTTY;
	const progress = showProgress
		? createProgress({ color, write: io.stderr })
		: undefined;
	if (loaded.path && showProgress)
		io.stderr(`\x1b[2mUsing ${loaded.path}\x1b[0m\n`);
	return progress;
};

const auditOptions = ({ flags, loaded, settings }: Run): AuditOptions => {
	const opts = loaded.config.options ?? {};
	return {
		offline: flags.offline || opts.offline,
		browser: flags.browser || opts.browser,
		maxPages: settings.maxPages,
		agentic: flags.agentic || opts.agentic,
		model: flags.model ?? opts.model,
		headers: { ...opts.headers, ...parseHeaders(flags.header) },
		settings: opts.settings,
		diffBase: flags.diff,
	};
};

/** Runs the auditors on the target, plus the files `--diff` keeps. */
const runTarget = async (run: Run, auditors: ReadonlyArray<Auditor>) => {
	const { flags, io, settings } = run;
	const progress = startProgress(run);
	const target = REMOTE_TARGET.test(flags.target)
		? flags.target
		: resolve(io.cwd, flags.target);
	const changed = flags.diff ? await diffFiles(target, flags.diff) : undefined;
	const result = await Effect.runPromise(
		Effect.result(
			runAudit({
				target,
				auditors,
				options: auditOptions(run),
				selection: settings.selection,
				// Suppressions are applied afterwards so they can be counted and disclosed.
				concurrency: settings.concurrency,
				onEvent: progress?.onEvent,
			}).pipe(Effect.provide(CoreLive)),
		),
	).finally(() => progress?.stop());
	return { result, changed };
};

const narrowToDiff = (
	report: Report,
	base: string,
	changed: ReadonlyArray<string>,
): AuditOutput => {
	const limited = limitToChangedFiles(report, base, changed);
	return { report: limited, suppressed: [...(limited.suppressed ?? [])] };
};

/** Applies config and baseline suppressions, then keeps only `--diff` files. */
const suppress = (
	{ flags, io, loaded, ignores, baseline }: Run,
	report: Report,
	changed: ReadonlyArray<string> | undefined,
): AuditOutput => {
	const applied = applySuppressions(report, [
		{
			source: loaded.path ? shownPath(io.cwd, loaded.path) : CONFIG_FILE,
			entries: ignores.active,
			expired: ignores.expired,
		},
		{
			source: `--baseline ${flags.baseline}`,
			entries: baseline.map((value) => ({
				kind: "fingerprint" as const,
				value,
			})),
		},
	]);
	// The engine's own count (findings in gitignored files) comes first.
	const suppressed = [
		...(report.suppressed ?? []),
		...applied.suppressed.filter(hasSuppressionNotice),
	];
	const kept: Report = suppressed.length
		? { ...applied.report, suppressed }
		: applied.report;
	return changed && flags.diff
		? narrowToDiff(kept, flags.diff, changed)
		: { report: kept, suppressed };
};

/** Prints a warning unless `--quiet`. */
const warn = ({ flags, io }: Run, text: string): void => {
	if (!flags.quiet) io.stderr(text);
};

/** Runs AI insights; a rejection becomes a failure with its message. */
const runInsights = (
	insights: typeof Agent.aiInsights,
	report: Report,
	model: string | undefined,
) =>
	Effect.runPromise(
		Effect.result(insights(report, model ? { model } : undefined)),
	).catch((cause: unknown) => ({
		_tag: "Failure" as const,
		failure: {
			message: cause instanceof Error ? cause.message : String(cause),
		},
	}));

/** Adds Claude's prioritised summary; failures only warn. */
const attachInsights = async (run: Run, report: Report): Promise<Report> => {
	const insights = (Agent as { aiInsights?: typeof Agent.aiInsights })
		.aiInsights;
	if (typeof insights !== "function") {
		warn(run, "openaudit: --ai is not available in this build\n");
		return report;
	}
	const model = run.flags.model ?? run.loaded.config.options?.model;
	const res = await runInsights(insights, report, model);
	if (res._tag === "Failure") {
		warn(
			run,
			`openaudit: AI insights failed, continuing without them: ${sanitizeText(res.failure.message)}\n`,
		);
		return report;
	}
	return { ...report, ai: res.success };
};

const finish = async (run: Run, output: AuditOutput): Promise<Finished> => {
	const { flags, io, settings } = run;
	const report =
		flags.ai || run.loaded.config.options?.ai
			? await attachInsights(run, output.report)
			: output.report;
	return { flags, io, settings, report, suppressed: output.suppressed };
};

const audit = async (
	flags: AuditFlags,
	io: Io,
	auditors: ReadonlyArray<Auditor>,
): Promise<number> => {
	const loaded = await loadConfig({
		explicit: flags.config,
		noConfig: flags.noConfig,
		target: flags.target,
		cwd: io.cwd,
	});
	const ignores = resolveIgnores(
		loaded.config.ignore,
		isoDay(flags.now ?? new Date()),
	);
	if (!flags.quiet)
		for (const notice of configNotices(loaded, ignores.expired))
			io.stderr(notice);
	const settings = auditSettings(flags, loaded);
	const baseline = flags.baseline
		? await readBaseline(resolve(io.cwd, flags.baseline))
		: [];
	const run: Run = { flags, io, loaded, settings, ignores, baseline };

	const { result, changed } = await runTarget(run, auditors);
	if (result._tag === "Failure") {
		io.stderr(`openaudit: ${sanitizeText(result.failure.message)}\n`);
		return EXIT.usage;
	}
	const finished = await finish(run, suppress(run, result.success, changed));
	await writeOutput(finished);
	discloseSuppressions(finished);
	return exitCode(finished);
};
