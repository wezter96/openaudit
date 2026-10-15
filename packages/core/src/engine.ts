import { Duration, Effect } from "effect";

import type { AuditContext, AuditOptions, Auditor } from "./auditor";
import { correlate, isPrimary } from "./correlate";
import type { TargetError } from "./errors";
import {
	type AuditorResult,
	type Category,
	type Finding,
	type FindingInput,
	type Location,
	type Report,
	SCHEMA_VERSION,
	severityRank,
	type TargetInfo,
	type TargetKind,
} from "./model";
import { summarize } from "./scoring";
import {
	Exec,
	Http,
	ignoredPathMatcher,
	type Workspace,
	Workspaces,
} from "./services";
import { resolveTarget } from "./target";

export const VERSION = "0.3.0";

export type AuditEvent =
	| { readonly type: "target"; readonly target: Report["target"] }
	| { readonly type: "start"; readonly auditor: Auditor }
	| { readonly type: "finish"; readonly result: AuditorResult };

export interface Selection {
	/** Auditor ids or patterns: `web.headers`, `web.*`, `web`. */
	readonly only?: ReadonlyArray<string>;
	readonly exclude?: ReadonlyArray<string>;
	readonly categories?: ReadonlyArray<Category>;
	/**
	 * Like `only`, but can only narrow the default set: it never enables an
	 * opt-in (`defaultEnabled: false`) or agentic auditor. Used for selections
	 * from untrusted sources such as a config file inside the target.
	 */
	readonly narrow?: ReadonlyArray<string>;
}

export interface Suppressions {
	/** Rule ids or patterns (`code.secrets/*`) to drop. */
	readonly rules?: ReadonlyArray<string>;
	/** Finding fingerprints to drop (e.g. from a baseline). */
	readonly fingerprints?: ReadonlyArray<string>;
	/** File globs whose findings are dropped. */
	readonly paths?: ReadonlyArray<string>;
}

export interface RunAuditInput {
	readonly target: string;
	readonly auditors: ReadonlyArray<Auditor>;
	readonly options?: AuditOptions;
	readonly selection?: Selection;
	readonly suppress?: Suppressions;
	readonly concurrency?: number;
	/** Per-auditor timeout (default 5 minutes; agentic auditors get 20). */
	readonly timeoutMs?: number;
	readonly onEvent?: (event: AuditEvent) => void;
}

/** `web.*`, `web` and `web.headers` all match `web.headers`. */
export const matchesPattern = (id: string, pattern: string): boolean => {
	if (pattern === id) return true;
	if (pattern.endsWith("*")) return id.startsWith(pattern.slice(0, -1));
	return id.startsWith(`${pattern}.`) || id.startsWith(`${pattern}/`);
};

export const selectAuditors = (
	auditors: ReadonlyArray<Auditor>,
	kinds: ReadonlyArray<TargetKind>,
	selection: Selection = {},
	options: AuditOptions = {},
): ReadonlyArray<Auditor> =>
	auditors.filter((a) => isSelected(a, kinds, selection, options));

type Patterns = ReadonlyArray<string> | undefined;

const matchesAny = (id: string, patterns: Patterns): boolean =>
	patterns?.some((p) => matchesPattern(id, p)) ?? false;

/** An empty or missing list of patterns does not narrow anything. */
const narrowedTo = (id: string, patterns: Patterns): boolean =>
	!patterns?.length || matchesAny(id, patterns);

const inCategories = (
	a: Auditor,
	categories: ReadonlyArray<Category> | undefined,
): boolean =>
	!categories?.length || a.categories.some((c) => categories.includes(c));

// Opt-in agentic auditors (e.g. ones that spend money per run) need
// `--agentic` and an explicit selection.
const enabledByDefault = (a: Auditor, options: AuditOptions): boolean => {
	if (a.defaultEnabled === false) return false;
	return a.engine !== "agentic" || options.agentic === true;
};

const isSelected = (
	a: Auditor,
	kinds: ReadonlyArray<TargetKind>,
	selection: Selection,
	options: AuditOptions,
): boolean => {
	if (!a.targets.some((t) => kinds.includes(t))) return false;
	if (matchesAny(a.id, selection.exclude)) return false;
	if (!inCategories(a, selection.categories)) return false;
	if (!narrowedTo(a.id, selection.narrow)) return false;
	if (selection.only?.length) return matchesAny(a.id, selection.only);
	return enabledByDefault(a, options);
};

/** Stable 16-hex-char fingerprint. */
export const fingerprintOf = (auditor: string, f: FindingInput): string => {
	const loc: Location = f.location ?? {};
	const key = [
		auditor,
		f.ruleId,
		loc.file ?? "",
		loc.url ?? "",
		loc.selector ?? "",
		f.evidence ?? loc.line ?? "",
	].join("|");
	return new Bun.CryptoHasher("sha256").update(key).digest("hex").slice(0, 16);
};

const isSuppressed = (f: Finding, s: Suppressions = {}): boolean =>
	(s.fingerprints?.includes(f.fingerprint) ?? false) ||
	matchesAny(f.ruleId, s.rules) ||
	inGlobs(f.location?.file, s.paths);

const inGlobs = (file: string | undefined, globs: Patterns): boolean => {
	if (!file) return false;
	return globs?.some((g) => new Bun.Glob(g).match(file)) ?? false;
};

/** Drops findings in gitignored files and counts them. */
interface IgnoredFilter {
	readonly matches: (path: string) => boolean;
	dropped: number;
}

/** True, and counted, when the finding is in an ignored file. */
const dropsIgnored = (filter: IgnoredFilter, f: Finding): boolean => {
	const file = f.location?.file;
	if (!file || !filter.matches(file)) return false;
	filter.dropped++;
	return true;
};

const finalize = (
	auditor: Auditor,
	inputs: ReadonlyArray<FindingInput>,
	suppress: Suppressions | undefined,
	ignored: IgnoredFilter | undefined,
): Finding[] => {
	const seen = new Set<string>();
	const out: Finding[] = [];
	const filter = auditor.keepIgnored ? undefined : ignored;
	for (const input of inputs) {
		const fingerprint = input.fingerprint ?? fingerprintOf(auditor.id, input);
		if (seen.has(fingerprint)) continue;
		seen.add(fingerprint);
		const f: Finding = { ...input, auditor: auditor.id, fingerprint };
		if (filter && dropsIgnored(filter, f)) continue;
		if (!isSuppressed(f, suppress)) out.push(f);
	}
	return out.sort(
		(a, b) => severityRank(a.severity) - severityRank(b.severity),
	);
};

/** Agentic auditors get 20 minutes, the others 5. */
const defaultTimeoutMs = (auditor: Auditor): number =>
	auditor.engine === "agentic" ? 20 * 60_000 : 5 * 60_000;

const statusOf = (findings: ReadonlyArray<Finding>): AuditorResult["status"] =>
	findings.some((f) => f.severity !== "info") ? "failed" : "passed";

const runOne = (
	auditor: Auditor,
	ctx: AuditContext,
	input: RunAuditInput,
	ignored: IgnoredFilter | undefined,
): Effect.Effect<AuditorResult> => {
	const base = {
		auditor: auditor.id,
		title: auditor.title,
		engine: auditor.engine,
		categories: [...auditor.categories],
	};
	const timeoutMs = input.timeoutMs ?? defaultTimeoutMs(auditor);
	const started = performance.now();
	const elapsed = () => Math.round(performance.now() - started);

	if (ctx.options.offline && auditor.network) {
		return Effect.succeed({
			...base,
			status: "skipped",
			message: "Requires network access (--offline)",
			durationMs: 0,
			findings: [],
		});
	}

	return auditor.run(ctx).pipe(
		Effect.timeoutOrElse({
			duration: Duration.millis(timeoutMs),
			orElse: () =>
				Effect.fail({
					_tag: "Timeout" as const,
					message: `Timed out after ${timeoutMs}ms`,
				}),
		}),
		Effect.map((inputs): AuditorResult => {
			const findings = finalize(auditor, inputs, input.suppress, ignored);
			return {
				...base,
				status: statusOf(findings),
				durationMs: elapsed(),
				findings,
			};
		}),
		Effect.catch((error) =>
			Effect.succeed<AuditorResult>({
				...base,
				...(error._tag === "SkipAudit"
					? { status: "skipped", message: error.reason }
					: { status: "error", message: error.message }),
				durationMs: elapsed(),
				findings: [],
			}),
		),
		// Defects in third-party auditors must never take down the whole audit.
		Effect.catchDefect((defect) =>
			Effect.succeed<AuditorResult>({
				...base,
				status: "error",
				message: `Unexpected error: ${defect instanceof Error ? defect.message : String(defect)}`,
				durationMs: elapsed(),
				findings: [],
			}),
		),
	);
};

/**
 * User-supplied headers (often credentials) only go to the exact target
 * origin; a prefix check would also match `https://target.com.evil.net`.
 */
const isOrigin = (url: string, origin: string | undefined): boolean => {
	try {
		return origin !== undefined && new URL(url).origin === origin;
	} catch {
		return false;
	}
};

const targetHttp = (
	http: { readonly request: AuditContext["http"] },
	info: TargetInfo,
	options: AuditOptions,
): AuditContext["http"] => {
	const targetOrigin = info.url ? new URL(info.url).origin : undefined;
	return (url, init = {}) =>
		http.request(url, {
			...init,
			headers: isOrigin(url, targetOrigin)
				? { ...options.headers, ...init.headers }
				: init.headers,
		});
};

// Wrapped tools walk the folder themselves; findings in files git
// ignores are dropped here, whichever tool reported them.
const ignoredFilterOf = (
	workspace: Workspace | undefined,
): Effect.Effect<IgnoredFilter | undefined> =>
	Effect.gen(function* () {
		if (!workspace) return undefined;
		const ignoredPaths = yield* workspace.ignored.pipe(
			Effect.catch(() => Effect.succeed([] as ReadonlyArray<string>)),
		);
		if (!ignoredPaths.length) return undefined;
		return {
			matches: ignoredPathMatcher(workspace.root, ignoredPaths),
			dropped: 0,
		};
	});

const gitignoreSuppressed = (
	ignored: IgnoredFilter | undefined,
): Pick<Report, "suppressed"> =>
	ignored?.dropped
		? {
				suppressed: [
					{
						source: ".gitignore",
						rules: 0,
						paths: ignored.dropped,
						fingerprints: 0,
					},
				],
			}
		: {};

/**
 * Resolves the target, selects applicable auditors, runs them concurrently and
 * produces a scored report. Auditor failures are captured per auditor; only an
 * unresolvable target fails the whole run.
 */
export const runAudit = (
	input: RunAuditInput,
): Effect.Effect<Report, TargetError, Workspaces | Http | Exec> =>
	Effect.gen(function* () {
		const workspaces = yield* Workspaces;
		const http = yield* Http;
		const exec = yield* Exec;
		const options = input.options ?? {};
		const startedAt = new Date();
		const emit = input.onEvent ?? (() => {});

		const { info, root } = yield* resolveTarget(
			input.target,
			options,
			workspaces.open,
		);
		emit({ type: "target", target: info });

		const ctx: AuditContext = {
			target: info,
			options,
			workspace: root ? workspaces.open(root) : undefined,
			http: targetHttp(http, info, options),
			exec,
			log: (message) => Effect.logDebug(message),
		};
		const ignored = yield* ignoredFilterOf(ctx.workspace);

		const selected = selectAuditors(
			input.auditors,
			info.kinds,
			input.selection,
			options,
		);

		const ran = yield* Effect.forEach(
			selected,
			(auditor) =>
				Effect.sync(() => emit({ type: "start", auditor })).pipe(
					Effect.andThen(runOne(auditor, ctx, input, ignored)),
					Effect.tap((result) =>
						Effect.sync(() => emit({ type: "finish", result })),
					),
				),
			{ concurrency: input.concurrency ?? 4 },
		);
		const results = correlate(ran);

		const finishedAt = new Date();
		return {
			schemaVersion: SCHEMA_VERSION,
			tool: { name: "openaudit", version: VERSION },
			target: info,
			startedAt: startedAt.toISOString(),
			finishedAt: finishedAt.toISOString(),
			durationMs: finishedAt.getTime() - startedAt.getTime(),
			summary: summarize(results),
			results,
			...gitignoreSuppressed(ignored),
		} satisfies Report;
	});

/**
 * All findings in a report, most severe first. Duplicates of another
 * auditor's finding are left out; the kept one lists them in `alsoReportedBy`.
 */
export const allFindings = (report: Report): ReadonlyArray<Finding> =>
	report.results
		.flatMap((r) => r.findings)
		.filter(isPrimary)
		.sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
