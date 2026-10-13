import { Duration, Effect } from "effect";

import type { AuditContext, AuditOptions, Auditor } from "./auditor";
import type { TargetError } from "./errors";
import {
	type AuditorResult,
	type Category,
	type Finding,
	type FindingInput,
	type Report,
	SCHEMA_VERSION,
	severityRank,
	type TargetKind,
} from "./model";
import { summarize } from "./scoring";
import { Exec, Http, Workspaces } from "./services";
import { resolveTarget } from "./target";

export const VERSION = "0.1.0";

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
	auditors.filter((a) => {
		if (!a.targets.some((t) => kinds.includes(t))) return false;
		if (selection.exclude?.some((p) => matchesPattern(a.id, p))) return false;
		if (
			selection.categories?.length &&
			!a.categories.some((c) => selection.categories?.includes(c))
		)
			return false;
		if (
			selection.narrow?.length &&
			!selection.narrow.some((p) => matchesPattern(a.id, p))
		)
			return false;
		if (selection.only?.length)
			return selection.only.some((p) => matchesPattern(a.id, p));
		// Opt-in agentic auditors (e.g. ones that spend money per run) need
		// `--agentic` and an explicit selection.
		if (a.engine === "agentic")
			return options.agentic === true && a.defaultEnabled !== false;
		return a.defaultEnabled !== false;
	});

/** Stable 16-hex-char fingerprint. */
export const fingerprintOf = (auditor: string, f: FindingInput): string => {
	const loc = f.location;
	const key = [
		auditor,
		f.ruleId,
		loc?.file ?? "",
		loc?.url ?? "",
		loc?.selector ?? "",
		f.evidence ?? loc?.line ?? "",
	].join("|");
	return new Bun.CryptoHasher("sha256").update(key).digest("hex").slice(0, 16);
};

const isSuppressed = (f: Finding, s: Suppressions | undefined): boolean => {
	if (!s) return false;
	if (s.fingerprints?.includes(f.fingerprint)) return true;
	if (s.rules?.some((p) => matchesPattern(f.ruleId, p))) return true;
	const file = f.location?.file;
	if (file && s.paths?.some((g) => new Bun.Glob(g).match(file))) return true;
	return false;
};

const finalize = (
	auditor: Auditor,
	inputs: ReadonlyArray<FindingInput>,
	suppress: Suppressions | undefined,
): Finding[] => {
	const seen = new Set<string>();
	const out: Finding[] = [];
	for (const input of inputs) {
		const fingerprint = input.fingerprint ?? fingerprintOf(auditor.id, input);
		if (seen.has(fingerprint)) continue;
		seen.add(fingerprint);
		const f: Finding = { ...input, auditor: auditor.id, fingerprint };
		if (!isSuppressed(f, suppress)) out.push(f);
	}
	return out.sort(
		(a, b) => severityRank(a.severity) - severityRank(b.severity),
	);
};

const runOne = (
	auditor: Auditor,
	ctx: AuditContext,
	input: RunAuditInput,
): Effect.Effect<AuditorResult> => {
	const base = {
		auditor: auditor.id,
		title: auditor.title,
		engine: auditor.engine,
		categories: [...auditor.categories],
	};
	const timeoutMs =
		input.timeoutMs ??
		(auditor.engine === "agentic" ? 20 * 60_000 : 5 * 60_000);
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
			const findings = finalize(auditor, inputs, input.suppress);
			return {
				...base,
				status: findings.some((f) => f.severity !== "info")
					? "failed"
					: "passed",
				durationMs: elapsed(),
				findings,
			};
		}),
		Effect.catch((error) =>
			Effect.succeed<AuditorResult>({
				...base,
				status: error._tag === "SkipAudit" ? "skipped" : "error",
				message: error._tag === "SkipAudit" ? error.reason : error.message,
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

		// User-supplied headers (often credentials) only go to the exact target
		// origin; a prefix check would also match `https://target.com.evil.net`.
		const targetOrigin = info.url ? new URL(info.url).origin : undefined;
		const isTargetOrigin = (url: string) => {
			try {
				return (
					targetOrigin !== undefined && new URL(url).origin === targetOrigin
				);
			} catch {
				return false;
			}
		};

		const ctx: AuditContext = {
			target: info,
			options,
			workspace: root ? workspaces.open(root) : undefined,
			http: (url, init) =>
				http.request(url, {
					...init,
					headers: isTargetOrigin(url)
						? { ...options.headers, ...init?.headers }
						: init?.headers,
				}),
			exec,
			log: (message) => Effect.logDebug(message),
		};

		const selected = selectAuditors(
			input.auditors,
			info.kinds,
			input.selection,
			options,
		);

		const results = yield* Effect.forEach(
			selected,
			(auditor) =>
				Effect.sync(() => emit({ type: "start", auditor })).pipe(
					Effect.andThen(runOne(auditor, ctx, input)),
					Effect.tap((result) =>
						Effect.sync(() => emit({ type: "finish", result })),
					),
				),
			{ concurrency: input.concurrency ?? 4 },
		);

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
		} satisfies Report;
	});

/** All findings in a report, most severe first. */
export const allFindings = (report: Report): ReadonlyArray<Finding> =>
	report.results
		.flatMap((r) => r.findings)
		.sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
