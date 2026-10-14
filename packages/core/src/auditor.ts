import { Effect } from "effect";

import { type AuditorError, SkipAudit } from "./errors";
import type {
	AuditorEngine,
	Category,
	FindingInput,
	TargetInfo,
	TargetKind,
} from "./model";
import type {
	ExecOptions,
	ExecResult,
	HttpRequest,
	HttpResponse,
	Workspace,
} from "./services";

/** Options that change how auditors behave. All optional. */
export interface AuditOptions {
	/** Do not make network requests other than to the target itself. */
	readonly offline?: boolean;
	/** Drive a real browser (Playwright) against URL targets. */
	readonly browser?: boolean;
	/** Max pages to crawl for URL/webapp targets. */
	readonly maxPages?: number;
	/** Enable agentic (LLM-driven) auditors. */
	readonly agentic?: boolean;
	/** Model override for agentic auditors and AI insights. */
	readonly model?: string;
	/** Extra headers sent to URL targets (e.g. auth cookies for staging). */
	readonly headers?: Record<string, string>;
	/** Per-auditor settings keyed by auditor id. */
	readonly settings?: Record<string, Record<string, unknown>>;
	/**
	 * Diff mode: the git ref the change is compared against (`--diff <ref>`).
	 * Callers validate it with `changedFilesSince` first; auditors that compare
	 * against the base (such as breaking API changes) read it here.
	 */
	readonly diffBase?: string;
}

/**
 * Everything an auditor may use. Infrastructure is resolved once by the engine
 * and closed over here, so `run` has no requirements of its own.
 */
export interface AuditContext {
	readonly target: TargetInfo;
	readonly options: AuditOptions;
	/** Present for directory targets (and the parent dir of file targets). */
	readonly workspace: Workspace | undefined;
	readonly http: (
		url: string,
		init?: HttpRequest,
	) => Effect.Effect<HttpResponse, AuditorError>;
	readonly exec: {
		readonly which: (bin: string) => Effect.Effect<string | undefined>;
		readonly run: (
			cmd: ReadonlyArray<string>,
			options?: ExecOptions,
		) => Effect.Effect<ExecResult, AuditorError>;
	};
	readonly log: (message: string) => Effect.Effect<void>;
}

export interface Auditor {
	/** Stable id, `<area>.<name>`, e.g. `web.headers`, `code.secrets`. */
	readonly id: string;
	readonly title: string;
	readonly description: string;
	readonly categories: ReadonlyArray<Category>;
	/** Target kinds this auditor applies to. */
	readonly targets: ReadonlyArray<TargetKind>;
	readonly engine: AuditorEngine;
	/** External binary this auditor wraps, if any. */
	readonly tool?: string;
	/** Needs network access beyond the target (e.g. OSV.dev). */
	readonly network?: boolean;
	/** Runs when no explicit selection is given. Defaults to true. */
	readonly defaultEnabled?: boolean;
	readonly run: (
		ctx: AuditContext,
	) => Effect.Effect<ReadonlyArray<FindingInput>, AuditorError | SkipAudit>;
}

export const defineAuditor = (auditor: Auditor): Auditor => auditor;

/* ------------------------------- helpers ---------------------------------- */

export const skip = (reason: string) => Effect.fail(new SkipAudit({ reason }));

/** The workspace, or skip when the target has none. */
export const requireWorkspace = (
	ctx: AuditContext,
): Effect.Effect<Workspace, SkipAudit> =>
	ctx.workspace
		? Effect.succeed(ctx.workspace)
		: Effect.fail(new SkipAudit({ reason: "Target has no local files" }));

/** The target URL, or skip when the target is not a URL. */
export const requireUrl = (
	ctx: AuditContext,
): Effect.Effect<string, SkipAudit> =>
	ctx.target.url
		? Effect.succeed(ctx.target.url)
		: Effect.fail(new SkipAudit({ reason: "Target is not a URL" }));

/** Path of an external binary, or skip with an install hint. */
export const requireTool = (
	ctx: AuditContext,
	bin: string,
	installHint: string,
): Effect.Effect<string, SkipAudit> =>
	Effect.flatMap(ctx.exec.which(bin), (path) =>
		path
			? Effect.succeed(path)
			: Effect.fail(
					new SkipAudit({ reason: `${bin} not found on PATH. ${installHint}` }),
				),
	);

/** 1-based line number of a character offset. */
export const lineOf = (text: string, index: number): number => {
	let line = 1;
	for (let i = 0; i < index && i < text.length; i++) {
		if (text.charCodeAt(i) === 10) line++;
	}
	return line;
};

/** The trimmed source line containing `index`, truncated for evidence. */
export const lineAt = (text: string, index: number, max = 160): string => {
	const start = text.lastIndexOf("\n", index - 1) + 1;
	const end = text.indexOf("\n", index);
	const line = text.slice(start, end === -1 ? undefined : end).trim();
	return line.length > max ? `${line.slice(0, max)}…` : line;
};

/** Masks a secret, keeping a short prefix so humans can recognise it. */
export const redact = (secret: string, keep = 4): string =>
	secret.length <= keep
		? "*".repeat(secret.length)
		: `${secret.slice(0, keep)}${"*".repeat(Math.min(12, secret.length - keep))}`;
