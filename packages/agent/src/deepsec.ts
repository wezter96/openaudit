import {
	type Dirent,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	type AuditContext,
	type Auditor,
	AuditorError,
	defineAuditor,
	type FindingInput,
	GIT_HARDENING_ENV,
	requireTool,
	requireWorkspace,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";
import { z } from "zod";

import { scrubSecrets } from "./auditors";

/**
 * Wraps Vercel Labs' deepsec (https://github.com/vercel-labs/deepsec), an
 * AI-agent vulnerability scanner.
 *
 * Flow (deepsec 2.3.x, "direct mode", no `deepsec init`, no `.deepsec/` in the
 * target): `DEEPSEC_DATA_ROOT=<tmp>/data deepsec scan --root <target>` finds
 * regex candidates, then `deepsec process --files a,b,c` runs the AI review in
 * small chunks, then `deepsec export --format json --out <tmp>/export.json`.
 * `process` has no cost flag (only `init`/`setup` take `--max-cost-usd`), so
 * the cost cap is enforced here between chunks from the `costUsd` deepsec
 * records per file. The overshoot is bounded by one chunk. In diff mode the
 * changed files come from a commit-to-commit `git diff <ref> HEAD` run here
 * (deepsec's own `--diff` compares the working tree, which runs clean filters
 * from the target's git config) and go through the same chunked review.
 *
 * deepsec drives a coding agent with shell access to the target: Claude gets
 * Read/Glob/Grep/Bash inside the Agent SDK's OS sandbox (deepsec falls back to
 * no sandbox when it cannot start one), Codex runs `workspace-write`. A hostile
 * repository can try to prompt-inject it, so the auditor is opt-in (explicit
 * `--only agent.deepsec`), never enabled by a config inside the target, and
 * only runs with explicit credentials in the environment. deepsec's own config
 * file is loaded from cwd upwards, so cwd is a fresh temp dir, never the
 * target. deepsec still runs git in the target (remote, rev-parse, log), so
 * repository config that runs commands (`core.fsmonitor`) is overridden
 * through the environment.
 */

export { GIT_HARDENING_ENV };

export const DEEPSEC_VERSION = "2.3.10";
const PROJECT_ID = "openaudit";
const CHUNK_SIZE = 5;
const RULE_PREFIX = "agent.deepsec";
const MAX_TEXT = 2_000;

/** A duration setting such as `30m`. */
type Duration = string;
/** A directory on the local filesystem. */
type DirPath = string;
/** A file on the local filesystem. */
type FilePath = string;
/** A path as deepsec or git reported it, not yet validated. */
type ReportedPath = string;
/** An upper bound on files to review. */
type FileCount = number;
/** A timeout in milliseconds. */
type Millis = number;
/** Raw `git diff --name-only -z` output. */
type GitOutput = string;
/** Markdown text from the deepsec export. */
type Markdown = string;
/** deepsec's vulnerability class, such as `sql-injection`. */
type VulnSlug = string;
/** deepsec's revalidation verdict, such as `true-positive`. */
type Verdict = string;
/** deepsec's own confidence label. */
type ConfidenceLabel = string;
/** A `## <heading>` section of an exported description. */
type SectionHeading = "Finding" | "Recommendation";
/** The deepsec subcommand an exit code belongs to. */
type DeepsecStep = "scan" | "process" | "export";

/* -------------------------------------------------------------------------- */
/*                                  Settings                                  */
/* -------------------------------------------------------------------------- */

const REF = /^[A-Za-z0-9][A-Za-z0-9._/@~^-]{0,99}$/;
const MODEL = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,79}$/;
const DURATION = /^[1-9][0-9]{0,2}[smh]$/;

export const DeepsecSettings = z.object({
	/** Stop starting new AI chunks once recorded spend reaches this. */
	maxCostUsd: z.number().positive().max(10_000).default(5),
	/** Wall-clock budget, e.g. `30m`. */
	maxDuration: z.string().regex(DURATION).default("30m"),
	/** `true` reviews changes against `origin/main`; a string is a git ref. */
	diff: z
		.union([z.boolean(), z.string().regex(REF)])
		.refine((v) => typeof v === "boolean" || !v.includes(".."), {
			message: "ranges are not supported",
		})
		.default(false),
	/** Files to review in full mode (highest regex-candidate count first). */
	maxFiles: z.number().int().positive().max(500).default(25),
	provider: z.enum(["anthropic", "openai"]).optional(),
	model: z.string().regex(MODEL).optional(),
	thinkingLevel: z
		.enum(["minimal", "low", "medium", "high", "xhigh"])
		.default("medium"),
});
export type DeepsecSettings = z.infer<typeof DeepsecSettings>;

export const durationMs = (d: Duration): number => {
	const n = Number.parseInt(d, 10);
	const unit = d.slice(-1);
	return n * (unit === "h" ? 3_600_000 : unit === "m" ? 60_000 : 1_000);
};

/* -------------------------------------------------------------------------- */
/*                                  Commands                                  */
/* -------------------------------------------------------------------------- */

export interface DeepsecPaths {
	readonly root: string;
	readonly exportFile: string;
}

export type DeepsecAgent = "claude" | "codex";

export const agentFor = (
	settings: Pick<DeepsecSettings, "provider">,
	env: Record<string, string | undefined>,
): DeepsecAgent => {
	if (settings.provider)
		return settings.provider === "openai" ? "codex" : "claude";
	const anthropic =
		env.ANTHROPIC_API_KEY ||
		env.ANTHROPIC_AUTH_TOKEN ||
		env.CLAUDE_CODE_OAUTH_TOKEN;
	if (!anthropic && env.OPENAI_API_KEY) return "codex";
	return "claude";
};

/** Env vars that carry credentials deepsec reads, per agent backend. */
const CREDENTIALS: Record<DeepsecAgent, ReadonlyArray<string>> = {
	claude: [
		"ANTHROPIC_API_KEY",
		"ANTHROPIC_AUTH_TOKEN",
		"CLAUDE_CODE_OAUTH_TOKEN",
		"AI_GATEWAY_API_KEY",
		"VERCEL_OIDC_TOKEN",
	],
	codex: ["OPENAI_API_KEY", "AI_GATEWAY_API_KEY", "VERCEL_OIDC_TOKEN"],
};

export const hasCredentials = (
	agent: DeepsecAgent,
	env: Record<string, string | undefined>,
): boolean => CREDENTIALS[agent].some((k) => !!env[k]);

/**
 * Pure argv builders (the binary is resolved by name from PATH). Every value
 * is a separate argv entry and settings are already validated.
 */
export const deepsecCommands = (
	settings: DeepsecSettings,
	paths: DeepsecPaths,
	agent: DeepsecAgent = "claude",
) => {
	const base = ["--project-id", PROJECT_ID, "--root", paths.root];
	const diffRef =
		settings.diff === true
			? "origin/main"
			: settings.diff === false
				? undefined
				: settings.diff;
	return {
		diffRef,
		scan: ["deepsec", "scan", ...base],
		/** Tree-to-tree diff: never touches the working tree or index. */
		gitDiff: diffRef
			? [
					"git",
					"-C",
					paths.root,
					"diff",
					"--name-only",
					"--no-renames",
					"--diff-filter=AM",
					"--no-ext-diff",
					"--no-textconv",
					"-z",
					diffRef,
					"HEAD",
					"--",
				]
			: undefined,
		process: (files?: ReadonlyArray<string>) => [
			"deepsec",
			"process",
			...base,
			"--agent",
			agent,
			...(settings.model ? ["--model", settings.model] : []),
			"--thinking-level",
			settings.thinkingLevel,
			"--concurrency",
			"2",
			"--batch-size",
			String(CHUNK_SIZE),
			"--max-turns",
			"60",
			"--files",
			(files ?? []).join(","),
		],
		export: [
			"deepsec",
			"export",
			"--format",
			"json",
			"--project-id",
			PROJECT_ID,
			"--out",
			paths.exportFile,
		],
	};
};

/* -------------------------------------------------------------------------- */
/*                                   Parsing                                  */
/* -------------------------------------------------------------------------- */

const SEVERITY: Record<string, Severity> = {
	CRITICAL: "critical",
	HIGH: "high",
	MEDIUM: "medium",
	LOW: "low",
	// Non-security bugs deepsec noticed while reviewing.
	HIGH_BUG: "medium",
	BUG: "low",
};

const RESOLVED = new Set([
	"false-positive",
	"fixed",
	"accepted-risk",
	"duplicate",
]);

const str = (v: unknown): string | undefined =>
	typeof v === "string" && v.length > 0 ? v : undefined;

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
	!!v && typeof v === "object" && !Array.isArray(v);

const obj = (v: unknown): Record<string, unknown> | undefined =>
	isPlainObject(v) ? v : undefined;

const clip = (s: Markdown) =>
	s.length > MAX_TEXT ? `${s.slice(0, MAX_TEXT)}…` : s;

/** Relative POSIX path inside the root, or undefined for anything else. */
const safeRel = (p: ReportedPath | undefined): string | undefined => {
	if (!p) return undefined;
	const n = p.replace(/\\/g, "/").replace(/^\.\//, "");
	if (n.startsWith("/") || /^[A-Za-z]:/.test(n)) return undefined;
	if (n.split("/").includes("..")) return undefined;
	return n;
};

/** Body of a `## <heading>` section of the exported markdown description. */
const section = (md: Markdown, heading: SectionHeading): string | undefined => {
	// heading is one of this module's literals.
	// nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
	const m = new RegExp(
		`^## ${heading}\\s*\\n([\\s\\S]*?)(?=^## |(?![\\s\\S]))`,
		"m",
	).exec(md);
	return m?.[1]?.trim() || undefined;
};

const slugOf = (raw: VulnSlug | undefined): string =>
	(raw ?? "")
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, "-")
		.replace(/^-+|-+$/g, "") || "finding";

/** One exported item with its `metadata` object. */
interface ExportEntry {
	readonly item: Record<string, unknown>;
	readonly meta: Record<string, unknown>;
}

/** deepsec's severity and revalidation for one item. */
interface Triage {
	readonly sevRaw: string;
	readonly severity: Severity;
	readonly verdict: Verdict | undefined;
	readonly reasoning: Markdown | undefined;
}

const parseJson = (input: unknown): unknown => {
	if (typeof input !== "string") return input;
	try {
		return JSON.parse(input);
	} catch {
		return undefined;
	}
};

const exportEntry = (item: unknown): ExportEntry | undefined => {
	const o = obj(item);
	const meta = obj(o?.metadata);
	return o && meta ? { item: o, meta } : undefined;
};

const isResolved = (verdict: Verdict | undefined) =>
	!!verdict && RESOLVED.has(verdict);

const confidenceOf = (
	verdict: Verdict | undefined,
	own: ConfidenceLabel | undefined,
) => {
	if (verdict === "true-positive") return "high";
	return verdict === "uncertain" || own === "low" ? "low" : "medium";
};

/** CWE numbers mentioned in `text`, deduplicated in order. */
const cwesIn = (text: Markdown): string[] => [
	...new Set(
		[...text.matchAll(/\bCWE-(\d{1,5})\b/gi)].map((m) => m[1] as string),
	),
];

const locationOf = (meta: Record<string, unknown>) => {
	const lines = Array.isArray(meta.lineNumbers)
		? meta.lineNumbers.filter((n): n is number => Number.isInteger(n) && n > 0)
		: [];
	const file = safeRel(str(meta.filePath));
	return file
		? { location: { file, ...(lines[0] ? { line: lines[0] } : {}) } }
		: {};
};

const evidenceOf = ({ verdict, reasoning }: Triage) =>
	reasoning
		? {
				evidence: scrubSecrets(
					clip(`Revalidation (${verdict ?? "unknown"}): ${reasoning}`),
				),
			}
		: {};

const referencesOf = (cwes: ReadonlyArray<string>) =>
	cwes.length
		? {
				references: cwes.map(
					(n) => `https://cwe.mitre.org/data/definitions/${n}.html`,
				),
			}
		: {};

const toFinding = (
	{ item, meta }: ExportEntry,
	triage: Triage,
): FindingInput => {
	const description = str(item.description) ?? "";
	const title = (str(item.title) ?? "deepsec finding").replace(
		/^\[[A-Z_]+\]\s*/,
		"",
	);
	const finding = section(description, "Finding") ?? title;
	const recommendation = section(description, "Recommendation");
	const cwes = cwesIn(`${title} ${finding}`);
	return {
		ruleId: `${RULE_PREFIX}/${slugOf(str(meta.vulnSlug))}`,
		title: scrubSecrets(title),
		severity: triage.severity,
		category: triage.sevRaw.endsWith("BUG") ? "reliability" : "security",
		message: scrubSecrets(clip(finding)),
		...locationOf(meta),
		...evidenceOf(triage),
		...(recommendation
			? { remediation: scrubSecrets(clip(recommendation)) }
			: {}),
		...referencesOf(cwes),
		confidence: confidenceOf(triage.verdict, str(meta.confidence)),
		tags: ["ai", "deepsec", ...cwes.map((n) => `cwe-${n}`)],
	};
};

/** One exported item as a finding, or undefined when it is unusable or resolved. */
const deepsecFinding = (raw: unknown): FindingInput | undefined => {
	const entry = exportEntry(raw);
	if (!entry) return undefined;
	const sevRaw = str(entry.meta.severity) ?? str(entry.item.severity) ?? "";
	const severity = SEVERITY[sevRaw];
	if (!severity) return undefined;
	const reval = obj(entry.meta.revalidation);
	const verdict = str(reval?.verdict);
	if (isResolved(verdict)) return undefined;
	return toFinding(entry, {
		sevRaw,
		severity,
		verdict,
		reasoning: str(reval?.reasoning),
	});
};

/**
 * Parses `deepsec export --format json`: an array of
 * `{ title, description, severity, labels, metadata }` where metadata holds
 * `filePath`, `lineNumbers`, `vulnSlug`, `confidence` and `revalidation`.
 * Triage priorities (P0-P2) are not part of the export, so severity comes from
 * deepsec's own CRITICAL/HIGH/MEDIUM/LOW scale.
 */
export const parseDeepsecExport = (input: unknown): FindingInput[] => {
	const data = parseJson(input);
	if (!Array.isArray(data)) return [];
	return data
		.map(deepsecFinding)
		.filter((f): f is FindingInput => f !== undefined);
};

/* -------------------------------------------------------------------------- */
/*                         deepsec data directory access                      */
/* -------------------------------------------------------------------------- */

interface FileInfo {
	readonly path: string;
	readonly candidates: number;
}

const isJsonFile = (e: Dirent) => e.isFile() && e.name.endsWith(".json");

/** `.json` files under `dir`, depth first. */
const jsonFiles = (dir: DirPath): string[] => {
	let entries: Dirent[];
	try {
		entries = readdirSync(dir, { withFileTypes: true });
	} catch {
		return [];
	}
	return entries.flatMap((e) => {
		const p = join(dir, e.name);
		if (e.isDirectory()) return jsonFiles(p);
		return isJsonFile(e) ? [p] : [];
	});
};

const readRecord = (path: FilePath): Record<string, unknown> | undefined => {
	try {
		return obj(JSON.parse(readFileSync(path, "utf8")));
	} catch {
		return undefined;
	}
};

/** Walk `<dataRoot>/<project>/files/**` (our own temp dir, no symlinks). */
const readRecords = (dataRoot: DirPath): Array<Record<string, unknown>> =>
	jsonFiles(join(dataRoot, PROJECT_ID, "files"))
		.map(readRecord)
		.filter((r): r is Record<string, unknown> => r !== undefined);

/** Chunk files travel through a comma-separated flag: keep them boring. */
const passableFile = (path: ReportedPath | undefined): path is string =>
	!!path && /^[A-Za-z0-9_./@+-]+$/.test(path) && !path.startsWith("-");

/** Paths from `git diff --name-only -z`, filtered and capped. */
export const changedFiles = (stdout: GitOutput, max: FileCount): string[] =>
	[
		...new Set(
			stdout
				.split("\0")
				.map((p) => safeRel(p))
				.filter(passableFile),
		),
	].slice(0, max);

/** Files with regex candidates, most suspicious first. */
export const candidateFiles = (dataRoot: DirPath, max: FileCount): string[] => {
	const infos: FileInfo[] = [];
	for (const r of readRecords(dataRoot)) {
		const path = safeRel(str(r.filePath));
		const n = Array.isArray(r.candidates) ? r.candidates.length : 0;
		if (passableFile(path) && n > 0) infos.push({ path, candidates: n });
	}
	return infos
		.sort((a, b) => b.candidates - a.candidates || a.path.localeCompare(b.path))
		.slice(0, max)
		.map((i) => i.path);
};

const isCost = (c: unknown): c is number =>
	typeof c === "number" && Number.isFinite(c);

/** The finite `costUsd` values of one record's analyses. */
const costsOf = (record: Record<string, unknown>): number[] =>
	Array.isArray(record.analysisHistory)
		? record.analysisHistory.map((h) => obj(h)?.costUsd).filter(isCost)
		: [];

/** Total `costUsd` deepsec recorded across all analyses. */
export const recordedCostUsd = (dataRoot: DirPath): number =>
	readRecords(dataRoot)
		.flatMap(costsOf)
		.reduce((total, c) => total + c, 0);

/* -------------------------------------------------------------------------- */
/*                                   Auditor                                  */
/* -------------------------------------------------------------------------- */

const INSTALL = `Install: npm i -g deepsec@${DEEPSEC_VERSION}`;

type ExecResult = Effect.Success<ReturnType<AuditContext["exec"]["run"]>>;

/** One deepsec run: its temp dirs, commands and time budget. */
interface DeepsecJob {
	readonly ctx: AuditContext;
	readonly settings: DeepsecSettings;
	readonly cmds: ReturnType<typeof deepsecCommands>;
	readonly tmp: DirPath;
	readonly dataRoot: DirPath;
	readonly exportFile: FilePath;
	readonly remaining: () => Millis;
	readonly run: (
		cmd: string[],
		ms: Millis,
	) => Effect.Effect<ExecResult, AuditorError>;
}

const parseSettings = (
	ctx: AuditContext,
): Effect.Effect<DeepsecSettings, AuditorError> => {
	const parsed = DeepsecSettings.safeParse(
		ctx.options.settings?.["agent.deepsec"] ?? {},
	);
	return parsed.success
		? Effect.succeed(parsed.data)
		: Effect.fail(
				new AuditorError({
					message: `Invalid agent.deepsec settings: ${z.prettifyError(parsed.error)}`,
				}),
			);
};

/** Creates the temp dirs; deepsec runs with cwd there, never in the target. */
const startJob = (
	ctx: AuditContext,
	settings: DeepsecSettings,
	root: DirPath,
	agent: DeepsecAgent,
): DeepsecJob => {
	const tmp = mkdtempSync(join(tmpdir(), "openaudit-deepsec-"));
	const dataRoot = join(tmp, "data");
	const exportFile = join(tmp, "export.json");
	mkdirSync(dataRoot);
	const cmds = deepsecCommands(settings, { root, exportFile }, agent);
	const budgetMs = durationMs(settings.maxDuration);
	const started = Date.now();
	return {
		ctx,
		settings,
		cmds,
		tmp,
		dataRoot,
		exportFile,
		remaining: () => budgetMs - (Date.now() - started),
		run: (cmd, ms) =>
			ctx.exec.run(cmd, {
				cwd: tmp,
				env: { ...GIT_HARDENING_ENV, DEEPSEC_DATA_ROOT: dataRoot },
				timeoutMs: Math.max(60_000, ms) + 60_000,
			}),
	};
};

// 0 = clean, 1 = findings produced; anything else is a failure.
const checkExit = (step: DeepsecStep, r: { code: number; stderr: string }) =>
	r.code === 0 || r.code === 1
		? Effect.void
		: Effect.fail(
				new AuditorError({
					message: `deepsec ${step} exited ${r.code}: ${scrubSecrets(r.stderr).slice(0, 500)}`,
				}),
			);

/** Changed files in diff mode, otherwise the files with most regex candidates. */
const filesToReview = (job: DeepsecJob) =>
	Effect.gen(function* () {
		const { cmds, settings } = job;
		if (!cmds.gitDiff) {
			yield* checkExit("scan", yield* job.run(cmds.scan, job.remaining()));
			return candidateFiles(job.dataRoot, settings.maxFiles);
		}
		const diff = yield* job.run(cmds.gitDiff, 120_000);
		if (diff.code !== 0)
			return yield* Effect.fail(
				new AuditorError({
					message: `git diff ${cmds.diffRef} HEAD failed: ${scrubSecrets(diff.stderr).slice(0, 300)}`,
				}),
			);
		return changedFiles(diff.stdout, settings.maxFiles);
	});

/** True (after logging why) once the duration or cost budget is used up. */
const budgetSpent = (job: DeepsecJob) =>
	Effect.gen(function* () {
		if (job.remaining() <= 0) {
			yield* job.ctx.log("deepsec: duration budget reached, stopping");
			return true;
		}
		const spent = recordedCostUsd(job.dataRoot);
		if (spent >= job.settings.maxCostUsd) {
			yield* job.ctx.log(
				`deepsec: cost cap reached ($${spent.toFixed(2)} of $${job.settings.maxCostUsd})`,
			);
			return true;
		}
		return false;
	});

const processChunks = (job: DeepsecJob, files: ReadonlyArray<string>) =>
	Effect.gen(function* () {
		for (let i = 0; i < files.length; i += CHUNK_SIZE) {
			if (yield* budgetSpent(job)) break;
			yield* checkExit(
				"process",
				yield* job.run(
					job.cmds.process(files.slice(i, i + CHUNK_SIZE)),
					job.remaining(),
				),
			);
		}
	});

const readExport = (exportFile: FilePath): string | undefined => {
	try {
		return readFileSync(exportFile, "utf8");
	} catch {
		return undefined;
	}
};

const review = (job: DeepsecJob) =>
	Effect.gen(function* () {
		const files = yield* filesToReview(job);
		if (files.length === 0) return [] as FindingInput[];
		yield* processChunks(job, files);
		yield* checkExit("export", yield* job.run(job.cmds.export, 120_000));
		const json = readExport(job.exportFile);
		return json === undefined ? [] : parseDeepsecExport(json);
	});

/** `env` is injectable for tests; defaults to the process environment. */
export const makeDeepsecAuditor = (
	env: Record<string, string | undefined> = process.env,
): Auditor =>
	defineAuditor({
		id: "agent.deepsec",
		title: "deepsec AI vulnerability scan",
		description:
			"Vercel Labs deepsec: regex candidate scan followed by an AI agent review of the riskiest files (or of changed files with settings diff). Opt-in: run with --only agent.deepsec. Costs real money (default cap about $5, enforced between chunks) and the review agent gets a sandboxed shell in the target, so only run it on code you trust. State goes to a temp directory, not the target.",
		categories: ["security"],
		targets: ["codebase"],
		engine: "agentic",
		tool: "deepsec",
		network: true,
		defaultEnabled: false,
		run: (ctx: AuditContext) =>
			Effect.gen(function* () {
				const ws = yield* requireWorkspace(ctx);
				if (!ctx.target.root) return yield* skip("Target has no local files");
				if (ctx.options.offline)
					return yield* skip("deepsec needs network access to an AI provider");
				yield* requireTool(ctx, "deepsec", INSTALL);

				const settings = yield* parseSettings(ctx);
				const agent = agentFor(settings, env);
				if (!hasCredentials(agent, env))
					return yield* skip(
						`No AI credentials in the environment for deepsec (${agent}). Set one of: ${CREDENTIALS[agent].join(", ")}`,
					);

				const job = startJob(ctx, settings, ws.root, agent);
				return yield* review(job).pipe(
					Effect.ensuring(
						Effect.sync(() =>
							rmSync(job.tmp, { recursive: true, force: true }),
						),
					),
				);
			}),
	});

export const deepsecAuditor = makeDeepsecAuditor();
