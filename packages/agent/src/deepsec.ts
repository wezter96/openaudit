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

export const durationMs = (d: string): number => {
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

const obj = (v: unknown): Record<string, unknown> | undefined =>
	v && typeof v === "object" && !Array.isArray(v)
		? (v as Record<string, unknown>)
		: undefined;

const clip = (s: string) =>
	s.length > MAX_TEXT ? `${s.slice(0, MAX_TEXT)}…` : s;

/** Relative POSIX path inside the root, or undefined for anything else. */
const safeRel = (p: string | undefined): string | undefined => {
	if (!p) return undefined;
	const n = p.replace(/\\/g, "/").replace(/^\.\//, "");
	if (n.startsWith("/") || /^[A-Za-z]:/.test(n)) return undefined;
	if (n.split("/").includes("..")) return undefined;
	return n;
};

/** Body of a `## <heading>` section of the exported markdown description. */
const section = (md: string, heading: string): string | undefined => {
	// heading is one of this module's literals.
	// nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
	const m = new RegExp(
		`^## ${heading}\\s*\\n([\\s\\S]*?)(?=^## |(?![\\s\\S]))`,
		"m",
	).exec(md);
	return m?.[1]?.trim() || undefined;
};

const slugOf = (raw: string | undefined): string =>
	(raw ?? "")
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, "-")
		.replace(/^-+|-+$/g, "") || "finding";

/**
 * Parses `deepsec export --format json`: an array of
 * `{ title, description, severity, labels, metadata }` where metadata holds
 * `filePath`, `lineNumbers`, `vulnSlug`, `confidence` and `revalidation`.
 * Triage priorities (P0-P2) are not part of the export, so severity comes from
 * deepsec's own CRITICAL/HIGH/MEDIUM/LOW scale.
 */
export const parseDeepsecExport = (input: unknown): FindingInput[] => {
	let data = input;
	if (typeof input === "string") {
		try {
			data = JSON.parse(input);
		} catch {
			return [];
		}
	}
	if (!Array.isArray(data)) return [];
	const out: FindingInput[] = [];
	for (const item of data) {
		const o = obj(item);
		const meta = obj(o?.metadata);
		if (!o || !meta) continue;
		const sevRaw = str(meta.severity) ?? str(o.severity) ?? "";
		const severity = SEVERITY[sevRaw];
		if (!severity) continue;
		const reval = obj(meta.revalidation);
		const verdict = str(reval?.verdict);
		if (verdict && RESOLVED.has(verdict)) continue;

		const description = str(o.description) ?? "";
		const title = (str(o.title) ?? "deepsec finding").replace(
			/^\[[A-Z_]+\]\s*/,
			"",
		);
		const finding = section(description, "Finding") ?? title;
		const recommendation = section(description, "Recommendation");
		const lines = Array.isArray(meta.lineNumbers)
			? meta.lineNumbers.filter(
					(n): n is number => Number.isInteger(n) && n > 0,
				)
			: [];
		const file = safeRel(str(meta.filePath));
		const own = str(meta.confidence);
		const confidence =
			verdict === "true-positive"
				? "high"
				: verdict === "uncertain" || own === "low"
					? "low"
					: "medium";
		const cwes = [
			...new Set(
				[...`${title} ${finding}`.matchAll(/\bCWE-(\d{1,5})\b/gi)].map(
					(m) => m[1] as string,
				),
			),
		];
		const reasoning = str(reval?.reasoning);
		out.push({
			ruleId: `${RULE_PREFIX}/${slugOf(str(meta.vulnSlug))}`,
			title: scrubSecrets(title),
			severity,
			category: sevRaw.endsWith("BUG") ? "reliability" : "security",
			message: scrubSecrets(clip(finding)),
			...(file
				? {
						location: {
							file,
							...(lines[0] ? { line: lines[0] } : {}),
						},
					}
				: {}),
			...(reasoning
				? {
						evidence: scrubSecrets(
							clip(`Revalidation (${verdict ?? "unknown"}): ${reasoning}`),
						),
					}
				: {}),
			...(recommendation
				? { remediation: scrubSecrets(clip(recommendation)) }
				: {}),
			...(cwes.length
				? {
						references: cwes.map(
							(n) => `https://cwe.mitre.org/data/definitions/${n}.html`,
						),
					}
				: {}),
			confidence,
			tags: ["ai", "deepsec", ...cwes.map((n) => `cwe-${n}`)],
		});
	}
	return out;
};

/* -------------------------------------------------------------------------- */
/*                         deepsec data directory access                      */
/* -------------------------------------------------------------------------- */

interface FileInfo {
	readonly path: string;
	readonly candidates: number;
}

/** Walk `<dataRoot>/<project>/files/**` (our own temp dir, no symlinks). */
const readRecords = (dataRoot: string): Array<Record<string, unknown>> => {
	const base = join(dataRoot, PROJECT_ID, "files");
	const records: Array<Record<string, unknown>> = [];
	const walk = (dir: string) => {
		let entries: Dirent[];
		try {
			entries = readdirSync(dir, { withFileTypes: true });
		} catch {
			return;
		}
		for (const e of entries) {
			const p = join(dir, e.name);
			if (e.isDirectory()) walk(p);
			else if (e.isFile() && e.name.endsWith(".json")) {
				try {
					const r = obj(JSON.parse(readFileSync(p, "utf8")));
					if (r) records.push(r);
				} catch {}
			}
		}
	};
	walk(base);
	return records;
};

/** Chunk files travel through a comma-separated flag: keep them boring. */
const passableFile = (path: string | undefined): path is string =>
	!!path && /^[A-Za-z0-9_./@+-]+$/.test(path) && !path.startsWith("-");

/** Paths from `git diff --name-only -z`, filtered and capped. */
export const changedFiles = (stdout: string, max: number): string[] =>
	[
		...new Set(
			stdout
				.split("\0")
				.map((p) => safeRel(p))
				.filter(passableFile),
		),
	].slice(0, max);

/** Files with regex candidates, most suspicious first. */
export const candidateFiles = (dataRoot: string, max: number): string[] => {
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

/** Total `costUsd` deepsec recorded across all analyses. */
export const recordedCostUsd = (dataRoot: string): number => {
	let total = 0;
	for (const r of readRecords(dataRoot)) {
		if (!Array.isArray(r.analysisHistory)) continue;
		for (const h of r.analysisHistory) {
			const c = obj(h)?.costUsd;
			if (typeof c === "number" && Number.isFinite(c)) total += c;
		}
	}
	return total;
};

/* -------------------------------------------------------------------------- */
/*                                   Auditor                                  */
/* -------------------------------------------------------------------------- */

const INSTALL = `Install: npm i -g deepsec@${DEEPSEC_VERSION}`;

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

				const parsed = DeepsecSettings.safeParse(
					ctx.options.settings?.["agent.deepsec"] ?? {},
				);
				if (!parsed.success)
					return yield* Effect.fail(
						new AuditorError({
							message: `Invalid agent.deepsec settings: ${z.prettifyError(parsed.error)}`,
						}),
					);
				const settings = parsed.data;
				const agent = agentFor(settings, env);
				if (!hasCredentials(agent, env))
					return yield* skip(
						`No AI credentials in the environment for deepsec (${agent}). Set one of: ${CREDENTIALS[agent].join(", ")}`,
					);

				const root = ws.root;
				const tmp = mkdtempSync(join(tmpdir(), "openaudit-deepsec-"));
				const dataRoot = join(tmp, "data");
				const exportFile = join(tmp, "export.json");
				mkdirSync(dataRoot);
				const cmds = deepsecCommands(settings, { root, exportFile }, agent);
				const budgetMs = durationMs(settings.maxDuration);
				const started = Date.now();
				const remaining = () => budgetMs - (Date.now() - started);
				const run = (cmd: string[], ms: number) =>
					ctx.exec.run(cmd, {
						cwd: tmp,
						env: { ...GIT_HARDENING_ENV, DEEPSEC_DATA_ROOT: dataRoot },
						timeoutMs: Math.max(60_000, ms) + 60_000,
					});
				// 0 = clean, 1 = findings produced; anything else is a failure.
				const check = (what: string, r: { code: number; stderr: string }) =>
					r.code === 0 || r.code === 1
						? Effect.void
						: Effect.fail(
								new AuditorError({
									message: `deepsec ${what} exited ${r.code}: ${scrubSecrets(r.stderr).slice(0, 500)}`,
								}),
							);

				return yield* Effect.gen(function* () {
					let files: string[];
					if (cmds.gitDiff) {
						const diff = yield* run(cmds.gitDiff, 120_000);
						if (diff.code !== 0)
							return yield* Effect.fail(
								new AuditorError({
									message: `git diff ${cmds.diffRef} HEAD failed: ${scrubSecrets(diff.stderr).slice(0, 300)}`,
								}),
							);
						files = changedFiles(diff.stdout, settings.maxFiles);
					} else {
						yield* check("scan", yield* run(cmds.scan, remaining()));
						files = candidateFiles(dataRoot, settings.maxFiles);
					}
					if (files.length === 0) return [] as FindingInput[];
					for (let i = 0; i < files.length; i += CHUNK_SIZE) {
						if (remaining() <= 0) {
							yield* ctx.log("deepsec: duration budget reached, stopping");
							break;
						}
						const spent = recordedCostUsd(dataRoot);
						if (spent >= settings.maxCostUsd) {
							yield* ctx.log(
								`deepsec: cost cap reached ($${spent.toFixed(2)} of $${settings.maxCostUsd})`,
							);
							break;
						}
						yield* check(
							"process",
							yield* run(
								cmds.process(files.slice(i, i + CHUNK_SIZE)),
								remaining(),
							),
						);
					}
					yield* check("export", yield* run(cmds.export, 120_000));
					let json: string;
					try {
						json = readFileSync(exportFile, "utf8");
					} catch {
						return [] as FindingInput[];
					}
					return parseDeepsecExport(json);
				}).pipe(
					Effect.ensuring(
						Effect.sync(() => rmSync(tmp, { recursive: true, force: true })),
					),
				);
			}),
	});

export const deepsecAuditor = makeDeepsecAuditor();
