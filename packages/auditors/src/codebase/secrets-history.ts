import { existsSync } from "node:fs";
import {
	lstat,
	mkdir,
	mkdtemp,
	readdir,
	readFile,
	realpath,
	rm,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import {
	type AuditContext,
	AuditorError,
	defineAuditor,
	type FindingInput,
	GIT_HARDENING_ENV,
	requireTool,
	requireWorkspace,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, num, parseJson, str } from "../tool";
import {
	cweUrl,
	isFixturePath,
	isRecord,
	isTestPath,
	kebab,
	scrubLine,
	truncate,
} from "./util";

const ID = "code.secrets-history";
const DEFAULT_MAX_COMMITS = 5000;
const MAX_COMMITS_LIMIT = 1_000_000;
const MAX_FINDINGS = 500;

/* -------------------------------------------------------------------------- */
/*                                Git hardening                               */
/* -------------------------------------------------------------------------- */

/**
 * `.git/config` of an untrusted repo can name commands git will run
 * (`core.fsmonitor`, `diff.*.textconv`, hooks, filters), and `.gitattributes`
 * can select those drivers. We never run git inside the target: we make a
 * bare mirror (which copies objects and refs but neither config, hooks nor a
 * working tree) and scan that, with every config source neutralised.
 * Builds on the shared `GIT_HARDENING_ENV` from core.
 */
export const gitHardeningEnv = (
	home: string,
	extra: ReadonlyArray<readonly [string, string]> = [],
): Record<string, string> => {
	const base = Number(GIT_HARDENING_ENV.GIT_CONFIG_COUNT);
	const env: Record<string, string> = {
		...GIT_HARDENING_ENV,
		GIT_CONFIG_GLOBAL: "/dev/null",
		HOME: home,
		XDG_CONFIG_HOME: home,
	};
	const more: ReadonlyArray<readonly [string, string]> = [
		["core.attributesFile", "/dev/null"],
		...extra,
	];
	more.forEach(([key, value], i) => {
		env[`GIT_CONFIG_KEY_${base + i}`] = key;
		env[`GIT_CONFIG_VALUE_${base + i}`] = value;
	});
	env.GIT_CONFIG_COUNT = String(base + more.length);
	return env;
};

/** The clone reads a local path, which git only allows with this override. */
export const cloneEnv = (home: string) =>
	gitHardeningEnv(home, [["protocol.file.allow", "always"]]);

/**
 * Environment for git and gitleaks on the mirror. Pins the repository to the
 * mirror, so an inherited `GIT_DIR`, `GIT_COMMON_DIR` or object directory
 * cannot point the scan at something else.
 */
export const scanEnv = (home: string, mirror: string) => ({
	...gitHardeningEnv(home),
	GIT_DIR: mirror,
	GIT_COMMON_DIR: mirror,
	GIT_OBJECT_DIRECTORY: join(mirror, "objects"),
	GIT_ALTERNATE_OBJECT_DIRECTORIES: "",
});

const shellQuote = (s: string) => `'${s.replaceAll("'", `'\\''`)}'`;

/**
 * The source side of the clone, run by git through `sh`. `--strict` makes
 * upload-pack serve exactly the confined git dir instead of looking for a
 * `.git` or gitfile inside it. The target's own config could hide refs from
 * the mirror (`uploadpack.hideRefs`); command-line config is read last, so
 * these entries expose every ref again. Grafts are switched off so the pack
 * follows the real parents (git does not pass our environment through).
 */
export const uploadPackCommand = (git: string) =>
	[
		`GIT_GRAFT_FILE=${shellQuote(GIT_HARDENING_ENV.GIT_GRAFT_FILE ?? "")}`,
		shellQuote(git),
		"-c",
		shellQuote("transfer.hideRefs=!refs"),
		"-c",
		shellQuote("transfer.hideRefs=!HEAD"),
		"upload-pack",
		"--strict",
	].join(" ");

/**
 * Mirrors `gitDir` (from `confineGitDir`). A `file://` URL, unlike a path,
 * is not resolved by the clone itself, which would follow a `.git` gitfile
 * planted inside the git dir.
 */
export const cloneArgs = (git: string, gitDir: string, dest: string) => [
	git,
	"clone",
	"--mirror",
	"--no-local",
	"--no-hardlinks",
	"--quiet",
	"--upload-pack",
	uploadPackCommand(git),
	"--",
	pathToFileURL(gitDir).href,
	dest,
];

/* -------------------------------------------------------------------------- */
/*                                 Confinement                                */
/* -------------------------------------------------------------------------- */

const within = (root: string, path: string) =>
	path === root || path.startsWith(`${root}${sep}`);

/** First symlink under `dir` (not followed), if any. */
const findSymlink = async (dir: string): Promise<string | undefined> => {
	for (const entry of await readdir(dir, { withFileTypes: true })) {
		const path = join(dir, entry.name);
		if (entry.isSymbolicLink()) return path;
		if (entry.isDirectory()) {
			const found = await findSymlink(path);
			if (found) return found;
		}
	}
	return undefined;
};

const realpathOrUndefined = (path: string) =>
	realpath(path).catch(() => undefined);

export type ConfinedGitDir =
	| { readonly gitDir: string }
	| { readonly refused: string };

/**
 * Resolves the target's git directory and refuses any repository layout that
 * would make git read objects or refs from outside the target root: a `.git`
 * symlink, a gitfile or `commondir` pointing outside, symlinks inside the git
 * directory, or `objects/info/alternates`. Otherwise secrets from another
 * repository on the auditor's machine would be reported as the target's.
 */
export const confineGitDir = async (root: string): Promise<ConfinedGitDir> => {
	const refuse = (why: string) => ({
		refused: `${why}, so git could read repository data from outside the target; the history scan was refused.`,
	});
	const top = await realpath(root);
	const dotGit = join(top, ".git");
	const st = await lstat(dotGit).catch(() => undefined);
	if (!st) return { refused: "Target is not the root of a git repository" };
	if (st.isSymbolicLink()) return refuse(".git is a symlink");

	let gitDir = dotGit;
	if (st.isFile()) {
		const pointer = /^gitdir: (.+)$/m.exec(await readFile(dotGit, "utf8"));
		const resolved =
			pointer?.[1] &&
			(await realpathOrUndefined(resolve(top, pointer[1].trim())));
		if (!resolved || !within(top, resolved))
			return refuse(
				".git is a gitfile that points outside the target (as in a linked worktree or submodule; audit the repository that owns it)",
			);
		gitDir = resolved;
	} else if (!st.isDirectory())
		return { refused: "Target is not the root of a git repository" };

	const label = (path: string) => relative(top, path) || ".";
	const dirs = [gitDir];
	const common = await readFile(join(gitDir, "commondir"), "utf8").catch(
		() => undefined,
	);
	if (common !== undefined) {
		// Like git, strip only trailing line breaks.
		const resolved = await realpathOrUndefined(
			resolve(gitDir, common.replace(/[\r\n]+$/, "")),
		);
		if (!resolved || !within(top, resolved))
			return refuse(`${label(gitDir)}/commondir points outside the target`);
		dirs.push(resolved);
	}
	for (const dir of new Set(dirs)) {
		const link = await findSymlink(dir);
		if (link) return refuse(`${label(link)} is a symlink`);
		const alternates = await readFile(
			join(dir, "objects", "info", "alternates"),
			"utf8",
		).catch(() => "");
		if (alternates.split("\n").some((l) => l && !l.startsWith("#")))
			return refuse(
				`${label(dir)}/objects/info/alternates borrows objects from another object store (run \`git repack -a -d\` and delete it to scan this repository)`,
			);
	}
	return { gitDir };
};

/* -------------------------------------------------------------------------- */
/*                                   Parsing                                  */
/* -------------------------------------------------------------------------- */

interface Hit {
	readonly rule: string;
	readonly description?: string;
	readonly file: string;
	readonly secret: string;
	readonly match: string;
	readonly commit: string;
	readonly author?: string;
	readonly date?: string;
	readonly entropy?: number;
	readonly tags: string[];
}

const toHits = (json: unknown): Hit[] =>
	arr(json).flatMap((item) => {
		if (!isRecord(item)) return [];
		const secret = str(item.Secret);
		const file = str(item.File);
		const commit = str(item.Commit);
		if (!secret || !file || !commit) return [];
		return [
			{
				rule: str(item.RuleID) ?? "secret",
				description: str(item.Description),
				file,
				secret,
				match: str(item.Match) ?? "",
				commit,
				author: str(item.Author),
				date: str(item.Date),
				entropy: num(item.Entropy),
				tags: arr(item.Tags).filter((t): t is string => typeof t === "string"),
			},
		];
	});

/**
 * Maps a `gitleaks git` JSON report (NOT redacted: the raw secret is needed to
 * check the current tree, and is masked before it reaches any finding) to
 * findings. One finding per rule, file and secret; gitleaks lists newest
 * commits first, so the last hit of a group is the commit that introduced it.
 *
 * `stillAtHead` maps a secret to whether it is present in HEAD's tree;
 * missing means unknown.
 */
export const parseSecretsHistory = (
	json: unknown,
	stillAtHead: ReadonlyMap<string, boolean> = new Map(),
): FindingInput[] => {
	const groups = new Map<string, Hit[]>();
	for (const hit of toHits(json)) {
		const key = `${hit.rule}\0${hit.file}\0${hit.secret}`;
		const list = groups.get(key);
		if (list) list.push(hit);
		else groups.set(key, [hit]);
	}
	const findings: FindingInput[] = [];
	for (const hits of groups.values()) {
		const first = hits[hits.length - 1] as Hit;
		const sha = first.commit.slice(0, 8);
		const date = first.date?.slice(0, 10);
		const where = [
			`commit ${sha}`,
			date ? `on ${date}` : "",
			first.author ? `by ${first.author}` : "",
		]
			.filter(Boolean)
			.join(" ");
		const more =
			hits.length > 1 ? ` It appears in ${hits.length} commits.` : "";
		const present = stillAtHead.get(first.secret);
		const status =
			present === false
				? "It was removed from the tree but is still in git history; rotate it."
				: present === true
					? "It is still present in the current tree and in git history; rotate it and remove it."
					: "Whether it is still in the current tree could not be determined; treat it as exposed and rotate it.";
		const evidence = truncate(scrubLine(first.match, [first.secret]));
		findings.push({
			ruleId: `${ID}/${kebab(first.rule)}`,
			title: first.description
				? `${truncate(first.description, 90)} (in git history)`
				: `Secret in git history (${first.rule})`,
			severity: "high",
			category: "security",
			message: `gitleaks rule \`${first.rule}\` matched a likely secret in ${first.file}, added in ${where}.${more} ${status}`,
			location: { file: first.file },
			evidence,
			remediation:
				"Revoke and rotate the credential: anyone with a clone of the repository can read it from history. Rewriting history (git filter-repo) only helps after rotation.",
			references: [cweUrl(798), "https://github.com/gitleaks/gitleaks"],
			// Secrets in tests and fixtures are usually fake.
			confidence:
				isTestPath(first.file) || isFixturePath(first.file) ? "low" : "medium",
			tags: [
				"cwe-798",
				"owasp-a07",
				"secrets",
				...(present === false ? ["removed-from-tree"] : []),
				...first.tags,
			],
		});
		if (findings.length >= MAX_FINDINGS) break;
	}
	return findings;
};

/**
 * An info finding when the scan could not see all of history, so a clean
 * result is not mistaken for a complete one. A `shallow` file (which a
 * hostile repository can also plant to hide old commits) cuts history at its
 * boundary; `maxCommits` keeps only the newest commits.
 */
export const incompleteHistory = (
	shallow: boolean,
	commits: number,
	maxCommits: number,
): FindingInput[] => {
	const reasons = [
		shallow
			? "The repository is shallow (it has a `shallow` file), so commits beyond its shallow boundary are missing and were not scanned."
			: "",
		commits > maxCommits
			? `Only the newest ${maxCommits} of ${commits} commits were scanned (settings["${ID}"].maxCommits).`
			: "",
	].filter(Boolean);
	if (reasons.length === 0) return [];
	return [
		{
			ruleId: `${ID}/incomplete-history`,
			title: "Git history scan is incomplete",
			severity: "info",
			category: "security",
			message: `${reasons.join(" ")} Secrets in the unscanned commits are not reported.`,
			remediation: shallow
				? "Scan a full clone (`git fetch --unshallow`, or `fetch-depth: 0` in actions/checkout)."
				: `Raise settings["${ID}"].maxCommits to cover the whole history.`,
			confidence: "high",
		},
	];
};

/* -------------------------------------------------------------------------- */
/*                                  Auditor                                   */
/* -------------------------------------------------------------------------- */

const readMaxCommits = (ctx: AuditContext): number => {
	const v = ctx.options.settings?.[ID]?.maxCommits;
	return typeof v === "number" &&
		Number.isInteger(v) &&
		v >= 1 &&
		v <= MAX_COMMITS_LIMIT
		? v
		: DEFAULT_MAX_COMMITS;
};

const fail = (what: string, res: { code: number; stderr: string }) =>
	Effect.fail(
		new AuditorError({
			message: `${what} exited with code ${res.code}: ${truncate(res.stderr.trim(), 300)}`,
		}),
	);

export const secretsHistory = defineAuditor({
	id: ID,
	title: "gitleaks git-history secret scan",
	description:
		"Scans the full git history (all refs, newest settings[\"code.secrets-history\"].maxCommits, default 5000) with gitleaks for secrets that were committed and later removed. The repository is first copied into a bare mirror in a temp dir and scanned there with git config, hooks, attributes and textconv/fsmonitor drivers neutralised, so a hostile .git/config cannot execute code. Repositories whose git data reaches outside the target (an outside gitfile or commondir, alternates, symlinks in .git) are refused; replace refs, grafts and hidden refs cannot hide commits, and shallow or truncated history is reported as incomplete. The target's own .gitleaks.toml, .gitleaksignore and inline gitleaks:allow comments are deliberately ignored (a repository must not be able to allow-list its own leaks); gitleaks' built-in rules apply. Slow on large histories, so opt-in.",
	categories: ["security"],
	targets: ["codebase"],
	engine: "external",
	tool: "gitleaks",
	defaultEnabled: false,
	// A secret committed once stays in history after its file is gitignored.
	keepIgnored: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const confined = yield* Effect.tryPromise({
				try: () => confineGitDir(ws.root),
				catch: (cause) =>
					new AuditorError({
						message: `Could not inspect the git directory: ${cause instanceof Error ? cause.message : String(cause)}`,
					}),
			});
			if ("refused" in confined) return yield* skip(confined.refused);
			const bin = yield* requireTool(
				ctx,
				"gitleaks",
				"Install: brew install gitleaks (https://github.com/gitleaks/gitleaks#installing).",
			);
			const git = yield* requireTool(ctx, "git", "Install git.");
			const maxCommits = readMaxCommits(ctx);

			const tmp = yield* Effect.promise(() =>
				mkdtemp(join(tmpdir(), "openaudit-secrets-history-")),
			);
			return yield* Effect.gen(function* () {
				const home = join(tmp, "home");
				const clone = join(tmp, "repo.git");
				const empty = join(tmp, "no-ignore");
				const reportPath = join(tmp, "report.json");
				yield* Effect.promise(() => Promise.all([mkdir(home), mkdir(empty)]));

				const cloned = yield* ctx.exec.run(
					cloneArgs(git, confined.gitDir, clone),
					{ cwd: tmp, env: cloneEnv(home), timeoutMs: 10 * 60_000 },
				);
				if (cloned.code !== 0) return yield* fail("git clone", cloned);

				const env = scanEnv(home, clone);
				const counted = yield* ctx.exec.run(
					[git, "rev-list", "--all", "--count"],
					{ cwd: tmp, env, timeoutMs: 5 * 60_000 },
				);
				if (counted.code !== 0) return yield* fail("git rev-list", counted);
				const incomplete = incompleteHistory(
					existsSync(join(clone, "shallow")),
					Number(counted.stdout.trim()),
					maxCommits,
				);
				const scan = yield* ctx.exec.run(
					[
						bin,
						"git",
						clone,
						"--report-format",
						"json",
						"--report-path",
						reportPath,
						"--no-banner",
						"--no-color",
						"--exit-code",
						"0",
						"--ignore-gitleaks-allow",
						"--gitleaks-ignore-path",
						empty,
						"--log-opts",
						`--no-textconv --no-ext-diff --no-mailmap --full-history --all -n ${maxCommits}`,
					],
					{ cwd: tmp, env, timeoutMs: 15 * 60_000 },
				);
				if (scan.code !== 0) return yield* fail("gitleaks", scan);
				const text = yield* Effect.promise(() =>
					readFile(reportPath, "utf8").catch(() => ""),
				);
				const json = yield* parseJson(text || "[]", "gitleaks");

				// Which found secrets are still in HEAD's tree? One `git grep -F`
				// over all single-line secrets; the patterns go through a file so
				// they never appear in a process listing.
				const secrets = [
					...new Set(
						toHits(json)
							.map((h) => h.secret)
							.filter((s) => !/[\r\n]/.test(s)),
					),
				];
				const stillAtHead = new Map<string, boolean>();
				if (secrets.length > 0) {
					const patterns = join(tmp, "patterns.txt");
					yield* Effect.promise(() =>
						writeFile(patterns, `${secrets.join("\n")}\n`, { mode: 0o600 }),
					);
					const grep = yield* ctx.exec.run(
						[
							git,
							`--git-dir=${clone}`,
							"grep",
							"-F",
							"-o",
							"-h",
							"--no-color",
							"-f",
							patterns,
							"HEAD",
						],
						{ cwd: tmp, env, timeoutMs: 5 * 60_000 },
					);
					// 0 = matches, 1 = none; anything else (e.g. empty repo) is unknown.
					if (grep.code === 0 || grep.code === 1) {
						const found = grep.stdout.split("\n").filter(Boolean);
						for (const s of secrets)
							stillAtHead.set(
								s,
								found.some((f) => f.includes(s)),
							);
					}
				}
				return [...parseSecretsHistory(json, stillAtHead), ...incomplete];
			}).pipe(
				Effect.ensuring(
					Effect.promise(() => rm(tmp, { recursive: true, force: true })),
				),
			);
		}),
});
