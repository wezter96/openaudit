import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
	type AuditContext,
	AuditorError,
	defineAuditor,
	type FindingInput,
	GIT_REF,
	lineOf,
	requireTool,
	requireWorkspace,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, num, parseJson, str, withTempDir } from "../tool";
import { findSpecFiles, type SpecFile } from "./api";
import { gitHardeningEnv } from "./secrets-history";
import { extOf, isRecord, kebab, scrubLine, truncate } from "./util";

/**
 * Breaking changes in OpenAPI specs between the `--diff` base and the current
 * tree, with oasdiff.
 *
 * Hardening, all enforced by us rather than by the target:
 * - The base version comes from git through commit-only plumbing (`merge-base`,
 *   `ls-tree`, `cat-file blob <oid>`) with `GIT_HARDENING_ENV`, global config
 *   off, lazy fetches and every transport disabled, so a hostile `.git/config`
 *   cannot make git run a command or reach the network. The user's ref only
 *   follows `--end-of-options`.
 * - Both versions are copied into a temp dir and oasdiff runs there, with
 *   relative file names (oasdiff treats any `a:b` argument as a git revision and
 *   would run git itself) and our own empty `--config`, so the target's
 *   `.oasdiff.*` is never read.
 * - oasdiff follows `$ref`s and fetches remote ones by default (verified
 *   against a local listener). `--allow-external-refs=false` makes it refuse
 *   every non-local ref, including keys spelled with JSON escapes that a
 *   text scan would miss (verified). Multi-file specs are therefore reported as not compared.
 */

const ID = "code.oasdiff";
const INSTALL =
	"Install: brew install oasdiff, or go install github.com/oasdiff/oasdiff@latest (https://github.com/oasdiff/oasdiff#installation).";
/** Same bound as spec discovery. */
const MAX_SPEC_BYTES = 5 * 1024 * 1024;
const OID = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;
/** oasdiff exit codes for a spec that could not be loaded or flattened. */
const NOT_LOADED = new Set([102, 122, 123]);

const REFERENCES = [
	"https://www.oasdiff.com/docs/breaking-changes",
	"https://github.com/oasdiff/oasdiff/blob/main/docs/BREAKING-CHANGES.md",
];

const LEVELS: Readonly<Record<string, Severity>> = {
	"3": "high",
	"2": "medium",
	"1": "info",
	error: "high",
	err: "high",
	warn: "medium",
	warning: "medium",
	info: "info",
};

const REMEDIATION: Readonly<Record<Severity, string>> = {
	critical: "",
	high: "This breaks existing clients. Keep the old contract (deprecate before removing, keep new inputs optional, do not narrow types or constraints), or ship the change as a new API version and tell its consumers.",
	medium:
		"This may break clients that relied on the old behaviour. Check with the API's consumers, or deprecate first and ship the change in a new API version.",
	low: "",
	info: "Not a breaking change; listed for review.",
};

/* -------------------------------------------------------------------------- */
/*                                   Parsing                                  */
/* -------------------------------------------------------------------------- */

const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const keyAt = (name: string) =>
	// name is escaped, so it only matches itself.
	// nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
	new RegExp(`(?:^|[{,\\s])["']?${escapeRegExp(name)}["']?\\s*:`, "gm");
/** Any key that looks like an API path, to bound the method search. */
const PATH_KEY = /(?:^|[{,\s])["']?\/[^"'\s:]*["']?\s*:/gm;

const indexFrom = (re: RegExp, text: string, from: number) => {
	re.lastIndex = from;
	const m = re.exec(text);
	return m ? { start: m.index, end: m.index + m[0].length } : undefined;
};

const lineAt = (text: string, i: number) =>
	lineOf(text, text[i] === "\n" ? i + 1 : i);

/** Start of the `method` key after a path key ending at `from`, before the next path. */
const methodStart = (text: string, from: number, method: string) => {
	const bound = indexFrom(PATH_KEY, text, from)?.start ?? text.length;
	const op = indexFrom(keyAt(method.toLowerCase()), text, from);
	return op && op.start < bound ? op.start : undefined;
};

/**
 * Line of `method` under `path` in a YAML or JSON spec, else the path's line.
 * A cheap text search, not a parse: good enough to point a reviewer at it.
 */
export const operationLine = (
	text: string,
	path: string | undefined,
	method: string | undefined,
): number | undefined => {
	if (!path) return undefined;
	const paths = indexFrom(keyAt("paths"), text, 0);
	const at = indexFrom(keyAt(path), text, paths?.end ?? 0);
	if (!at) return undefined;
	const op = method ? methodStart(text, at.end, method) : undefined;
	return lineAt(text, op ?? at.start);
};

export interface CompareContext {
	/** The spec's path in the workspace. */
	readonly file: string;
	/** The spec's current text, to locate operations. */
	readonly text: string;
	/** The revision file name oasdiff was given, as it reports sources. */
	readonly revisionFile: string;
	/** The ref compared against, as the user gave it. */
	readonly base: string;
}

/** One reported change, once it has the fields a finding needs. */
interface Change {
	readonly item: Record<string, unknown>;
	readonly id: string;
	readonly text: string;
	readonly severity: Severity;
}

const changeOf = (item: unknown): Change | undefined => {
	if (!isRecord(item)) return undefined;
	const id = str(item.id);
	const text = str(item.text);
	const severity = LEVELS[String(item.level).toLowerCase()];
	if (!severity) return undefined;
	return id && text ? { item, id, text, severity } : undefined;
};

/** The line oasdiff reported in the revision, else a text search for the operation. */
const changeLine = (
	{ item }: Change,
	ctx: CompareContext,
	path: string | undefined,
	method: string | undefined,
) => {
	const rev = isRecord(item.revisionSource) ? item.revisionSource : {};
	const reported =
		str(rev.file) === ctx.revisionFile ? num(rev.line) : undefined;
	return reported ?? operationLine(ctx.text, path, method);
};

const changeFinding = (change: Change, ctx: CompareContext): FindingInput => {
	const { item, id, text, severity } = change;
	const method = str(item.operation);
	const path = str(item.path);
	const where = [method, path].filter(Boolean).join(" ");
	const line = changeLine(change, ctx, path, method);
	const comment = str(item.comment);
	return {
		ruleId: `${ID}/${kebab(id)}`,
		title: truncate(text, 120),
		severity,
		category: "reliability",
		message: `${where ? `${where}: ` : ""}${text} (compared with ${ctx.base}).${comment ? ` ${comment}` : ""}`,
		location: { file: ctx.file, ...(line ? { line } : {}) },
		evidence: truncate(scrubLine(where ? `${where}: ${text}` : text), 200),
		remediation: REMEDIATION[severity],
		references: REFERENCES,
		confidence: severity === "high" ? "high" : "medium",
		tags: ["openapi", "breaking-change"],
	};
};

/** Maps `oasdiff breaking --format json` output (an array of changes). */
export const parseOasdiffOutput = (
	json: unknown,
	ctx: CompareContext,
): FindingInput[] =>
	arr(json).flatMap((item): FindingInput[] => {
		const change = changeOf(item);
		return change ? [changeFinding(change, ctx)] : [];
	});

const notCompared = (file: string, why: string): FindingInput => ({
	ruleId: `${ID}/not-compared`,
	title: "OpenAPI spec not checked for breaking changes",
	severity: "info",
	category: "reliability",
	message: `${file} could not be compared with its base version: ${why}`,
	location: { file },
	remediation:
		"Bundle a multi-file spec into one document (for example with `redocly bundle`) to have it checked, or review the change for breaking changes by hand.",
	references: REFERENCES,
	confidence: "high",
	tags: ["openapi", "breaking-change"],
});

interface TreeEntry {
	readonly type: string;
	readonly oid: string;
	readonly size: number;
}

/** One `ls-tree -l` record as `[path, entry]`; every group is non-empty when it matches. */
const lsTreeRecord = (record: string): [string, TreeEntry] | undefined => {
	const m = /^\d+ (\w+) ([0-9a-f]+) +(\d+|-)\t(.+)$/s.exec(record);
	if (!m) return undefined;
	const [, type = "", oid = "", size = "", path = ""] = m;
	return [path, { type, oid, size: Number(size) }];
};

/** Parses `git ls-tree -l -z` output, keyed by path. */
export const parseLsTree = (stdout: string): Map<string, TreeEntry> => {
	const out = new Map<string, TreeEntry>();
	for (const record of stdout.split("\0")) {
		const entry = lsTreeRecord(record);
		if (entry) out.set(...entry);
	}
	return out;
};

/* -------------------------------------------------------------------------- */
/*                                  Auditor                                   */
/* -------------------------------------------------------------------------- */

/**
 * Git environment for reading the base: the shared hardening, no global or
 * system config, no transports, and no lazy fetch of missing objects from a
 * promisor remote (which could run `core.sshCommand`).
 */
export const oasdiffGitEnv = (home: string): Record<string, string> => ({
	...gitHardeningEnv(home, [["protocol.allow", "never"]]),
	GIT_NO_LAZY_FETCH: "1",
	GIT_LITERAL_PATHSPECS: "1",
	GIT_OPTIONAL_LOCKS: "0",
});

const fail = (what: string, res: { code: number; stderr: string }) =>
	Effect.fail(
		new AuditorError({
			message: `${what} exited with code ${res.code}: ${truncate(res.stderr.trim(), 300)}`,
		}),
	);

/** One comparison run: the tools, the temp dir and the hardened git env. */
interface Session {
	readonly ctx: AuditContext;
	readonly root: string;
	readonly base: string;
	readonly bin: string;
	readonly git: string;
	readonly tmp: string;
	readonly config: string;
	readonly env: Record<string, string>;
}

/** A spec's base and revision files, relative to the temp dir. */
interface Pair {
	readonly spec: SpecFile;
	readonly baseFile: string;
	readonly revisionFile: string;
}

const runGit = (s: Session, args: ReadonlyArray<string>) =>
	s.ctx.exec.run([s.git, "-C", s.root, ...args], {
		cwd: s.tmp,
		env: s.env,
		timeoutMs: 60_000,
	});

/** The specs' entries in the merge base's tree. */
const baseTree = (s: Session, specs: ReadonlyArray<SpecFile>) =>
	Effect.gen(function* () {
		// Like `--diff` itself (`base...HEAD`), compare with the merge base.
		const mb = yield* runGit(s, [
			"merge-base",
			"--end-of-options",
			s.base,
			"HEAD",
		]);
		const sha = mb.stdout.trim();
		if (mb.code !== 0 || !OID.test(sha))
			return yield* fail(`git merge-base ${s.base} HEAD`, mb);
		const tree = yield* runGit(s, [
			"ls-tree",
			"-l",
			"-z",
			sha,
			"--",
			...specs.map((spec) => spec.path),
		]);
		if (tree.code !== 0) return yield* fail("git ls-tree", tree);
		return parseLsTree(tree.stdout);
	});

const isBaseBlob = (entry: TreeEntry | undefined): entry is TreeEntry =>
	entry?.type === "blob" && OID.test(entry.oid);

const notLoadedReason = (s: Session, pair: Pair, stderr: string) =>
	/disallowed external ref/i.test(stderr)
		? "it uses external $refs, which oasdiff is not allowed to follow (they could make it fetch URLs chosen by the repository)."
		: truncate(
				scrubLine(
					(stderr.trim().split("\n")[0] ?? "")
						.replace(/^Error:\s*/, "")
						.replaceAll(pair.baseFile, `${pair.spec.path} at ${s.base}`)
						.replaceAll(pair.revisionFile, pair.spec.path),
				),
				300,
			);

const runOasdiff = (s: Session, pair: Pair) =>
	Effect.gen(function* () {
		const res = yield* s.ctx.exec.run(
			[
				s.bin,
				"breaking",
				pair.baseFile,
				pair.revisionFile,
				"--format",
				"json",
				"--allow-external-refs=false",
				"--config",
				s.config,
			],
			{ cwd: s.tmp, timeoutMs: 5 * 60_000 },
		);
		if (NOT_LOADED.has(res.code))
			return [
				notCompared(pair.spec.path, notLoadedReason(s, pair, res.stderr)),
			];
		if (res.code !== 0) return yield* fail("oasdiff", res);
		const json = yield* parseJson(res.stdout, "oasdiff");
		return parseOasdiffOutput(json, {
			file: pair.spec.path,
			text: pair.spec.text,
			revisionFile: pair.revisionFile,
			base: s.base,
		});
	});

/** Writes both versions of the `i`th spec to the temp dir and compares them. */
const comparePair = (s: Session, spec: SpecFile, i: number, baseText: string) =>
	Effect.gen(function* () {
		const ext = extOf(spec.path) === "json" ? ".json" : ".yaml";
		const pair: Pair = {
			spec,
			baseFile: `${i}/base${ext}`,
			revisionFile: `${i}/revision${ext}`,
		};
		yield* Effect.promise(async () => {
			await mkdir(join(s.tmp, String(i)));
			await writeFile(join(s.tmp, pair.baseFile), baseText);
			await writeFile(join(s.tmp, pair.revisionFile), spec.text);
		});
		return yield* runOasdiff(s, pair);
	});

const compareSpec = (
	s: Session,
	entry: TreeEntry | undefined,
	spec: SpecFile,
	i: number,
) =>
	Effect.gen(function* () {
		// Missing at the base: a new API, nothing to break.
		if (!isBaseBlob(entry)) return [];
		if (!(entry.size <= MAX_SPEC_BYTES))
			return [notCompared(spec.path, `its version at ${s.base} is too large.`)];
		const blob = yield* runGit(s, ["cat-file", "blob", entry.oid]);
		if (blob.code !== 0) return yield* fail("git cat-file", blob);
		if (blob.stdout === spec.text) return [];
		return yield* comparePair(s, spec, i, blob.stdout);
	});

const compare = (
	ctx: AuditContext,
	root: string,
	base: string,
	specs: ReadonlyArray<SpecFile>,
) =>
	Effect.gen(function* () {
		const bin = yield* requireTool(ctx, "oasdiff", INSTALL);
		const git = yield* requireTool(ctx, "git", "Install git.");
		return yield* withTempDir("openaudit-oasdiff-", (tmp) =>
			Effect.gen(function* () {
				const home = join(tmp, "home");
				const config = join(tmp, "oasdiff.yaml");
				yield* Effect.promise(() =>
					Promise.all([mkdir(home), writeFile(config, "")]),
				);
				const env = oasdiffGitEnv(home);
				const s: Session = { ctx, root, base, bin, git, tmp, config, env };
				const entries = yield* baseTree(s, specs);
				const findings: FindingInput[] = [];
				for (const [i, spec] of specs.entries())
					findings.push(
						...(yield* compareSpec(s, entries.get(spec.path), spec, i)),
					);
				return findings;
			}),
		);
	});

export const oasdiff = defineAuditor({
	id: ID,
	title: "oasdiff breaking API changes",
	description:
		"Reports breaking changes in OpenAPI 3 specs between the --diff base and the current tree, with oasdiff. Only runs with --diff <ref>. The base version is read from git at the merge base with hardened, commit-only git calls; both versions are compared in a temp dir with the project's oasdiff config ignored and external $refs disabled, so a spec cannot make oasdiff fetch URLs. Specs that use external $refs are reported as not compared.",
	categories: ["reliability"],
	targets: ["codebase"],
	engine: "external",
	tool: "oasdiff",
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const base = ctx.options.diffBase;
			if (!base)
				return yield* skip(
					"Only runs with --diff <ref>: it compares OpenAPI specs with their version at that ref.",
				);
			if (!GIT_REF.test(base) || base.includes(".."))
				return yield* Effect.fail(
					new AuditorError({ message: `Invalid git ref "${base}".` }),
				);
			const specs = yield* findSpecFiles(ws, ["openapi"]);
			if (specs.length === 0) return [];
			return yield* compare(ctx, ws.root, base, specs);
		}),
});
