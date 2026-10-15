import {
	defineAuditor,
	type FindingInput,
	requireWorkspace,
	skip,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import { baseName, isFixturePath, type SourceFile } from "../util";
import { composerJsonFindings, composerLockFindings } from "./composer";
import { CONFIG_READERS, configsFor, type FileConfig } from "./config";
import { uncheckedFinding, unparsedConfigFinding } from "./findings";
import { configFindings, lockfileFindings } from "./npm-findings";
import { LOCKFILE_PARSERS, parseLockfile } from "./parse";
import { pipfileFindings, requirementsFindings } from "./pip";
import { scrubFinding } from "./scrub";
import { dirOf, LOCKFILES_ID, MAX_LOCKFILE_BYTES } from "./shared";
import { resolveInRepo } from "./sources";

export { parseBunLock } from "./bun";
export { composerJsonFindings, composerLockFindings } from "./composer";
export type { FileConfig } from "./config";
export { capPerRule } from "./findings";
export { parseNpmLock } from "./npm";
export { lockfileFindings } from "./npm-findings";
export { conflictSides, parseLockfile } from "./parse";
export { pipfileFindings, requirementsFindings } from "./pip";
export { parsePnpmLock } from "./pnpm";
export { scrubFinding, scrubText } from "./scrub";
export {
	LOCKFILES_ID,
	type LockedPackage,
	type Lockfile,
	MAX_FINDINGS_PER_RULE,
	type Manager,
	type Problem,
} from "./shared";
export {
	classifySource,
	displayUrl,
	escapesRoot,
	type IntegrityStrength,
	integrityStrength,
	type Source,
} from "./sources";
export { parseYarnLock } from "./yarn";

/*
 * Lockfile integrity and install-time risk, in the spirit of lockfile-lint and
 * Socket's install-script signal. Everything is read offline from lockfiles
 * and package-manager configs; nothing is installed or executed.
 *
 * Every file read here is controlled by whoever controls the target, configs
 * included. A config can explain a finding (a private registry, an allow-list
 * for install scripts) but never makes it disappear: settings are only
 * honoured where the package manager itself reads and enforces them, and what
 * they allow is still reported.
 *
 * Files and entries that cannot be read are reported (`unparseable-lockfile`,
 * `unparseable-config`, `truncated`), never skipped.
 *
 * Known limitations, ways an entry can still evade these checks:
 * - Package substitution on the public registry: an entry for `a` whose
 *   tarball is another package on registry.npmjs.org is not flagged, because
 *   npm aliases make that legitimate.
 * - Settings from outside the repository (user and global .npmrc,
 *   `npm_config_*` variables, CI configuration) and pnpm's registry settings
 *   in pnpm-workspace.yaml are not read. Entries without a recorded URL are
 *   assumed to come from the registry the repository configures.
 * - Integrity hashes are checked for presence and algorithm only. Nothing is
 *   downloaded, so a hash that does not match its tarball goes unnoticed.
 * - A file that parses here but is read differently by a package-manager
 *   version not modelled here (for example Yarn 1's quirks inside a merge
 *   conflict) is checked as parsed here. Only parse failures are reported.
 * - `-r`/`-c` includes missing from the checkout (generated at install time)
 *   are not checked.
 * - `${VAR}` in .npmrc and .yarnrc.yml is read as unset (npm keeps it, `?`
 *   empties it, Yarn uses the fallback); a registry only the environment
 *   decides is reported but not checked. bunfig.toml expansion is not modelled.
 *
 * Every finding passes through scrubFinding (scrub.ts) on the way out:
 * userinfo (after any run of `/` and `\` that WHATWG accepts for a special
 * scheme, across tabs and newlines, scp-like, or as `%40`), credential-named
 * query, fragment and path parameters (names percent-decoded first), JWTs,
 * basic auth, UUIDs (classic npm tokens), well-known token prefixes and long
 * mixed-case alphanumeric runs are masked with `redact`, in keys as in values;
 * a string cut at the length cap loses the whole word the cut lands in.
 * A secret that looks like none of these (a short or lower-case token in a
 * path segment with an ordinary name, or a URL password holding a literal
 * space, which ends the authority here) can still be shown, and a host WHATWG
 * takes from what another parser reads as userinfo is masked, so such a
 * finding may not name the host that is fetched.
 */

const isRequirements = (path: string) =>
	/^requirements[\w.-]*\.txt$/.test(baseName(path)) ||
	/(^|\/)requirements\/[^/]+\.txt$/.test(path);

const OTHER_READERS: Readonly<
	Record<string, (file: SourceFile) => FindingInput[]>
> = {
	Pipfile: pipfileFindings,
	"composer.json": composerJsonFindings,
	"composer.lock": composerLockFindings,
};

/** A file that could not be decoded or read, reported by kind. */
const unreadFinding = (f: {
	readonly path: string;
	readonly unreadable: string;
}): FindingInput => {
	const name = baseName(f.path);
	return name in LOCKFILE_PARSERS || name === "composer.lock"
		? uncheckedFinding(
				"unparseable-lockfile",
				f.path,
				`${f.path} ${f.unreadable}.`,
			)
		: unparsedConfigFinding(f.path, f.unreadable);
};

/** Lockfiles in binary formats that package managers install from but cannot be read here. */
const BINARY_LOCKFILES = new Set(["bun.lockb"]);

/** Requirements files read in total, including those reached through `-r`/`-c`. */
const MAX_REQUIREMENTS_FILES = 200;

const isRelevant = (path: string) => {
	if (isFixturePath(path)) return false;
	const name = baseName(path);
	return (
		name in LOCKFILE_PARSERS ||
		BINARY_LOCKFILES.has(name) ||
		name in CONFIG_READERS ||
		name in OTHER_READERS ||
		isRequirements(path)
	);
};

/** A file read in full, or why it was not. */
type ReadResult =
	| SourceFile
	| { readonly path: string; readonly size: number }
	| { readonly path: string; readonly unreadable: string }
	| undefined;

const UTF16_BOMS = [
	[0xff, 0xfe],
	[0xfe, 0xff],
];

const isUtf16 = (bytes: Uint8Array) =>
	UTF16_BOMS.some(([a, b]) => bytes[0] === a && bytes[1] === b);

/** Reads a file up to `MAX_LOCKFILE_BYTES` (Workspace.readText stops at 2 MB). */
const readLarge = (ws: Workspace, path: string): Effect.Effect<ReadResult> =>
	Effect.gen(function* () {
		const size = yield* ws.size(path);
		if (size === 0) return undefined;
		if (size > MAX_LOCKFILE_BYTES) return { path, size };
		const bytes = yield* ws.readBytes(path);
		// Read as UTF-8 like the package managers do, NUL bytes included:
		// Yarn and npm's ini parser accept them in comments.
		return isUtf16(bytes)
			? { path, unreadable: "is UTF-16 encoded" }
			: { path, text: new TextDecoder().decode(bytes) };
	}).pipe(
		Effect.orElseSucceed(() => ({ path, unreadable: "could not be read" })),
	);

const LIMIT_MB = MAX_LOCKFILE_BYTES / 1024 / 1024;

const isSourceFile = (f: ReadResult): f is SourceFile =>
	f !== undefined && "text" in f;

/** A finding for a file found at the top level that was not read. */
const readFailureFindings = (f: ReadResult): FindingInput[] => {
	if (f === undefined || isSourceFile(f)) return [];
	if ("unreadable" in f) return [unreadFinding(f)];
	return [
		uncheckedFinding(
			"truncated",
			f.path,
			`${f.path} is ${(f.size / 1024 / 1024).toFixed(1)} MB, above the ${LIMIT_MB} MB limit.`,
		),
	];
};

const binaryLockfileFinding = (path: string): FindingInput =>
	uncheckedFinding(
		"unparseable-lockfile",
		path,
		`${path} is a binary lockfile, which openaudit cannot read. Run \`bun install --save-text-lockfile\` to migrate to bun.lock.`,
	);

const isBinaryLockfile = (path: string) => BINARY_LOCKFILES.has(baseName(path));

const isLockfile = (f: SourceFile) => baseName(f.path) in LOCKFILE_PARSERS;

/** Nothing the auditor checks: no lockfile, no report so far, only package.json manifests. */
const nothingToCheck = (
	files: ReadonlyArray<SourceFile>,
	findings: ReadonlyArray<FindingInput>,
) => {
	if (files.some(isLockfile) || findings.length) return false;
	return files.every((f) => baseName(f.path) === "package.json");
};

/** Package-manager configs and manifests, and the findings from reading them. */
interface ReadConfigs {
	readonly configs: Map<string, FileConfig>;
	readonly manifests: Map<string, SourceFile>;
	readonly findings: FindingInput[];
}

/** Reads one config file into `configs`, with its findings. */
const readConfig = (
	f: SourceFile,
	configs: Map<string, FileConfig>,
): FindingInput[] => {
	const reader = CONFIG_READERS[baseName(f.path)];
	if (!reader) return [];
	const config: FileConfig = { file: f.path, registries: [] };
	const unparsed = reader(f, config)
		? []
		: [unparsedConfigFinding(f.path, "could not be parsed")];
	configs.set(f.path, config);
	return [...unparsed, ...configFindings(config)];
};

const readConfigs = (files: ReadonlyArray<SourceFile>): ReadConfigs => {
	const out: ReadConfigs = {
		configs: new Map(),
		manifests: new Map(),
		findings: [],
	};
	for (const f of files) {
		const name = baseName(f.path);
		out.findings.push(...readConfig(f, out.configs));
		if (name === "package.json") out.manifests.set(f.path, f);
		const other = OTHER_READERS[name];
		if (other) out.findings.push(...other(f));
	}
	return out;
};

/** Requirements files still to check, and those already queued. */
interface RequirementsWalk {
	readonly ws: Workspace;
	readonly queue: SourceFile[];
	readonly seen: Set<string>;
	readonly findings: FindingInput[];
	/** The include limit was reported. */
	capped: boolean;
}

/** An include that was found but not queued: unreadable or too large. */
const queueIncluded = (
	walk: RequirementsWalk,
	path: string,
	included: ReadResult,
) => {
	if (!included) return;
	if ("text" in included) walk.queue.push(included);
	else if ("unreadable" in included)
		walk.findings.push(unreadFinding(included));
	else
		walk.findings.push(
			uncheckedFinding(
				"truncated",
				path,
				`${path} is above the ${LIMIT_MB} MB limit.`,
			),
		);
};

/** Reports the first include beyond `MAX_REQUIREMENTS_FILES`. */
const capIncludes = (
	walk: RequirementsWalk,
	from: SourceFile,
	path: string,
) => {
	if (!walk.capped)
		walk.findings.push(
			uncheckedFinding(
				"truncated",
				path,
				`${from.path} includes ${path}, beyond the ${MAX_REQUIREMENTS_FILES} requirements files openaudit reads.`,
			),
		);
	walk.capped = true;
};

/** Queues a `-r`/`-c` include of `from`, once. */
const followInclude = (
	walk: RequirementsWalk,
	from: SourceFile,
	include: string,
) =>
	Effect.gen(function* () {
		const path = resolveInRepo(dirOf(from.path), include);
		if (path === undefined || walk.seen.has(path)) return;
		if (walk.seen.size >= MAX_REQUIREMENTS_FILES)
			return capIncludes(walk, from, path);
		walk.seen.add(path);
		// pip fails on a missing include, so there is nothing to check.
		if (!(yield* walk.ws.exists(path))) return;
		queueIncluded(walk, path, yield* readLarge(walk.ws, path));
	});

/** pip follows -r/-c includes, whatever their names, so do we. */
const requirementsWalkFindings = (
	ws: Workspace,
	files: ReadonlyArray<SourceFile>,
) =>
	Effect.gen(function* () {
		const queue = files.filter((f) => isRequirements(f.path));
		const walk: RequirementsWalk = {
			ws,
			queue,
			seen: new Set(queue.map((f) => f.path)),
			findings: [],
			capped: false,
		};
		for (let f = queue.shift(); f; f = queue.shift()) {
			const result = requirementsFindings(f);
			walk.findings.push(...result.findings);
			for (const include of result.includes)
				yield* followInclude(walk, f, include);
		}
		return walk.findings;
	});

const parsedLockfileFindings = (
	f: SourceFile,
	{ configs, manifests }: ReadConfigs,
): FindingInput[] => {
	const lock = parseLockfile(f);
	if (!lock)
		return [
			uncheckedFinding(
				"unparseable-lockfile",
				f.path,
				`${f.path} could not be parsed.`,
			),
		];
	return lockfileFindings(lock, configsFor(configs, lock), manifests);
};

export const lockfiles = defineAuditor({
	id: LOCKFILES_ID,
	title: "Lockfile integrity and install scripts",
	description:
		"Checks npm, pnpm, Bun and Yarn lockfiles offline, in the spirit of lockfile-lint: packages resolved over plain HTTP, from unexpected or repository-configured registries, git or local paths outside the repository, entries without (or with SHA-1-only) integrity hashes, dependencies that run install scripts without an allow-list, and lockfiles out of date with package.json. Also flags insecure registries and pip/Composer index settings.",
	categories: ["supply-chain"],
	targets: ["codebase"],
	engine: "builtin",
	network: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const paths = (yield* ws.files).filter(isRelevant).sort();
			const read = yield* Effect.forEach(
				paths.filter((p) => !isBinaryLockfile(p)),
				(p) => readLarge(ws, p),
				{ concurrency: 16 },
			);
			const files = read.filter(isSourceFile);
			const unread = [
				...paths.filter(isBinaryLockfile).map(binaryLockfileFinding),
				...read.flatMap(readFailureFindings),
			];
			if (nothingToCheck(files, unread))
				return yield* skip(
					"No lockfiles, package-manager configs, requirements files or composer.json found",
				);
			const configs = readConfigs(files);
			const requirements = yield* requirementsWalkFindings(ws, files);
			const findings = [
				...unread,
				...configs.findings,
				...requirements,
				...files
					.filter(isLockfile)
					.flatMap((f) => parsedLockfileFindings(f, configs)),
			];
			// Defence in depth: whatever the builders quoted, no credential leaves.
			return findings.map(scrubFinding);
		}),
});
