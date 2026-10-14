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
 * userinfo (also scp-like, after a backslash or as `%40`), credential-named
 * query, fragment and path parameters, JWTs, basic auth, well-known token
 * prefixes and long mixed-case alphanumeric runs are masked with `redact`.
 * A secret that looks like none of these (a short or lower-case token in a
 * path segment with an ordinary name) can still be shown, and a host WHATWG
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

/** Reads a file up to `MAX_LOCKFILE_BYTES` (Workspace.readText stops at 2 MB). */
const readLarge = (
	ws: Workspace,
	path: string,
): Effect.Effect<
	| SourceFile
	| { readonly path: string; readonly size: number }
	| { readonly path: string; readonly unreadable: string }
	| undefined
> =>
	Effect.gen(function* () {
		const size = yield* ws.size(path);
		if (size === 0) return undefined;
		if (size > MAX_LOCKFILE_BYTES) return { path, size };
		const bytes = yield* ws.readBytes(path);
		// Read as UTF-8 like the package managers do, NUL bytes included:
		// Yarn and npm's ini parser accept them in comments.
		return (bytes[0] === 0xff && bytes[1] === 0xfe) ||
			(bytes[0] === 0xfe && bytes[1] === 0xff)
			? { path, unreadable: "is UTF-16 encoded" }
			: { path, text: new TextDecoder().decode(bytes) };
	}).pipe(
		Effect.orElseSucceed(() => ({ path, unreadable: "could not be read" })),
	);

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
			const findings: FindingInput[] = paths
				.filter((p) => BINARY_LOCKFILES.has(baseName(p)))
				.map((p) =>
					uncheckedFinding(
						"unparseable-lockfile",
						p,
						`${p} is a binary lockfile, which openaudit cannot read. Run \`bun install --save-text-lockfile\` to migrate to bun.lock.`,
					),
				);
			const read = yield* Effect.forEach(
				paths.filter((p) => !BINARY_LOCKFILES.has(baseName(p))),
				(p) => readLarge(ws, p),
				{ concurrency: 16 },
			);
			const files: SourceFile[] = [];
			for (const f of read) {
				if (!f) continue;
				if ("text" in f) files.push(f);
				else if ("unreadable" in f) findings.push(unreadFinding(f));
				else
					findings.push(
						uncheckedFinding(
							"truncated",
							f.path,
							`${f.path} is ${(f.size / 1024 / 1024).toFixed(1)} MB, above the ${MAX_LOCKFILE_BYTES / 1024 / 1024} MB limit.`,
						),
					);
			}
			const lockfileList = files.filter(
				(f) => baseName(f.path) in LOCKFILE_PARSERS,
			);
			if (
				!lockfileList.length &&
				!findings.length &&
				!files.some((f) => baseName(f.path) !== "package.json")
			)
				return yield* skip(
					"No lockfiles, package-manager configs, requirements files or composer.json found",
				);

			const configs = new Map<string, FileConfig>();
			const manifests = new Map<string, SourceFile>();
			for (const f of files) {
				const name = baseName(f.path);
				const reader = CONFIG_READERS[name];
				if (reader) {
					const config: FileConfig = { file: f.path, registries: [] };
					if (!reader(f, config))
						findings.push(unparsedConfigFinding(f.path, "could not be parsed"));
					configs.set(f.path, config);
					findings.push(...configFindings(config));
				}
				if (name === "package.json") manifests.set(f.path, f);
				const other = OTHER_READERS[name];
				if (other) findings.push(...other(f));
			}

			// pip follows -r/-c includes, whatever their names, so do we.
			const queue = files.filter((f) => isRequirements(f.path));
			const seen = new Set(queue.map((f) => f.path));
			let capped = false;
			for (let f = queue.shift(); f; f = queue.shift()) {
				const result = requirementsFindings(f);
				findings.push(...result.findings);
				for (const include of result.includes) {
					const path = resolveInRepo(dirOf(f.path), include);
					if (path === undefined || seen.has(path)) continue;
					if (seen.size >= MAX_REQUIREMENTS_FILES) {
						if (!capped)
							findings.push(
								uncheckedFinding(
									"truncated",
									path,
									`${f.path} includes ${path}, beyond the ${MAX_REQUIREMENTS_FILES} requirements files openaudit reads.`,
								),
							);
						capped = true;
						continue;
					}
					seen.add(path);
					// pip fails on a missing include, so there is nothing to check.
					if (!(yield* ws.exists(path))) continue;
					const included = yield* readLarge(ws, path);
					if (!included) continue;
					if ("text" in included) queue.push(included);
					else if ("unreadable" in included)
						findings.push(unreadFinding(included));
					else
						findings.push(
							uncheckedFinding(
								"truncated",
								path,
								`${path} is above the ${MAX_LOCKFILE_BYTES / 1024 / 1024} MB limit.`,
							),
						);
				}
			}

			for (const f of lockfileList) {
				const lock = parseLockfile(f);
				if (!lock) {
					findings.push(
						uncheckedFinding(
							"unparseable-lockfile",
							f.path,
							`${f.path} could not be parsed.`,
						),
					);
					continue;
				}
				findings.push(
					...lockfileFindings(lock, configsFor(configs, lock), manifests),
				);
			}
			// Defence in depth: whatever the builders quoted, no credential leaves.
			return findings.map(scrubFinding);
		}),
});
