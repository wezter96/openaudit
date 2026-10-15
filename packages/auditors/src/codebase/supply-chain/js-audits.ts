import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	type AuditContext,
	type Auditor,
	AuditorError,
	defineAuditor,
	type FindingInput,
	requireTool,
	requireWorkspace,
	skip,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, cweTags, parseJson, severityOf, str } from "../../tool";
import { parseBunLock } from "../dependencies";
import { isRecord, truncate } from "../util";
import {
	type FilePath,
	type FileText,
	firstPerKey,
	type Json,
	type Keyed,
	type PackageName,
	type RootPath,
	strings,
	type ToolBin,
	type Url,
} from "./report";
import {
	baseOf,
	dirOf,
	findFiles,
	fixedFromPatched,
	fixedFromRange,
	ghsaOf,
	NPM_REGISTRY,
	run,
	vulnFinding,
} from "./shared";

/* -------------------------------------------------------------------------- */
/*                    npm / pnpm / bun audit (lockfile only)                  */
/* -------------------------------------------------------------------------- */

export interface LockText {
	readonly file: FilePath;
	readonly text: FileText;
}

const errorMessage = (json: unknown): string | undefined => {
	if (!isRecord(json) || !isRecord(json.error)) return undefined;
	return (
		str(json.error.summary) ??
		str(json.error.message) ??
		str(json.error.detail) ??
		str(json.error.code) ??
		"audit failed"
	);
};

/** Advisory page, if any. */
const jsRefs = (url: Url | undefined) => (url ? [url] : []);

/* --------------------------------- npm audit -------------------------------- */

/** package-lock.json's `packages` map, when the lockfile parses. */
const lockedPackages = (lock?: LockText): Json => {
	try {
		const parsed: unknown = lock ? JSON.parse(lock.text) : undefined;
		if (isRecord(parsed) && isRecord(parsed.packages)) return parsed.packages;
	} catch {
		// Versions are optional.
	}
	return {};
};

/** The installed version, from the package's first node in the lockfile. */
const lockedVersion = (entry: Json, packages: Json) => {
	const node = str(arr(entry.nodes)[0]);
	const locked = node ? packages[node] : undefined;
	return isRecord(locked) ? str(locked.version) : undefined;
};

const npmFixHint = (fa: unknown, name: PackageName) => {
	if (isRecord(fa))
		return `Upgrade ${str(fa.name) ?? name} to ${str(fa.version) ?? "the latest version"} (npm audit fix${fa.isSemVerMajor ? " --force, a breaking change" : ""}).`;
	return fa === true
		? "Run npm audit fix to update to a patched version."
		: undefined;
};

/** One entry of npm's `vulnerabilities` map. */
interface NpmVulnerable {
	readonly key: PackageName;
	readonly version?: string;
	readonly fixAvailable: unknown;
	readonly file?: FilePath;
}

const npmViaFinding = (via: Json, pkg: NpmVulnerable): Keyed => {
	const name = str(via.name) ?? pkg.key;
	const url = str(via.url);
	const id = ghsaOf(url) ?? String(via.source ?? url ?? "unknown");
	const fixed = fixedFromRange(str(via.range));
	const finding = vulnFinding({
		auditor: "code.npm-audit",
		name,
		version: pkg.version,
		ecosystem: "npm",
		id,
		summary: str(via.title) ?? id,
		severity: severityOf(via.severity),
		fixed: fixed ? [fixed] : [],
		fixHint: npmFixHint(pkg.fixAvailable, name),
		file: pkg.file,
		references: jsRefs(url),
		tags: cweTags(strings(via.cwe)),
	});
	return { key: `${name}|${id}`, finding };
};

const npmEntryFindings = (
	[key, entry]: [PackageName, unknown],
	packages: Json,
	file?: FilePath,
): Keyed[] => {
	if (!isRecord(entry)) return [];
	const pkg: NpmVulnerable = {
		key,
		version: lockedVersion(entry, packages),
		fixAvailable: entry.fixAvailable,
		file,
	};
	// String entries only name another vulnerable package (reported on its own).
	return arr(entry.via)
		.filter(isRecord)
		.map((via) => npmViaFinding(via, pkg));
};

/** Parses `npm audit --json` (npm v7+: `vulnerabilities` map with `via`). */
export const parseNpmAuditReport = (
	json: unknown,
	_root: RootPath,
	lock?: LockText,
): FindingInput[] => {
	if (!isRecord(json) || !isRecord(json.vulnerabilities)) return [];
	const packages = lockedPackages(lock);
	return firstPerKey(
		Object.entries(json.vulnerabilities).flatMap((entry) =>
			npmEntryFindings(entry, packages, lock?.file),
		),
	);
};

/* -------------------------------- pnpm audit -------------------------------- */

/** Installed versions an advisory was found in (one undefined entry when none are listed). */
const pnpmVersions = (adv: Json): Array<string | undefined> => {
	const versions = [
		...new Set(
			arr(adv.findings)
				.filter(isRecord)
				.map((f) => str(f.version))
				.filter((v): v is string => !!v),
		),
	];
	return versions.length ? versions : [undefined];
};

const pnpmAdvisoryFindings = (adv: unknown, file?: FilePath): Keyed[] => {
	if (!isRecord(adv)) return [];
	const name = str(adv.module_name) ?? "unknown";
	const url = str(adv.url);
	const id =
		str(adv.github_advisory_id) ?? ghsaOf(url) ?? String(adv.id ?? "unknown");
	const fixed = fixedFromPatched(str(adv.patched_versions));
	return pnpmVersions(adv).map((version) => ({
		key: `${name}|${id}|${version}`,
		finding: vulnFinding({
			auditor: "code.pnpm-audit",
			name,
			version,
			ecosystem: "npm",
			id,
			aliases: strings(adv.cves),
			summary: str(adv.title) ?? id,
			severity: severityOf(adv.severity),
			fixed: fixed ? [fixed] : [],
			file,
			references: jsRefs(url),
			tags: cweTags(strings(adv.cwe)),
		}),
	}));
};

/** Parses `pnpm audit --json` (legacy `advisories` map). */
export const parsePnpmAuditReport = (
	json: unknown,
	_root: RootPath,
	file?: FilePath,
): FindingInput[] => {
	if (!isRecord(json) || !isRecord(json.advisories)) return [];
	return firstPerKey(
		Object.values(json.advisories).flatMap((adv) =>
			pnpmAdvisoryFindings(adv, file),
		),
	);
};

/* --------------------------------- bun audit -------------------------------- */

/** Versions per package in bun.lock. */
const bunLockVersions = (lock?: LockText) => {
	const versions = new Map<PackageName, string[]>();
	if (lock)
		for (const d of parseBunLock(lock.text, lock.file))
			versions.set(d.name, [...(versions.get(d.name) ?? []), d.version]);
	return versions;
};

const isBunAdvisory = (adv: unknown): adv is Json =>
	isRecord(adv) && !!(adv.id || adv.url);

interface BunPackage {
	readonly name: PackageName;
	/** Versions in bun.lock: bun does not print the installed version. */
	readonly known: ReadonlyArray<string>;
	readonly file?: FilePath;
}

const bunAdvisoryFinding = (adv: Json, pkg: BunPackage): Keyed => {
	const url = str(adv.url);
	const id = ghsaOf(url) ?? String(adv.id ?? "unknown");
	const fixed = fixedFromRange(str(adv.vulnerable_versions));
	const finding = vulnFinding({
		auditor: "code.bun-audit",
		name: pkg.name,
		version: pkg.known.length ? pkg.known.join(", ") : undefined,
		ecosystem: "npm",
		id,
		summary: str(adv.title) ?? id,
		severity: severityOf(adv.severity),
		fixed: fixed ? [fixed] : [],
		file: pkg.file,
		references: jsRefs(url),
		tags: cweTags(strings(adv.cwe)),
	});
	return { key: `${pkg.name}|${id}`, finding };
};

/** Parses `bun audit --json` (`{ "<package>": [advisory, ...] }`). */
export const parseBunAuditReport = (
	json: unknown,
	_root: RootPath,
	lock?: LockText,
): FindingInput[] => {
	if (!isRecord(json) || isRecord(json.error)) return [];
	const versions = bunLockVersions(lock);
	return firstPerKey(
		Object.entries(json).flatMap(([name, list]) => {
			const pkg: BunPackage = {
				name,
				known: [...new Set(versions.get(name) ?? [])],
				file: lock?.file,
			};
			return arr(list)
				.filter(isBunAdvisory)
				.map((adv) => bunAdvisoryFinding(adv, pkg));
		}),
	);
};

/* ---------------------------------- runner ---------------------------------- */

interface JsAuditOptions {
	readonly id: string;
	readonly title: string;
	readonly tool: string;
	readonly lockfiles: ReadonlyArray<string>;
	readonly install: string;
	readonly args: ReadonlyArray<string>;
	readonly env?: Record<string, string>;
	readonly parse: (
		json: unknown,
		root: RootPath,
		file: FilePath,
		lockText: FileText,
	) => FindingInput[];
}

/** A lockfile and its package.json, read for copying into a scratch dir. */
interface LockCopy {
	readonly lock: FilePath;
	readonly text: FileText;
	readonly pkg?: FileText;
}

const manifestOf = (lock: FilePath) =>
	dirOf(lock) ? `${dirOf(lock)}/package.json` : "package.json";

const readLockCopy = (ws: Workspace, lock: FilePath) =>
	Effect.gen(function* () {
		const text = yield* ws.readText(lock).pipe(Effect.orElseSucceed(() => ""));
		const pkg = yield* ws
			.readText(manifestOf(lock))
			.pipe(Effect.orElseSucceed(() => undefined));
		return { lock, text, pkg } satisfies LockCopy;
	});

const writeCopies = (scratch: string, copy: LockCopy) =>
	Effect.promise(async () => {
		await writeFile(join(scratch, baseOf(copy.lock)), copy.text);
		if (copy.pkg !== undefined)
			await writeFile(join(scratch, "package.json"), copy.pkg);
	});

/**
 * Runs the audit against copies of the lockfile and package.json only, so the
 * project's .npmrc / bunfig.toml / pnpm-workspace.yaml / hook files are never
 * read (they can set proxies, CAs or run code).
 */
const auditCopy = (
	ctx: AuditContext,
	tool: { readonly opts: JsAuditOptions; readonly bin: ToolBin },
	copy: LockCopy,
) =>
	Effect.gen(function* () {
		const scratch = yield* Effect.promise(() =>
			mkdtemp(join(tmpdir(), "openaudit-js-audit-")),
		);
		// Exit 1 = vulnerabilities found (or an error, reported as JSON).
		return yield* writeCopies(scratch, copy).pipe(
			Effect.andThen(
				run(ctx, [tool.bin, ...tool.opts.args, "--registry", NPM_REGISTRY], {
					cwd: scratch,
					okCodes: [0, 1],
					env: tool.opts.env,
				}),
			),
			Effect.ensuring(
				Effect.promise(() => rm(scratch, { recursive: true, force: true })),
			),
		);
	});

const jsAudit = (opts: JsAuditOptions): Auditor =>
	defineAuditor({
		id: opts.id,
		title: opts.title,
		description: `Runs \`${opts.tool} ${opts.args.join(" ")}\` per lockfile (${opts.lockfiles.join(", ")}). Runs on a temporary copy of the lockfile and package.json, so nothing is installed, no script runs and the project's .npmrc/bunfig/workspace config is never read. The registry is pinned to registry.npmjs.org; private registries are therefore not audited.`,
		categories: ["supply-chain", "security"],
		targets: ["codebase"],
		engine: "external",
		tool: opts.tool,
		network: true,
		defaultEnabled: true,
		run: (ctx) =>
			Effect.gen(function* () {
				const ws = yield* requireWorkspace(ctx);
				const locks = yield* findFiles(ctx, (p) =>
					opts.lockfiles.includes(baseOf(p)),
				);
				if (!locks.length)
					return yield* skip(`No ${opts.lockfiles.join(" / ")} found`);
				const bin = yield* requireTool(ctx, opts.tool, opts.install);
				const findings: FindingInput[] = [];
				for (const lock of locks) {
					const copy = yield* readLockCopy(ws, lock);
					const res = yield* auditCopy(ctx, { opts, bin }, copy);
					const json = yield* parseJson(res.stdout || "{}", opts.tool);
					const err = errorMessage(json);
					if (err)
						return yield* Effect.fail(
							new AuditorError({
								message: `${opts.tool} audit failed: ${truncate(err, 300)}`,
							}),
						);
					findings.push(...opts.parse(json, ws.root, lock, copy.text));
				}
				return findings;
			}),
	});

export const npmAudit = jsAudit({
	id: "code.npm-audit",
	title: "npm audit",
	tool: "npm",
	lockfiles: ["package-lock.json", "npm-shrinkwrap.json"],
	install: "Install Node.js (npm ships with it): https://nodejs.org.",
	args: ["audit", "--json", "--package-lock-only"],
	parse: (json, root, file, text) =>
		parseNpmAuditReport(json, root, { file, text }),
});

export const pnpmAudit = jsAudit({
	id: "code.pnpm-audit",
	title: "pnpm audit",
	tool: "pnpm",
	lockfiles: ["pnpm-lock.yaml"],
	install: "Install: npm install -g pnpm (or corepack enable).",
	// A project's pnpm-workspace.yaml/.npmrc overrides env config but not
	// `--config.*` flags. Never run the project's .pnpmfile.cjs (pnpm loads it
	// even for `audit`) or let its packageManager or devEngines.packageManager
	// field download and switch to another package manager: pnpm 10 obeys
	// manage-package-manager-versions, pnpm 11 only pm-on-fail.
	args: [
		"audit",
		"--json",
		"--config.ignore-pnpmfile=true",
		"--config.manage-package-manager-versions=false",
		"--config.pm-on-fail=ignore",
	],
	env: {
		npm_config_ignore_pnpmfile: "true",
		npm_config_manage_package_manager_versions: "false",
		npm_config_pm_on_fail: "ignore",
	},
	parse: (json, root, file) => parsePnpmAuditReport(json, root, file),
});

export const bunAudit = jsAudit({
	id: "code.bun-audit",
	title: "bun audit",
	tool: "bun",
	lockfiles: ["bun.lock"],
	install:
		"Install: curl -fsSL https://bun.sh/install | bash (bun >= 1.2.15 has `bun audit`).",
	args: ["audit", "--json"],
	parse: (json, root, file, text) =>
		parseBunAuditReport(json, root, { file, text }),
});
