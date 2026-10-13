import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	type Auditor,
	AuditorError,
	defineAuditor,
	type FindingInput,
	requireTool,
	requireWorkspace,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, cweTags, parseJson, severityOf, str } from "../../tool";
import { parseBunLock } from "../dependencies";
import { isRecord, truncate } from "../util";
import {
	baseOf,
	dirOf,
	findFiles,
	fixedFromPatched,
	fixedFromRange,
	ghsaOf,
	NPM_REGISTRY,
	osvUrl,
	run,
	vulnFinding,
} from "./shared";

/* -------------------------------------------------------------------------- */
/*                    npm / pnpm / bun audit (lockfile only)                  */
/* -------------------------------------------------------------------------- */

export interface LockText {
	readonly file: string;
	readonly text: string;
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

const jsRefs = (url: string | undefined, id?: string) => [
	...(url ? [url] : []),
	...(id ? [osvUrl(id)] : []),
];

/** Parses `npm audit --json` (npm v7+: `vulnerabilities` map with `via`). */
export const parseNpmAuditReport = (
	json: unknown,
	_root: string,
	lock?: LockText,
): FindingInput[] => {
	if (!isRecord(json) || !isRecord(json.vulnerabilities)) return [];
	let packages: Record<string, unknown> = {};
	try {
		const parsed: unknown = lock ? JSON.parse(lock.text) : undefined;
		if (isRecord(parsed) && isRecord(parsed.packages))
			packages = parsed.packages;
	} catch {
		// Versions are optional.
	}
	const findings: FindingInput[] = [];
	const seen = new Set<string>();
	for (const [key, entry] of Object.entries(json.vulnerabilities)) {
		if (!isRecord(entry)) continue;
		const node = str(arr(entry.nodes)[0]);
		const locked = node ? packages[node] : undefined;
		const version = isRecord(locked) ? str(locked.version) : undefined;
		const fa = entry.fixAvailable;
		for (const via of arr(entry.via)) {
			// String entries only name another vulnerable package (reported on its own).
			if (!isRecord(via)) continue;
			const name = str(via.name) ?? key;
			const url = str(via.url);
			const id = ghsaOf(url) ?? String(via.source ?? url ?? "unknown");
			const dedupe = `${name}|${id}`;
			if (seen.has(dedupe)) continue;
			seen.add(dedupe);
			const fixed = fixedFromRange(str(via.range));
			const cwes = arr(via.cwe).filter(
				(c): c is string => typeof c === "string",
			);
			findings.push(
				vulnFinding({
					auditor: "code.npm-audit",
					name,
					version,
					ecosystem: "npm",
					id,
					summary: str(via.title) ?? id,
					severity: severityOf(via.severity),
					fixed: fixed ? [fixed] : [],
					fixHint: isRecord(fa)
						? `Upgrade ${str(fa.name) ?? name} to ${str(fa.version) ?? "the latest version"} (npm audit fix${fa.isSemVerMajor ? " --force, a breaking change" : ""}).`
						: fa === true
							? "Run npm audit fix to update to a patched version."
							: undefined,
					file: lock?.file,
					references: jsRefs(url),
					tags: cweTags(cwes),
				}),
			);
		}
	}
	return findings;
};

/** Parses `pnpm audit --json` (legacy `advisories` map). */
export const parsePnpmAuditReport = (
	json: unknown,
	_root: string,
	file?: string,
): FindingInput[] => {
	if (!isRecord(json) || !isRecord(json.advisories)) return [];
	const findings: FindingInput[] = [];
	const seen = new Set<string>();
	for (const adv of Object.values(json.advisories)) {
		if (!isRecord(adv)) continue;
		const name = str(adv.module_name) ?? "unknown";
		const url = str(adv.url);
		const id =
			str(adv.github_advisory_id) ?? ghsaOf(url) ?? String(adv.id ?? "unknown");
		const cves = arr(adv.cves).filter(
			(c): c is string => typeof c === "string",
		);
		const cwes = arr(adv.cwe).filter((c): c is string => typeof c === "string");
		const fixed = fixedFromPatched(str(adv.patched_versions));
		const versions = [
			...new Set(
				arr(adv.findings)
					.filter(isRecord)
					.map((f) => str(f.version))
					.filter((v): v is string => !!v),
			),
		];
		for (const version of versions.length ? versions : [undefined]) {
			const dedupe = `${name}|${id}|${version}`;
			if (seen.has(dedupe)) continue;
			seen.add(dedupe);
			findings.push(
				vulnFinding({
					auditor: "code.pnpm-audit",
					name,
					version,
					ecosystem: "npm",
					id,
					aliases: cves,
					summary: str(adv.title) ?? id,
					severity: severityOf(adv.severity),
					fixed: fixed ? [fixed] : [],
					file,
					references: jsRefs(url),
					tags: cweTags(cwes),
				}),
			);
		}
	}
	return findings;
};

/** Parses `bun audit --json` (`{ "<package>": [advisory, ...] }`). */
export const parseBunAuditReport = (
	json: unknown,
	_root: string,
	lock?: LockText,
): FindingInput[] => {
	if (!isRecord(json) || isRecord(json.error)) return [];
	const versions = new Map<string, string[]>();
	if (lock)
		for (const d of parseBunLock(lock.text, lock.file))
			versions.set(d.name, [...(versions.get(d.name) ?? []), d.version]);
	const findings: FindingInput[] = [];
	const seen = new Set<string>();
	for (const [name, list] of Object.entries(json)) {
		for (const adv of arr(list)) {
			if (!isRecord(adv) || (!adv.id && !adv.url)) continue;
			const url = str(adv.url);
			const id = ghsaOf(url) ?? String(adv.id ?? "unknown");
			if (seen.has(`${name}|${id}`)) continue;
			seen.add(`${name}|${id}`);
			const fixed = fixedFromRange(str(adv.vulnerable_versions));
			const cwes = arr(adv.cwe).filter(
				(c): c is string => typeof c === "string",
			);
			const known = [...new Set(versions.get(name) ?? [])];
			findings.push(
				vulnFinding({
					auditor: "code.bun-audit",
					name,
					// bun does not print the installed version; take it from bun.lock.
					version: known.length ? known.join(", ") : undefined,
					ecosystem: "npm",
					id,
					summary: str(adv.title) ?? id,
					severity: severityOf(adv.severity),
					fixed: fixed ? [fixed] : [],
					file: lock?.file,
					references: jsRefs(url),
					tags: cweTags(cwes),
				}),
			);
		}
	}
	return findings;
};

const jsAudit = (opts: {
	id: string;
	title: string;
	tool: string;
	lockfiles: ReadonlyArray<string>;
	install: string;
	args: ReadonlyArray<string>;
	env?: Record<string, string>;
	parse: (
		json: unknown,
		root: string,
		file: string,
		lockText: string,
	) => FindingInput[];
}): Auditor =>
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
					const text = yield* ws
						.readText(lock)
						.pipe(Effect.orElseSucceed(() => ""));
					const manifest = dirOf(lock)
						? `${dirOf(lock)}/package.json`
						: "package.json";
					const pkg = yield* ws
						.readText(manifest)
						.pipe(Effect.orElseSucceed(() => undefined));
					// Run against copies of the lockfile and package.json only, so the
					// project's .npmrc / bunfig.toml / pnpm-workspace.yaml / hook files
					// are never read (they can set proxies, CAs or run code).
					const scratch = yield* Effect.promise(() =>
						mkdtemp(join(tmpdir(), "openaudit-js-audit-")),
					);
					// Exit 1 = vulnerabilities found (or an error, reported as JSON).
					const res = yield* Effect.promise(async () => {
						await writeFile(join(scratch, baseOf(lock)), text);
						if (pkg !== undefined)
							await writeFile(join(scratch, "package.json"), pkg);
					}).pipe(
						Effect.andThen(
							run(ctx, [bin, ...opts.args, "--registry", NPM_REGISTRY], {
								cwd: scratch,
								okCodes: [0, 1],
								env: opts.env,
							}),
						),
						Effect.ensuring(
							Effect.promise(() =>
								rm(scratch, { recursive: true, force: true }),
							),
						),
					);
					const json = yield* parseJson(res.stdout || "{}", opts.tool);
					const err = errorMessage(json);
					if (err)
						return yield* Effect.fail(
							new AuditorError({
								message: `${opts.tool} audit failed: ${truncate(err, 300)}`,
							}),
						);
					findings.push(...opts.parse(json, ws.root, lock, text));
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
	// even for `audit`) or let its packageManager field download another pnpm.
	args: [
		"audit",
		"--json",
		"--config.ignore-pnpmfile=true",
		"--config.manage-package-manager-versions=false",
	],
	env: {
		npm_config_ignore_pnpmfile: "true",
		npm_config_manage_package_manager_versions: "false",
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
