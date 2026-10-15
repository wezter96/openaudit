import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
	type AuditContext,
	AuditorError,
	defineAuditor,
	type FindingInput,
	requireTool,
	requireWorkspace,
	skip,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, parseJson, str } from "../../tool";
import { isRecord, truncate } from "../util";
import {
	type AdvisoryId,
	type FilePath,
	type FileText,
	firstPerKey,
	type Json,
	type PackageName,
	type RootPath,
	strings,
	type ToolBin,
} from "./report";
import {
	baseOf,
	findFiles,
	osvUrl,
	run,
	vulnFinding,
	withTempDir,
} from "./shared";

/* -------------------------------------------------------------------------- */
/*                                  pip-audit                                 */
/* -------------------------------------------------------------------------- */

export interface PinnedRequirements {
	/** `name[extras]==version` lines (markers, hashes and options dropped). */
	readonly pins: ReadonlyArray<string>;
	/** Reasons the file is not fully pinned; empty when it is. */
	readonly unpinned: ReadonlyArray<string>;
}

const PIN =
	/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*===?\s*([A-Za-z0-9][A-Za-z0-9._!+-]*)$/;
// Options that make a file depend on something we do not audit.
const INCLUDE_OPTION = /^(-r|--requirement|-c|--constraint|-e|--editable)\b/;

interface PinsBuilder {
	readonly pins: string[];
	readonly unpinned: string[];
}

/** `name[extras]==version` of an exactly pinned requirement, if it is one. */
const pinOf = (line: string): string | undefined => {
	const req = line
		.replace(/\s+--[\w-]+(=\S+|\s+\S+)?/g, "")
		.split(";")[0]
		?.trim();
	const m = req ? PIN.exec(req) : null;
	return m?.[1] && m[3] ? `${m[1]}${m[2] ?? ""}==${m[3]}` : undefined;
};

const addRequirement = (out: PinsBuilder, line: string): void => {
	if (line.startsWith("-")) {
		// --hash, --index-url, ...: irrelevant to which versions are pinned
		if (INCLUDE_OPTION.test(line))
			out.unpinned.push(
				`${line.split(/\s+/)[0]} includes other files or editable installs`,
			);
		return;
	}
	const pin = pinOf(line);
	if (pin) out.pins.push(pin);
	else out.unpinned.push(truncate(line, 60));
};

/** Extracts exact pins from a requirements.txt without resolving anything. */
export const parseRequirementsPins = (text: FileText): PinnedRequirements => {
	const out: PinsBuilder = { pins: [], unpinned: [] };
	const lines = text.replace(/\\\r?\n/g, " ").split(/\r?\n/);
	for (const raw of lines) {
		const line = raw.replace(/(^|\s)#.*$/, "").trim();
		if (line) addRequirement(out, line);
	}
	return out;
};

/** Exact pins from a `poetry.lock`. */
export const parsePoetryLockPins = (text: FileText): PinnedRequirements => ({
	pins: [
		...text.matchAll(
			/\[\[package\]\]\s*\r?\nname = "([^"]+)"\s*\r?\nversion = "([^"]+)"/g,
		),
	].map((m) => `${m[1]}==${m[2]}`),
	unpinned: [],
});

const sectionPins = (deps: unknown): string[] => {
	if (!isRecord(deps)) return [];
	return Object.entries(deps).flatMap(([name, spec]) => {
		const version = isRecord(spec) ? str(spec.version) : undefined;
		return version && /^===?\d/.test(version)
			? [`${name}==${version.replace(/^===?/, "")}`]
			: [];
	});
};

/** Exact pins from a `Pipfile.lock` (`default` and `develop`). */
export const parsePipfileLockPins = (text: FileText): PinnedRequirements => {
	let json: unknown;
	try {
		json = JSON.parse(text);
	} catch {
		return { pins: [], unpinned: ["Pipfile.lock is not valid JSON"] };
	}
	const pins = isRecord(json)
		? ["default", "develop"].flatMap((section) => sectionPins(json[section]))
		: [];
	return { pins, unpinned: [] };
};

/** The first sentence of an advisory, or its truncated description. */
const pipSummary = (raw: string | undefined, id: AdvisoryId) => {
	const description = (raw ?? "").replace(/\s+/g, " ").trim();
	const first = /^(.{20,160}?[.!?])(\s|$)/.exec(description)?.[1];
	return first ?? (truncate(description, 120) || id);
};

interface PipDependency {
	readonly name: PackageName;
	readonly version?: string;
	readonly file?: FilePath;
}

const pipVulnFinding = (
	v: Json,
	id: AdvisoryId,
	dep: PipDependency,
): FindingInput => {
	const aliases = strings(v.aliases);
	// pip-audit carries no severity; medium is the neutral default.
	return vulnFinding({
		auditor: "code.pip-audit",
		name: dep.name,
		version: dep.version,
		ecosystem: "PyPI",
		id,
		aliases,
		summary: pipSummary(str(v.description), id),
		severity: "medium",
		fixed: strings(v.fix_versions),
		file: dep.file,
		references: [
			osvUrl(id),
			...aliases.filter((a) => a.startsWith("GHSA-")).map(osvUrl),
		],
	});
};

const pipDependencyFindings = (d: Json, file?: FilePath): FindingInput[] => {
	const dep: PipDependency = {
		name: str(d.name) ?? "unknown",
		version: str(d.version),
		file,
	};
	// pip-audit repeats advisories.
	return firstPerKey(
		arr(d.vulns)
			.filter(isRecord)
			.flatMap((v) => {
				const id = str(v.id);
				return id ? [{ key: id, finding: pipVulnFinding(v, id, dep) }] : [];
			}),
	);
};

/** Parses `pip-audit --format json`. */
export const parsePipAuditReport = (
	json: unknown,
	_root: RootPath,
	file?: FilePath,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	return arr(json.dependencies)
		.filter(isRecord)
		.filter((d) => !str(d.skip_reason))
		.flatMap((d) => pipDependencyFindings(d, file));
};

export const isPyRequirements = (p: FilePath) =>
	/(^|\/)requirements[^/]*\.txt$/i.test(p) ||
	/(^|\/)requirements\/[^/]+\.txt$/i.test(p);
const LOCK_PARSERS = new Map<string, (text: FileText) => PinnedRequirements>([
	["poetry.lock", parsePoetryLockPins],
	["Pipfile.lock", parsePipfileLockPins],
]);

const isPythonPins = (p: FilePath) =>
	isPyRequirements(p) || LOCK_PARSERS.has(baseOf(p));

const pinsOf = (file: FilePath, text: FileText) =>
	(LOCK_PARSERS.get(baseOf(file)) ?? parseRequirementsPins)(text);

/** Why a file cannot be audited, or undefined when it is fully pinned. */
const notPinned = (file: FilePath, parsed: PinnedRequirements) =>
	parsed.unpinned.length || !parsed.pins.length
		? `${file}: ${parsed.unpinned[0] ?? "no pinned packages"}`
		: undefined;

const noPinsReason = (ws: Workspace) =>
	Effect.map(ws.files, (files) =>
		files.some((p) => baseOf(p) === "pyproject.toml")
			? "pyproject.toml has no pinned requirements; commit a poetry.lock or a pinned requirements.txt to audit it"
			: "No requirements*.txt, poetry.lock or Pipfile.lock found",
	);

/** Runs pip-audit on a temporary `name==version` file holding the pins. */
const auditPins = (
	ctx: AuditContext,
	bin: ToolBin,
	pins: ReadonlyArray<string>,
) =>
	withTempDir((dir) =>
		Effect.gen(function* () {
			const req = join(dir, "requirements.txt");
			yield* Effect.tryPromise({
				try: () => writeFile(req, `${pins.join("\n")}\n`),
				catch: (cause) =>
					new AuditorError({ message: "Could not write pins", cause }),
			});
			// Exit 1 = vulnerabilities found.
			return yield* run(
				ctx,
				[
					bin,
					"-r",
					req,
					"--no-deps",
					"--disable-pip",
					"--format",
					"json",
					"--progress-spinner",
					"off",
				],
				{ cwd: dir, okCodes: [0, 1] },
			);
		}),
	);

export const pipAudit = defineAuditor({
	id: "code.pip-audit",
	title: "pip-audit (Python vulnerabilities)",
	description:
		"Audits exactly pinned Python requirements (requirements*.txt, poetry.lock, Pipfile.lock) with pip-audit. Pins are rewritten into a temporary name==version file and audited with --no-deps --disable-pip, so nothing is resolved, downloaded or installed and no build script runs. Files that are not fully pinned are skipped.",
	categories: ["supply-chain", "security"],
	targets: ["codebase"],
	engine: "external",
	tool: "pip-audit",
	network: true,
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const files = yield* findFiles(ctx, isPythonPins);
			if (!files.length) return yield* skip(yield* noPinsReason(ws));
			const bin = yield* requireTool(
				ctx,
				"pip-audit",
				"Install: pipx install pip-audit (or uv tool install pip-audit).",
			);
			const findings: FindingInput[] = [];
			const skipped: string[] = [];
			for (const file of files) {
				const parsed = pinsOf(file, yield* ws.readText(file));
				const reason = notPinned(file, parsed);
				if (reason) {
					skipped.push(reason);
					continue;
				}
				const out = yield* auditPins(ctx, bin, parsed.pins);
				if (!out.stdout.trim())
					return yield* Effect.fail(
						new AuditorError({
							message: `pip-audit produced no output: ${truncate(out.stderr, 300)}`,
						}),
					);
				findings.push(
					...parsePipAuditReport(
						yield* parseJson(out.stdout, "pip-audit"),
						ws.root,
						file,
					),
				);
			}
			if (skipped.length === files.length)
				return yield* skip(
					`Not fully pinned, nothing audited (${skipped.join("; ")})`,
				);
			return findings;
		}),
});
