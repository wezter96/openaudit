import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
	AuditorError,
	defineAuditor,
	type FindingInput,
	requireTool,
	requireWorkspace,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, parseJson, str } from "../../tool";
import { isRecord, truncate } from "../util";
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

/** Extracts exact pins from a requirements.txt without resolving anything. */
export const parseRequirementsPins = (text: string): PinnedRequirements => {
	const pins: string[] = [];
	const unpinned: string[] = [];
	const lines = text.replace(/\\\r?\n/g, " ").split(/\r?\n/);
	for (const raw of lines) {
		const line = raw.replace(/(^|\s)#.*$/, "").trim();
		if (!line) continue;
		if (line.startsWith("-")) {
			if (INCLUDE_OPTION.test(line))
				unpinned.push(
					`${line.split(/\s+/)[0]} includes other files or editable installs`,
				);
			continue; // --hash, --index-url, ...: irrelevant to which versions are pinned
		}
		const req = line
			.replace(/\s+--[\w-]+(=\S+|\s+\S+)?/g, "")
			.split(";")[0]
			?.trim();
		const m = req ? PIN.exec(req) : null;
		if (m?.[1] && m[3]) pins.push(`${m[1]}${m[2] ?? ""}==${m[3]}`);
		else unpinned.push(truncate(line, 60));
	}
	return { pins, unpinned };
};

/** Exact pins from a `poetry.lock`. */
export const parsePoetryLockPins = (text: string): PinnedRequirements => ({
	pins: [
		...text.matchAll(
			/\[\[package\]\]\s*\r?\nname = "([^"]+)"\s*\r?\nversion = "([^"]+)"/g,
		),
	].map((m) => `${m[1]}==${m[2]}`),
	unpinned: [],
});

/** Exact pins from a `Pipfile.lock` (`default` and `develop`). */
export const parsePipfileLockPins = (text: string): PinnedRequirements => {
	let json: unknown;
	try {
		json = JSON.parse(text);
	} catch {
		return { pins: [], unpinned: ["Pipfile.lock is not valid JSON"] };
	}
	const pins: string[] = [];
	if (isRecord(json))
		for (const section of ["default", "develop"]) {
			const deps = json[section];
			if (!isRecord(deps)) continue;
			for (const [name, spec] of Object.entries(deps)) {
				const version = isRecord(spec) ? str(spec.version) : undefined;
				if (version && /^===?\d/.test(version))
					pins.push(`${name}==${version.replace(/^===?/, "")}`);
			}
		}
	return { pins, unpinned: [] };
};

/** Parses `pip-audit --format json`. */
export const parsePipAuditReport = (
	json: unknown,
	_root: string,
	file?: string,
): FindingInput[] => {
	if (!isRecord(json)) return [];
	const findings: FindingInput[] = [];
	for (const d of arr(json.dependencies)) {
		if (!isRecord(d) || str(d.skip_reason)) continue;
		const name = str(d.name) ?? "unknown";
		const version = str(d.version);
		const seen = new Set<string>();
		for (const v of arr(d.vulns)) {
			if (!isRecord(v)) continue;
			const id = str(v.id);
			if (!id || seen.has(id)) continue; // pip-audit repeats advisories
			seen.add(id);
			const aliases = arr(v.aliases).filter(
				(a): a is string => typeof a === "string",
			);
			const description = (str(v.description) ?? "")
				.replace(/\s+/g, " ")
				.trim();
			const first = /^(.{20,160}?[.!?])(\s|$)/.exec(description)?.[1];
			// pip-audit carries no severity; medium is the neutral default.
			findings.push(
				vulnFinding({
					auditor: "code.pip-audit",
					name,
					version,
					ecosystem: "PyPI",
					id,
					aliases,
					summary: first ?? (truncate(description, 120) || id),
					severity: "medium",
					fixed: arr(v.fix_versions).filter(
						(x): x is string => typeof x === "string",
					),
					file,
					references: [
						osvUrl(id),
						...aliases.filter((a) => a.startsWith("GHSA-")).map(osvUrl),
					],
				}),
			);
		}
	}
	return findings;
};

const isPyRequirements = (p: string) =>
	/(^|\/)requirements[^/]*\.txt$/i.test(p) ||
	/(^|\/)requirements\/[^/]+\.txt$/i.test(p);
const PY_LOCKS = new Set(["poetry.lock", "Pipfile.lock"]);

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
			const files = yield* findFiles(
				ctx,
				(p) => isPyRequirements(p) || PY_LOCKS.has(baseOf(p)),
			);
			if (!files.length) {
				const hasPyproject = (yield* ws.files).some(
					(p) => baseOf(p) === "pyproject.toml",
				);
				return yield* skip(
					hasPyproject
						? "pyproject.toml has no pinned requirements; commit a poetry.lock or a pinned requirements.txt to audit it"
						: "No requirements*.txt, poetry.lock or Pipfile.lock found",
				);
			}
			const bin = yield* requireTool(
				ctx,
				"pip-audit",
				"Install: pipx install pip-audit (or uv tool install pip-audit).",
			);
			const findings: FindingInput[] = [];
			const skipped: string[] = [];
			for (const file of files) {
				const text = yield* ws.readText(file);
				const base = baseOf(file);
				const parsed =
					base === "poetry.lock"
						? parsePoetryLockPins(text)
						: base === "Pipfile.lock"
							? parsePipfileLockPins(text)
							: parseRequirementsPins(text);
				if (parsed.unpinned.length || !parsed.pins.length) {
					skipped.push(
						`${file}: ${parsed.unpinned[0] ?? "no pinned packages"}`,
					);
					continue;
				}
				const out = yield* withTempDir((dir) =>
					Effect.gen(function* () {
						const req = join(dir, "requirements.txt");
						yield* Effect.tryPromise({
							try: () => writeFile(req, `${parsed.pins.join("\n")}\n`),
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
