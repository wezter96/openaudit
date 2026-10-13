import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	AuditorError,
	defineAuditor,
	type FindingInput,
	requireTool,
	requireWorkspace,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, parseJson, relPath, runTool, str } from "../tool";
import { isRecord, kebab, truncate } from "./util";

/* -------------------------------------------------------------------------- */
/*                                  mobsfscan                                 */
/* -------------------------------------------------------------------------- */

const MOBSFSCAN_SEVERITY: Record<string, Severity> = {
	ERROR: "high",
	WARNING: "medium",
	// INFO rules mostly report the absence of a hardening measure (root
	// detection, certificate pinning), so they are advisory.
	INFO: "info",
};

/** Findings kept per rule, so one noisy rule cannot drown the report. */
const MAX_PER_RULE = 100;

/** Source markers for Android and iOS projects (matched on workspace files). */
const MOBILE_SOURCE =
	/(^|\/)AndroidManifest\.xml$|(^|\/)Podfile$|\.(swift|kt|m|mm)$/;

export const hasMobileSource = (files: ReadonlyArray<string>): boolean =>
	files.some((f) => MOBILE_SOURCE.test(f));

/**
 * mobsfscan reports some files relative to a truncated absolute path (for
 * example `scan-1234/…/app/AndroidManifest.xml` for `/tmp/scan-1234/…`),
 * so try the root and each of its trailing segments before giving up.
 */
const relativeToRoot = (root: string, file: string): string => {
	const posix = file.split("\\").join("/");
	if (posix.startsWith("/")) return relPath(root, posix) ?? posix;
	const segments = root.split("/").filter(Boolean);
	for (let i = 0; i < segments.length; i++) {
		const prefix = `${segments.slice(i).join("/")}/`;
		if (posix.startsWith(prefix)) return posix.slice(prefix.length);
	}
	return posix.replace(/^\.\//, "");
};

/** `CWE-327: Use of …` and the lowercase `cwe-489` form both become `cwe-N`. */
const cweTag = (value: string | undefined): string[] => {
	const m = value ? /cwe-(\d+)/i.exec(value) : null;
	return m ? [`cwe-${m[1]}`] : [];
};

/** `M5: Insufficient Cryptography` and `m10` become `owasp-mobile-m5`. */
const owaspMobileTag = (value: string | undefined): string[] => {
	const m = value ? /^m(\d{1,2})\b/i.exec(value.trim()) : null;
	return m ? [`owasp-mobile-m${m[1]}`] : [];
};

/** `MSTG-CRYPTO-4` and the legacy `code-2` become `masvs-…` tags. */
const masvsTag = (value: string | undefined): string[] =>
	value?.trim() ? [`masvs-${kebab(value)}`] : [];

const cweNumber = (value: string | undefined) =>
	/cwe-(\d+)/i.exec(value ?? "")?.[1];

/** Parses `mobsfscan --json` output. `root` is the scanned directory. */
export const parseMobsfscanReport = (
	json: unknown,
	root: string,
): FindingInput[] => {
	if (!isRecord(json) || !isRecord(json.results)) return [];
	const findings: FindingInput[] = [];
	for (const [rule, entry] of Object.entries(json.results)) {
		if (!isRecord(entry)) continue;
		const meta = isRecord(entry.metadata) ? entry.metadata : {};
		const severityLabel = (str(meta.severity) ?? "WARNING").toUpperCase();
		const severity = MOBSFSCAN_SEVERITY[severityLabel] ?? "medium";
		const description = str(meta.description) ?? rule;
		const cwe = str(meta.cwe);
		const owasp = str(meta["owasp-mobile"]);
		const masvs = str(meta.masvs);
		const reference = str(meta.reference);
		const cweId = cweNumber(cwe);
		const base = {
			ruleId: `code.mobsfscan/${kebab(rule)}`,
			title: truncate(rule.replace(/_/g, " "), 100),
			severity,
			category: "security" as const,
			message: description,
			remediation: reference
				? `See the referenced OWASP MASTG guidance${masvs ? ` (${masvs})` : ""} for the recommended fix.`
				: "Review the code against the OWASP MASVS requirement for this check.",
			references: [
				...(reference ? [reference] : []),
				...(cweId
					? [`https://cwe.mitre.org/data/definitions/${cweId}.html`]
					: []),
			],
			confidence: severity === "info" ? ("low" as const) : ("medium" as const),
			tags: [...cweTag(cwe), ...owaspMobileTag(owasp), ...masvsTag(masvs)],
		};
		const files = arr(entry.files).filter(isRecord);
		// Rules without file matches (none observed) still surface once.
		if (files.length === 0) {
			findings.push(base);
			continue;
		}
		for (const f of files.slice(0, MAX_PER_RULE)) {
			const path = str(f.file_path);
			const lines = arr(f.match_lines);
			const line = typeof lines[0] === "number" ? lines[0] : undefined;
			const position = arr(f.match_position);
			const column =
				typeof position[0] === "number" && line !== undefined
					? position[0]
					: undefined;
			const match = str(f.match_string)?.trim();
			findings.push({
				...base,
				location: {
					...(path ? { file: relativeToRoot(root, path) } : {}),
					...(line !== undefined ? { line } : {}),
					...(column !== undefined ? { column } : {}),
				},
				...(match ? { evidence: truncate(match) } : {}),
			});
		}
	}
	return findings;
};

export const mobsfscan = defineAuditor({
	id: "code.mobsfscan",
	title: "mobsfscan mobile SAST",
	description:
		"Runs mobsfscan (OWASP MASVS-oriented Semgrep rules bundled with the tool, no registry download) over Android (Java/Kotlin, manifests) and iOS (Swift/Objective-C) source. Only runs when mobile source is detected. Honors the project's .mobsf ignore rules (YAML data).",
	categories: ["security", "privacy"],
	targets: ["codebase"],
	engine: "external",
	tool: "mobsfscan",
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const files = yield* ws.files;
			if (!hasMobileSource(files))
				return yield* skip(
					"No Android or iOS source found (AndroidManifest.xml, Podfile, *.swift, *.kt, *.m)",
				);
			const bin = yield* requireTool(
				ctx,
				"mobsfscan",
				"Install: pipx install mobsfscan (also installs semgrep; https://github.com/MobSF/mobsfscan).",
			);
			// A private dir for the report doubles as cwd, so nothing is read from
			// or written into the target.
			const dir = yield* Effect.tryPromise({
				try: () => mkdtemp(join(tmpdir(), "openaudit-mobsfscan-")),
				catch: (cause) =>
					new AuditorError({ message: "Cannot create temp dir", cause }),
			});
			const report = join(dir, "report.json");
			const text = yield* runTool(
				ctx,
				[bin, "--json", "--no-fail", "-o", report, ws.root],
				dir,
				[0],
			).pipe(
				Effect.andThen(
					Effect.tryPromise({
						try: () => Bun.file(report).text(),
						catch: (cause) =>
							new AuditorError({
								message: "mobsfscan did not write a report",
								cause,
							}),
					}),
				),
				Effect.ensuring(
					Effect.promise(() => rm(dir, { recursive: true, force: true })),
				),
			);
			const json = yield* parseJson(text, "mobsfscan");
			const errors = isRecord(json)
				? arr(json.errors).filter((e): e is string => typeof e === "string")
				: [];
			if (errors.some((e) => /semgrep not found/i.test(e)))
				return yield* skip(
					"mobsfscan needs semgrep on PATH. Install: pipx install mobsfscan (bundles semgrep).",
				);
			for (const e of errors) yield* ctx.log(`code.mobsfscan: ${e}`);
			return parseMobsfscanReport(json, ws.root);
		}),
});
