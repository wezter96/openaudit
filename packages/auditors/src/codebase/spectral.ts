import { lstat, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, posix } from "node:path";
import {
	defineAuditor,
	type FindingInput,
	requireTool,
	requireWorkspace,
	type Severity,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, num, parseJson, relPath, runTool, str } from "../tool";
import { findSpecFiles, type SpecFile } from "./api";
import { isRecord, kebab, scrubLine, truncate } from "./util";

/**
 * Spectral lint for OpenAPI and AsyncAPI documents.
 *
 * Hardening, all enforced by us rather than by the target:
 * - The target's `.spectral.*` rulesets are never loaded: they may contain
 *   custom JavaScript functions. We write our own ruleset to a temp dir, run
 *   from that dir, and pass it with `--ruleset`.
 * - Spectral resolves `$ref`s itself, and it does fetch `http(s)://` refs
 *   (verified against a local listener), which would let a hostile spec make
 *   the scanner send requests anywhere. The CLI has no switch to turn that
 *   off, so documents with a remote ref, an absolute or workspace-escaping
 *   file ref, or a symlinked ref target are not linted. They are reported as
 *   an info finding instead. Relative refs are followed transitively when
 *   checking.
 */

const RULESET = `extends: ["spectral:oas", "spectral:asyncapi"]\n`;
/** Files per spectral invocation. */
const MAX_FILES = 25;
const MAX_REF_FILES = 60;

const SEVERITY: Readonly<Record<number, Severity>> = {
	0: "medium",
	1: "low",
	2: "info",
	3: "info",
};

/** Parses `spectral lint -f json` output (an array of results). */
export const parseSpectralOutput = (
	json: unknown,
	root: string,
): FindingInput[] => {
	const findings: FindingInput[] = [];
	for (const item of arr(json)) {
		if (!isRecord(item)) continue;
		const code = str(item.code) ?? (num(item.code) ?? "").toString();
		if (!code) continue;
		const message = str(item.message) ?? code;
		const range = isRecord(item.range) ? item.range : {};
		const start = isRecord(range.start) ? range.start : {};
		const line = num(start.line);
		const path = arr(item.path)
			.map((p) => String(p))
			.join(".");
		const schemaError = /schema|invalid-ref|unresolved|parser/i.test(code);
		findings.push({
			ruleId: `code.spectral/${kebab(code) || "unknown"}`,
			title: truncate(message, 120),
			severity: SEVERITY[num(item.severity) ?? 1] ?? "low",
			category: schemaError ? "reliability" : "best-practices",
			message: path ? `${message} (at ${path})` : message,
			location: {
				file: relPath(root, str(item.source)),
				line: line === undefined ? undefined : line + 1,
			},
			evidence: truncate(scrubLine(path ? `${code}: ${path}` : code), 200),
			remediation: `Fix the definition so the Spectral rule "${code}" passes, or see the ruleset docs for the rationale.`,
			references: [
				"https://docs.stoplight.io/docs/spectral/4dec24461f3af-open-api-rules",
			],
			confidence: "high",
			tags: ["spectral", "api"],
		});
	}
	return findings;
};

/* -------------------------------- $ref guard ------------------------------ */

const REF = /["']?\$ref["']?\s*:\s*["']?([^"'\s,}\]]+)/g;
const SCHEME = /^[a-z][a-z0-9+.-]*:/i;

export type RefVerdict =
	| { readonly kind: "ok"; readonly files: ReadonlyArray<string> }
	| { readonly kind: "unsafe"; readonly reason: string };

/**
 * Classifies the `$ref`s of one document: local `#/…` refs are fine, relative
 * file refs that stay inside the workspace are collected for transitive
 * checking, and everything else is unsafe.
 */
export const classifyRefs = (path: string, text: string): RefVerdict => {
	const files = new Set<string>();
	for (const m of text.matchAll(REF)) {
		const ref = m[1] ?? "";
		if (ref.startsWith("#") || ref === "") continue;
		const target = ref.split("#")[0] ?? "";
		if (target === "") continue;
		if (SCHEME.test(target) || target.startsWith("//")) {
			return { kind: "unsafe", reason: `remote $ref ${truncate(target, 80)}` };
		}
		if (target.startsWith("/") || target.includes("\\")) {
			return {
				kind: "unsafe",
				reason: `absolute $ref ${truncate(target, 80)}`,
			};
		}
		let decoded = target;
		try {
			decoded = decodeURIComponent(target);
		} catch {
			return { kind: "unsafe", reason: "undecodable $ref" };
		}
		const resolved = posix.normalize(posix.join(posix.dirname(path), decoded));
		if (resolved.startsWith("..") || resolved.startsWith("/")) {
			return {
				kind: "unsafe",
				reason: `$ref ${truncate(target, 80)} leaves the project`,
			};
		}
		files.add(resolved);
	}
	return { kind: "ok", files: [...files] };
};

/** Checks a spec and every file it references (transitively). */
const guardSpec = (ws: Workspace, spec: SpecFile) =>
	Effect.gen(function* () {
		const seen = new Set<string>([spec.path]);
		const queue: Array<{ path: string; text: string }> = [
			{ path: spec.path, text: spec.text },
		];
		while (queue.length > 0) {
			const cur = queue.shift();
			if (!cur) break;
			const verdict = classifyRefs(cur.path, cur.text);
			if (verdict.kind === "unsafe") {
				return cur.path === spec.path
					? verdict.reason
					: `${verdict.reason} in ${cur.path}`;
			}
			for (const file of verdict.files) {
				if (seen.has(file)) continue;
				seen.add(file);
				if (seen.size > MAX_REF_FILES) return "too many referenced files";
				const link = yield* Effect.promise(() =>
					lstat(ws.absolute(file)).then(
						(s) => s.isSymbolicLink(),
						() => false,
					),
				);
				if (link) return `$ref target ${file} is a symlink`;
				const text = yield* ws
					.readText(file)
					.pipe(Effect.orElseSucceed(() => ""));
				if (text) queue.push({ path: file, text });
			}
		}
		return undefined;
	});

/* --------------------------------- auditor -------------------------------- */

export const spectral = defineAuditor({
	id: "code.spectral",
	title: "Spectral API linting",
	description:
		"Lints OpenAPI, Swagger and AsyncAPI documents with Spectral's built-in oas and asyncapi rulesets. Project .spectral.* rulesets are ignored because they can run custom JavaScript. Documents with remote or out-of-project $refs are not linted, since Spectral would fetch them.",
	categories: ["best-practices", "reliability"],
	targets: ["codebase"],
	engine: "external",
	tool: "spectral",
	defaultEnabled: true,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const bin = yield* requireTool(
				ctx,
				"spectral",
				"Install: npm install -g @stoplight/spectral-cli (https://github.com/stoplightio/spectral).",
			);
			const specs = yield* findSpecFiles(ws);
			if (specs.length === 0) return [];

			const findings: FindingInput[] = [];
			const safe: SpecFile[] = [];
			for (const spec of specs) {
				const problem = yield* guardSpec(ws, spec).pipe(
					Effect.orElseSucceed(() => "references could not be checked"),
				);
				if (problem) {
					findings.push({
						ruleId: "code.spectral/skipped-unsafe-ref",
						title: "API definition not linted: unsafe $ref",
						severity: "info",
						category: "best-practices",
						message: `${spec.path} was not linted because of ${problem}. Spectral would fetch or read it while resolving references.`,
						location: { file: spec.path },
						evidence: truncate(scrubLine(problem), 200),
						remediation:
							"Bundle external references into the project (relative file refs) so the document can be linted offline.",
						confidence: "high",
						tags: ["spectral", "ssrf"],
					});
				} else safe.push(spec);
			}
			if (safe.length === 0) return findings;

			const tmp = yield* Effect.promise(() =>
				mkdtemp(join(tmpdir(), "openaudit-spectral-")),
			);
			return yield* Effect.gen(function* () {
				const ruleset = join(tmp, "ruleset.yaml");
				yield* Effect.promise(() => writeFile(ruleset, RULESET));
				for (let i = 0; i < safe.length; i += MAX_FILES) {
					const batch = safe.slice(i, i + MAX_FILES);
					const res = yield* runTool(
						ctx,
						[
							bin,
							"lint",
							"--ruleset",
							ruleset,
							"-f",
							"json",
							"--quiet",
							"--ignore-unknown-format",
							...batch.map((s) => ws.absolute(s.path)),
						],
						tmp,
						[0, 1],
					);
					const out = res.stdout.trim();
					if (out) {
						findings.push(
							...parseSpectralOutput(
								yield* parseJson(out, "spectral"),
								ws.root,
							),
						);
					}
				}
				return findings;
			}).pipe(
				Effect.ensuring(
					Effect.promise(() => rm(tmp, { recursive: true, force: true })),
				),
			);
		}),
});
