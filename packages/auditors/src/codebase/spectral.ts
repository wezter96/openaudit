import { lstat, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, posix } from "node:path";
import {
	type AuditContext,
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

/** A workspace-relative or absolute file path. */
type FilePath = string;
/** A `$ref` value, or its file part. */
type Ref = string;
/** A Spectral rule code. */
type RuleCode = string;
/** Why a spec is not linted. */
type Reason = string;

const SEVERITY: Readonly<Record<number, Severity>> = {
	0: "medium",
	1: "low",
	2: "info",
	3: "info",
};

/** 1-based line where a result's range starts. */
const startLine = (item: Record<string, unknown>) => {
	const range = isRecord(item.range) ? item.range : {};
	const start = isRecord(range.start) ? range.start : {};
	const line = num(start.line);
	return line === undefined ? undefined : line + 1;
};

const spectralFinding = (
	item: Record<string, unknown>,
	code: RuleCode,
	root: FilePath,
): FindingInput => {
	const message = str(item.message) ?? code;
	const path = arr(item.path)
		.map((p) => String(p))
		.join(".");
	const schemaError = /schema|invalid-ref|unresolved|parser/i.test(code);
	return {
		ruleId: `code.spectral/${kebab(code) || "unknown"}`,
		title: truncate(message, 120),
		severity: SEVERITY[num(item.severity) ?? 1] ?? "low",
		category: schemaError ? "reliability" : "best-practices",
		message: path ? `${message} (at ${path})` : message,
		location: {
			file: relPath(root, str(item.source)),
			line: startLine(item),
		},
		evidence: truncate(scrubLine(path ? `${code}: ${path}` : code), 200),
		remediation: `Fix the definition so the Spectral rule "${code}" passes, or see the ruleset docs for the rationale.`,
		references: [
			"https://docs.stoplight.io/docs/spectral/4dec24461f3af-open-api-rules",
		],
		confidence: "high",
		tags: ["spectral", "api"],
	};
};

/** Parses `spectral lint -f json` output (an array of results). */
export const parseSpectralOutput = (
	json: unknown,
	root: FilePath,
): FindingInput[] => {
	const findings: FindingInput[] = [];
	for (const item of arr(json)) {
		if (!isRecord(item)) continue;
		const code = str(item.code) ?? (num(item.code) ?? "").toString();
		if (code) findings.push(spectralFinding(item, code, root));
	}
	return findings;
};

/* -------------------------------- $ref guard ------------------------------ */

const REF = /["']?\$ref["']?\s*:\s*["']?([^"'\s,}\]]+)/g;
const SCHEME = /^[a-z][a-z0-9+.-]*:/i;

export type RefVerdict =
	| { readonly kind: "ok"; readonly files: ReadonlyArray<string> }
	| { readonly kind: "unsafe"; readonly reason: string };

/** Where one `$ref` leads: a workspace file to check, or why it is unsafe. */
type RefTarget = { readonly file: string } | { readonly unsafe: string };

const isLocalRef = (ref: Ref) => ref.startsWith("#") || ref === "";
const isRemoteRef = (target: Ref) =>
	SCHEME.test(target) || target.startsWith("//");
const isAbsoluteRef = (target: Ref) =>
	target.startsWith("/") || target.includes("\\");
const leavesProject = (resolved: FilePath) =>
	resolved.startsWith("..") || resolved.startsWith("/");

/** Resolves a relative file ref against the document it appears in. */
const resolveRef = (path: FilePath, target: Ref): RefTarget => {
	let decoded = target;
	try {
		decoded = decodeURIComponent(target);
	} catch {
		return { unsafe: "undecodable $ref" };
	}
	const resolved = posix.normalize(posix.join(posix.dirname(path), decoded));
	if (leavesProject(resolved))
		return { unsafe: `$ref ${truncate(target, 80)} leaves the project` };
	return { file: resolved };
};

/** The target of one `$ref` in `path`, or undefined for a ref within the document. */
const refTarget = (path: FilePath, ref: Ref): RefTarget | undefined => {
	if (isLocalRef(ref)) return undefined;
	const target = ref.split("#")[0] ?? "";
	if (target === "") return undefined;
	if (isRemoteRef(target))
		return { unsafe: `remote $ref ${truncate(target, 80)}` };
	if (isAbsoluteRef(target))
		return { unsafe: `absolute $ref ${truncate(target, 80)}` };
	return resolveRef(path, target);
};

/**
 * Classifies the `$ref`s of one document: local `#/…` refs are fine, relative
 * file refs that stay inside the workspace are collected for transitive
 * checking, and everything else is unsafe.
 */
export const classifyRefs = (path: FilePath, text: string): RefVerdict => {
	const files = new Set<string>();
	for (const m of text.matchAll(REF)) {
		const target = refTarget(path, m[1] ?? "");
		if (target === undefined) continue;
		if ("unsafe" in target) return { kind: "unsafe", reason: target.unsafe };
		files.add(target.file);
	}
	return { kind: "ok", files: [...files] };
};

/** A breadth-first walk over a spec and the files it references. */
interface RefWalk {
	readonly ws: Workspace;
	readonly seen: Set<string>;
	readonly queue: Array<{ path: string; text: string }>;
}

const isSymlink = (ws: Workspace, file: FilePath) =>
	Effect.promise(() =>
		lstat(ws.absolute(file)).then(
			(s) => s.isSymbolicLink(),
			() => false,
		),
	);

/** Queues the referenced files not seen yet, or says why the walk must stop. */
const enqueueRefs = (walk: RefWalk, files: ReadonlyArray<FilePath>) =>
	Effect.gen(function* () {
		// The files are distinct, so filtering up front skips the same ones.
		for (const file of files.filter((f) => !walk.seen.has(f))) {
			walk.seen.add(file);
			if (walk.seen.size > MAX_REF_FILES) return "too many referenced files";
			if (yield* isSymlink(walk.ws, file))
				return `$ref target ${file} is a symlink`;
			const text = yield* walk.ws
				.readText(file)
				.pipe(Effect.orElseSucceed(() => ""));
			if (text) walk.queue.push({ path: file, text });
		}
		return undefined;
	});

/** Checks a spec and every file it references (transitively). */
const guardSpec = (ws: Workspace, spec: SpecFile) =>
	Effect.gen(function* () {
		const walk: RefWalk = {
			ws,
			seen: new Set<string>([spec.path]),
			queue: [{ path: spec.path, text: spec.text }],
		};
		for (let cur = walk.queue.shift(); cur; cur = walk.queue.shift()) {
			const verdict = classifyRefs(cur.path, cur.text);
			if (verdict.kind === "unsafe") {
				return cur.path === spec.path
					? verdict.reason
					: `${verdict.reason} in ${cur.path}`;
			}
			const problem = yield* enqueueRefs(walk, verdict.files);
			if (problem) return problem;
		}
		return undefined;
	});

/* --------------------------------- auditor -------------------------------- */

const unsafeRefFinding = (spec: SpecFile, problem: Reason): FindingInput => ({
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

/** Splits specs into those safe to lint and findings for the rest. */
const guardSpecs = (ws: Workspace, specs: ReadonlyArray<SpecFile>) =>
	Effect.gen(function* () {
		const findings: FindingInput[] = [];
		const safe: SpecFile[] = [];
		for (const spec of specs) {
			const problem = yield* guardSpec(ws, spec).pipe(
				Effect.orElseSucceed(() => "references could not be checked"),
			);
			if (problem) findings.push(unsafeRefFinding(spec, problem));
			else safe.push(spec);
		}
		return { findings, safe };
	});

/** Lints `specs` in batches, from a temp dir that holds our own ruleset. */
const lintSpecs = (
	ctx: AuditContext,
	bin: FilePath,
	ws: Workspace,
	specs: ReadonlyArray<SpecFile>,
) =>
	Effect.gen(function* () {
		const tmp = yield* Effect.promise(() =>
			mkdtemp(join(tmpdir(), "openaudit-spectral-")),
		);
		return yield* Effect.gen(function* () {
			const ruleset = join(tmp, "ruleset.yaml");
			yield* Effect.promise(() => writeFile(ruleset, RULESET));
			const findings: FindingInput[] = [];
			for (let i = 0; i < specs.length; i += MAX_FILES) {
				const batch = specs.slice(i, i + MAX_FILES);
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
				if (out)
					findings.push(
						...parseSpectralOutput(yield* parseJson(out, "spectral"), ws.root),
					);
			}
			return findings;
		}).pipe(
			Effect.ensuring(
				Effect.promise(() => rm(tmp, { recursive: true, force: true })),
			),
		);
	});

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
			const { findings, safe } = yield* guardSpecs(ws, specs);
			if (safe.length === 0) return findings;
			return [...findings, ...(yield* lintSpecs(ctx, bin, ws, safe))];
		}),
});
