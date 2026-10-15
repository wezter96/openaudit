import type { FindingInput, Workspace } from "@openaudit/core";
import { Effect } from "effect";

import {
	asRecord,
	byDepth,
	type FilePath,
	finding,
	lineOfIndex,
	parseToml,
	readOrEmpty,
	SOURCE_LIMIT,
	type SourceLocation,
	type SourceText,
} from "./strictness-common";
import {
	baseName,
	extOf,
	isGeneratedPath,
	isRecord,
	isTestPath,
	nonCodeMask,
	readTextFiles,
	type SourceFile,
} from "./util";

const MANIFEST_LIMIT = 10;
/** Occurrences at or above which usage counts as widespread. */
const UNSAFE_WIDESPREAD = 10;

/** `"forbid"` out of `"forbid"` or `{ level = "forbid", priority = -1 }`. */
const lintLevel = (v: unknown): string | undefined =>
	typeof v === "string" ? v : isRecord(v) ? lintLevel(v.level) : undefined;

interface CargoManifest {
	readonly path: FilePath;
	readonly doc: Record<string, unknown>;
	readonly isPackage: boolean;
	readonly isWorkspace: boolean;
	/** `[lints]`, `[lints] workspace = true` or `[workspace.lints]`. */
	readonly hasLints: boolean;
	readonly unsafeLevel: string | undefined;
}

const parseCargo = (path: FilePath, text: SourceText): CargoManifest => {
	const doc = parseToml(text);
	const workspace = asRecord(doc.workspace);
	const own = asRecord(doc.lints);
	const shared = asRecord(workspace.lints);
	const rust = (t: Record<string, unknown>) => asRecord(t.rust);
	return {
		path,
		doc,
		isPackage: isRecord(doc.package),
		isWorkspace: isRecord(doc.workspace),
		hasLints: Object.keys(own).length > 0 || Object.keys(shared).length > 0,
		unsafeLevel:
			lintLevel(rust(own).unsafe_code) ?? lintLevel(rust(shared).unsafe_code),
	};
};

const FORBIDDING = new Set(["forbid", "deny"]);

const UNSAFE_USE = /\bunsafe\s*(?:\{|fn\b|impl\b|trait\b|extern\b)/g;
const CRATE_FORBIDS_UNSAFE = /#!\[\s*(?:forbid|deny)\s*\([^)]*\bunsafe_code\b/;
const BLANKET_ALLOW =
	/#!?\[\s*allow\s*\([^\]]*\b(clippy::all|clippy::correctness|warnings)\b/g;

/** Rust source with string literals and comments blanked out. */
const codeOnly = (text: SourceText) => {
	const mask = nonCodeMask(text, "rust");
	let out = "";
	for (let i = 0; i < text.length; i++)
		out += mask[i] && text[i] !== "\n" ? " " : text[i];
	return out;
};

const readManifests = (ws: Workspace, files: ReadonlyArray<FilePath>) =>
	Effect.gen(function* () {
		const paths = files
			.filter((f) => baseName(f) === "Cargo.toml")
			.sort(byDepth)
			.slice(0, MANIFEST_LIMIT);
		const manifests: CargoManifest[] = [];
		for (const p of paths)
			manifests.push(parseCargo(p, yield* readOrEmpty(ws, p)));
		return manifests;
	});

const isRustSource = (p: FilePath) =>
	extOf(p) === "rs" && !isGeneratedPath(p) && !isTestPath(p);

interface UnsafeUsage {
	count: number;
	readonly files: Set<FilePath>;
	first: SourceLocation | undefined;
}

const countUnsafe = (usage: UnsafeUsage, path: FilePath, clean: SourceText) => {
	for (const m of clean.matchAll(UNSAFE_USE)) {
		usage.count++;
		usage.files.add(path);
		usage.first ??= { file: path, line: lineOfIndex(clean, m.index) };
	}
};

const blanketAllowFinding = (
	path: FilePath,
	clean: SourceText,
	m: RegExpExecArray,
): FindingInput =>
	finding("rust-blanket-allow", {
		title: `Blanket \`allow(${m[1]})\` disables lints`,
		severity: "low",
		message: `\`${m[0].trim()}\` switches off ${m[1] === "warnings" ? "every compiler warning" : "clippy's default lint groups"} for the whole crate or module.`,
		remediation:
			"Remove the blanket allow and fix the warnings, or allow individual lints on the specific items that need it, with a reason.",
		file: path,
		line: lineOfIndex(clean, m.index),
		evidence: m[0].trim(),
		tags: ["rust", "clippy"],
	});

/** Counts `unsafe` uses and flags blanket allows, in source order. */
const scanSources = (sources: ReadonlyArray<SourceFile>) => {
	const usage: UnsafeUsage = { count: 0, files: new Set(), first: undefined };
	const blanket: FindingInput[] = [];
	for (const s of sources) {
		const clean = codeOnly(s.text);
		countUnsafe(usage, s.path, clean);
		for (const m of clean.matchAll(BLANKET_ALLOW))
			blanket.push(blanketAllowFinding(s.path, clean, m));
	}
	return { usage, blanket };
};

const noLintsFindings = (
	manifests: ReadonlyArray<CargoManifest>,
	root: CargoManifest,
): FindingInput[] =>
	manifests.some((m) => m.hasLints)
		? []
		: [
				finding("rust-no-lints-table", {
					title: "Cargo.toml has no [lints] table",
					severity: "info",
					message:
						"No Cargo.toml configures [lints] (or [workspace.lints]), so compiler and clippy strictness is whatever each developer's command line says.",
					remediation:
						'Add a [lints] table, e.g. `[lints.rust] unsafe_code = "forbid"` and `[lints.clippy] all = { level = "warn", priority = -1 }`, and inherit it in workspace members with `[lints] workspace = true`.',
					file: root.path,
					references: [
						"https://doc.rust-lang.org/cargo/reference/manifest.html#the-lints-section",
					],
					tags: ["rust"],
				}),
			];

const forbidsUnsafe = (
	manifests: ReadonlyArray<CargoManifest>,
	sources: ReadonlyArray<SourceFile>,
) =>
	manifests.some((m) => m.unsafeLevel && FORBIDDING.has(m.unsafeLevel)) ||
	sources.some((s) => CRATE_FORBIDS_UNSAFE.test(s.text));

const unsafeNotForbiddenFinding = (
	root: CargoManifest,
	unsafeCount: number,
): FindingInput =>
	finding("rust-unsafe-not-forbidden", {
		title: "unsafe_code is not forbidden or denied",
		severity: "info",
		message:
			unsafeCount === 0
				? "The code uses no `unsafe`, but nothing stops it from being introduced: unsafe_code is not set to forbid/deny."
				: "unsafe_code is not set to forbid/deny, so new `unsafe` code is not flagged in review or CI.",
		remediation:
			'Set `[lints.rust] unsafe_code = "forbid"` (or "deny" with narrow `#[allow(unsafe_code)]` where required), or `#![forbid(unsafe_code)]` in the crate root.',
		file: root.path,
		tags: ["rust", "unsafe"],
	});

const unsafeUsageFindings = ({
	count,
	files,
	first,
}: UnsafeUsage): FindingInput[] => {
	if (count <= 0 || !first) return [];
	return [
		finding("rust-unsafe-usage", {
			title: `${count} unsafe block${count === 1 ? "" : "s"} or item${count === 1 ? "" : "s"}`,
			severity: count >= UNSAFE_WIDESPREAD ? "low" : "info",
			message: `Found ${count} \`unsafe\` block(s), fn(s) or impl(s) in ${files.size} file(s).${count >= UNSAFE_WIDESPREAD ? " Widespread unsafe code multiplies the surface for memory-safety bugs." : ""}`,
			remediation:
				"Keep unsafe code small and isolated behind safe APIs, document each block with a `// SAFETY:` comment, and run Miri over it.",
			file: first.file,
			line: first.line,
			confidence: "medium",
			tags: ["rust", "unsafe"],
		}),
	];
};

/** Release-profile settings worth an info finding, in report order. */
const PROFILE_CHECKS: ReadonlyArray<{
	readonly rule: string;
	readonly flags: (release: Record<string, unknown>) => boolean;
	readonly title: string;
	readonly message: string;
	readonly remediation: string;
}> = [
	{
		rule: "rust-panic-abort",
		flags: (release) => release.panic === "abort",
		title: 'Release profile sets panic = "abort"',
		message:
			'`[profile.release] panic = "abort"` skips unwinding: destructors do not run on panic, `catch_unwind` and panic-isolating test harnesses do not work, and a panic in any thread ends the process.',
		remediation:
			"Fine for many binaries; make sure nothing relies on Drop for cleanup or on catching panics at a boundary.",
	},
	{
		rule: "rust-release-overflow-checks-off",
		flags: (release) => release["overflow-checks"] !== true,
		title: "Integer overflow checks are off in release builds",
		message:
			"`[profile.release] overflow-checks` is not enabled, so arithmetic overflow silently wraps in release builds while panicking in debug builds.",
		remediation:
			"Set `overflow-checks = true` under `[profile.release]` for code that handles untrusted sizes or money, or use checked/saturating arithmetic.",
	},
];

const profileFindings = (
	m: CargoManifest,
	root: CargoManifest,
): FindingInput[] => {
	if (!m.isPackage && !m.isWorkspace) return [];
	// Profiles are only honoured in the workspace root manifest.
	if (m !== root && !m.isWorkspace) return [];
	const release = asRecord(asRecord(m.doc.profile).release);
	return PROFILE_CHECKS.filter((c) => c.flags(release)).map((c) =>
		finding(c.rule, {
			title: c.title,
			severity: "info",
			message: c.message,
			remediation: c.remediation,
			file: m.path,
			tags: ["rust"],
		}),
	);
};

export const rustStrictness = (ws: Workspace, files: ReadonlyArray<FilePath>) =>
	Effect.gen(function* () {
		const manifests = yield* readManifests(ws, files);
		const root = manifests[0];
		if (!root) return [];
		const sources = yield* readTextFiles(ws, isRustSource, {
			limit: SOURCE_LIMIT,
		});
		const { usage, blanket } = scanSources(sources);
		return [
			...noLintsFindings(manifests, root),
			...blanket,
			...(forbidsUnsafe(manifests, sources)
				? []
				: [unsafeNotForbiddenFinding(root, usage.count)]),
			...unsafeUsageFindings(usage),
			...manifests.flatMap((m) => profileFindings(m, root)),
		];
	});
