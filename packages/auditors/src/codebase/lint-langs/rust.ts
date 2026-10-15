import {
	type AuditContext,
	AuditorError,
	type Category,
	defineAuditor,
	type FindingInput,
	requireTool,
	requireWorkspace,
	type Severity,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import { arr, jsonLines, num, str } from "../../tool";
import { isRecord, kebab, scrubLine, truncate } from "../util";
import {
	dedupe,
	type FilePath,
	inRoot,
	isMinor,
	manifestDirs,
	run,
	withTempDir,
} from "./shared";

/* -------------------------------------------------------------------------- */
/*                                   clippy                                   */
/* -------------------------------------------------------------------------- */

type ClippyGroup =
	| "correctness"
	| "suspicious"
	| "perf"
	| "complexity"
	| "style"
	| "other";

const words = (s: string) => new Set(s.split(/\s+/).filter(Boolean));

// The JSON `code` field carries only the lint name (`clippy::needless_bool`),
// not its group, so the groups are listed here. Unlisted clippy lints at
// `error` level are deny-by-default, which is the correctness group.
const CLIPPY_CORRECTNESS = words(`
	absurd_extreme_comparisons approx_constant async_yields_async bad_bit_mask
	cast_slice_different_sizes deprecated_semver derive_ord_xor_partial_ord
	derived_hash_with_manual_eq eager_transmute enum_clike_unportable_variant
	eq_op erasing_op fn_address_comparisons if_let_mutex ifs_same_cond
	impl_hash_borrow_with_str_and_bytes impossible_comparisons ineffective_bit_mask
	infinite_iter inherent_to_string_shadow_display inline_fn_without_body
	invalid_null_ptr_usage invalid_regex invisible_characters iter_next_loop
	iter_skip_zero let_underscore_lock lint_groups_priority match_str_case_mismatch
	mem_replace_with_uninit min_max mismatched_target_os mistyped_literal_suffixes
	modulo_one mut_from_ref nonsensical_open_options not_unsafe_ptr_arg_deref
	option_env_unwrap out_of_bounds_indexing overly_complex_bool_expr
	panicking_overflow_checks panicking_unwrap read_line_without_trim
	recursive_format_impl redundant_comparisons reversed_empty_ranges
	self_assignment serde_api_misuse size_of_in_element_count suspicious_splitn
	transmute_null_to_fn transmuting_null uninit_assumed_init uninit_vec
	unit_cmp unit_hash unit_return_expecting_ord unused_io_amount
	while_immutable_condition wrong_transmute zst_offset
`);

const CLIPPY_SUSPICIOUS = words(`
	almost_complete_range arc_with_non_send_sync await_holding_invalid_type
	await_holding_lock await_holding_refcell_ref blanket_clippy_restriction_lints
	cast_abs_to_unsigned cast_enum_constructor cast_enum_truncation
	cast_nan_to_int cast_slice_from_raw_parts crate_in_macro_def
	drop_non_drop duplicate_underscore_argument duration_subsec empty_docs
	empty_loop float_equality_without_abs forget_non_drop four_forward_slashes
	from_raw_with_void_ptr ifs_same_cond incompatible_msrv ineffective_open_options
	inherent_to_string_shadow_display js_unwrap_in_wasm let_underscore_future
	lines_filter_map_ok maybe_misused_cfg misnamed_getters misrefactored_assign_op
	mixed_attributes_style multiple_bound_locations mut_range_bound mutable_key_type
	no_effect_replace non_canonical_clone_impl non_canonical_partial_ord_impl
	octal_escapes path_ends_with_ext possible_missing_comma print_in_format_impl
	rc_clone_in_vec_init repeat_vec_with_capacity single_component_path_imports
	size_of_ref suspicious_arithmetic_impl suspicious_assignment_formatting
	suspicious_command_arg_space suspicious_doc_comments suspicious_else_formatting
	suspicious_map suspicious_op_assign_impl suspicious_open_options
	suspicious_to_owned suspicious_unary_op_formatting swap_ptr_to_ref
	test_attr_in_doctest type_id_on_box unconditional_recursion
	unnecessary_clippy_cfg unused_format_specs
`);

const CLIPPY_PERF = words(`
	box_collection boxed_local cmp_owned collapsible_str_replace drain_collect
	expect_fun_call extend_with_drain format_collect format_in_format_args
	iter_overeager_cloned iter_nth large_const_arrays large_enum_variant
	manual_contains manual_memcpy manual_retain manual_str_repeat manual_try_fold
	map_entry missing_const_for_thread_local needless_collect redundant_allocation
	result_large_err single_char_pattern slow_vector_initialization
	to_string_in_format_args unnecessary_to_owned useless_vec vec_init_then_push
	waker_clone_wake
`);

const CLIPPY_COMPLEXITY = words(`
	bind_instead_of_map borrowed_box bool_comparison clone_on_copy
	collapsible_if collapsible_else_if crosspointer_transmute deprecated_cfg_attr
	double_comparisons explicit_auto_deref explicit_counter_loop filter_next
	identity_op if_same_then_else int_plus_one iter_count let_and_return
	manual_filter manual_flatten manual_map manual_range_contains manual_strip
	map_flatten match_like_matches_macro needless_bool needless_borrow
	needless_lifetimes needless_option_as_deref needless_range_loop
	needless_return nonminimal_bool option_map_unit_fn partialeq_ne_impl
	redundant_closure redundant_slicing search_is_some too_many_arguments
	type_complexity unit_arg unnecessary_cast unnecessary_unwrap useless_conversion
	useless_format
`);

/** Lints about memory safety or unsound `unsafe`. */
const CLIPPY_SECURITY = words(`
	not_unsafe_ptr_arg_deref uninit_assumed_init uninit_vec wrong_transmute
	transmute_null_to_fn transmuting_null mem_replace_with_uninit zst_offset
	cast_ptr_alignment cast_slice_different_sizes transmute_ptr_to_ref
	missing_safety_doc undocumented_unsafe_blocks unsound_collection_transmute
	from_raw_with_void_ptr invalid_null_ptr_usage
`);

const CLIPPY_GROUPS: ReadonlyArray<[ClippyGroup, Set<string>]> = [
	["correctness", CLIPPY_CORRECTNESS],
	["suspicious", CLIPPY_SUSPICIOUS],
	["perf", CLIPPY_PERF],
	["complexity", CLIPPY_COMPLEXITY],
];

// Deny-by-default lints that are not listed above are correctness lints.
const clippyGroup = (name: string, level: string): ClippyGroup =>
	CLIPPY_GROUPS.find(([, lints]) => lints.has(name))?.[0] ??
	(level === "error" ? "correctness" : "style");

/** rustc lints that point at a likely bug rather than tidiness. */
const RUSTC_RELIABILITY = words(`
	arithmetic_overflow unconditional_recursion overflowing_literals
	unused_must_use unused_comparisons unreachable_code unreachable_patterns
	invalid_value unconditional_panic useless_deprecated ambiguous_associated_items
	unused_results_ignored dropping_references forgetting_references
`);

const CLIPPY_SEVERITY: Record<ClippyGroup, Severity> = {
	correctness: "high",
	suspicious: "medium",
	perf: "low",
	complexity: "low",
	style: "info",
	other: "info",
};

/** Category of a clippy lint group, unless it is a security lint. */
const CLIPPY_CATEGORY: Record<ClippyGroup, Category> = {
	correctness: "reliability",
	suspicious: "reliability",
	perf: "performance",
	complexity: "maintainability",
	style: "maintainability",
	other: "maintainability",
};

type Level = "warning" | "error";

/** A compiler message with a primary span inside the workspace. */
interface Diagnostic {
	readonly level: Level;
	readonly message: string;
	readonly isClippy: boolean;
	/** The lint name without `clippy::`, or a rustc code (`E0308`). */
	readonly name: string | undefined;
	readonly span: Record<string, unknown>;
	readonly file: FilePath;
}

interface DiagnosticKind {
	readonly category: Category;
	readonly severity: Severity;
	readonly message: string;
	readonly remediation: string;
	readonly references: string[];
	readonly tags: string[];
}

const ERROR_CODE = /^E\d{4}$/;

const isReported = (level: string | undefined): level is Level =>
	level === "warning" || level === "error";

const compilerMessage = (record: Record<string, unknown>) =>
	record.reason === "compiler-message" && isRecord(record.message)
		? record.message
		: undefined;

const primarySpan = (msg: Record<string, unknown>) =>
	arr(msg.spans).find(
		(s): s is Record<string, unknown> => isRecord(s) && s.is_primary === true,
	);

const codeOf = (msg: Record<string, unknown>) =>
	isRecord(msg.code) ? str(msg.code.code) : undefined;

/** The lint name of a `clippy::` code. */
const clippyLint = (code: string | undefined) =>
	code?.startsWith("clippy::") ? code.slice("clippy::".length) : undefined;

const parseDiagnostic = (
	record: Record<string, unknown>,
	root: FilePath,
): Diagnostic | undefined => {
	const msg = compilerMessage(record);
	if (!msg) return undefined;
	const level = str(msg.level);
	if (!isReported(level)) return undefined;
	const span = primarySpan(msg);
	if (!span) return undefined;
	const file = inRoot(root, str(span.file_name));
	if (!file) return undefined;
	const code = codeOf(msg);
	const lint = clippyLint(code);
	return {
		level,
		message: str(msg.message) ?? "lint",
		isClippy: lint !== undefined,
		name: lint ?? code,
		span,
		file,
	};
};

const isUnnamedError = (d: Diagnostic) => d.level === "error" && !d.name;

/** A compile error (E0xxx) or a rustc error without a lint name. */
const isCompileProblem = (d: Diagnostic) =>
	!d.isClippy && (isUnnamedError(d) || ERROR_CODE.test(d.name ?? ""));

// Deny-level configuration (`-D warnings`, `[lints.clippy]`) is the
// project's own bar: never report it below low.
const denyFloor = (level: Level, severity: Severity): Severity =>
	level === "error" && severity === "info" ? "low" : severity;

const clippyReferences = (lint: string | undefined) =>
	lint
		? [`https://rust-lang.github.io/rust-clippy/master/index.html#${lint}`]
		: [];

const clippyClass = (
	lint: string | undefined,
	group: ClippyGroup,
	level: Level,
): Pick<DiagnosticKind, "category" | "severity"> => {
	const base = CLIPPY_SEVERITY[group];
	const security = CLIPPY_SECURITY.has(lint ?? "");
	return {
		category: security ? "security" : CLIPPY_CATEGORY[group],
		severity: denyFloor(level, security && isMinor(base) ? "medium" : base),
	};
};

const clippyKind = (d: Diagnostic): DiagnosticKind => {
	const lint = d.name ? d.name : undefined;
	const group = lint ? clippyGroup(lint, d.level) : "other";
	return {
		...clippyClass(lint, group, d.level),
		message: `${d.message} (clippy::${d.name}, ${group})`,
		remediation:
			"Apply the suggested change, or silence a justified false positive with a scoped `#[allow(clippy::...)]` that explains why.",
		references: clippyReferences(lint),
		tags: [`clippy-${group}`],
	};
};

const rustcClass = (
	d: Diagnostic,
): Pick<DiagnosticKind, "category" | "severity"> => {
	if (isCompileProblem(d))
		return { category: "reliability", severity: "medium" };
	if (d.level === "error") return { category: "reliability", severity: "high" };
	if (d.name && RUSTC_RELIABILITY.has(d.name))
		return { category: "reliability", severity: "low" };
	return { category: "maintainability", severity: "info" };
};

const rustcKind = (d: Diagnostic): DiagnosticKind => ({
	...rustcClass(d),
	message: `${d.message} (rustc${d.name ? ` ${d.name}` : ""})`,
	remediation: "Fix the diagnostic reported by the compiler.",
	references: [],
	tags: [],
});

const spanEvidence = (span: Record<string, unknown>) => {
	const text = arr(span.text)
		.map((t) => (isRecord(t) ? str(t.text) : undefined))
		.find(Boolean);
	return text ? truncate(scrubLine(text)) : undefined;
};

// A rustc diagnostic without a code is a compile error at `error` level.
const clippyLabel = (d: Diagnostic) =>
	d.name ?? (d.level === "error" ? "compile-error" : "diagnostic");

const clippyFinding = (d: Diagnostic, prefix: FilePath): FindingInput => {
	const kind = d.isClippy ? clippyKind(d) : rustcKind(d);
	return {
		ruleId: `code.clippy/${kebab(clippyLabel(d))}`,
		title: truncate(d.message, 100),
		severity: kind.severity,
		category: kind.category,
		message: kind.message,
		location: {
			file: prefix ? `${prefix}/${d.file}` : d.file,
			line: num(d.span.line_start),
			column: num(d.span.column_start),
		},
		evidence: spanEvidence(d.span),
		remediation: kind.remediation,
		references: kind.references,
		confidence: isCompileProblem(d) ? "low" : "high",
		tags: ["rust", ...kind.tags],
	};
};

/**
 * Parses `cargo clippy --message-format=json` output (one JSON object per
 * line). Only `compiler-message` records with a primary span inside the
 * workspace become findings; duplicates from building one crate for several
 * targets (lib, bin, tests) are collapsed.
 */
export const parseClippyReport = (
	stdout: string,
	root: FilePath,
	prefix: FilePath = "",
): FindingInput[] =>
	dedupe(
		jsonLines(stdout).flatMap((record) => {
			const d = parseDiagnostic(record, root);
			return d ? [clippyFinding(d, prefix)] : [];
		}),
	);

const hasLockfile = (files: ReadonlyArray<FilePath>, dir: FilePath) =>
	files.includes(dir ? `${dir}/Cargo.lock` : "Cargo.lock");

/** Runs clippy on one crate or workspace with a throwaway target dir. */
const lintCrate = (
	ctx: AuditContext,
	cargo: FilePath,
	cwd: FilePath,
	dir: FilePath,
) =>
	Effect.gen(function* () {
		const res = yield* withTempDir((target) =>
			run(
				ctx,
				[
					cargo,
					"clippy",
					"--message-format=json",
					"--all-targets",
					"--workspace",
					"--locked",
					"--offline",
					"--target-dir",
					target,
				],
				{
					cwd,
					// 101 = a lint at deny level or a compile error.
					okCodes: [0, 101],
					env: {
						CARGO_TERM_COLOR: "never",
						CARGO_NET_OFFLINE: "true",
					},
				},
			),
		);
		// Resolution failures print to stderr and never reach build-finished.
		if (!res.stdout.includes('"reason":"build-finished"'))
			return yield* Effect.fail(
				new AuditorError({
					message: `cargo clippy failed: ${truncate(res.stderr || res.stdout, 300)}`,
				}),
			);
		return parseClippyReport(res.stdout, cwd, dir);
	});

export const clippy = defineAuditor({
	id: "code.clippy",
	title: "Rust clippy lints",
	description:
		"Runs `cargo clippy` over Rust crates and workspaces. NOT safe on untrusted code: clippy compiles the crate, so it runs build.rs scripts, proc-macros and any .cargo/config.toml hooks of the target, which is why it is opt-in. Runs with --locked --offline (needs a committed Cargo.lock and already vendored or cached dependencies; nothing is downloaded) and a throwaway target dir. clippy::correctness findings are high, suspicious medium, perf and complexity low, style info; compile errors are reported with low confidence.",
	categories: ["reliability", "maintainability", "performance", "security"],
	targets: ["codebase"],
	engine: "external",
	tool: "cargo",
	defaultEnabled: false,
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const files = yield* ws.files;
			const crates = manifestDirs(files, "Cargo.toml", false);
			if (crates.length === 0)
				return yield* skip("No Cargo.toml in the workspace");
			const locked = crates.filter((d) => hasLockfile(files, d));
			if (locked.length === 0)
				return yield* skip(
					"No Cargo.lock next to Cargo.toml: clippy runs --locked --offline and would otherwise have to resolve (download) dependencies",
				);
			const cargo = yield* requireTool(
				ctx,
				"cargo",
				"Install the Rust toolchain: https://rustup.rs.",
			);
			yield* requireTool(
				ctx,
				"cargo-clippy",
				"Install: rustup component add clippy.",
			);
			const findings: FindingInput[] = [];
			for (const dir of locked)
				findings.push(
					...(yield* lintCrate(ctx, cargo, ws.absolute(dir || "."), dir)),
				);
			return findings;
		}),
});
